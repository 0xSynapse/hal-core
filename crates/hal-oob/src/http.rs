use crate::pwa::{HAL_KEY_ICON_SVG, HAL_KEY_INDEX_HTML, HAL_KEY_MANIFEST_JSON};
use crate::service::{OobController, OobError};
use hal_proto::SystemMode;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Enforces the OOB isolation invariant: `hal-oob` must NEVER bind wildcard `0.0.0.0` or `::`.
pub fn validate_oob_bind_addr(addr: SocketAddr) -> Result<(), OobError> {
    if addr.ip().is_unspecified() {
        return Err(OobError::InvalidConfig {
            code: "WILDCARD_BIND_FORBIDDEN",
            reason: format!(
                "hal-oob refuses wildcard bind address '{addr}'; bind strictly to mgmt0/loopback IP"
            ),
        });
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct ParsedHttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn parse_headers(head_bytes: &[u8]) -> io::Result<(String, HashMap<String, String>, usize)> {
    let head = std::str::from_utf8(head_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut lines = head.split("\r\n");
    let start_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP start line"))?
        .to_string();
    let mut headers = HashMap::new();
    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_len = val.parse::<usize>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad Content-Length: {e}"))
                })?;
            }
            headers.insert(key, val);
        }
    }
    Ok((start_line, headers, content_len))
}

fn read_http_request(
    stream: &mut TcpStream,
    shutdown: &AtomicBool,
) -> io::Result<Option<ParsedHttpRequest>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut header_end: Option<usize> = None;
    let mut content_len = 0usize;
    let mut start_line = String::new();
    let mut headers = HashMap::new();

    loop {
        match stream.read(&mut tmp) {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                break;
            }
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if buf.is_empty() && shutdown.load(Ordering::Relaxed) {
                    return Ok(None);
                }
                continue;
            }
            Err(e) => return Err(e),
        }

        if header_end.is_none() {
            if let Some(hend) = find_header_end(&buf) {
                let (sl, hdrs, clen) = parse_headers(&buf[..hend - 4])?;
                start_line = sl;
                headers = hdrs;
                content_len = clen;
                header_end = Some(hend);
            }
        }
        if let Some(hend) = header_end {
            if buf.len() >= hend + content_len {
                break;
            }
        }
    }

    let Some(hend) = header_end else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete HTTP request headers",
        ));
    };
    let mut parts = start_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let end = (hend + content_len).min(buf.len());
    Ok(Some(ParsedHttpRequest {
        method,
        target,
        headers,
        body: buf[hend..end].to_vec(),
    }))
}

const HTML_CSP: &str = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

fn send_http_bytes(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) {
    let mut header = format!(
        "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nCache-Control: no-store\r\n",
        body.len()
    );
    for &(k, v) in extra_headers {
        header.push_str(&format!("{k}: {v}\r\n"));
    }
    header.push_str("Connection: close\r\n\r\n");
    let mut frame = Vec::with_capacity(header.len() + body.len());
    frame.extend_from_slice(header.as_bytes());
    frame.extend_from_slice(body);
    let _ = stream.write_all(&frame);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
}

fn send_http_json(stream: &mut TcpStream, status_code: u16, status_text: &str, payload: &Value) {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    send_http_bytes(
        stream,
        status_code,
        status_text,
        "application/json",
        &[],
        &body,
    );
}

fn try_serve_static_pwa(stream: &mut TcpStream, req: &ParsedHttpRequest) -> bool {
    if req.method != "GET" {
        return false;
    }
    let path = req
        .target
        .split_once('?')
        .map_or(req.target.as_str(), |(p, _)| p);
    match path {
        "/" | "/index.html" => {
            send_http_bytes(
                stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                &[("Content-Security-Policy", HTML_CSP)],
                HAL_KEY_INDEX_HTML.as_bytes(),
            );
            true
        }
        "/manifest.json" => {
            send_http_bytes(
                stream,
                200,
                "OK",
                "application/manifest+json; charset=utf-8",
                &[],
                HAL_KEY_MANIFEST_JSON.as_bytes(),
            );
            true
        }
        "/icon.svg" => {
            send_http_bytes(
                stream,
                200,
                "OK",
                "image/svg+xml; charset=utf-8",
                &[],
                HAL_KEY_ICON_SVG.as_bytes(),
            );
            true
        }
        _ => false,
    }
}

fn error_status_for_oob(err: &OobError) -> (u16, &'static str, String, String) {
    match err {
        OobError::Bus { code, reason } => {
            let status = match code.as_str() {
                "UNAUTHORIZED" => (403, "Forbidden"),
                "APPROVAL_NOT_FOUND" => (404, "Not Found"),
                "APPROVAL_ALREADY_RESOLVED" | "LEASE_CONFLICT" | "MODE_CHANGE_DENIED" => {
                    (409, "Conflict")
                }
                _ => (400, "Bad Request"),
            };
            (status.0, status.1, code.clone(), reason.clone())
        }
        OobError::InvalidConfig { code, reason } => {
            (400, "Bad Request", (*code).to_string(), reason.clone())
        }
        other => (500, "Internal Server Error", "OOB_ERROR".into(), other.to_string()),
    }
}

fn parse_json_body(body: &[u8]) -> Result<Value, (u16, &'static str, Value)> {
    if body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(body).map_err(|e| {
        (
            400,
            "Bad Request",
            json!({"code": "INVALID_JSON", "reason": e.to_string()}),
        )
    })
}

fn route_request(ctrl: &OobController, req: &ParsedHttpRequest) -> (u16, &'static str, Value) {
    let (path, query) = req
        .target
        .split_once('?')
        .unwrap_or((req.target.as_str(), ""));

    let res: Result<Value, OobError> = match (req.method.as_str(), path) {
        ("GET", "/api/v1/status") => ctrl
            .status()
            .and_then(|s| serde_json::to_value(s).map_err(|e| OobError::Io(io::Error::other(e)))),
        ("GET", "/api/v1/agents") => ctrl
            .list_agents()
            .map(|(agents, mode)| json!({"system_mode": mode, "agents": agents})),
        ("GET", "/api/v1/approvals") => ctrl
            .list_approvals()
            .map(|approvals| json!({"approvals": approvals})),
        ("GET", "/api/v1/audit/verify") => ctrl.verify_audit().map(|r| {
            json!({
                "record_count": r.record_count,
                "head_seq": r.head_seq,
                "head_hash": r.head_hash,
            })
        }),
        ("GET", "/api/v1/audit/records") => {
            let after_seq = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("after_seq="))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            ctrl.read_audit_records(after_seq)
                .map(|records| json!({"records": records}))
        }
        ("POST", "/api/v1/mode") => {
            let body = match parse_json_body(&req.body) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let Some(mode_str) = body.get("mode").and_then(|v| v.as_str()) else {
                return (
                    400,
                    "Bad Request",
                    json!({"code": "MISSING_MODE", "reason": "JSON body must contain 'mode'"}),
                );
            };
            let mode = match SystemMode::from_str(mode_str) {
                Ok(m) => m,
                Err(e) => {
                    return (
                        400,
                        "Bad Request",
                        json!({"code": "INVALID_MODE", "reason": e}),
                    );
                }
            };
            let reason = body
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("hal-oob-http");
            ctrl.set_mode(mode, reason)
                .map(|updated| json!({"mode": updated}))
        }
        ("POST", "/api/v1/leases/preempt") => {
            let body = match parse_json_body(&req.body) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let Some(resource_path) = body.get("resource_path").and_then(|v| v.as_str()) else {
                return (
                    400,
                    "Bad Request",
                    json!({"code": "MISSING_RESOURCE_PATH", "reason": "body requires 'resource_path'"}),
                );
            };
            let ttl_ms = body.get("ttl_ms").and_then(|v| v.as_u64()).unwrap_or(60_000);
            let now_ms = body
                .get("now_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(now_unix_ms);
            ctrl.preempt_lease(resource_path, ttl_ms, now_ms)
                .map(|(lease, preempted)| json!({"lease": lease, "preempted_lease_id": preempted}))
        }
        ("POST", p) if p.starts_with("/api/v1/agents/") => {
            let tail = &p["/api/v1/agents/".len()..];
            let body = match parse_json_body(&req.body) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            if let Some(id) = tail.strip_suffix("/freeze") {
                let reason = body
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hal-oob-freeze");
                ctrl.freeze_agent(id, reason)
                    .map(|agent_id| json!({"agent_id": agent_id, "frozen": true}))
            } else if let Some(id) = tail.strip_suffix("/unfreeze") {
                ctrl.unfreeze_agent(id)
                    .map(|agent_id| json!({"agent_id": agent_id, "frozen": false}))
            } else if let Some(id) = tail.strip_suffix("/revoke") {
                let reason = body
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("hal-oob-revoke");
                ctrl.revoke_agent(id, reason)
                    .map(|agent_id| json!({"agent_id": agent_id, "revoked": true}))
            } else {
                return (
                    404,
                    "Not Found",
                    json!({"code": "NOT_FOUND", "reason": format!("unknown agent route '{p}'")}),
                );
            }
        }
        ("POST", p) if p.starts_with("/api/v1/approvals/") => {
            let tail = &p["/api/v1/approvals/".len()..];
            let body = match parse_json_body(&req.body) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let now_ms = body
                .get("now_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(now_unix_ms);
            if let Some(id) = tail.strip_suffix("/approve") {
                let note = body
                    .get("note")
                    .and_then(|v| v.as_str())
                    .unwrap_or("approved via hal-oob");
                ctrl.resolve_approval(id, true, note, now_ms)
                    .map(|approval| json!({"approval": approval}))
            } else if let Some(id) = tail.strip_suffix("/reject") {
                let note = body
                    .get("note")
                    .and_then(|v| v.as_str())
                    .unwrap_or("rejected via hal-oob");
                ctrl.resolve_approval(id, false, note, now_ms)
                    .map(|approval| json!({"approval": approval}))
            } else {
                return (
                    404,
                    "Not Found",
                    json!({"code": "NOT_FOUND", "reason": format!("unknown approval route '{p}'")}),
                );
            }
        }
        _ => {
            return (
                404,
                "Not Found",
                json!({"code": "NOT_FOUND", "reason": format!("unknown route {} {}", req.method, path)}),
            );
        }
    };

    match res {
        Ok(val) => (200, "OK", val),
        Err(err) => {
            let (status, text, code, reason) = error_status_for_oob(&err);
            (status, text, json!({"code": code, "reason": reason}))
        }
    }
}

/// Handle for a running `hal-oob` HTTP management server on `mgmt0` / loopback.
pub struct OobHttpServerHandle {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl OobHttpServerHandle {
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for OobHttpServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Out-of-band human sovereignty HTTP/JSON management API bound strictly to non-wildcard IP.
pub struct OobHttpServer;

impl OobHttpServer {
    pub fn spawn(
        bind_addr: SocketAddr,
        auth_token: String,
        controller: Arc<OobController>,
    ) -> Result<OobHttpServerHandle, OobError> {
        validate_oob_bind_addr(bind_addr)?;
        if auth_token.trim().is_empty() {
            return Err(OobError::InvalidConfig {
                code: "EMPTY_OOB_TOKEN",
                reason: "hal-oob HTTP server requires a non-empty auth_token".to_string(),
            });
        }
        let listener = TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = Arc::clone(&shutdown);

        let accept_thread = thread::spawn(move || {
            let mut workers: Vec<JoinHandle<()>> = Vec::new();
            while !sd.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let ctrl = Arc::clone(&controller);
                        let tok = auth_token.clone();
                        let sd_conn = Arc::clone(&sd);
                        workers.push(thread::spawn(move || {
                            if stream.set_nonblocking(false).is_err() {
                                return;
                            }
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                            match read_http_request(&mut stream, &sd_conn) {
                                Ok(Some(req)) => {
                                    if try_serve_static_pwa(&mut stream, &req) {
                                        return;
                                    }
                                    let supplied = req
                                        .headers
                                        .get("x-hal-oob-token")
                                        .map(String::as_bytes)
                                        .unwrap_or(&[]);
                                    if !constant_time_eq(supplied, tok.as_bytes()) {
                                        send_http_json(
                                            &mut stream,
                                            401,
                                            "Unauthorized",
                                            &json!({"code": "UNAUTHORIZED", "reason": "invalid or missing X-Hal-Oob-Token"}),
                                        );
                                    } else {
                                        let (code, text, body) = route_request(&ctrl, &req);
                                        send_http_json(&mut stream, code, text, &body);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    send_http_json(
                                        &mut stream,
                                        400,
                                        "Bad Request",
                                        &json!({"code": "BAD_HTTP_REQUEST", "reason": e.to_string()}),
                                    );
                                }
                            }
                        }));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        eprintln!("hal-oob HTTP accept error: {e}");
                        thread::sleep(Duration::from_millis(25));
                    }
                }
            }
            for w in workers {
                let _ = w.join();
            }
        });

        Ok(OobHttpServerHandle {
            local_addr,
            shutdown,
            accept_thread: Some(accept_thread),
        })
    }
}

/// Minimal std-only HTTP/1.1 client for talking to `OobHttpServer`.
#[derive(Debug, Clone)]
pub struct OobHttpClient {
    addr: SocketAddr,
    auth_token: String,
}

impl OobHttpClient {
    #[must_use]
    pub fn new(addr: SocketAddr, auth_token: impl Into<String>) -> Self {
        Self {
            addr,
            auth_token: auth_token.into(),
        }
    }

    pub fn request_raw(
        &self,
        method: &str,
        path: &str,
        include_token: bool,
    ) -> io::Result<(u16, HashMap<String, String>, Vec<u8>)> {
        self.send_raw(method, path, None, include_token)
    }

    fn send_raw(
        &self,
        method: &str,
        path: &str,
        body_bytes: Option<&[u8]>,
        include_token: bool,
    ) -> io::Result<(u16, HashMap<String, String>, Vec<u8>)> {
        let mut stream = TcpStream::connect(self.addr)?;
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.addr);
        if include_token {
            req.push_str(&format!("X-Hal-Oob-Token: {}\r\n", self.auth_token));
        }
        req.push_str("Connection: close\r\n");
        if let Some(bytes) = body_bytes {
            if !bytes.is_empty() {
                req.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n",
                    bytes.len()
                ));
            }
        }
        req.push_str("\r\n");

        let extra_len = body_bytes.map_or(0, <[u8]>::len);
        let mut frame = Vec::with_capacity(req.len() + extra_len);
        frame.extend_from_slice(req.as_bytes());
        if let Some(bytes) = body_bytes {
            frame.extend_from_slice(bytes);
        }
        stream.write_all(&frame)?;
        stream.flush()?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        let hend = find_header_end(&buf).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed HTTP response from hal-oob",
            )
        })?;
        let (start_line, headers, _) = parse_headers(&buf[..hend - 4])?;
        let status_code = start_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?;
        Ok((status_code, headers, buf[hend..].to_vec()))
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> io::Result<(u16, Value)> {
        let body_bytes = match body {
            Some(v) => Some(
                serde_json::to_vec(v)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            ),
            None => None,
        };
        let (status_code, _, raw_body) =
            self.send_raw(method, path, body_bytes.as_deref(), true)?;
        let json_val: Value = if raw_body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw_body)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        };
        Ok((status_code, json_val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_audit::AuditLog;
    use hal_bus::{BusServer, EndpointBinding, HalBusState};
    use hal_os_hal::OsPeerCredProvider;
    use hal_policy::{IpcMatrix, PolicyConfig, PolicyEngine};
    use hal_proto::{AgentAuthKind, AgentPrincipal, TrustDomain};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    #[test]
    fn rejects_wildcard_bind_enforces_token_and_serves_status() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(format!(
            "/tmp/hal_oob_http_{}_{}",
            std::process::id(),
            nanos % 1_000_000_000
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.jsonl");
        let audit = AuditLog::open(&audit_path).unwrap();
        let matrix = IpcMatrix::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/ipc-matrix.toml"),
        )
        .unwrap();
        let state = Arc::new(Mutex::new(HalBusState::new(
            PolicyEngine::new(PolicyConfig {
                token_secret: b"oob-http-test-secret-key-32byte!".to_vec(),
            }),
            matrix,
            audit,
        )));
        let euid = unsafe { libc::geteuid() } as u32;
        let oob_sock = dir.join("oob.sock");
        let mut bus = BusServer::spawn(
            state,
            vec![(
                oob_sock.clone(),
                EndpointBinding {
                    principal: AgentPrincipal {
                        agent_id: "hal-oob".into(),
                        trust_domain: TrustDomain::ResidentCore,
                        auth_kind: AgentAuthKind::LocalNoIpJail,
                        parent_agent_id: None,
                        peer_cred_or_cert_fp: "unbound".into(),
                    },
                    expected_uid: Some(euid),
                    is_oob: true,
                    is_watchdog: false,
                    is_gateway: false,
                },
            )],
            Arc::new(OsPeerCredProvider),
        )
        .unwrap();

        let ctrl = Arc::new(OobController::new(oob_sock, audit_path));
        let wildcard: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        let err = OobHttpServer::spawn(wildcard, "secret".into(), Arc::clone(&ctrl))
            .err()
            .unwrap();
        assert!(matches!(
            err,
            OobError::InvalidConfig {
                code: "WILDCARD_BIND_FORBIDDEN",
                ..
            }
        ));

        let mut http = OobHttpServer::spawn(
            "127.0.0.1:0".parse().unwrap(),
            "oob-secret-token".into(),
            ctrl,
        )
        .unwrap();

        let bad_client = OobHttpClient::new(http.local_addr(), "wrong-token");
        let (st_unauth, _) = bad_client.request("GET", "/api/v1/status", None).unwrap();
        assert_eq!(st_unauth, 401);

        let good_client = OobHttpClient::new(http.local_addr(), "oob-secret-token");
        let (st_ok, body) = good_client.request("GET", "/api/v1/status", None).unwrap();
        assert_eq!(st_ok, 200);
        assert_eq!(body["system_mode"], "Autonomous");

        // Embedded HAL Key PWA routes serve without token + include strict security headers
        let (st_html, hdrs_html, raw_html) = good_client.request_raw("GET", "/", false).unwrap();
        assert_eq!(st_html, 200);
        assert!(hdrs_html
            .get("content-type")
            .is_some_and(|v| v.contains("text/html")));
        assert_eq!(
            hdrs_html.get("x-frame-options").map(String::as_str),
            Some("DENY")
        );
        assert_eq!(
            hdrs_html.get("x-content-type-options").map(String::as_str),
            Some("nosniff")
        );
        assert!(hdrs_html.contains_key("content-security-policy"));
        let html_str = String::from_utf8(raw_html).unwrap();
        assert!(html_str.contains("HAL Key"));

        let (st_mf, hdrs_mf, raw_mf) = good_client
            .request_raw("GET", "/manifest.json", false)
            .unwrap();
        assert_eq!(st_mf, 200);
        assert!(hdrs_mf
            .get("content-type")
            .is_some_and(|v| v.contains("manifest+json")));
        let mf_json: Value = serde_json::from_slice(&raw_mf).unwrap();
        assert_eq!(mf_json["short_name"], "HAL Key");

        let (st_svg, hdrs_svg, raw_svg) =
            good_client.request_raw("GET", "/icon.svg", false).unwrap();
        assert_eq!(st_svg, 200);
        assert!(hdrs_svg
            .get("content-type")
            .is_some_and(|v| v.contains("image/svg+xml")));
        assert!(String::from_utf8(raw_svg).unwrap().contains("<svg"));

        // API remains strictly gated even when PWA shell is public on mgmt0/wg-oob
        let (st_api_no_tok, _, _) = good_client
            .request_raw("GET", "/api/v1/status", false)
            .unwrap();
        assert_eq!(st_api_no_tok, 401);

        http.shutdown();
        bus.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
