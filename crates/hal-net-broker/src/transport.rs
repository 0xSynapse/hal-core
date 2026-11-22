use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static CURL_TMP_SEQ: AtomicU64 = AtomicU64::new(1);
const CURL_STATUS_MARKER: &[u8] = b"\n__HAL_HTTP_STATUS__:";

/// Wire request emitted by `hal-net-broker` after allowlist, DLP, quota, and secret injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHttpRequest {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Raw upstream HTTP status & body read back by `hal-net-broker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Transport abstraction allowing real TCP/loopback HTTP tests on Linux and proxied TLS on FreeBSD.
pub trait EgressTransport: Send + Sync {
    fn send(
        &self,
        req: &UpstreamHttpRequest,
        max_response_bytes: usize,
    ) -> Result<UpstreamHttpResponse, String>;
}

/// Real `TcpStream` HTTP/1.1 transport with bounded response size and optional host->SocketAddr overrides.
#[derive(Debug, Clone)]
pub struct LoopbackHttpTransport {
    pub host_overrides: HashMap<String, SocketAddr>,
    pub timeout: Duration,
}

impl Default for LoopbackHttpTransport {
    fn default() -> Self {
        Self {
            host_overrides: HashMap::new(),
            timeout: Duration::from_secs(5),
        }
    }
}

impl EgressTransport for LoopbackHttpTransport {
    fn send(
        &self,
        req: &UpstreamHttpRequest,
        max_response_bytes: usize,
    ) -> Result<UpstreamHttpResponse, String> {
        let mut stream = if let Some(&addr) = self.host_overrides.get(&req.host) {
            TcpStream::connect_timeout(&addr, self.timeout)
                .map_err(|e| format!("upstream connect to {addr} failed: {e}"))?
        } else {
            TcpStream::connect((req.host.as_str(), req.port))
                .map_err(|e| format!("upstream connect to {}:{} failed: {e}", req.host, req.port))?
        };
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("set_read_timeout failed: {e}"))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("set_write_timeout failed: {e}"))?;

        let mut raw_req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            req.method,
            req.path,
            req.host,
            req.body.len()
        )
        .into_bytes();
        for (k, v) in &req.headers {
            raw_req.extend_from_slice(k.as_bytes());
            raw_req.extend_from_slice(b": ");
            raw_req.extend_from_slice(v.as_bytes());
            raw_req.extend_from_slice(b"\r\n");
        }
        raw_req.extend_from_slice(b"\r\n");
        raw_req.extend_from_slice(&req.body);

        stream
            .write_all(&raw_req)
            .and_then(|_| stream.flush())
            .map_err(|e| format!("upstream write failed: {e}"))?;

        let max_total = max_response_bytes.saturating_add(16 * 1024);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len().saturating_add(n) > max_total {
                        return Err(format!(
                            "upstream response exceeded max_response_bytes ({max_response_bytes})"
                        ));
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) => return Err(format!("upstream read failed: {e}")),
            }
        }

        let (head_bytes, body_bytes) = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            (&buf[..pos], &buf[pos + 4..])
        } else if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
            (&buf[..pos], &buf[pos + 2..])
        } else {
            return Err("malformed HTTP response missing header terminator".to_string());
        };

        if body_bytes.len() > max_response_bytes {
            return Err(format!(
                "upstream response body {} exceeds limit {max_response_bytes}",
                body_bytes.len()
            ));
        }

        let head_str = std::str::from_utf8(head_bytes)
            .map_err(|_| "upstream response status header is not UTF-8".to_string())?;
        let status_line = head_str
            .lines()
            .next()
            .ok_or_else(|| "empty HTTP response status line".to_string())?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| format!("invalid HTTP status line '{status_line}'"))?;

        Ok(UpstreamHttpResponse {
            status,
            body: body_bytes.to_vec(),
        })
    }
}

/// Deterministic mock transport capturing wire requests for unit tests.
#[derive(Debug)]
pub struct MockTransport {
    pub sent: Mutex<Vec<UpstreamHttpRequest>>,
    pub status: u16,
    pub body: Vec<u8>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            status: 200,
            body: br#"{"ok":true}"#.to_vec(),
        }
    }
}

impl EgressTransport for MockTransport {
    fn send(
        &self,
        req: &UpstreamHttpRequest,
        max_response_bytes: usize,
    ) -> Result<UpstreamHttpResponse, String> {
        if self.body.len() > max_response_bytes {
            return Err("mock response exceeds max_response_bytes".to_string());
        }
        self.sent
            .lock()
            .expect("MockTransport mutex poisoned")
            .push(req.clone());
        Ok(UpstreamHttpResponse {
            status: self.status,
            body: self.body.clone(),
        })
    }
}

struct TempCurlConfigGuard {
    path: PathBuf,
}

impl Drop for TempCurlConfigGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn escape_curl_config_value(s: &str) -> Result<String, String> {
    if s.contains(['\r', '\n', '\0']) {
        return Err("control character rejected in curl config value".to_string());
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Real external HTTPS egress transport via system `curl` using `0600` config files and stdin body
/// piping so injected credentials never appear on command-line argv.
#[derive(Debug, Clone)]
pub struct CurlHttpsTransport {
    pub timeout: Duration,
    pub require_tls: bool,
    pub allow_insecure_loopback_http: bool,
    pub curl_bin: String,
}

impl Default for CurlHttpsTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            require_tls: true,
            allow_insecure_loopback_http: false,
            curl_bin: "curl".to_string(),
        }
    }
}

impl CurlHttpsTransport {
    pub fn build_url(&self, req: &UpstreamHttpRequest) -> Result<String, String> {
        if req.host.trim().is_empty()
            || req.host.contains(['\r', '\n', '\0', ' ', '/', '@'])
            || req.port == 0
        {
            return Err(format!("invalid upstream host/port '{}:{}'", req.host, req.port));
        }
        if !req.path.starts_with('/') || req.path.contains(['\r', '\n', '\0', ' ']) {
            return Err(format!("invalid upstream path '{}'", req.path));
        }
        let scheme = if self.require_tls {
            "https"
        } else if self.allow_insecure_loopback_http && is_loopback_host(&req.host) {
            "http"
        } else {
            return Err(format!(
                "plain HTTP egress forbidden for non-loopback host '{}'",
                req.host
            ));
        };
        let host_fmt = if req.host.contains(':') {
            format!("[{}]", req.host)
        } else {
            req.host.clone()
        };
        Ok(format!("{scheme}://{host_fmt}:{}{}", req.port, req.path))
    }

    pub fn build_curl_config(
        &self,
        req: &UpstreamHttpRequest,
        max_response_bytes: usize,
    ) -> Result<String, String> {
        if req.method.is_empty() || !req.method.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(format!("invalid HTTP method '{}'", req.method));
        }
        let url = self.build_url(req)?;
        let secs = self.timeout.as_secs().max(1);
        let mut cfg = format!(
            "url = \"{}\"\nrequest = \"{}\"\nconnect-timeout = {secs}\nmax-time = {secs}\nmax-filesize = {max_response_bytes}\nheader = \"Host: {}\"\n",
            escape_curl_config_value(&url)?,
            escape_curl_config_value(&req.method)?,
            escape_curl_config_value(&req.host)?,
        );
        for (k, v) in &req.headers {
            if k.is_empty() || k.contains([':', '\r', '\n', '\0']) {
                return Err(format!("invalid header name '{k}'"));
            }
            let hdr_line = format!("{k}: {v}");
            cfg.push_str(&format!(
                "header = \"{}\"\n",
                escape_curl_config_value(&hdr_line)?
            ));
        }
        Ok(cfg)
    }

    pub fn parse_curl_output(
        raw: &[u8],
        max_response_bytes: usize,
    ) -> Result<UpstreamHttpResponse, String> {
        let Some(pos) = raw
            .windows(CURL_STATUS_MARKER.len())
            .rposition(|w| w == CURL_STATUS_MARKER)
        else {
            return Err("curl output missing HTTP status trailer".to_string());
        };
        let body = &raw[..pos];
        if body.len() > max_response_bytes {
            return Err(format!(
                "upstream response body {} exceeds limit {max_response_bytes}",
                body.len()
            ));
        }
        let status_bytes = &raw[pos + CURL_STATUS_MARKER.len()..];
        let status_str = std::str::from_utf8(status_bytes)
            .map_err(|_| "curl HTTP status is not UTF-8".to_string())?
            .trim();
        let status = status_str
            .parse::<u16>()
            .map_err(|_| format!("invalid curl HTTP status '{status_str}'"))?;
        Ok(UpstreamHttpResponse {
            status,
            body: body.to_vec(),
        })
    }
}

impl EgressTransport for CurlHttpsTransport {
    fn send(
        &self,
        req: &UpstreamHttpRequest,
        max_response_bytes: usize,
    ) -> Result<UpstreamHttpResponse, String> {
        let cfg_text = self.build_curl_config(req, max_response_bytes)?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let seq = CURL_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let cfg_path = std::env::temp_dir().join(format!(
            "hal_curl_cfg_{}_{}_{seq}.txt",
            std::process::id(),
            nanos % 1_000_000_000
        ));

        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&cfg_path)
            .map_err(|e| format!("failed to create curl config: {e}"))?;
        let _guard = TempCurlConfigGuard {
            path: cfg_path.clone(),
        };
        file.write_all(cfg_text.as_bytes())
            .and_then(|_| file.flush())
            .map_err(|e| format!("failed to write curl config: {e}"))?;
        drop(file);

        let mut cmd = Command::new(&self.curl_bin);
        cmd.arg("--silent")
            .arg("--show-error")
            .arg("--max-redirs")
            .arg("0")
            .arg("--config")
            .arg(&cfg_path)
            .arg("--write-out")
            .arg("\n__HAL_HTTP_STATUS__:%{http_code}");
        if self.require_tls {
            cmd.arg("--proto").arg("=https");
        }
        if !req.body.is_empty() {
            cmd.arg("--data-binary").arg("@-");
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn {}: {e}", self.curl_bin))?;
        if !req.body.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(&req.body)
                    .map_err(|e| format!("failed to write request body to curl stdin: {e}"))?;
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed waiting for curl: {e}"))?;
        if !output.status.success() {
            let err_txt = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "curl egress failed (exit={:?}): {}",
                output.status.code(),
                err_txt.trim()
            ));
        }
        Self::parse_curl_output(&output.stdout, max_response_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn curl_transport_validates_urls_escapes_config_and_parses_status() {
        let https_t = CurlHttpsTransport::default();
        let req = UpstreamHttpRequest {
            host: "api.deepseek.com".to_string(),
            port: 443,
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            headers: vec![
                ("Authorization".to_string(), "Bearer sk-test\"quote\\".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body: br#"{"ok":true}"#.to_vec(),
        };
        assert_eq!(
            https_t.build_url(&req).unwrap(),
            "https://api.deepseek.com:443/v1/chat/completions"
        );
        let cfg = https_t.build_curl_config(&req, 4096).unwrap();
        assert!(cfg.contains("header = \"Authorization: Bearer sk-test\\\"quote\\\\\""));

        let bad_http = CurlHttpsTransport {
            require_tls: false,
            allow_insecure_loopback_http: true,
            ..Default::default()
        };
        assert!(bad_http.build_url(&req).is_err());

        let parsed =
            CurlHttpsTransport::parse_curl_output(b"{\"hi\":1}\n__HAL_HTTP_STATUS__:201", 1024)
                .unwrap();
        assert_eq!(parsed.status, 201);
        assert_eq!(parsed.body, b"{\"hi\":1}");
        assert!(CurlHttpsTransport::parse_curl_output(b"0123456\n__HAL_HTTP_STATUS__:200", 4).is_err());

        // Injecting CRLF into header rejected cleanly
        let crlf_req = UpstreamHttpRequest {
            headers: vec![("X-Test".into(), "ok\r\nX-Evil: 1".into())],
            ..req
        };
        assert!(https_t.build_curl_config(&crlf_req, 1024).is_err());
    }

    #[test]
    fn curl_transport_optional_live_loopback_roundtrip_when_curl_installed() {
        if Command::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 2048];
            let mut header_end = None;
            let mut clen = 0usize;
            loop {
                let n = sock.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if header_end.is_none() {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        let head = String::from_utf8_lossy(&buf[..pos]);
                        for line in head.lines() {
                            if let Some((_, v)) = line
                                .split_once(':')
                                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            {
                                clen = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(hend) = header_end {
                    if buf.len() >= hend + clen {
                        break;
                    }
                }
            }
            let raw = String::from_utf8_lossy(&buf);
            assert!(raw.contains("Authorization: Bearer curl-loopback-secret"));
            assert!(raw.contains("hello-body"));
            let body = r#"{"ok":"curl"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).unwrap();
            let _ = sock.shutdown(std::net::Shutdown::Write);
        });

        let transport = CurlHttpsTransport {
            require_tls: false,
            allow_insecure_loopback_http: true,
            ..Default::default()
        };
        let res = transport
            .send(
                &UpstreamHttpRequest {
                    host: "127.0.0.1".into(),
                    port: addr.port(),
                    method: "POST".into(),
                    path: "/test".into(),
                    headers: vec![("Authorization".into(), "Bearer curl-loopback-secret".into())],
                    body: b"hello-body".to_vec(),
                },
                4096,
            )
            .unwrap();
        srv.join().unwrap();
        assert_eq!(res.status, 200);
        assert_eq!(res.body, br#"{"ok":"curl"}"#);
    }
}
