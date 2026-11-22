use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

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
