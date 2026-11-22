use crate::allowlist::EgressAllowlist;
use crate::dlp::DlpScanner;
use crate::quota::AgentQuotaTracker;
use crate::secrets::SecretStore;
use crate::transport::{EgressTransport, UpstreamHttpRequest};
use hal_audit::{AuditInput, AuditLog};
use hal_policy::TaintTracker;
use hal_proto::{AgentPrincipal, TaintTag};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

const FORBIDDEN_CLIENT_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
];

/// Logical secretless egress request submitted by an unprivileged agent or sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRequest {
    pub service_id: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Vec<u8>,
}

/// Sanitized response returned from `hal-net-broker`, always carrying `UntrustedWeb` taint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressResponse {
    pub status: u16,
    pub body: String,
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub taint_tags: BTreeSet<TaintTag>,
}

/// Deterministic denial returned by `hal-net-broker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerError {
    pub code: &'static str,
    pub reason: String,
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for BrokerError {}

/// Zero-trust outbound proxy executing inside the `_hal_broker` domain.
pub struct NetBroker<T: EgressTransport> {
    allowlist: EgressAllowlist,
    secrets: SecretStore,
    dlp: DlpScanner,
    quotas: AgentQuotaTracker,
    transport: T,
    audit: AuditLog,
}

impl<T: EgressTransport> NetBroker<T> {
    #[must_use]
    pub fn new(
        allowlist: EgressAllowlist,
        secrets: SecretStore,
        transport: T,
        audit: AuditLog,
    ) -> Self {
        let dlp = DlpScanner::from_config(&allowlist.dlp);
        Self {
            allowlist,
            secrets,
            dlp,
            quotas: AgentQuotaTracker::default(),
            transport,
            audit,
        }
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn log_event(
        &mut self,
        now_ms: u64,
        principal: &AgentPrincipal,
        episode_id: &str,
        service_id: &str,
        action: &str,
        summary: String,
    ) {
        let _ = self.audit.append(AuditInput {
            ts_ms: now_ms,
            principal: principal.clone(),
            episode_id: episode_id.to_string(),
            target_path: format!("/net/broker/{service_id}"),
            action: action.to_string(),
            trigger_event_ids: Vec::new(),
            proposal_id: None,
            decision_summary: summary,
            workspace_snapshot_id: None,
        });
    }

    /// Executes an allowlisted, DLP-scanned, secret-injected, quota-bounded outbound call.
    pub fn execute(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        episode_taints: &BTreeSet<TaintTag>,
        req: &EgressRequest,
        now_ms: u64,
    ) -> Result<EgressResponse, BrokerError> {
        // 1. Lethal Trifecta check before touching allowlist or sockets
        if TaintTracker::is_lethal_trifecta(episode_taints) {
            let reason = format!(
                "lethal trifecta taint conflict blocked brokered egress to '{}'",
                req.service_id
            );
            self.log_event(
                now_ms,
                principal,
                episode_id,
                &req.service_id,
                "broker_egress",
                format!("Deny(TAINT_EXFIL_BLOCKED: {reason})"),
            );
            return Err(BrokerError {
                code: "TAINT_EXFIL_BLOCKED",
                reason,
            });
        }

        // 2. Reject client-supplied credential or CRLF-injected headers
        for (name, val) in &req.headers {
            if name.is_empty()
                || name.contains(['\r', '\n', '\0', ':'])
                || val.contains(['\r', '\n', '\0'])
            {
                let reason = format!("invalid HTTP header syntax on '{}'", name);
                self.log_event(
                    now_ms,
                    principal,
                    episode_id,
                    &req.service_id,
                    "broker_egress",
                    format!("Deny(CREDENTIAL_HEADER_FORBIDDEN: {reason})"),
                );
                return Err(BrokerError {
                    code: "CREDENTIAL_HEADER_FORBIDDEN",
                    reason,
                });
            }
            let lower = name.to_ascii_lowercase();
            if FORBIDDEN_CLIENT_HEADERS.iter().any(|&h| h == lower) {
                let reason = format!(
                    "agent-supplied credential header '{name}' is forbidden in secretless mode"
                );
                self.log_event(
                    now_ms,
                    principal,
                    episode_id,
                    &req.service_id,
                    "broker_egress",
                    format!("Deny(CREDENTIAL_HEADER_FORBIDDEN: {reason})"),
                );
                return Err(BrokerError {
                    code: "CREDENTIAL_HEADER_FORBIDDEN",
                    reason,
                });
            }
        }

        // 3. Validate allowlist (service, agent, method, path, size)
        let rule = self
            .allowlist
            .authorize(
                &principal.agent_id,
                &req.service_id,
                &req.method,
                &req.path,
                req.body.len(),
            )
            .map_err(|reason| BrokerError {
                code: "ALLOWLIST_DENIED",
                reason,
            });
        let rule = match rule {
            Ok(r) => r.clone(),
            Err(err) => {
                self.log_event(
                    now_ms,
                    principal,
                    episode_id,
                    &req.service_id,
                    "broker_egress",
                    format!("Deny({}: {})", err.code, err.reason),
                );
                return Err(err);
            }
        };

        // 4. Outbound DLP scan (never leak raw secret values into errors or audit records!)
        let sealed_values = self.secrets.all_secret_values();
        if let Err(viol) = self.dlp.scan_text("path", &req.path, &sealed_values) {
            let reason = viol.to_string();
            self.log_event(
                now_ms,
                principal,
                episode_id,
                &req.service_id,
                "broker_egress",
                format!("Deny(DLP_SECRET_LEAK_BLOCKED: {reason})"),
            );
            return Err(BrokerError {
                code: "DLP_SECRET_LEAK_BLOCKED",
                reason,
            });
        }
        for (name, val) in &req.headers {
            if let Err(viol) = self.dlp.scan_text(&format!("header:{name}"), val, &sealed_values) {
                let reason = viol.to_string();
                self.log_event(
                    now_ms,
                    principal,
                    episode_id,
                    &req.service_id,
                    "broker_egress",
                    format!("Deny(DLP_SECRET_LEAK_BLOCKED: {reason})"),
                );
                return Err(BrokerError {
                    code: "DLP_SECRET_LEAK_BLOCKED",
                    reason,
                });
            }
        }
        let body_lossy = String::from_utf8_lossy(&req.body);
        if let Err(viol) = self.dlp.scan_text("body", &body_lossy, &sealed_values) {
            let reason = viol.to_string();
            self.log_event(
                now_ms,
                principal,
                episode_id,
                &req.service_id,
                "broker_egress",
                format!("Deny(DLP_SECRET_LEAK_BLOCKED: {reason})"),
            );
            return Err(BrokerError {
                code: "DLP_SECRET_LEAK_BLOCKED",
                reason,
            });
        }

        // 5. Resolve sealed credential before committing quota or connecting
        let mut wire_headers = req.headers.clone();
        if let Some(ref secret_ref) = rule.secret_ref {
            let Some((hname, hval)) = self.secrets.inject_header(secret_ref) else {
                let reason = format!(
                    "required sealed secret '{secret_ref}' is missing from broker SecretStore"
                );
                self.log_event(
                    now_ms,
                    principal,
                    episode_id,
                    &req.service_id,
                    "broker_egress",
                    format!("Deny(SECRET_UNAVAILABLE: {reason})"),
                );
                return Err(BrokerError {
                    code: "SECRET_UNAVAILABLE",
                    reason,
                });
            };
            wire_headers.push((hname, hval));
        }

        // 6. Per-agent outbound rate & byte quota enforcement
        if let Err(qerr) =
            self.quotas
                .check_outbound(&principal.agent_id, req.body.len(), &self.allowlist.quotas, now_ms)
        {
            self.log_event(
                now_ms,
                principal,
                episode_id,
                &req.service_id,
                "broker_egress",
                format!("Deny(AGENT_EGRESS_BUDGET_EXCEEDED: {})", qerr.reason),
            );
            return Err(BrokerError {
                code: "AGENT_EGRESS_BUDGET_EXCEEDED",
                reason: qerr.reason,
            });
        }

        let wire_req = UpstreamHttpRequest {
            host: rule.host.clone(),
            port: rule.port,
            method: req.method.clone(),
            path: req.path.clone(),
            headers: wire_headers,
            body: req.body.clone(),
        };

        let upstream = self
            .transport
            .send(&wire_req, rule.max_response_bytes)
            .map_err(|reason| BrokerError {
                code: "UPSTREAM_TRANSPORT_ERROR",
                reason,
            });
        let upstream = match upstream {
            Ok(resp) => resp,
            Err(err) => {
                self.log_event(
                    now_ms,
                    principal,
                    episode_id,
                    &req.service_id,
                    "broker_egress",
                    format!("Deny({}: {})", err.code, err.reason),
                );
                return Err(err);
            }
        };

        if let Err(qerr) = self.quotas.record_inbound(
            &principal.agent_id,
            upstream.body.len(),
            &self.allowlist.quotas,
        ) {
            self.log_event(
                now_ms,
                principal,
                episode_id,
                &req.service_id,
                "broker_egress",
                format!("Deny(AGENT_EGRESS_BUDGET_EXCEEDED: {})", qerr.reason),
            );
            return Err(BrokerError {
                code: "AGENT_EGRESS_BUDGET_EXCEEDED",
                reason: qerr.reason,
            });
        }

        let clean_body = self
            .secrets
            .scrub_secrets(&String::from_utf8_lossy(&upstream.body));
        let taints = BTreeSet::from([TaintTag::UntrustedWeb]);
        self.log_event(
            now_ms,
            principal,
            episode_id,
            &req.service_id,
            "broker_egress",
            format!(
                "Allow(host={}:{}, status={}, bytes_sent={}, bytes_recv={}, taint=UntrustedWeb)",
                rule.host,
                rule.port,
                upstream.status,
                req.body.len(),
                upstream.body.len()
            ),
        );

        Ok(EgressResponse {
            status: upstream.status,
            body: clean_body,
            bytes_sent: req.body.len(),
            bytes_recv: upstream.body.len(),
            taint_tags: taints,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SealedSecret;
    use crate::transport::{LoopbackHttpTransport, MockTransport};
    use hal_proto::{AgentAuthKind, TrustDomain};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_audit_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hal_broker_{label}_{}_{}.jsonl",
            std::process::id(),
            nanos
        ))
    }

    fn test_principal(id: &str) -> AgentPrincipal {
        AgentPrincipal {
            agent_id: id.to_string(),
            trust_domain: TrustDomain::WorkspaceWorker,
            auth_kind: AgentAuthKind::LocalNoIpJail,
            parent_agent_id: None,
            peer_cred_or_cert_fp: "uid:1003".to_string(),
        }
    }

    fn read_http_request(sock: &mut std::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        let mut header_end = None;
        let mut content_len = 0usize;
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
                        if let Some(val) = line
                            .split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse::<usize>().unwrap_or(0))
                        {
                            content_len = val;
                        }
                    }
                }
            }
            if let Some(hend) = header_end {
                if buf.len() >= hend + content_len {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    #[test]
    fn broker_injects_secret_over_real_tcp_loopback_and_scrubs_echoed_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let raw = read_http_request(&mut sock);
            assert!(raw.contains("Authorization: Bearer s3cr3t-ship-key-987654"));
            assert!(raw.contains("Host: status.ship.local"));
            let reply_body = r#"{"status":"ok","echo":"s3cr3t-ship-key-987654"}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                reply_body.len(),
                reply_body
            );
            sock.write_all(reply.as_bytes()).unwrap();
            let _ = sock.shutdown(std::net::Shutdown::Write);
        });

        let allowlist = EgressAllowlist::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/egress-allowlist.toml"),
        )
        .unwrap();
        let mut secrets = SecretStore::default();
        secrets.insert(
            "ship_status_token",
            SealedSecret::new("Authorization", "Bearer ", "s3cr3t-ship-key-987654"),
        );

        let mut transport = LoopbackHttpTransport::default();
        transport
            .host_overrides
            .insert("status.ship.local".to_string(), addr);

        let audit_path = tmp_audit_path("loopback");
        let audit = AuditLog::open(&audit_path).unwrap();
        let mut broker = NetBroker::new(allowlist, secrets, transport, audit);

        let resp = broker
            .execute(
                &test_principal("agent-coder"),
                "ep_1",
                &BTreeSet::new(),
                &EgressRequest {
                    service_id: "ship_status_api".into(),
                    method: "POST".into(),
                    path: "/v1/telemetry".into(),
                    headers: vec![("Content-Type".into(), "application/json".into())],
                    body: br#"{"temp_c":21.5}"#.to_vec(),
                },
                1_000,
            )
            .unwrap();

        srv.join().unwrap();
        assert_eq!(resp.status, 200);
        assert!(!resp.body.contains("s3cr3t-ship-key-987654"));
        assert!(resp.body.contains("[REDACTED_SECRET]"));
        assert!(resp.taint_tags.contains(&TaintTag::UntrustedWeb));
        let _ = std::fs::remove_file(audit_path);
    }

    #[test]
    fn broker_rejects_client_auth_header_dlp_and_trifecta_without_touching_transport() {
        let allowlist = EgressAllowlist::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/egress-allowlist.toml"),
        )
        .unwrap();
        let mut secrets = SecretStore::default();
        secrets.insert(
            "github_pat",
            SealedSecret::new("Authorization", "Bearer ", "ghp_RealSealedPatToken123456"),
        );
        let audit_path = tmp_audit_path("blocks");
        let audit = AuditLog::open(&audit_path).unwrap();
        let mut broker = NetBroker::new(allowlist, secrets, MockTransport::default(), audit);
        let p = test_principal("agent-coder");

        // Spoofed Authorization header
        let e1 = broker
            .execute(
                &p,
                "ep1",
                &BTreeSet::new(),
                &EgressRequest {
                    service_id: "github_api".into(),
                    method: "POST".into(),
                    path: "/repos/0xSynapse/hal-os".into(),
                    headers: vec![("Authorization".into(), "Bearer fake".into())],
                    body: b"{}".to_vec(),
                },
                10,
            )
            .unwrap_err();
        assert_eq!(e1.code, "CREDENTIAL_HEADER_FORBIDDEN");

        // DLP blocked literal
        let e2 = broker
            .execute(
                &p,
                "ep1",
                &BTreeSet::new(),
                &EgressRequest {
                    service_id: "github_api".into(),
                    method: "POST".into(),
                    path: "/repos/0xSynapse/hal-os".into(),
                    headers: Vec::new(),
                    body: b"leak VAULT_SECRET_CANARY here".to_vec(),
                },
                11,
            )
            .unwrap_err();
        assert_eq!(e2.code, "DLP_SECRET_LEAK_BLOCKED");

        // Lethal Trifecta
        let taints = BTreeSet::from([TaintTag::UntrustedWeb, TaintTag::PrivateVault]);
        let e3 = broker
            .execute(
                &p,
                "ep1",
                &taints,
                &EgressRequest {
                    service_id: "github_api".into(),
                    method: "POST".into(),
                    path: "/repos/0xSynapse/hal-os".into(),
                    headers: Vec::new(),
                    body: b"{\"clean\":true}".to_vec(),
                },
                12,
            )
            .unwrap_err();
        assert_eq!(e3.code, "TAINT_EXFIL_BLOCKED");

        assert!(broker.transport().sent.lock().unwrap().is_empty());
        let _ = HashMap::<String, String>::new();
        let _ = std::fs::remove_file(audit_path);
    }
}
