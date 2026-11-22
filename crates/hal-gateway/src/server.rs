use crate::config::GatewayConfig;
use crate::protocol::{verify_cert_proof, GatewayRequest, GatewayResponse, RemoteAuthHandshake};
use hal_audit::{AuditInput, AuditLog};
use hal_bus::BusClient;
use hal_proto::wire::{read_frame, write_frame, BusRequest, BusResponse};
use hal_proto::{verify_token_signature, AgentAuthKind, AgentPrincipal, TrustDomain};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayError {
    pub code: &'static str,
    pub reason: String,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for GatewayError {}

/// Stateful admission controller enforcing allowlisted remote mTLS identities, CIDR filters,
/// replay resistance, capability bounds, and revocation.
pub struct GatewayState {
    config: GatewayConfig,
    token_secret: Vec<u8>,
    peer_proof_keys: HashMap<String, Vec<u8>>,
    revoked_agents: BTreeSet<String>,
    used_nonces: BTreeSet<String>,
    audit: AuditLog,
    session_seq: u64,
}

impl GatewayState {
    #[must_use]
    pub fn new(config: GatewayConfig, token_secret: Vec<u8>, audit: AuditLog) -> Self {
        Self {
            config,
            token_secret,
            peer_proof_keys: HashMap::new(),
            revoked_agents: BTreeSet::new(),
            used_nonces: BTreeSet::new(),
            audit,
            session_seq: 0,
        }
    }

    pub fn set_peer_key(&mut self, agent_id: impl Into<String>, key: Vec<u8>) {
        self.peer_proof_keys.insert(agent_id.into(), key);
    }

    pub fn revoke_agent(&mut self, agent_id: &str) {
        self.revoked_agents.insert(agent_id.to_string());
    }

    #[must_use]
    pub fn is_revoked(&self, agent_id: &str) -> bool {
        self.revoked_agents.contains(agent_id)
    }

    fn record_auth_audit(
        &mut self,
        now_ms: u64,
        agent_id: &str,
        cert_fp: &str,
        summary: String,
    ) {
        let principal = AgentPrincipal {
            agent_id: agent_id.to_string(),
            trust_domain: TrustDomain::RemoteExternal,
            auth_kind: AgentAuthKind::RemoteGatewayMtls,
            parent_agent_id: None,
            peer_cred_or_cert_fp: cert_fp.to_string(),
        };
        let _ = self.audit.append(AuditInput {
            ts_ms: now_ms,
            principal,
            episode_id: "gateway-auth".to_string(),
            target_path: format!("/agents/{agent_id}/gateway"),
            action: "remote_authenticate".to_string(),
            trigger_event_ids: Vec::new(),
            proposal_id: None,
            decision_summary: summary,
            workspace_snapshot_id: None,
        });
    }

    fn reject(
        &mut self,
        now_ms: u64,
        agent_id: &str,
        cert_fp: &str,
        code: &'static str,
        reason: impl Into<String>,
    ) -> GatewayError {
        let reason = reason.into();
        self.record_auth_audit(now_ms, agent_id, cert_fp, format!("Deny({code}: {reason})"));
        GatewayError { code, reason }
    }

    /// Authenticates a remote peer connection and yields its bound `AgentPrincipal` and session id.
    pub fn authenticate_remote(
        &mut self,
        source_ip: IpAddr,
        handshake: &RemoteAuthHandshake,
    ) -> Result<(AgentPrincipal, String), GatewayError> {
        let cert_fp = format!("mtls:sha256:{}", handshake.cert_sha256);
        let Some(peer) = self.config.find_by_cert(&handshake.cert_sha256).cloned() else {
            return Err(self.reject(
                handshake.now_ms,
                &handshake.claimed_agent_id,
                &cert_fp,
                "GATEWAY_PEER_DENIED",
                format!(
                    "certificate fingerprint '{}' is unknown or disabled",
                    handshake.cert_sha256
                ),
            ));
        };

        if self.revoked_agents.contains(&peer.agent_id) {
            return Err(self.reject(
                handshake.now_ms,
                &peer.agent_id,
                &cert_fp,
                "AGENT_REVOKED",
                format!("remote agent '{}' has been revoked", peer.agent_id),
            ));
        }

        if !peer.allowed_cidrs.iter().any(|c| c.contains(source_ip)) {
            return Err(self.reject(
                handshake.now_ms,
                &peer.agent_id,
                &cert_fp,
                "GATEWAY_CIDR_DENIED",
                format!(
                    "source IP '{source_ip}' outside allowed CIDRs for '{}'",
                    peer.agent_id
                ),
            ));
        }

        if handshake.claimed_agent_id != peer.agent_id {
            return Err(self.reject(
                handshake.now_ms,
                &handshake.claimed_agent_id,
                &cert_fp,
                "IDENTITY_MISMATCH",
                format!(
                    "claimed agent '{}' does not match peer certificate subject '{}'",
                    handshake.claimed_agent_id, peer.agent_id
                ),
            ));
        }

        if handshake.client_nonce.trim().is_empty()
            || !self.used_nonces.insert(format!(
                "{}:{}",
                peer.agent_id, handshake.client_nonce
            ))
        {
            return Err(self.reject(
                handshake.now_ms,
                &peer.agent_id,
                &cert_fp,
                "GATEWAY_REPLAY_DENIED",
                "empty or replayed authentication nonce",
            ));
        }

        if self.config.require_cert_proof {
            let Some(key) = self.peer_proof_keys.get(&peer.agent_id).cloned() else {
                return Err(self.reject(
                    handshake.now_ms,
                    &peer.agent_id,
                    &cert_fp,
                    "GATEWAY_CERT_PROOF_FAILED",
                    format!("no registered proof key for peer '{}'", peer.agent_id),
                ));
            };
            if !verify_cert_proof(
                &key,
                &peer.agent_id,
                &peer.cert_sha256,
                &handshake.client_nonce,
                &handshake.cert_proof_hmac,
            ) {
                return Err(self.reject(
                    handshake.now_ms,
                    &peer.agent_id,
                    &cert_fp,
                    "GATEWAY_CERT_PROOF_FAILED",
                    "peer certificate proof HMAC mismatch",
                ));
            }
        }

        let tok = &handshake.cap_token;
        if !verify_token_signature(tok, &self.token_secret) {
            return Err(self.reject(
                handshake.now_ms,
                &peer.agent_id,
                &cert_fp,
                "INVALID_CAP_TOKEN",
                "capability token HMAC verification failed",
            ));
        }
        if tok.expires_at_ms <= handshake.now_ms {
            return Err(self.reject(
                handshake.now_ms,
                &peer.agent_id,
                &cert_fp,
                "TOKEN_EXPIRED",
                "capability token has expired",
            ));
        }
        if tok.subject_agent_id != peer.agent_id {
            return Err(self.reject(
                handshake.now_ms,
                &peer.agent_id,
                &cert_fp,
                "IDENTITY_MISMATCH",
                format!(
                    "token subject '{}' does not match peer '{}'",
                    tok.subject_agent_id, peer.agent_id
                ),
            ));
        }
        if tok.max_risk_tier > peer.max_risk_tier {
            return Err(self.reject(
                handshake.now_ms,
                &peer.agent_id,
                &cert_fp,
                "RISK_TIER_DENIED",
                format!(
                    "token max_risk_tier {:?} exceeds peer ceiling {:?}",
                    tok.max_risk_tier, peer.max_risk_tier
                ),
            ));
        }

        self.session_seq += 1;
        let session_id = format!("gw_sess_{}", self.session_seq);
        let principal = AgentPrincipal {
            agent_id: peer.agent_id,
            trust_domain: TrustDomain::RemoteExternal,
            auth_kind: AgentAuthKind::RemoteGatewayMtls,
            parent_agent_id: None,
            peer_cred_or_cert_fp: cert_fp.clone(),
        };
        self.record_auth_audit(
            handshake.now_ms,
            &principal.agent_id,
            &cert_fp,
            format!("Authenticated(session={session_id}, source={source_ip})"),
        );
        Ok((principal, session_id))
    }
}

/// Framed blocking client for remote agents connecting to `hal-gateway`.
pub struct GatewayClient {
    stream: TcpStream,
}

impl GatewayClient {
    pub fn connect(addr: SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        Ok(Self { stream })
    }

    pub fn call(&mut self, req: &GatewayRequest) -> io::Result<GatewayResponse> {
        write_frame(&mut self.stream, req)?;
        read_frame(&mut self.stream)
    }

    pub fn authenticate(
        &mut self,
        handshake: RemoteAuthHandshake,
    ) -> io::Result<GatewayResponse> {
        self.call(&GatewayRequest::Authenticate { handshake })
    }
}

/// Running TCP ingress server handle; shuts down accept/worker threads cleanly on drop.
pub struct GatewayServerHandle {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl GatewayServerHandle {
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

impl Drop for GatewayServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Ingress TCP gateway mapping authenticated remote connections onto the privileged `hal-bus` socket.
pub struct GatewayServer;

impl GatewayServer {
    pub fn spawn(
        listen_addr: SocketAddr,
        bus_gateway_socket: PathBuf,
        state: Arc<Mutex<GatewayState>>,
    ) -> io::Result<GatewayServerHandle> {
        let listener = TcpListener::bind(listen_addr)?;
        listener.set_nonblocking(true)?;
        let local_addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let sd = Arc::clone(&shutdown);

        let accept_thread = thread::spawn(move || {
            let mut workers: Vec<JoinHandle<()>> = Vec::new();
            while !sd.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        let st_conn = Arc::clone(&state);
                        let bus_sock = bus_gateway_socket.clone();
                        let sd_conn = Arc::clone(&sd);
                        workers.push(thread::spawn(move || {
                            handle_client(stream, peer_addr, &bus_sock, &st_conn, &sd_conn);
                        }));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        eprintln!("hal-gateway accept error: {e}");
                        thread::sleep(Duration::from_millis(25));
                    }
                }
            }
            for w in workers {
                let _ = w.join();
            }
        });

        Ok(GatewayServerHandle {
            local_addr,
            shutdown,
            accept_thread: Some(accept_thread),
        })
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn gw_err(code: &str, reason: impl Into<String>) -> GatewayResponse {
    GatewayResponse::Error {
        code: code.to_string(),
        reason: reason.into(),
    }
}

fn handle_client(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    bus_gateway_socket: &std::path::Path,
    state: &Arc<Mutex<GatewayState>>,
    shutdown: &AtomicBool,
) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));

    let mut session: Option<(AgentPrincipal, String)> = None;
    let mut bus_client: Option<BusClient> = None;

    while !shutdown.load(Ordering::Relaxed) {
        let req: GatewayRequest = match read_frame(&mut stream) {
            Ok(req) => req,
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };

        let resp = match req {
            GatewayRequest::Authenticate { handshake } => {
                let mut guard = state.lock().expect("GatewayState mutex poisoned");
                match guard.authenticate_remote(peer_addr.ip(), &handshake) {
                    Ok((principal, session_id)) => {
                        session = Some((principal.clone(), session_id.clone()));
                        GatewayResponse::Authenticated {
                            principal,
                            session_id,
                        }
                    }
                    Err(err) => gw_err(err.code, err.reason),
                }
            }
            other => {
                let Some((ref principal, _)) = session else {
                    if write_frame(
                        &mut stream,
                        &gw_err("UNAUTHENTICATED", "must Authenticate before sending gateway calls"),
                    )
                    .is_err()
                    {
                        break;
                    }
                    continue;
                };

                let revoked = {
                    let guard = state.lock().expect("GatewayState mutex poisoned");
                    guard.is_revoked(&principal.agent_id)
                };
                if revoked {
                    if write_frame(
                        &mut stream,
                        &gw_err(
                            "AGENT_REVOKED",
                            format!("remote agent '{}' has been revoked", principal.agent_id),
                        ),
                    )
                    .is_err()
                    {
                        break;
                    }
                    continue;
                }

                if bus_client.is_none() {
                    match BusClient::connect(bus_gateway_socket) {
                        Ok(c) => bus_client = Some(c),
                        Err(e) => {
                            let _ = write_frame(
                                &mut stream,
                                &gw_err("BUS_UNAVAILABLE", format!("failed to connect to hal-bus: {e}")),
                            );
                            break;
                        }
                    }
                }
                let client = bus_client.as_mut().expect("bus_client initialized");

                match other {
                    GatewayRequest::Authenticate { .. } => unreachable!(),
                    GatewayRequest::Ping => match client.call(&BusRequest::Ping) {
                        Ok(BusResponse::Pong { system_mode, .. }) => GatewayResponse::Bus {
                            response: BusResponse::Pong {
                                principal: principal.clone(),
                                system_mode,
                            },
                        },
                        Ok(other_resp) => GatewayResponse::Bus {
                            response: other_resp,
                        },
                        Err(e) => gw_err("BUS_ERROR", e.to_string()),
                    },
                    GatewayRequest::SubmitProposal { proposal, now_ms } => {
                        let ts = if now_ms == 0 { now_unix_ms() } else { now_ms };
                        match client.call(&BusRequest::GatewaySubmitProposal {
                            remote_principal: principal.clone(),
                            proposal,
                            now_ms: ts,
                        }) {
                            Ok(response) => GatewayResponse::Bus { response },
                            Err(e) => gw_err("BUS_ERROR", e.to_string()),
                        }
                    }
                    GatewayRequest::SendIpc {
                        message,
                        from_episode_id,
                        to_episode_id,
                    } => match client.call(&BusRequest::GatewaySendIpc {
                        remote_principal: principal.clone(),
                        message,
                        from_episode_id,
                        to_episode_id,
                    }) {
                        Ok(response) => GatewayResponse::Bus { response },
                        Err(e) => gw_err("BUS_ERROR", e.to_string()),
                    },
                    GatewayRequest::PublishEvent { event, episode_id } => {
                        match client.call(&BusRequest::GatewayPublishEvent {
                            remote_principal: principal.clone(),
                            event,
                            episode_id,
                        }) {
                            Ok(response) => GatewayResponse::Bus { response },
                            Err(e) => gw_err("BUS_ERROR", e.to_string()),
                        }
                    }
                }
            }
        };

        if write_frame(&mut stream, &resp).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::compute_cert_proof;
    use hal_bus::{BusServer, EndpointBinding, HalBusState};
    use hal_os_hal::OsPeerCredProvider;
    use hal_policy::{IpcMatrix, PolicyConfig, PolicyEngine};
    use hal_proto::{sign_token, ActionProposal, CapabilityToken, PolicyDecision, RiskTier};
    use std::path::Path;

    const TOK_SECRET: &[u8] = b"hal-gateway-unit-token-secret-1!";
    const PEER_KEY: &[u8] = b"remote-laptop-01-proof-secret!!";
    const LAPTOP_FP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn unique_tmp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(format!(
            "/tmp/hal_gw_{label}_{}_{}",
            std::process::id(),
            nanos % 1_000_000_000
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn laptop_token(tier: RiskTier) -> CapabilityToken {
        let mut t = CapabilityToken {
            token_id: "tok_remote".into(),
            subject_agent_id: "remote-laptop-01".into(),
            path_patterns: vec!["/work/agents/remote-laptop-01/**".into(), "/habitat/**".into()],
            allowed_ops: vec!["read".into(), "write".into(), "lock".into()],
            max_risk_tier: tier,
            delegation_depth: 0,
            max_delegation_depth: 1,
            expires_at_ms: 99_000_000,
            rate_limit_per_min: 30,
            token_budget: Some(100),
            hmac_sha256: String::new(),
        };
        sign_token(&mut t, TOK_SECRET);
        t
    }

    fn handshake(nonce: &str, cert_proof: String) -> RemoteAuthHandshake {
        RemoteAuthHandshake {
            claimed_agent_id: "remote-laptop-01".into(),
            cert_sha256: LAPTOP_FP.into(),
            client_nonce: nonce.into(),
            cert_proof_hmac: cert_proof,
            cap_token: laptop_token(RiskTier::L2IrreversibleOrExternal),
            now_ms: 10_000,
        }
    }

    #[test]
    fn admission_checks_cidr_proof_replay_and_forbids_unauthenticated_calls() {
        let dir = unique_tmp_dir("auth");
        let cfg = GatewayConfig::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/gateway-peers.toml"),
        )
        .unwrap();
        let matrix = IpcMatrix::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/ipc-matrix.toml"),
        )
        .unwrap();
        let bus_audit = AuditLog::open(dir.join("bus.jsonl")).unwrap();
        let gw_audit = AuditLog::open(dir.join("gw.jsonl")).unwrap();

        let bus_state = Arc::new(Mutex::new(HalBusState::new(
            PolicyEngine::new(PolicyConfig {
                token_secret: TOK_SECRET.to_vec(),
            }),
            matrix,
            bus_audit,
        )));
        let euid = unsafe { libc::geteuid() } as u32;
        let gw_sock = dir.join("gateway.sock");
        let mut bus_handle = BusServer::spawn(
            bus_state,
            vec![(
                gw_sock.clone(),
                EndpointBinding {
                    principal: AgentPrincipal {
                        agent_id: "hal-gateway".into(),
                        trust_domain: TrustDomain::RemoteExternal,
                        auth_kind: AgentAuthKind::RemoteGatewayMtls,
                        parent_agent_id: None,
                        peer_cred_or_cert_fp: "unbound".into(),
                    },
                    expected_uid: Some(euid),
                    is_oob: false,
                    is_watchdog: false,
                    is_gateway: true,
                },
            )],
            Arc::new(OsPeerCredProvider),
        )
        .unwrap();

        let mut gw_state = GatewayState::new(cfg, TOK_SECRET.to_vec(), gw_audit);
        gw_state.set_peer_key("remote-laptop-01", PEER_KEY.to_vec());

        // Reject outside CIDR
        let bad_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
        let err = gw_state
            .authenticate_remote(
                bad_ip,
                &handshake(
                    "n1",
                    compute_cert_proof(PEER_KEY, "remote-laptop-01", LAPTOP_FP, "n1"),
                ),
            )
            .unwrap_err();
        assert_eq!(err.code, "GATEWAY_CIDR_DENIED");

        let shared = Arc::new(Mutex::new(gw_state));
        let mut srv =
            GatewayServer::spawn("127.0.0.1:0".parse().unwrap(), gw_sock, Arc::clone(&shared))
                .unwrap();

        let mut client = GatewayClient::connect(srv.local_addr()).unwrap();
        assert!(matches!(
            client.call(&GatewayRequest::Ping).unwrap(),
            GatewayResponse::Error { ref code, .. } if code == "UNAUTHENTICATED"
        ));

        // Bad cert proof rejected over TCP
        assert!(matches!(
            client
                .authenticate(handshake("n2", "deadbeef".repeat(8)))
                .unwrap(),
            GatewayResponse::Error { ref code, .. } if code == "GATEWAY_CERT_PROOF_FAILED"
        ));

        // Valid auth succeeds
        let proof = compute_cert_proof(PEER_KEY, "remote-laptop-01", LAPTOP_FP, "n3");
        assert!(matches!(
            client.authenticate(handshake("n3", proof.clone())).unwrap(),
            GatewayResponse::Authenticated { .. }
        ));

        // Replay of same nonce rejected
        assert!(matches!(
            client.authenticate(handshake("n3", proof)).unwrap(),
            GatewayResponse::Error { ref code, .. } if code == "GATEWAY_REPLAY_DENIED"
        ));

        // Proposal forwarded to hal-bus under RemoteExternal identity -> L2 approval required
        let resp = client
            .call(&GatewayRequest::SubmitProposal {
                proposal: ActionProposal {
                    proposal_id: "p_gw".into(),
                    episode_id: "ep_gw".into(),
                    agent_id: "remote-laptop-01".into(),
                    cap_token: laptop_token(RiskTier::L2IrreversibleOrExternal),
                    target_path: "/habitat/entry/lock".into(),
                    action: "lock".into(),
                    args: serde_json::json!({"lock": true}),
                    reason: "remote test".into(),
                    trigger_event_ids: vec![],
                },
                now_ms: 10_100,
            })
            .unwrap();
        assert!(matches!(
            resp,
            GatewayResponse::Bus {
                response: BusResponse::ProposalDecision {
                    decision: PolicyDecision::RequireApproval { .. }
                }
            }
        ));

        drop(client);
        srv.shutdown();
        bus_handle.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
