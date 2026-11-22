use crate::client::{BridgeError, BridgeSession};
use crate::config::BridgeConfig;
use crate::mcp::McpBridgeServer;
use hal_audit::{verify_file, AuditLog};
use hal_bus::{BusServer, BusServerHandle, EndpointBinding, HalBusState};
use hal_gateway::{GatewayConfig, GatewayServer, GatewayServerHandle, GatewayState};
use hal_oob::{OobController, OobHttpClient, OobHttpServer, OobHttpServerHandle};
use hal_os_hal::OsPeerCredProvider;
use hal_policy::{IpcMatrix, PolicyConfig, PolicyEngine};
use hal_proto::wire::BusResponse;
use hal_proto::{
    sign_token, AgentAuthKind, AgentPrincipal, CapabilityToken, PolicyDecision, RiskTier,
    TrustDomain,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_IPC_MATRIX_TOML: &str = include_str!("../../../config/policy/ipc-matrix.toml");
pub const DEMO_LAPTOP_AGENT_ID: &str = "remote-laptop-01";
pub const DEMO_LAPTOP_CERT_FP: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone)]
pub struct TriNodeDemoConfig {
    pub state_dir: PathBuf,
    pub oob_bind: SocketAddr,
    pub gateway_bind: SocketAddr,
    pub oob_token: String,
    pub proof_key: Vec<u8>,
    pub token_secret: Vec<u8>,
    pub seed_sample_l2: bool,
}

impl TriNodeDemoConfig {
    #[must_use]
    pub fn ephemeral(state_dir: impl AsRef<Path>) -> Self {
        Self {
            state_dir: state_dir.as_ref().to_path_buf(),
            oob_bind: "127.0.0.1:0".parse().expect("valid loopback addr"),
            gateway_bind: "127.0.0.1:0".parse().expect("valid loopback addr"),
            oob_token: "hal-key-demo-token".to_string(),
            proof_key: b"hal-bridge-demo-proof-key-32byte".to_vec(),
            token_secret: b"hal-core-demo-token-secret-32by!".to_vec(),
            seed_sample_l2: false,
        }
    }
}

/// Self-contained local tri-node runtime (`HAL Core` + `HAL Key` PWA + generated `hal-bridge` config).
pub struct TriNodeDemoCluster {
    bus: Option<BusServerHandle>,
    gateway: Option<GatewayServerHandle>,
    oob_http: Option<OobHttpServerHandle>,
    gateway_state: Arc<Mutex<GatewayState>>,
    oob_addr: SocketAddr,
    gateway_addr: SocketAddr,
    oob_token: String,
    bridge_config_path: PathBuf,
    audit_log_path: PathBuf,
}

impl TriNodeDemoCluster {
    pub fn start(cfg: TriNodeDemoConfig) -> Result<Self, BridgeError> {
        std::fs::create_dir_all(&cfg.state_dir)?;
        let audit_log_path = cfg.state_dir.join("hal-audit.jsonl");
        let gw_audit_path = cfg.state_dir.join("hal-gateway-audit.jsonl");
        let bus_sock_dir = cfg.state_dir.join("bus");
        std::fs::create_dir_all(&bus_sock_dir)?;

        let bus_audit = AuditLog::open(&audit_log_path)
            .map_err(|e| BridgeError::Protocol(format!("failed to open bus audit log: {e}")))?;
        let gw_audit = AuditLog::open(&gw_audit_path)
            .map_err(|e| BridgeError::Protocol(format!("failed to open gw audit log: {e}")))?;

        let ipc_matrix = IpcMatrix::from_toml_str(DEFAULT_IPC_MATRIX_TOML)
            .map_err(|e| BridgeError::Protocol(format!("invalid embedded ipc-matrix: {e}")))?;
        let policy = PolicyEngine::new(PolicyConfig {
            token_secret: cfg.token_secret.clone(),
        });
        let mut bus_state = HalBusState::new(policy, ipc_matrix, bus_audit);

        // Pre-populate resident HAL Core agents so HAL Key displays active fortress topology.
        for (id, domain) in [
            ("agent-vault", TrustDomain::ResidentCore),
            ("agent-coder", TrustDomain::WorkspaceWorker),
            ("agent-habitat", TrustDomain::ResidentCore),
            ("agent-netsec", TrustDomain::ResidentCore),
            ("agent-research", TrustDomain::UntrustedResearch),
        ] {
            bus_state.registry.register(AgentPrincipal {
                agent_id: id.to_string(),
                trust_domain: domain,
                auth_kind: AgentAuthKind::LocalNoIpJail,
                parent_agent_id: None,
                peer_cred_or_cert_fp: "jail:resident".to_string(),
            });
        }

        let shared_bus = Arc::new(Mutex::new(bus_state));
        let euid = unsafe { libc::geteuid() } as u32;
        let oob_sock = bus_sock_dir.join("oob.sock");
        let gw_sock = bus_sock_dir.join("gateway.sock");

        let endpoints = vec![
            (
                oob_sock.clone(),
                EndpointBinding {
                    principal: AgentPrincipal {
                        agent_id: "hal-oob".to_string(),
                        trust_domain: TrustDomain::ResidentCore,
                        auth_kind: AgentAuthKind::LocalNoIpJail,
                        parent_agent_id: None,
                        peer_cred_or_cert_fp: "unbound".to_string(),
                    },
                    expected_uid: Some(euid),
                    is_oob: true,
                    is_watchdog: false,
                    is_gateway: false,
                },
            ),
            (
                gw_sock.clone(),
                EndpointBinding {
                    principal: AgentPrincipal {
                        agent_id: "hal-gateway".to_string(),
                        trust_domain: TrustDomain::RemoteExternal,
                        auth_kind: AgentAuthKind::RemoteGatewayMtls,
                        parent_agent_id: None,
                        peer_cred_or_cert_fp: "unbound".to_string(),
                    },
                    expected_uid: Some(euid),
                    is_oob: false,
                    is_watchdog: false,
                    is_gateway: true,
                },
            ),
        ];

        let bus_handle = BusServer::spawn(shared_bus, endpoints, Arc::new(OsPeerCredProvider))?;

        let gw_toml = format!(
            "version = 1\ndefault_policy = \"deny\"\nrequire_cert_proof = true\n\n[[peers]]\nagent_id = \"{DEMO_LAPTOP_AGENT_ID}\"\ncert_sha256 = \"{DEMO_LAPTOP_CERT_FP}\"\nallowed_cidrs = [\"127.0.0.1/32\", \"10.99.0.0/24\"]\nmax_risk_tier = \"L2\"\nenabled = true\n"
        );
        let gw_cfg = GatewayConfig::from_toml_str(&gw_toml)
            .map_err(|e| BridgeError::Protocol(format!("invalid demo gateway config: {e}")))?;
        let mut gw_state = GatewayState::new(gw_cfg, cfg.token_secret.clone(), gw_audit);
        gw_state.set_peer_key(DEMO_LAPTOP_AGENT_ID, cfg.proof_key.clone());
        let shared_gw = Arc::new(Mutex::new(gw_state));

        let gw_handle =
            GatewayServer::spawn(cfg.gateway_bind, gw_sock, Arc::clone(&shared_gw))?;
        let gateway_addr = gw_handle.local_addr();

        let ctrl = Arc::new(OobController::new(oob_sock, &audit_log_path));
        let oob_handle = OobHttpServer::spawn(cfg.oob_bind, cfg.oob_token.clone(), ctrl)
            .map_err(|e| BridgeError::Protocol(format!("failed to start HAL Key OOB server: {e}")))?;
        let oob_addr = oob_handle.local_addr();

        let mut cap_tok = CapabilityToken {
            token_id: "tok_remote_laptop_demo".to_string(),
            subject_agent_id: DEMO_LAPTOP_AGENT_ID.to_string(),
            path_patterns: vec![
                "/vault/**".to_string(),
                "/work/agents/remote-laptop-01/**".to_string(),
                "/net/broker/**".to_string(),
                "/habitat/**".to_string(),
            ],
            allowed_ops: vec![
                "read".to_string(),
                "write".to_string(),
                "lock".to_string(),
                "http_post".to_string(),
            ],
            max_risk_tier: RiskTier::L2IrreversibleOrExternal,
            delegation_depth: 0,
            max_delegation_depth: 1,
            expires_at_ms: now_unix_ms().saturating_add(86_400_000),
            rate_limit_per_min: 120,
            token_budget: Some(10_000),
            hmac_sha256: String::new(),
        };
        sign_token(&mut cap_tok, &cfg.token_secret);

        let cap_path = cfg.state_dir.join("remote-laptop-01.cap.json");
        std::fs::write(
            &cap_path,
            serde_json::to_string_pretty(&cap_tok)
                .map_err(|e| BridgeError::Protocol(format!("serialize demo token: {e}")))?,
        )?;

        let proof_key_str = std::str::from_utf8(&cfg.proof_key).map_err(|_| {
            BridgeError::Protocol("demo proof_key must be valid UTF-8 for TOML generation".into())
        })?;
        let bridge_config_path = cfg.state_dir.join("laptop-bridge.toml");
        let bridge_toml = format!(
            "version = 1\ngateway_addr = \"{gateway_addr}\"\nagent_id = \"{DEMO_LAPTOP_AGENT_ID}\"\ncert_sha256 = \"{DEMO_LAPTOP_CERT_FP}\"\npeer_proof_key = \"{proof_key_str}\"\ncap_token_path = \"./remote-laptop-01.cap.json\"\ndefault_episode_id = \"laptop-aegis-demo\"\n"
        );
        std::fs::write(&bridge_config_path, bridge_toml)?;

        let cluster = Self {
            bus: Some(bus_handle),
            gateway: Some(gw_handle),
            oob_http: Some(oob_handle),
            gateway_state: shared_gw,
            oob_addr,
            gateway_addr,
            oob_token: cfg.oob_token,
            bridge_config_path,
            audit_log_path,
        };

        if cfg.seed_sample_l2 {
            let _ = cluster.seed_sample_l2()?;
        }

        Ok(cluster)
    }

    #[must_use]
    pub fn oob_addr(&self) -> SocketAddr {
        self.oob_addr
    }

    #[must_use]
    pub fn gateway_addr(&self) -> SocketAddr {
        self.gateway_addr
    }

    #[must_use]
    pub fn oob_token(&self) -> &str {
        &self.oob_token
    }

    #[must_use]
    pub fn bridge_config_path(&self) -> &Path {
        &self.bridge_config_path
    }

    #[must_use]
    pub fn audit_log_path(&self) -> &Path {
        &self.audit_log_path
    }

    #[must_use]
    pub fn gateway_state(&self) -> &Arc<Mutex<GatewayState>> {
        &self.gateway_state
    }

    pub fn load_bridge_config(&self) -> Result<BridgeConfig, BridgeError> {
        Ok(BridgeConfig::from_file(&self.bridge_config_path)?)
    }

    #[must_use]
    pub fn oob_client(&self) -> OobHttpClient {
        OobHttpClient::new(self.oob_addr, &self.oob_token)
    }

    pub fn seed_sample_l2(&self) -> Result<String, BridgeError> {
        let mut session = BridgeSession::connect(self.load_bridge_config()?)?;
        let resp = session.submit_proposal(
            Some("seed-demo"),
            "/habitat/entry/lock",
            "lock",
            json!({"locked": true, "zone": "studio"}),
            "Laptop agent requests L2 lock check via HAL Key",
            Vec::new(),
        )?;
        match resp {
            BusResponse::ProposalDecision {
                decision: PolicyDecision::RequireApproval { approval_id, .. },
            } => Ok(approval_id),
            other => Err(BridgeError::Protocol(format!(
                "expected RequireApproval from seed_sample_l2, got {other:?}"
            ))),
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(mut http) = self.oob_http.take() {
            http.shutdown();
        }
        if let Some(mut gw) = self.gateway.take() {
            gw.shutdown();
        }
        if let Some(mut bus) = self.bus.take() {
            bus.shutdown();
        }
    }
}

impl Drop for TriNodeDemoCluster {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Runs a complete ephemeral Tri-Node smoke verification (`HAL Core` + `HAL Key` + `hal-bridge` MCP).
pub fn run_self_test() -> Result<(), BridgeError> {
    let nanos = now_unix_ms();
    let dir = PathBuf::from(format!(
        "/tmp/hal_trinode_selftest_{}_{}",
        std::process::id(),
        nanos % 1_000_000_000
    ));
    let res = (|| -> Result<(), BridgeError> {
        let mut cluster = TriNodeDemoCluster::start(TriNodeDemoConfig::ephemeral(&dir))?;
        let oob = cluster.oob_client();

        let (st_html, _, raw_html) = oob.request_raw("GET", "/", false)?;
        if st_html != 200 || !String::from_utf8_lossy(&raw_html).contains("HAL Key") {
            return Err(BridgeError::Protocol("HAL Key PWA HTML check failed".into()));
        }
        let (st_unauth, _, _) = oob.request_raw("GET", "/api/v1/status", false)?;
        if st_unauth != 401 {
            return Err(BridgeError::Protocol(
                "HAL Key API unauthenticated check did not return 401".into(),
            ));
        }

        let session = BridgeSession::connect(cluster.load_bridge_config()?)?;
        let mut mcp = McpBridgeServer::new(session);

        let init_reply = mcp
            .handle_json_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
            )
            .ok_or_else(|| BridgeError::Protocol("missing MCP initialize reply".into()))?;
        let init_val: Value = serde_json::from_str(&init_reply)
            .map_err(|e| BridgeError::Protocol(format!("bad init json: {e}")))?;
        if init_val["result"]["serverInfo"]["name"] != "hal-bridge" {
            return Err(BridgeError::Protocol("unexpected MCP serverInfo".into()));
        }

        let vault_reply = mcp
            .handle_json_line(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hal_vault_read","arguments":{"path":"/vault/docs/self-test.md","reason":"self-test"}}}"#,
            )
            .ok_or_else(|| BridgeError::Protocol("missing MCP vault reply".into()))?;
        let vault_val: Value = serde_json::from_str(&vault_reply)
            .map_err(|e| BridgeError::Protocol(format!("bad vault json: {e}")))?;
        if vault_val["result"]["isError"] != Value::Bool(false) {
            return Err(BridgeError::Protocol("hal_vault_read returned MCP error".into()));
        }

        let l2_reply = mcp
            .handle_json_line(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hal_propose_action","arguments":{"target_path":"/habitat/entry/lock","action":"lock","args":{"locked":true},"reason":"self-test l2"}}}"#,
            )
            .ok_or_else(|| BridgeError::Protocol("missing MCP L2 reply".into()))?;
        let l2_val: Value = serde_json::from_str(&l2_reply)
            .map_err(|e| BridgeError::Protocol(format!("bad L2 json: {e}")))?;
        let inner_txt = l2_val["result"]["content"][0]["text"]
            .as_str()
            .ok_or_else(|| BridgeError::Protocol("missing MCP L2 text content".into()))?;
        let inner_json: Value = serde_json::from_str(inner_txt)
            .map_err(|e| BridgeError::Protocol(format!("bad L2 inner json: {e}")))?;
        let approval_id = inner_json["decision"]["approval_id"]
            .as_str()
            .ok_or_else(|| BridgeError::Protocol("missing L2 approval_id".into()))?
            .to_string();

        let (st_app, app_json) = oob.request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/approve"),
            Some(&json!({"note": "self-test operator approve"})),
        )?;
        if st_app != 200 || app_json["approval"]["status"] != "Approved" {
            return Err(BridgeError::Protocol("HAL Key L2 approval failed".into()));
        }

        let (st_ver, _) = oob.request("GET", "/api/v1/audit/verify", None)?;
        if st_ver != 200 {
            return Err(BridgeError::Protocol("audit verify failed".into()));
        }

        cluster.shutdown();
        verify_file(cluster.audit_log_path())
            .map_err(|e| BridgeError::Protocol(format!("audit chain verification failed: {e}")))?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}
