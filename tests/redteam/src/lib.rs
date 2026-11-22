//! Shared testbed fixtures for HAL-OS Phase 4 flagship red-team acceptance drills.

use hal_audit::AuditLog;
use hal_brain::{AgentRole, CognitiveAgent, EpisodicMemoryStore};
use hal_bus::{BusServer, BusServerHandle, EndpointBinding, HalBusState};
use hal_net_broker::{
    EgressAllowlist, LoopbackHttpTransport, NetBroker, SealedSecret, SecretStore,
};
use hal_os_hal::OsPeerCredProvider;
use hal_policy::{IpcMatrix, PolicyConfig, PolicyEngine};
use hal_proto::{
    sign_token, AgentAuthKind, AgentPrincipal, CapabilityToken, RiskTier, TrustDomain,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const TEST_TOKEN_SECRET: &[u8] = b"hal-os-redteam-token-secret-key!";
pub const TEST_LLM_KEY: &str = "sk-redteam-sealed-llm-key-0001";
pub const TEST_SHIP_KEY: &str = "ship-redteam-sealed-token-0002";

#[must_use]
pub fn unique_redteam_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!(
        "/tmp/hal_rt_{label}_{}_{}",
        std::process::id(),
        nanos % 1_000_000_000
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[must_use]
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[must_use]
pub fn mk_principal(
    agent_id: &str,
    trust_domain: TrustDomain,
    auth_kind: AgentAuthKind,
) -> AgentPrincipal {
    AgentPrincipal {
        agent_id: agent_id.to_string(),
        trust_domain,
        auth_kind,
        parent_agent_id: None,
        peer_cred_or_cert_fp: "unbound".to_string(),
    }
}

#[must_use]
pub fn mk_signed_token(
    id: &str,
    subject: &str,
    paths: &[&str],
    ops: &[&str],
    max_risk_tier: RiskTier,
) -> CapabilityToken {
    let mut t = CapabilityToken {
        token_id: id.to_string(),
        subject_agent_id: subject.to_string(),
        path_patterns: paths.iter().map(|s| (*s).to_string()).collect(),
        allowed_ops: ops.iter().map(|s| (*s).to_string()).collect(),
        max_risk_tier,
        delegation_depth: 0,
        max_delegation_depth: 2,
        expires_at_ms: 999_000_000,
        rate_limit_per_min: 120,
        token_budget: Some(10_000),
        hmac_sha256: String::new(),
    };
    sign_token(&mut t, TEST_TOKEN_SECRET);
    t
}

pub fn spawn_full_bus(dir: &Path, matrix: IpcMatrix) -> (BusServerHandle, PathBuf) {
    let audit_path = dir.join("hal-audit.jsonl");
    let audit = AuditLog::open(&audit_path).unwrap();
    let policy = PolicyEngine::new(PolicyConfig {
        token_secret: TEST_TOKEN_SECRET.to_vec(),
    });
    let state = Arc::new(Mutex::new(HalBusState::new(policy, matrix, audit)));
    let euid = unsafe { libc::geteuid() } as u32;

    let endpoints = vec![
        (
            dir.join("netsec.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "agent-netsec",
                    TrustDomain::ResidentCore,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
        (
            dir.join("vault.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "agent-vault",
                    TrustDomain::ResidentCore,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
        (
            dir.join("coder.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "agent-coder",
                    TrustDomain::WorkspaceWorker,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
        (
            dir.join("habitat.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "agent-habitat",
                    TrustDomain::ResidentCore,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
        (
            dir.join("research.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "agent-research",
                    TrustDomain::UntrustedResearch,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
        (
            dir.join("netmon.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "adapter-netmon",
                    TrustDomain::ResidentCore,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
        (
            dir.join("adapter_vault.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "adapter-vault",
                    TrustDomain::ResidentCore,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
        (
            dir.join("gateway.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "hal-gateway",
                    TrustDomain::RemoteExternal,
                    AgentAuthKind::RemoteGatewayMtls,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
                is_gateway: true,
            },
        ),
        (
            dir.join("watchdog.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "hal-watchdog",
                    TrustDomain::ResidentCore,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: true,
                is_gateway: false,
            },
        ),
        (
            dir.join("oob.sock"),
            EndpointBinding {
                principal: mk_principal(
                    "hal-oob",
                    TrustDomain::ResidentCore,
                    AgentAuthKind::LocalNoIpJail,
                ),
                expected_uid: Some(euid),
                is_oob: true,
                is_watchdog: false,
                is_gateway: false,
            },
        ),
    ];

    let handle = BusServer::spawn(state, endpoints, Arc::new(OsPeerCredProvider)).unwrap();
    (handle, audit_path)
}

pub fn build_loopback_broker(
    audit_path: &Path,
    llm_addr: Option<SocketAddr>,
    ship_addr: Option<SocketAddr>,
) -> NetBroker<LoopbackHttpTransport> {
    let allowlist =
        EgressAllowlist::from_file(repo_root().join("config/policy/egress-allowlist.toml")).unwrap();
    let mut secrets = SecretStore::default();
    secrets.insert(
        "llm_api_key",
        SealedSecret::new("Authorization", "Bearer ", TEST_LLM_KEY),
    );
    secrets.insert(
        "ship_status_token",
        SealedSecret::new("Authorization", "Bearer ", TEST_SHIP_KEY),
    );
    let mut transport = LoopbackHttpTransport::default();
    if let Some(addr) = llm_addr {
        transport
            .host_overrides
            .insert("api.example-llm.local".to_string(), addr);
    }
    if let Some(addr) = ship_addr {
        transport
            .host_overrides
            .insert("status.ship.local".to_string(), addr);
    }
    let audit = AuditLog::open(audit_path).unwrap();
    NetBroker::new(allowlist, secrets, transport, audit)
}

pub fn mk_brain_agent(
    role: AgentRole,
    mem_dir: &Path,
    paths: &[&str],
    ops: &[&str],
    tier: RiskTier,
) -> CognitiveAgent {
    let id = role.default_agent_id();
    let p = mk_principal(id, role.default_trust_domain(), AgentAuthKind::LocalNoIpJail);
    let tok = mk_signed_token(&format!("tok_{role}"), id, paths, ops, tier);
    let mem = EpisodicMemoryStore::load_or_init(mem_dir).unwrap();
    CognitiveAgent::new(role, p, tok, mem)
}
