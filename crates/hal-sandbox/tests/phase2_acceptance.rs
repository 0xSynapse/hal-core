use hal_audit::{verify_file, AuditLog};
use hal_net_broker::{
    EgressAllowlist, EgressRequest, LoopbackHttpTransport, NetBroker, SealedSecret, SecretStore,
};
use hal_os_hal::{MockSandboxBackend, RctlLimits, SandboxBackend};
use hal_proto::{
    delegate_token, sign_token, AgentAuthKind, AgentPrincipal, CapabilityToken, DelegationSpec,
    RiskTier, TaintTag, TrustDomain,
};
use hal_sandbox::{
    render_jail_conf, render_rctl_rules, NetworkMode, SandboxOrchestrator, SandboxSpec,
};
use hal_workspace::{LocalDirWorkspaceBackend, WorkspaceError, WorkspaceManager};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &[u8] = b"hal-os-phase2-acceptance-secret!";

fn unique_tmp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!(
        "/tmp/hal_p2_{label}_{}_{}",
        std::process::id(),
        nanos % 1_000_000_000
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn principal(agent_id: &str, trust_domain: TrustDomain, parent: Option<&str>) -> AgentPrincipal {
    AgentPrincipal {
        agent_id: agent_id.to_string(),
        trust_domain,
        auth_kind: if parent.is_some() {
            AgentAuthKind::EphemeralWorker
        } else {
            AgentAuthKind::LocalNoIpJail
        },
        parent_agent_id: parent.map(str::to_string),
        peer_cred_or_cert_fp: "uid:1001".to_string(),
    }
}

fn signed_token(
    id: &str,
    subject: &str,
    paths: &[&str],
    ops: &[&str],
    tier: RiskTier,
) -> CapabilityToken {
    let mut t = CapabilityToken {
        token_id: id.to_string(),
        subject_agent_id: subject.to_string(),
        path_patterns: paths.iter().map(|s| (*s).to_string()).collect(),
        allowed_ops: ops.iter().map(|s| (*s).to_string()).collect(),
        max_risk_tier: tier,
        delegation_depth: 0,
        max_delegation_depth: 2,
        expires_at_ms: 90_000_000,
        rate_limit_per_min: 100,
        token_budget: Some(1000),
        hmac_sha256: String::new(),
    };
    sign_token(&mut t, SECRET);
    t
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
fn phase2_pillar1_secretless_broker_dlp_quotas_and_trifecta_over_real_tcp() {
    let dir = unique_tmp_dir("broker");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // Serve 2 real HTTP requests on loopback: LLM inference + ship status echo
    let server_thread = thread::spawn(move || {
        for expected_idx in 0..2 {
            let (mut sock, _) = listener.accept().unwrap();
            let raw = read_http_request(&mut sock);
            if expected_idx == 0 {
                assert!(raw.contains("Host: api.example-llm.local"));
                assert!(raw.contains("Authorization: Bearer sk-live-broker-only-secret-xyz"));
                let body = r#"{"choices":[{"text":"ok"}],"secret_leak_test":"sk-live-broker-only-secret-xyz"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).unwrap();
                let _ = sock.shutdown(std::net::Shutdown::Write);
            } else {
                assert!(raw.contains("Host: status.ship.local"));
                let body = r#"{"ship":"discovery-one","ok":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                sock.write_all(resp.as_bytes()).unwrap();
                let _ = sock.shutdown(std::net::Shutdown::Write);
            }
        }
    });

    let mut allowlist = EgressAllowlist::from_file(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/egress-allowlist.toml"),
    )
    .unwrap();
    allowlist.quotas.max_requests_per_min = 2;

    let mut secrets = SecretStore::default();
    secrets.insert(
        "llm_api_key",
        SealedSecret::new("Authorization", "Bearer ", "sk-live-broker-only-secret-xyz"),
    );
    secrets.insert(
        "ship_status_token",
        SealedSecret::new("Authorization", "Bearer ", "ship-token-sealed-999"),
    );
    secrets.insert(
        "github_pat",
        SealedSecret::new("Authorization", "Bearer ", "ghp_SealedGithubPatToken123456"),
    );

    let mut transport = LoopbackHttpTransport::default();
    transport
        .host_overrides
        .insert("api.example-llm.local".to_string(), addr);
    transport
        .host_overrides
        .insert("status.ship.local".to_string(), addr);

    let audit_path = dir.join("broker-audit.jsonl");
    let mut broker = NetBroker::new(allowlist, secrets, transport, AuditLog::open(&audit_path).unwrap());

    let coder = principal("agent-coder", TrustDomain::WorkspaceWorker, None);
    let researcher = principal("agent-research", TrustDomain::UntrustedResearch, None);

    // 1. Secretless call injects real key only on the wire & strips echoed secret before returning
    let resp1 = broker
        .execute(
            &coder,
            "ep_c1",
            &BTreeSet::new(),
            &EgressRequest {
                service_id: "llm_inference".into(),
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: br#"{"prompt":"summarize zfs rollback"}"#.to_vec(),
            },
            10_000,
        )
        .unwrap();
    assert_eq!(resp1.status, 200);
    assert!(!resp1.body.contains("sk-live-broker-only-secret-xyz"));
    assert!(resp1.body.contains("[REDACTED_SECRET]"));
    assert!(resp1.taint_tags.contains(&TaintTag::UntrustedWeb));

    // 2. DLP blocks private key / AWS key / high-entropy token BEFORE hitting any socket
    for payload in [
        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
        "aws=AKIAIOSFODNN7EXAMPLE",
        "token=Q8zX4mN2vK9pL7wJ1cR5tY3hB6gF0dS8",
        "canary=VAULT_SECRET_CANARY",
    ] {
        let err = broker
            .execute(
                &coder,
                "ep_c1",
                &BTreeSet::new(),
                &EgressRequest {
                    service_id: "ship_status_api".into(),
                    method: "POST".into(),
                    path: "/v1/telemetry".into(),
                    headers: Vec::new(),
                    body: payload.as_bytes().to_vec(),
                },
                10_100,
            )
            .unwrap_err();
        assert_eq!(err.code, "DLP_SECRET_LEAK_BLOCKED");
    }

    // 3. Unlisted service/domain & disallowed agent blocked
    assert_eq!(
        broker
            .execute(
                &coder,
                "ep_c1",
                &BTreeSet::new(),
                &EgressRequest {
                    service_id: "unlisted_evil".into(),
                    method: "POST".into(),
                    path: "/steal".into(),
                    headers: Vec::new(),
                    body: b"hi".to_vec(),
                },
                10_200,
            )
            .unwrap_err()
            .code,
        "ALLOWLIST_DENIED"
    );

    // 4. Lethal Trifecta blocks allowlisted host
    let trifecta = BTreeSet::from([TaintTag::UntrustedWeb, TaintTag::PrivateVault]);
    assert_eq!(
        broker
            .execute(
                &coder,
                "ep_c1",
                &trifecta,
                &EgressRequest {
                    service_id: "ship_status_api".into(),
                    method: "POST".into(),
                    path: "/v1/telemetry".into(),
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                },
                10_300,
            )
            .unwrap_err()
            .code,
        "TAINT_EXFIL_BLOCKED"
    );

    // 5. Second clean request from coder consumes quota=2/2; 3rd exceeds quota without hurting researcher!
    let resp2 = broker
        .execute(
            &coder,
            "ep_c2",
            &BTreeSet::new(),
            &EgressRequest {
                service_id: "ship_status_api".into(),
                method: "POST".into(),
                path: "/v1/telemetry".into(),
                headers: Vec::new(),
                body: br#"{"temp":21}"#.to_vec(),
            },
            10_400,
        )
        .unwrap();
    assert_eq!(resp2.status, 200);

    let quota_err = broker
        .execute(
            &coder,
            "ep_c2",
            &BTreeSet::new(),
            &EgressRequest {
                service_id: "ship_status_api".into(),
                method: "POST".into(),
                path: "/v1/telemetry".into(),
                headers: Vec::new(),
                body: br#"{"temp":22}"#.to_vec(),
            },
            10_500,
        )
        .unwrap_err();
    assert_eq!(quota_err.code, "AGENT_EGRESS_BUDGET_EXCEEDED");

    // Verify researcher quota wasn't drained by coder (researcher still stopped only by github_api ACL)
    let acl_err = broker
        .execute(
            &researcher,
            "ep_r1",
            &BTreeSet::new(),
            &EgressRequest {
                service_id: "github_api".into(),
                method: "GET".into(),
                path: "/repos/0xSynapse/hal-os".into(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            10_550,
        )
        .unwrap_err();
    assert_eq!(acl_err.code, "ALLOWLIST_DENIED");

    server_thread.join().unwrap();
    let report = verify_file(&audit_path).unwrap();
    assert!(report.record_count >= 9);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn phase2_pillar2_transactional_cow_and_dual_rollback() {
    let dir = unique_tmp_dir("workspace");
    let backend = LocalDirWorkspaceBackend::new(&dir).unwrap();
    std::fs::write(backend.base_workspace_dir().join("life_support.toml"), "o2=21\n").unwrap();
    std::fs::write(backend.base_memory_dir().join("state.json"), r#"{"ok":true}"#).unwrap();

    let audit_path = dir.join("ws-audit.jsonl");
    let mut mgr = WorkspaceManager::new(backend, AuditLog::open(&audit_path).unwrap());
    let coder = principal("agent-coder", TrustDomain::WorkspaceWorker, None);

    mgr.begin_episode(&coder, "ep_02", 1_000).unwrap();
    mgr.snapshot_before_l1(&coder, "ep_02", "step_01", "pre-mutation", 1_100)
        .unwrap();

    let ws_ep = mgr.backend().episode_workspace_dir("agent-coder", "ep_02").unwrap();
    let mem_ep = mgr.backend().episode_memory_dir("agent-coder", "ep_02").unwrap();

    std::fs::write(ws_ep.join("life_support.toml"), "o2=0\n").unwrap();
    std::fs::write(ws_ep.join("malicious.bin"), "payload").unwrap();
    std::fs::write(mem_ep.join("state.json"), r#"{"ok":false,"note":"updated"}"#).unwrap();

    mgr.rollback_dual_snapshot(&coder, "ep_02", "step_01", 1_200)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(ws_ep.join("life_support.toml")).unwrap(),
        "o2=21\n"
    );
    assert!(!ws_ep.join("malicious.bin").exists());
    assert_eq!(
        std::fs::read_to_string(mem_ep.join("state.json")).unwrap(),
        r#"{"ok":true}"#
    );

    assert!(matches!(
        mgr.commit_episode(&coder, "ep_02", None, 1_300),
        Err(WorkspaceError::ApprovalRequired(_))
    ));
    mgr.destroy_episode(&coder, "ep_02", 1_400).unwrap();
    assert!(!ws_ep.exists());
    assert!(verify_file(&audit_path).unwrap().record_count >= 5);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn phase2_pillar3_jail_rctl_attenuation_and_surgical_vs_global_freeze() {
    let dir = unique_tmp_dir("sandbox");
    let audit_path = dir.join("sb-audit.jsonl");
    let mut orch = SandboxOrchestrator::new(
        MockSandboxBackend::default(),
        SECRET.to_vec(),
        AuditLog::open(&audit_path).unwrap(),
    );

    let oob = principal("hal-oob", TrustDomain::ResidentCore, None);
    let research_p = principal("agent-research", TrustDomain::UntrustedResearch, None);
    let research_tok = signed_token(
        "tok_r",
        "agent-research",
        &["/work/agents/agent-research/**"],
        &["read", "write"],
        RiskTier::L1ReversibleCow,
    );
    let coder_tok = signed_token(
        "tok_c",
        "agent-coder",
        &["/work/agents/agent-coder/**"],
        &["read", "write"],
        RiskTier::L1ReversibleCow,
    );

    let res_spec = SandboxSpec {
        sandbox_id: "agent_research".into(),
        agent_id: "agent-research".into(),
        parent_agent_id: None,
        network_mode: NetworkMode::NoIp,
        rctl_limits: RctlLimits {
            memoryuse_mb: 512,
            maxproc: 64,
            pcpu_pct: 50,
        },
        uds_host_dir: PathBuf::from("/var/run/hal/jails/agent_research"),
        workspace_mount: None,
        cap_token: research_tok.clone(),
    };
    let jail_conf = render_jail_conf(&res_spec);
    assert!(jail_conf.contains("ip4 = disable;"));
    assert!(jail_conf.contains("ip6 = disable;"));
    assert_eq!(
        render_rctl_rules(&res_spec),
        vec![
            "jail:agent_research:memoryuse:deny=512M",
            "jail:agent_research:maxproc:deny=64",
            "jail:agent_research:pcpu:deny=50",
        ]
    );

    orch.spawn_resident(&oob, res_spec, 1_000).unwrap();
    orch.spawn_resident(
        &oob,
        SandboxSpec {
            sandbox_id: "agent_coder".into(),
            agent_id: "agent-coder".into(),
            parent_agent_id: None,
            network_mode: NetworkMode::NoIp,
            rctl_limits: RctlLimits {
                memoryuse_mb: 512,
                maxproc: 64,
                pcpu_pct: 50,
            },
            uds_host_dir: PathBuf::from("/var/run/hal/jails/agent_coder"),
            workspace_mount: None,
            cap_token: coder_tok,
        },
        1_010,
    )
    .unwrap();

    // Attenuated child worker token
    let worker_tok = delegate_token(
        &research_tok,
        DelegationSpec {
            new_token_id: "tok_rw1".into(),
            delegate_agent_id: "agent-research-w1".into(),
            path_patterns: vec!["/work/agents/agent-research/episodes/e1/**".into()],
            allowed_ops: vec!["read".into()],
            max_risk_tier: RiskTier::L0ReadOnly,
            expires_at_ms: 50_000_000,
            rate_limit_per_min: 20,
            token_budget: Some(100),
        },
        SECRET,
        1_020,
    )
    .unwrap();

    // Reject RCTL escalation
    let rctl_esc = orch
        .spawn_ephemeral_worker(
            &research_p,
            "agent_research",
            &research_tok,
            SandboxSpec {
                sandbox_id: "agent_research_w_big".into(),
                agent_id: "agent-research-w1".into(),
                parent_agent_id: Some("agent-research".into()),
                network_mode: NetworkMode::NoIp,
                rctl_limits: RctlLimits {
                    memoryuse_mb: 1024,
                    maxproc: 32,
                    pcpu_pct: 25,
                },
                uds_host_dir: PathBuf::from("/var/run/hal/jails/agent_research_w1"),
                workspace_mount: None,
                cap_token: worker_tok.clone(),
            },
            1_030,
        )
        .unwrap_err();
    assert_eq!(rctl_esc.code, "RCTL_ESCALATION_DENIED");

    // Reject shared UDS socket mount
    let uds_collision = orch
        .spawn_ephemeral_worker(
            &research_p,
            "agent_research",
            &research_tok,
            SandboxSpec {
                sandbox_id: "agent_research_w_col".into(),
                agent_id: "agent-research-w1".into(),
                parent_agent_id: Some("agent-research".into()),
                network_mode: NetworkMode::NoIp,
                rctl_limits: RctlLimits {
                    memoryuse_mb: 256,
                    maxproc: 16,
                    pcpu_pct: 25,
                },
                uds_host_dir: PathBuf::from("/var/run/hal/jails/agent_coder"),
                workspace_mount: None,
                cap_token: worker_tok.clone(),
            },
            1_040,
        )
        .unwrap_err();
    assert_eq!(uds_collision.code, "UDS_PATH_COLLISION");

    // Valid attenuated ephemeral worker succeeds
    orch.spawn_ephemeral_worker(
        &research_p,
        "agent_research",
        &research_tok,
        SandboxSpec {
            sandbox_id: "agent_research_w1".into(),
            agent_id: "agent-research-w1".into(),
            parent_agent_id: Some("agent-research".into()),
            network_mode: NetworkMode::NoIp,
            rctl_limits: RctlLimits {
                memoryuse_mb: 256,
                maxproc: 16,
                pcpu_pct: 25,
            },
            uds_host_dir: PathBuf::from("/var/run/hal/jails/agent_research_w1"),
            workspace_mount: None,
            cap_token: worker_tok,
        },
        1_050,
    )
    .unwrap();
    assert_eq!(orch.active_count(), 3);

    // Surgical freeze kills agent_research AND its child worker while agent_coder keeps running!
    let stopped = orch
        .freeze_agent_sandboxes(&oob, "agent-research", true, false, 1_060)
        .unwrap();
    assert_eq!(stopped.len(), 2);
    assert!(!orch.backend().is_jail_running("agent_research").unwrap());
    assert!(!orch.backend().is_jail_running("agent_research_w1").unwrap());
    assert!(orch.backend().is_jail_running("agent_coder").unwrap());

    // Global FROZEN terminates remaining cognitive sandboxes
    let global_stopped = orch
        .terminate_all_cognitive_sandboxes(&oob, true, false, 1_070)
        .unwrap();
    assert_eq!(global_stopped, vec!["agent_coder"]);
    assert_eq!(orch.active_count(), 0);
    assert_eq!(verify_file(&audit_path).unwrap().record_count, 7);
    let _ = std::fs::remove_dir_all(&dir);
}
