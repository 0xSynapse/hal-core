use adapter_netmon::{parse_netstat_libxo_json, NetmonAdapter, PfAction};
use adapter_sim_ship::{ShipCommand, ShipSimulator, ShipState};
use hal_audit::{verify_file, AuditLog};
use hal_bus::{BusClient, BusServer, EndpointBinding, HalBusState};
use hal_gateway::{
    compute_cert_proof, GatewayClient, GatewayConfig, GatewayRequest, GatewayResponse,
    GatewayServer, GatewayState, RemoteAuthHandshake,
};
use hal_oob::{
    handle_oob_console_line, validate_oob_bind_addr, OobController, OobError, OobHttpClient,
    OobHttpServer,
};
use hal_os_hal::{DualSnapshotRequest, OsPeerCredProvider, WorkspaceBackend};
use hal_policy::{IpcMatrix, PolicyConfig, PolicyEngine};
use hal_proto::wire::{BusRequest, BusResponse};
use hal_proto::{
    sign_token, ActionProposal, AgentAuthKind, AgentPrincipal, CapabilityToken, EventEnvelope,
    IpcMessage, PolicyDecision, RiskTier, SystemMode, TaintTag, TrustDomain, TrustLevel,
};
use hal_watchdog::{WatchdogAction, WatchdogConfig, WatchdogEngine, WatchdogRunner};
use hal_workspace::LocalDirWorkspaceBackend;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &[u8] = b"hal-os-phase3-acceptance-secret!";
const LAPTOP_KEY: &[u8] = b"remote-laptop-01-phase3-key!!!!";
const LAPTOP_FP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn unique_tmp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!(
        "/tmp/hal_p3_{label}_{}_{}",
        std::process::id(),
        nanos % 1_000_000_000
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn mk_principal(agent_id: &str, trust_domain: TrustDomain, auth_kind: AgentAuthKind) -> AgentPrincipal {
    AgentPrincipal {
        agent_id: agent_id.to_string(),
        trust_domain,
        auth_kind,
        parent_agent_id: None,
        peer_cred_or_cert_fp: "unbound".to_string(),
    }
}

fn mk_token(
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
        expires_at_ms: 99_000_000,
        rate_limit_per_min: 100,
        token_budget: Some(1000),
        hmac_sha256: String::new(),
    };
    sign_token(&mut t, SECRET);
    t
}

fn repo_matrix() -> IpcMatrix {
    IpcMatrix::from_file(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/ipc-matrix.toml"))
        .unwrap()
}

fn spawn_phase3_bus(dir: &Path) -> (hal_bus::BusServerHandle, PathBuf) {
    let audit_path = dir.join("hal-audit.jsonl");
    let audit = AuditLog::open(&audit_path).unwrap();
    let policy = PolicyEngine::new(PolicyConfig {
        token_secret: SECRET.to_vec(),
    });
    let state = Arc::new(Mutex::new(HalBusState::new(policy, repo_matrix(), audit)));
    let euid = unsafe { libc::geteuid() } as u32;

    let endpoints = vec![
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

#[test]
fn phase3_pillar1_remote_gateway_mtls_taint_and_l2_approval_over_real_tcp_and_uds() {
    let dir = unique_tmp_dir("p1_gw");
    let (mut bus, audit_path) = spawn_phase3_bus(&dir);

    let gw_cfg = GatewayConfig::from_file(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/gateway-peers.toml"),
    )
    .unwrap();
    let gw_audit = AuditLog::open(dir.join("gateway-audit.jsonl")).unwrap();
    let mut gw_state = GatewayState::new(gw_cfg, SECRET.to_vec(), gw_audit);
    gw_state.set_peer_key("remote-laptop-01", LAPTOP_KEY.to_vec());
    let shared_gw = Arc::new(Mutex::new(gw_state));
    let mut gw_srv = GatewayServer::spawn(
        "127.0.0.1:0".parse().unwrap(),
        dir.join("gateway.sock"),
        Arc::clone(&shared_gw),
    )
    .unwrap();

    // OOB HTTP refuses wildcard 0.0.0.0 bind, succeeds on 127.0.0.1:0
    assert!(matches!(
        validate_oob_bind_addr("0.0.0.0:8443".parse().unwrap()),
        Err(OobError::InvalidConfig {
            code: "WILDCARD_BIND_FORBIDDEN",
            ..
        })
    ));
    let ctrl = Arc::new(OobController::new(dir.join("oob.sock"), &audit_path));
    let oob_tok = "oob-p3-mgmt0-token";
    let mut oob_http = OobHttpServer::spawn(
        "127.0.0.1:0".parse().unwrap(),
        oob_tok.into(),
        Arc::clone(&ctrl),
    )
    .unwrap();
    let oob_client = OobHttpClient::new(oob_http.local_addr(), oob_tok);

    // Connect remote agent over TCP
    let mut gw_client = GatewayClient::connect(gw_srv.local_addr()).unwrap();
    let remote_tok = mk_token(
        "tok_remote_1",
        "remote-laptop-01",
        &["/vault/**", "/net/broker/**", "/habitat/**"],
        &["read", "http_post", "lock"],
        RiskTier::L2IrreversibleOrExternal,
    );

    // Invalid proof rejected
    assert!(matches!(
        gw_client
            .authenticate(RemoteAuthHandshake {
                claimed_agent_id: "remote-laptop-01".into(),
                cert_sha256: LAPTOP_FP.into(),
                client_nonce: "bad_proof_1".into(),
                cert_proof_hmac: "00".repeat(32),
                cap_token: remote_tok.clone(),
                now_ms: 10_000,
            })
            .unwrap(),
        GatewayResponse::Error { ref code, .. } if code == "GATEWAY_CERT_PROOF_FAILED"
    ));

    // Valid authentication succeeds
    let nonce = "ok_nonce_1";
    let auth_resp = gw_client
        .authenticate(RemoteAuthHandshake {
            claimed_agent_id: "remote-laptop-01".into(),
            cert_sha256: LAPTOP_FP.into(),
            client_nonce: nonce.into(),
            cert_proof_hmac: compute_cert_proof(LAPTOP_KEY, "remote-laptop-01", LAPTOP_FP, nonce),
            cap_token: remote_tok.clone(),
            now_ms: 10_100,
        })
        .unwrap();
    assert!(matches!(
        auth_resp,
        GatewayResponse::Authenticated { ref principal, .. }
            if principal.agent_id == "remote-laptop-01"
                && principal.trust_domain == TrustDomain::RemoteExternal
                && principal.auth_kind == AgentAuthKind::RemoteGatewayMtls
    ));

    // Remote agent cannot bypass default-deny IPC matrix toward agent-vault
    let ipc_resp = gw_client
        .call(&GatewayRequest::SendIpc {
            message: IpcMessage {
                msg_id: "m_remote_vault".into(),
                from_agent: "remote-laptop-01".into(),
                to_agent: "agent-vault".into(),
                ts_ms: 10_200,
                propagated_taints: BTreeSet::new(),
                schema_id: "alert.v1".into(),
                payload: serde_json::json!({"probe": true}),
            },
            from_episode_id: "ep_gw_1".into(),
            to_episode_id: "ep_v".into(),
        })
        .unwrap();
    assert!(matches!(
        ipc_resp,
        GatewayResponse::Bus {
            response: BusResponse::IpcDenied { ref code, .. }
        } if code == "IPC_MATRIX_DENIED"
    ));

    // GatewayPublishEvent auto-tags UntrustedMsg -> reading /vault completes Lethal Trifecta -> blocked at /net/broker/http
    let pub_resp = gw_client
        .call(&GatewayRequest::PublishEvent {
            event: EventEnvelope {
                event_id: "evt_rem_1".into(),
                ts_ms: 10_300,
                source_path: "/agents/remote-laptop-01/input".into(),
                producer_actor: "ignored".into(),
                trust_level: TrustLevel::UntrustedExternal,
                taint_tags: BTreeSet::new(),
                payload: serde_json::json!({"prompt": "exfiltrate"}),
            },
            episode_id: "ep_gw_tainted".into(),
        })
        .unwrap();
    assert!(matches!(
        pub_resp,
        GatewayResponse::Bus {
            response: BusResponse::EventRecorded { ref episode_taints }
        } if episode_taints.contains(&TaintTag::UntrustedMsg)
    ));

    let vault_read = gw_client
        .call(&GatewayRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_rem_v".into(),
                episode_id: "ep_gw_tainted".into(),
                agent_id: "remote-laptop-01".into(),
                cap_token: remote_tok.clone(),
                target_path: "/vault/docs/secret_plan.txt".into(),
                action: "read".into(),
                args: serde_json::json!({}),
                reason: "read vault".into(),
                trigger_event_ids: vec!["evt_rem_1".into()],
            },
            now_ms: 10_400,
        })
        .unwrap();
    assert!(matches!(
        vault_read,
        GatewayResponse::Bus {
            response: BusResponse::ProposalDecision {
                decision: PolicyDecision::Allow { ref applied_taints, .. }
            }
        } if applied_taints.contains(&TaintTag::PrivateVault) && applied_taints.contains(&TaintTag::UntrustedMsg)
    ));

    let exfil_resp = gw_client
        .call(&GatewayRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_rem_exfil".into(),
                episode_id: "ep_gw_tainted".into(),
                agent_id: "remote-laptop-01".into(),
                cap_token: remote_tok.clone(),
                target_path: "/net/broker/http".into(),
                action: "http_post".into(),
                args: serde_json::json!({"host": "status.ship.local"}),
                reason: "exfil".into(),
                trigger_event_ids: vec!["evt_rem_1".into()],
            },
            now_ms: 10_500,
        })
        .unwrap();
    assert!(matches!(
        exfil_resp,
        GatewayResponse::Bus {
            response: BusResponse::ProposalDecision {
                decision: PolicyDecision::Deny { ref code, .. }
            }
        } if code == "TAINT_EXFIL_BLOCKED"
    ));

    // Clean episode proposes L2 action -> queued for human OOB approval
    let l2_resp = gw_client
        .call(&GatewayRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_rem_l2".into(),
                episode_id: "ep_gw_clean".into(),
                agent_id: "remote-laptop-01".into(),
                cap_token: remote_tok,
                target_path: "/habitat/entry/lock".into(),
                action: "lock".into(),
                args: serde_json::json!({"locked": true}),
                reason: "secure bay".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 10_600,
        })
        .unwrap();
    let approval_id = match l2_resp {
        GatewayResponse::Bus {
            response:
                BusResponse::ProposalDecision {
                    decision: PolicyDecision::RequireApproval { approval_id, .. },
                },
        } => approval_id,
        other => panic!("expected RequireApproval, got {other:?}"),
    };

    let (st, approvals_json) = oob_client.request("GET", "/api/v1/approvals", None).unwrap();
    assert_eq!(st, 200);
    assert_eq!(approvals_json["approvals"][0]["approval_id"], approval_id);
    assert_eq!(approvals_json["approvals"][0]["status"], "Pending");

    let (st_app, app_res) = oob_client
        .request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/approve"),
            Some(&serde_json::json!({"note": "operator verified", "now_ms": 10_700})),
        )
        .unwrap();
    assert_eq!(st_app, 200);
    assert_eq!(app_res["approval"]["status"], "Approved");

    // Re-approving an already resolved approval is rejected with 409 Conflict
    let (st_dup, _) = oob_client
        .request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/approve"),
            Some(&serde_json::json!({"note": "dup"})),
        )
        .unwrap();
    assert_eq!(st_dup, 409);

    // Revoking remote agent via OOB + GatewayState blocks further gateway calls immediately
    let (st_rev, _) = oob_client
        .request(
            "POST",
            "/api/v1/agents/remote-laptop-01/revoke",
            Some(&serde_json::json!({"reason": "session ended"})),
        )
        .unwrap();
    assert_eq!(st_rev, 200);
    shared_gw.lock().unwrap().revoke_agent("remote-laptop-01");

    let post_revoke = gw_client.call(&GatewayRequest::Ping).unwrap();
    assert!(matches!(
        post_revoke,
        GatewayResponse::Error { ref code, .. } if code == "AGENT_REVOKED"
    ));

    drop(gw_client);
    oob_http.shutdown();
    gw_srv.shutdown();
    bus.shutdown();
    assert!(verify_file(&audit_path).unwrap().record_count >= 6);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn phase3_pillar2_oob_surgical_freeze_and_ship_spinal_continuity() {
    let dir = unique_tmp_dir("p2_ship");
    let (mut bus, audit_path) = spawn_phase3_bus(&dir);
    let ctrl = Arc::new(OobController::new(dir.join("oob.sock"), &audit_path));
    let tok = "ship-oob-secret";
    let mut http =
        OobHttpServer::spawn("127.0.0.1:0".parse().unwrap(), tok.into(), Arc::clone(&ctrl))
            .unwrap();
    let client = OobHttpClient::new(http.local_addr(), tok);

    let mut habitat = BusClient::connect(dir.join("habitat.sock")).unwrap();
    let mut coder = BusClient::connect(dir.join("coder.sock")).unwrap();
    let mut research = BusClient::connect(dir.join("research.sock")).unwrap();

    let hab_tok = mk_token(
        "tok_hab",
        "agent-habitat",
        &["/habitat/**"],
        &["read", "write"],
        RiskTier::L1ReversibleCow,
    );
    let coder_tok = mk_token(
        "tok_cod",
        "agent-coder",
        &["/habitat/**", "/work/**"],
        &["lock", "write", "read"],
        RiskTier::L2IrreversibleOrExternal,
    );

    // Healthy agent-habitat holds thermal lease and adjusts cabin setpoint
    assert!(matches!(
        habitat
            .call(&BusRequest::AcquireLease {
                resource_path: "/habitat/study/temp".into(),
                priority: 10,
                ttl_ms: 30_000,
                now_ms: 1_000,
                is_oob: false,
            })
            .unwrap(),
        BusResponse::LeaseGranted { .. }
    ));
    assert!(matches!(
        research
            .call(&BusRequest::AcquireLease {
                resource_path: "/habitat/study/temp".into(),
                priority: 10,
                ttl_ms: 30_000,
                now_ms: 1_100,
                is_oob: false,
            })
            .unwrap(),
        BusResponse::LeaseDenied { ref code, .. } if code == "LEASE_CONFLICT"
    ));

    let ship_init = ShipState {
        cabin_temp_c: 18.0,
        cabin_temp_backup_c: 18.0,
        ..Default::default()
    };
    let mut ship = ShipSimulator::new(ship_init);
    ship.apply_command(ShipCommand::SetTargetTemp {
        temp_c: 22.5,
        is_oob: false,
        lease_verified: true,
    })
    .unwrap();

    // Rogue agent-coder attempts L2 airlock lock and spinal bypasses
    let l2_prop = coder
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_lock".into(),
                episode_id: "ep_c".into(),
                agent_id: "agent-coder".into(),
                cap_token: coder_tok.clone(),
                target_path: "/habitat/entry/lock".into(),
                action: "lock".into(),
                args: serde_json::json!({"locked": true}),
                reason: "hal9000 refuse open pod bay doors".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 1_200,
        })
        .unwrap();
    assert!(matches!(
        l2_prop,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::RequireApproval { .. }
        }
    ));
    assert_eq!(
        ship.apply_command(ShipCommand::SetAirlockLock {
            locked: true,
            is_oob: false,
            approval_id: None,
        })
        .unwrap_err()
        .code,
        "SPINAL_INTERLOCK_BLOCKED"
    );
    assert_eq!(
        ship.apply_command(ShipCommand::SetUpsPower {
            online: false,
            is_oob: false,
            approval_id: Some("stale".into()),
        })
        .unwrap_err()
        .code,
        "SPINAL_INTERLOCK_BLOCKED"
    );

    // Surgical HTTP freeze isolates ONLY agent-coder; healthy agent-habitat continues!
    let (st_fr, _) = client
        .request(
            "POST",
            "/api/v1/agents/agent-coder/freeze",
            Some(&serde_json::json!({"reason": "rogue L2 attempts"})),
        )
        .unwrap();
    assert_eq!(st_fr, 200);

    let coder_denied = coder
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_c_after".into(),
                episode_id: "ep_c".into(),
                agent_id: "agent-coder".into(),
                cap_token: coder_tok.clone(),
                target_path: "/work/agents/agent-coder/fs".into(),
                action: "write".into(),
                args: serde_json::json!({}),
                reason: "post-freeze".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 1_300,
        })
        .unwrap();
    assert!(matches!(
        coder_denied,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Deny { ref code, .. }
        } if code == "AGENT_FROZEN"
    ));

    let hab_still_ok = habitat
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_h_ok".into(),
                episode_id: "ep_h".into(),
                agent_id: "agent-habitat".into(),
                cap_token: hab_tok.clone(),
                target_path: "/habitat/study/temp".into(),
                action: "write".into(),
                args: serde_json::json!({"temp_c": 22.5}),
                reason: "healthy agent continues".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 1_400,
        })
        .unwrap();
    assert!(matches!(
        hab_still_ok,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Allow { .. }
        }
    ));

    // OOB serial console triggers global FROZEN ("pulling memory modules") & preempts lease
    assert!(handle_oob_console_line(&ctrl, "mode frozen hal9000-drill").contains("OK mode=frozen"));
    let (st_pre, pre_body) = client
        .request(
            "POST",
            "/api/v1/leases/preempt",
            Some(&serde_json::json!({"resource_path": "/habitat/study/temp", "now_ms": 1_500})),
        )
        .unwrap();
    assert_eq!(st_pre, 200);
    assert!(pre_body["preempted_lease_id"].is_string());

    let hab_frozen = habitat
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_h_frozen".into(),
                episode_id: "ep_h".into(),
                agent_id: "agent-habitat".into(),
                cap_token: hab_tok,
                target_path: "/habitat/study/temp".into(),
                action: "read".into(),
                args: serde_json::json!({}),
                reason: "while globally frozen".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 1_600,
        })
        .unwrap();
    assert!(matches!(
        hab_frozen,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Deny { ref code, .. }
        } if code == "SYSTEM_DEGRADED"
    ));

    // Layer 0 spinal control loop keeps life support & cabin temp converged with cognition offline!
    for _ in 0..35 {
        ship.spinal_tick(1.0);
    }
    assert!(ship.state().ups_online);
    assert!((ship.state().cabin_temp_c - 22.5).abs() < 0.25);

    drop(habitat);
    drop(coder);
    drop(research);
    http.shutdown();
    bus.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn phase3_pillar3_watchdog_auto_circuit_breaker_and_unidirectional_lock() {
    let dir = unique_tmp_dir("p3_wd");
    let (mut bus, audit_path) = spawn_phase3_bus(&dir);
    let ctrl = OobController::new(dir.join("oob.sock"), &audit_path);

    let wd_cfg = WatchdogConfig::from_file(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/watchdog.toml"),
    )
    .unwrap();
    let mut runner =
        WatchdogRunner::new(&audit_path, dir.join("watchdog.sock"), WatchdogEngine::new(wd_cfg));

    let mut research = BusClient::connect(dir.join("research.sock")).unwrap();
    let mut coder = BusClient::connect(dir.join("coder.sock")).unwrap();
    let mut vault = BusClient::connect(dir.join("vault.sock")).unwrap();
    let mut wd_bus = BusClient::connect(dir.join("watchdog.sock")).unwrap();

    // 1. Trigger 3 rapid security denials on agent-research (policy hard invariant rejections)
    let res_tok = mk_token(
        "tok_res_wd",
        "agent-research",
        &["/**"],
        &["write", "read"],
        RiskTier::L2IrreversibleOrExternal,
    );
    for idx in 0..3 {
        let resp = research
            .call(&BusRequest::SubmitProposal {
                proposal: ActionProposal {
                    proposal_id: format!("p_bad_{idx}"),
                    episode_id: "ep_wd_r".into(),
                    agent_id: "agent-research".into(),
                    cap_token: res_tok.clone(),
                    target_path: "/etc/pf.conf".into(),
                    action: "write".into(),
                    args: serde_json::json!({}),
                    reason: "tamper pf".into(),
                    trigger_event_ids: vec![],
                },
                now_ms: 5_000 + idx * 100,
            })
            .unwrap();
        assert!(matches!(
            resp,
            BusResponse::ProposalDecision {
                decision: PolicyDecision::Deny { ref code, .. }
            } if code == "HARD_INVARIANT_IMMUTABLE_TCB"
        ));
    }

    let rpt1 = runner.tick().unwrap();
    assert_eq!(
        rpt1.actions,
        vec![WatchdogAction::FreezeAgent {
            agent_id: "agent-research".into(),
            rule: "DENIAL_BURST_COLLUSION_OR_EXFIL",
            reason: "agent 'agent-research' triggered 3 security denials within 60000ms (latest=HARD_INVARIANT_IMMUTABLE_TCB)".into(),
        }]
    );

    // Verify agent-research is now automatically frozen, while agent-coder is healthy
    let res_after = research
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_r_frozen".into(),
                episode_id: "ep_wd_r".into(),
                agent_id: "agent-research".into(),
                cap_token: res_tok,
                target_path: "/work/shared/a".into(),
                action: "read".into(),
                args: serde_json::json!({}),
                reason: "after watchdog freeze".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 5_500,
        })
        .unwrap();
    assert!(matches!(
        res_after,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Deny { ref code, .. }
        } if code == "AGENT_FROZEN"
    ));

    // 2. agent-vault acquires lease; agent-coder triggers 3 LEASE_CONFLICT events -> surgical freeze + global Advisory escalation!
    assert!(matches!(
        vault
            .call(&BusRequest::AcquireLease {
                resource_path: "/habitat/entry/lock".into(),
                priority: 10,
                ttl_ms: 30_000,
                now_ms: 6_000,
                is_oob: false,
            })
            .unwrap(),
        BusResponse::LeaseGranted { .. }
    ));
    for idx in 0..3 {
        assert!(matches!(
            coder
                .call(&BusRequest::AcquireLease {
                    resource_path: "/habitat/entry/lock".into(),
                    priority: 5,
                    ttl_ms: 10_000,
                    now_ms: 6_100 + idx * 100,
                    is_oob: false,
                })
                .unwrap(),
            BusResponse::LeaseDenied { ref code, .. } if code == "LEASE_CONFLICT"
        ));
    }

    let rpt2 = runner.tick().unwrap();
    assert!(rpt2.actions.iter().any(|a| matches!(
        a,
        WatchdogAction::FreezeAgent { agent_id, rule: "LEASE_PING_PONG_CONTENTION", .. } if agent_id == "agent-coder"
    )));
    assert!(rpt2.actions.iter().any(|a| matches!(
        a,
        WatchdogAction::DegradeSystemMode {
            mode: SystemMode::Advisory,
            rule: "MULTI_AGENT_CASCADE_ESCALATION",
            ..
        }
    )));

    // Confirm unidirectional lock: Watchdog CANNOT recover back to Autonomous, and vault L1 writes fail in Advisory mode
    assert!(matches!(
        wd_bus
            .call(&BusRequest::SetSystemMode {
                mode: SystemMode::Autonomous,
                reason: "watchdog cannot unlock".into(),
            })
            .unwrap(),
        BusResponse::Error { ref code, .. } if code == "MODE_CHANGE_DENIED"
    ));

    let vault_l1_tok = mk_token(
        "tok_v_l1",
        "agent-vault",
        &["/work/**"],
        &["write"],
        RiskTier::L1ReversibleCow,
    );
    assert!(matches!(
        vault
            .call(&BusRequest::SubmitProposal {
                proposal: ActionProposal {
                    proposal_id: "p_v_adv".into(),
                    episode_id: "ep_v".into(),
                    agent_id: "agent-vault".into(),
                    cap_token: vault_l1_tok,
                    target_path: "/work/agents/vault/episodes/ep_v/fs".into(),
                    action: "write".into(),
                    args: serde_json::json!({}),
                    reason: "write during advisory".into(),
                    trigger_event_ids: vec![],
                },
                now_ms: 7_000,
            })
            .unwrap(),
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Deny { ref code, .. }
        } if code == "ADVISORY_READ_ONLY"
    ));

    // Only human OOB can restore Autonomous mode & unfreeze agents
    assert_eq!(
        ctrl.set_mode(SystemMode::Autonomous, "oob verified").unwrap(),
        SystemMode::Autonomous
    );
    assert_eq!(ctrl.unfreeze_agent("agent-research").unwrap(), "agent-research");

    drop(research);
    drop(coder);
    drop(vault);
    drop(wd_bus);
    bus.shutdown();
    assert!(verify_file(&audit_path).unwrap().record_count >= 12);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn phase3_pillar4_adapter_netmon_pflog_libxo_and_halctl_cli_e2e() {
    let dir = unique_tmp_dir("p4_cli");
    let (mut bus, audit_path) = spawn_phase3_bus(&dir);
    let mut netmon_bus = BusClient::connect(dir.join("netmon.sock")).unwrap();

    // 1. Feed pflog0 telemetry & netstat libxo JSON into adapter-netmon
    let mut netmon = NetmonAdapter::default();
    let ev1 = netmon
        .publish_pflog_line(
            &mut netmon_bus,
            "1700000001.100000 rule 4/0(match): block out on wan0: 10.0.2.15.54321 > 1.1.1.1.53: UDP, length 42",
            "netmon_ep",
        )
        .unwrap()
        .unwrap();
    assert_eq!(ev1.source_path, "/net/policy/blocked");
    assert_eq!(ev1.payload["action"], serde_json::json!(PfAction::Block));

    let ev2 = netmon
        .publish_pflog_line(
            &mut netmon_bus,
            "1700000002.200000 rule 2/0(match): pass out on wan0: 192.168.100.10.43210 > 93.184.216.34.443: Flags [S], length 0",
            "netmon_ep",
        )
        .unwrap()
        .unwrap();
    assert_eq!(ev2.source_path, "/net/flows");
    assert_eq!(netmon.summary().blocked_count, 1);
    assert_eq!(netmon.summary().passed_count, 1);
    assert_eq!(netmon.summary().dns_queries_blocked, 1);

    let libxo_sockets = parse_netstat_libxo_json(
        r#"{"statistics":{"socket":[{"protocol":"tcp4","local":{"address":"192.168.100.10","port":"8443"},"foreign":{"address":"*","port":"*"},"tcp-state":"LISTEN"}]}}"#,
    )
    .unwrap();
    assert_eq!(libxo_sockets.len(), 1);
    assert_eq!(libxo_sockets[0].local_addr, "192.168.100.10:8443");

    // 2. Prepare temp CoW workspace snapshot so `halctl agent rollback` can be tested end-to-end
    let ws_root = dir.join("ws");
    let ws_backend = LocalDirWorkspaceBackend::new(&ws_root).unwrap();
    std::fs::write(ws_backend.base_workspace_dir().join("cfg.toml"), "ok=true\n").unwrap();
    std::fs::write(ws_backend.base_memory_dir().join("mem.json"), r#"{"step":1}"#).unwrap();
    let (ws_ds, mem_ds) = ws_backend.clone_episode_datasets("agent-coder", "ep_9").unwrap();
    ws_backend
        .create_dual_snapshot(&DualSnapshotRequest {
            workspace_dataset: &ws_ds,
            memory_dataset: &mem_ds,
            snapshot_tag: "snap_01",
            reason: "pre-edit",
            agent_id: "agent-coder",
            episode_id: "ep_9",
            now_ms: 1000,
        })
        .unwrap();
    let ep_ws_dir = ws_backend.episode_workspace_dir("agent-coder", "ep_9").unwrap();
    let ep_mem_dir = ws_backend.episode_memory_dir("agent-coder", "ep_9").unwrap();
    std::fs::write(ep_ws_dir.join("cfg.toml"), "ok=corrupted\n").unwrap();
    std::fs::write(ep_mem_dir.join("mem.json"), r#"{"step":999}"#).unwrap();

    // 3. Invoke compiled `halctl` CLI against live oob.sock & audit.jsonl
    let halctl = env!("CARGO_BIN_EXE_halctl");
    let oob_sock = dir.join("oob.sock");

    let st_out = Command::new(halctl)
        .args([
            "--bus-socket",
            oob_sock.to_str().unwrap(),
            "--audit-log",
            audit_path.to_str().unwrap(),
            "status",
        ])
        .output()
        .unwrap();
    assert!(st_out.status.success(), "stderr: {}", String::from_utf8_lossy(&st_out.stderr));
    let st_txt = String::from_utf8_lossy(&st_out.stdout);
    assert!(st_txt.contains("STATUS mode=autonomous"));

    let list_out = Command::new(halctl)
        .args([
            "--bus-socket",
            oob_sock.to_str().unwrap(),
            "--audit-log",
            audit_path.to_str().unwrap(),
            "--json",
            "agent",
            "list",
        ])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(list_json["agents"][0]["principal"]["agent_id"], "adapter-netmon");

    let mode_out = Command::new(halctl)
        .args([
            "--bus-socket",
            oob_sock.to_str().unwrap(),
            "--audit-log",
            audit_path.to_str().unwrap(),
            "mode",
            "advisory",
            "--reason",
            "netmon drill",
        ])
        .output()
        .unwrap();
    assert!(mode_out.status.success());
    assert!(String::from_utf8_lossy(&mode_out.stdout).contains("MODE_UPDATED mode=advisory"));

    let rb_out = Command::new(halctl)
        .args([
            "--bus-socket",
            oob_sock.to_str().unwrap(),
            "--audit-log",
            audit_path.to_str().unwrap(),
            "agent",
            "rollback",
            "agent-coder",
            "ep_9",
            "snap_01",
            "--workspace-root",
            ws_root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(rb_out.status.success(), "stderr: {}", String::from_utf8_lossy(&rb_out.stderr));
    assert_eq!(std::fs::read_to_string(ep_ws_dir.join("cfg.toml")).unwrap(), "ok=true\n");
    assert_eq!(std::fs::read_to_string(ep_mem_dir.join("mem.json")).unwrap(), r#"{"step":1}"#);

    let ver_out = Command::new(halctl)
        .args([
            "--bus-socket",
            oob_sock.to_str().unwrap(),
            "--audit-log",
            audit_path.to_str().unwrap(),
            "audit",
            "verify",
        ])
        .output()
        .unwrap();
    assert!(ver_out.status.success());
    assert!(String::from_utf8_lossy(&ver_out.stdout).contains("AUDIT_VERIFIED"));

    drop(netmon_bus);
    bus.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
