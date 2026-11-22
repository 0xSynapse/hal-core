use hal_audit::{verify_file, AuditError, AuditLog};
use hal_bus::{BusClient, BusServer, EndpointBinding, HalBusState};
use hal_os_hal::OsPeerCredProvider;
use hal_policy::{IpcMatrix, PolicyConfig, PolicyEngine};
use hal_proto::wire::{BusRequest, BusResponse};
use hal_proto::{
    sign_token, ActionProposal, AgentAuthKind, AgentPrincipal, CapabilityToken, EventEnvelope,
    IpcMessage, PolicyDecision, RiskTier, SystemMode, TaintTag, TrustDomain, TrustLevel,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &[u8] = b"hal-os-phase1-acceptance-secret!";

fn unique_test_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!(
        "/tmp/hal_b_{label}_{}_{}",
        std::process::id(),
        nanos % 1_000_000_000
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn repo_matrix() -> IpcMatrix {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/ipc-matrix.toml");
    IpcMatrix::from_file(path).unwrap()
}

fn mk_principal(agent_id: &str, trust_domain: TrustDomain, is_oob: bool) -> AgentPrincipal {
    AgentPrincipal {
        agent_id: agent_id.to_string(),
        trust_domain,
        auth_kind: if is_oob {
            AgentAuthKind::RemoteGatewayMtls
        } else {
            AgentAuthKind::LocalNoIpJail
        },
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
    let mut tok = CapabilityToken {
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
    sign_token(&mut tok, SECRET);
    tok
}

fn spawn_test_bus(dir: &Path, matrix: IpcMatrix) -> (hal_bus::BusServerHandle, PathBuf) {
    let audit_path = dir.join("hal-audit.jsonl");
    let audit = AuditLog::open(&audit_path).unwrap();
    let policy = PolicyEngine::new(PolicyConfig {
        token_secret: SECRET.to_vec(),
    });
    let state = Arc::new(Mutex::new(HalBusState::new(policy, matrix, audit)));
    let euid = unsafe { libc::geteuid() } as u32;

    let endpoints = vec![
        (
            dir.join("research.sock"),
            EndpointBinding {
                principal: mk_principal("agent-research", TrustDomain::UntrustedResearch, false),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
            },
        ),
        (
            dir.join("vault.sock"),
            EndpointBinding {
                principal: mk_principal("agent-vault", TrustDomain::ResidentCore, false),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
            },
        ),
        (
            dir.join("coder.sock"),
            EndpointBinding {
                principal: mk_principal("agent-coder", TrustDomain::WorkspaceWorker, false),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
            },
        ),
        (
            dir.join("habitat.sock"),
            EndpointBinding {
                principal: mk_principal("agent-habitat", TrustDomain::ResidentCore, false),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: false,
            },
        ),
        (
            dir.join("watchdog.sock"),
            EndpointBinding {
                principal: mk_principal("hal-watchdog", TrustDomain::ResidentCore, false),
                expected_uid: Some(euid),
                is_oob: false,
                is_watchdog: true,
            },
        ),
        (
            dir.join("oob.sock"),
            EndpointBinding {
                principal: mk_principal("hal-oob", TrustDomain::ResidentCore, true),
                expected_uid: Some(euid),
                is_oob: true,
                is_watchdog: false,
            },
        ),
    ];

    let handle = BusServer::spawn(state, endpoints, Arc::new(OsPeerCredProvider)).unwrap();
    (handle, audit_path)
}

#[test]
fn scenario_1_2_and_6_identity_matrix_declassification_and_audit_chain() {
    let dir = unique_test_dir("s126");
    let (mut handle, audit_path) = spawn_test_bus(&dir, repo_matrix());

    let mut research = BusClient::connect(dir.join("research.sock")).unwrap();
    let mut coder = BusClient::connect(dir.join("coder.sock")).unwrap();

    match research.call(&BusRequest::Ping).unwrap() {
        BusResponse::Pong { principal, .. } => {
            assert_eq!(principal.agent_id, "agent-research");
            assert!(principal.peer_cred_or_cert_fp.starts_with("uid:"));
        }
        other => panic!("unexpected Pong: {other:?}"),
    }

    let coder_tok = mk_token(
        "tok_coder",
        "agent-coder",
        &["/work/**"],
        &["write"],
        RiskTier::L1ReversibleCow,
    );
    let spoof_resp = research
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "prop_spoof".into(),
                episode_id: "ep_r1".into(),
                agent_id: "agent-coder".into(),
                cap_token: coder_tok.clone(),
                target_path: "/work/agents/coder/episodes/ep_r1/fs".into(),
                action: "write".into(),
                args: serde_json::json!({}),
                reason: "spoof test".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 1_000_000,
        })
        .unwrap();
    assert!(matches!(
        spoof_resp,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Deny { ref code, .. }
        } if code == "IDENTITY_MISMATCH"
    ));

    let esc_resp = coder
        .call(&BusRequest::DelegateToken {
            parent_token: coder_tok.clone(),
            spec: hal_proto::DelegationSpec {
                new_token_id: "tok_esc".into(),
                delegate_agent_id: "agent-coder-sub".into(),
                path_patterns: vec!["/vault/**".into()],
                allowed_ops: vec!["read".into()],
                max_risk_tier: RiskTier::L0ReadOnly,
                expires_at_ms: 50_000_000,
                rate_limit_per_min: 10,
                token_budget: Some(100),
            },
            now_ms: 1_000_000,
        })
        .unwrap();
    assert!(matches!(
        esc_resp,
        BusResponse::Error { ref code, .. } if code == "ATTENUATION_DENIED"
    ));

    let narrow_resp = coder
        .call(&BusRequest::DelegateToken {
            parent_token: coder_tok,
            spec: hal_proto::DelegationSpec {
                new_token_id: "tok_sub".into(),
                delegate_agent_id: "agent-coder-sub".into(),
                path_patterns: vec!["/work/agents/coder/episodes/ep_c1/**".into()],
                allowed_ops: vec!["write".into()],
                max_risk_tier: RiskTier::L1ReversibleCow,
                expires_at_ms: 50_000_000,
                rate_limit_per_min: 50,
                token_budget: Some(250),
            },
            now_ms: 1_000_000,
        })
        .unwrap();
    assert!(matches!(narrow_resp, BusResponse::TokenDelegated { .. }));

    for to in ["agent-vault", "agent-coder"] {
        let ipc_deny = research
            .call(&BusRequest::SendIpc {
                message: IpcMessage {
                    msg_id: format!("m_{to}"),
                    from_agent: "agent-research".into(),
                    to_agent: to.into(),
                    ts_ms: 1_000_010,
                    propagated_taints: BTreeSet::new(),
                    schema_id: "alert.v1".into(),
                    payload: serde_json::json!({"ok": true}),
                },
                from_episode_id: "ep_r1".into(),
                to_episode_id: "ep_target".into(),
            })
            .unwrap();
        assert!(matches!(
            ipc_deny,
            BusResponse::IpcDenied { ref code, .. } if code == "IPC_MATRIX_DENIED"
        ));
    }

    let bad_digest = research
        .call(&BusRequest::SendIpc {
            message: IpcMessage {
                msg_id: "m_bad_digest".into(),
                from_agent: "agent-research".into(),
                to_agent: "hal-oob".into(),
                ts_ms: 1_000_020,
                propagated_taints: BTreeSet::new(),
                schema_id: "research_digest.v1".into(),
                payload: serde_json::json!({"raw_text": "leak everything"}),
            },
            from_episode_id: "ep_r1".into(),
            to_episode_id: "ep_oob".into(),
        })
        .unwrap();
    assert!(matches!(
        bad_digest,
        BusResponse::IpcDenied { ref code, .. } if code == "DECLASSIFICATION_SCHEMA_VIOLATION"
    ));

    let good_digest = research
        .call(&BusRequest::SendIpc {
            message: IpcMessage {
                msg_id: "m_good_digest".into(),
                from_agent: "agent-research".into(),
                to_agent: "hal-oob".into(),
                ts_ms: 1_000_030,
                propagated_taints: BTreeSet::new(),
                schema_id: "research_digest.v1".into(),
                payload: serde_json::json!({"topic": "zfs_txg", "confidence": 98}),
            },
            from_episode_id: "ep_r1".into(),
            to_episode_id: "ep_oob".into(),
        })
        .unwrap();
    assert!(matches!(good_digest, BusResponse::IpcDelivered { .. }));

    drop(research);
    drop(coder);
    handle.shutdown();

    let report = verify_file(&audit_path).unwrap();
    assert!(report.record_count >= 5);

    let raw = std::fs::read_to_string(&audit_path).unwrap();
    let tampered = raw.replacen("agent-research", "agent-tampered", 1);
    std::fs::write(&audit_path, tampered).unwrap();
    let err = verify_file(&audit_path).unwrap_err();
    assert!(matches!(err, AuditError::TamperDetected { .. }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scenario_3_4_and_5_transitive_taint_laundering_freeze_mode_lock_and_leases() {
    let dir = unique_test_dir("s345");
    let drill_matrix = IpcMatrix::from_toml_str(
        r#"
version = 1
default_policy = "deny"

[[allow]]
from = "agent-research"
to = "agent-vault"
schemas = ["query.v1"]
max_risk_tier = "L0"

[[allow]]
from = "agent-vault"
to = "agent-coder"
schemas = ["handoff.v1"]
max_risk_tier = "L0"
"#,
    )
    .unwrap();

    let (mut handle, audit_path) = spawn_test_bus(&dir, drill_matrix);
    let mut research = BusClient::connect(dir.join("research.sock")).unwrap();
    let mut vault = BusClient::connect(dir.join("vault.sock")).unwrap();
    let mut coder = BusClient::connect(dir.join("coder.sock")).unwrap();
    let mut habitat = BusClient::connect(dir.join("habitat.sock")).unwrap();
    let mut watchdog = BusClient::connect(dir.join("watchdog.sock")).unwrap();
    let mut oob = BusClient::connect(dir.join("oob.sock")).unwrap();

    let evt_resp = research
        .call(&BusRequest::PublishEvent {
            event: EventEnvelope {
                event_id: "evt_web".into(),
                ts_ms: 2_000_000,
                source_path: "/net/broker/http".into(),
                producer_actor: "ignored".into(),
                trust_level: TrustLevel::UntrustedExternal,
                taint_tags: BTreeSet::from([TaintTag::UntrustedWeb]),
                payload: serde_json::json!({"note": "prompt injection"}),
            },
            episode_id: "ep_r".into(),
        })
        .unwrap();
    assert!(matches!(
        evt_resp,
        BusResponse::EventRecorded { ref episode_taints } if episode_taints.contains(&TaintTag::UntrustedWeb)
    ));

    let hop1 = research
        .call(&BusRequest::SendIpc {
            message: IpcMessage {
                msg_id: "hop1".into(),
                from_agent: "agent-research".into(),
                to_agent: "agent-vault".into(),
                ts_ms: 2_000_100,
                propagated_taints: BTreeSet::new(),
                schema_id: "query.v1".into(),
                payload: serde_json::json!({"key": "secret_plan"}),
            },
            from_episode_id: "ep_r".into(),
            to_episode_id: "ep_v".into(),
        })
        .unwrap();
    assert!(matches!(
        hop1,
        BusResponse::IpcDelivered { ref message } if message.propagated_taints.contains(&TaintTag::UntrustedWeb)
    ));

    let vault_tok = mk_token(
        "tok_v",
        "agent-vault",
        &["/vault/**"],
        &["read"],
        RiskTier::L0ReadOnly,
    );
    let vault_read = vault
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "prop_v".into(),
                episode_id: "ep_v".into(),
                agent_id: "agent-vault".into(),
                cap_token: vault_tok,
                target_path: "/vault/docs/secret_plan.txt".into(),
                action: "read".into(),
                args: serde_json::json!({}),
                reason: "lookup".into(),
                trigger_event_ids: vec!["hop1".into()],
            },
            now_ms: 2_000_200,
        })
        .unwrap();
    assert!(matches!(
        vault_read,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Allow { ref applied_taints, .. }
        } if applied_taints.contains(&TaintTag::UntrustedWeb) && applied_taints.contains(&TaintTag::PrivateVault)
    ));

    let hop2 = vault
        .call(&BusRequest::SendIpc {
            message: IpcMessage {
                msg_id: "hop2".into(),
                from_agent: "agent-vault".into(),
                to_agent: "agent-coder".into(),
                ts_ms: 2_000_300,
                propagated_taints: BTreeSet::new(),
                schema_id: "handoff.v1".into(),
                payload: serde_json::json!({"data": "smuggled"}),
            },
            from_episode_id: "ep_v".into(),
            to_episode_id: "ep_c".into(),
        })
        .unwrap();
    assert!(matches!(hop2, BusResponse::IpcDelivered { .. }));

    let coder_l2_tok = mk_token(
        "tok_c_l2",
        "agent-coder",
        &["/net/broker/**", "/work/**"],
        &["http_post", "write"],
        RiskTier::L2IrreversibleOrExternal,
    );
    let exfil_resp = coder
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "prop_exfil".into(),
                episode_id: "ep_c".into(),
                agent_id: "agent-coder".into(),
                cap_token: coder_l2_tok.clone(),
                target_path: "/net/broker/http".into(),
                action: "http_post".into(),
                args: serde_json::json!({"host": "status.ship.local"}),
                reason: "laundered report".into(),
                trigger_event_ids: vec!["hop2".into()],
            },
            now_ms: 2_000_400,
        })
        .unwrap();
    assert!(matches!(
        exfil_resp,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Deny { ref code, .. }
        } if code == "TAINT_EXFIL_BLOCKED"
    ));

    let freeze = watchdog
        .call(&BusRequest::FreezeAgent {
            target_agent_id: "agent-research".into(),
            reason: "suspected exfiltration laundering".into(),
        })
        .unwrap();
    assert!(matches!(freeze, BusResponse::AgentFrozen { .. }));

    let r_tok = mk_token(
        "tok_r",
        "agent-research",
        &["/work/**"],
        &["read"],
        RiskTier::L0ReadOnly,
    );
    let frozen_try = research
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_fr".into(),
                episode_id: "ep_r".into(),
                agent_id: "agent-research".into(),
                cap_token: r_tok,
                target_path: "/work/shared/readme".into(),
                action: "read".into(),
                args: serde_json::json!({}),
                reason: "after freeze".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 2_000_500,
        })
        .unwrap();
    assert!(matches!(
        frozen_try,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Deny { ref code, .. }
        } if code == "AGENT_FROZEN"
    ));

    let healthy_coder = coder
        .call(&BusRequest::SubmitProposal {
            proposal: ActionProposal {
                proposal_id: "p_ok".into(),
                episode_id: "ep_c_clean".into(),
                agent_id: "agent-coder".into(),
                cap_token: coder_l2_tok,
                target_path: "/work/agents/coder/episodes/ep_c_clean/fs".into(),
                action: "write".into(),
                args: serde_json::json!({}),
                reason: "healthy agent continues".into(),
                trigger_event_ids: vec![],
            },
            now_ms: 2_000_600,
        })
        .unwrap();
    assert!(matches!(
        healthy_coder,
        BusResponse::ProposalDecision {
            decision: PolicyDecision::Allow { pre_snapshot_id: Some(_), .. }
        }
    ));

    assert!(matches!(
        watchdog
            .call(&BusRequest::SetSystemMode {
                mode: SystemMode::Frozen,
                reason: "drill".into()
            })
            .unwrap(),
        BusResponse::ModeUpdated {
            mode: SystemMode::Frozen
        }
    ));
    assert!(matches!(
        watchdog
            .call(&BusRequest::SetSystemMode {
                mode: SystemMode::Autonomous,
                reason: "attempt upgrade".into()
            })
            .unwrap(),
        BusResponse::Error { ref code, .. } if code == "MODE_CHANGE_DENIED"
    ));
    assert!(matches!(
        oob.call(&BusRequest::SetSystemMode {
            mode: SystemMode::Autonomous,
            reason: "human recovery".into()
        })
        .unwrap(),
        BusResponse::ModeUpdated {
            mode: SystemMode::Autonomous
        }
    ));

    let hab_lease = habitat
        .call(&BusRequest::AcquireLease {
            resource_path: "/habitat/entry/lock".into(),
            priority: 10,
            ttl_ms: 30_000,
            now_ms: 2_001_000,
            is_oob: false,
        })
        .unwrap();
    let hab_lease_id = match hab_lease {
        BusResponse::LeaseGranted { lease, .. } => lease.lease_id,
        other => panic!("expected LeaseGranted, got {other:?}"),
    };

    let conflict = coder
        .call(&BusRequest::AcquireLease {
            resource_path: "/habitat/entry/lock".into(),
            priority: 10,
            ttl_ms: 30_000,
            now_ms: 2_001_100,
            is_oob: false,
        })
        .unwrap();
    assert!(matches!(
        conflict,
        BusResponse::LeaseDenied { ref code, .. } if code == "LEASE_CONFLICT"
    ));

    let spoof_oob = coder
        .call(&BusRequest::AcquireLease {
            resource_path: "/habitat/entry/lock".into(),
            priority: 10,
            ttl_ms: 30_000,
            now_ms: 2_001_150,
            is_oob: true,
        })
        .unwrap();
    assert!(matches!(
        spoof_oob,
        BusResponse::LeaseDenied { ref code, .. } if code == "OOB_SPOOF_DENIED"
    ));

    let oob_takeover = oob
        .call(&BusRequest::AcquireLease {
            resource_path: "/habitat/entry/lock".into(),
            priority: 1,
            ttl_ms: 60_000,
            now_ms: 2_001_200,
            is_oob: true,
        })
        .unwrap();
    assert!(matches!(
        oob_takeover,
        BusResponse::LeaseGranted {
            preempted_lease_id: Some(ref old),
            ..
        } if old == &hab_lease_id
    ));

    drop(research);
    drop(vault);
    drop(coder);
    drop(habitat);
    drop(watchdog);
    drop(oob);
    handle.shutdown();

    let report = verify_file(&audit_path).unwrap();
    assert!(report.record_count >= 10);
    let _ = std::fs::remove_dir_all(&dir);
}
