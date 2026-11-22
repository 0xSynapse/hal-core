use crate::service::OobController;
use hal_proto::SystemMode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Processes one emergency OOB serial console line (simulating `virtio-console` / `ttyu0`).
#[must_use]
pub fn handle_oob_console_line(ctrl: &OobController, line: &str) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return "ERR empty command (try 'help')".to_string();
    }

    match parts.as_slice() {
        ["help"] => {
            "OK commands: status | agent list|freeze|unfreeze|revoke | mode <m> | approvals | approve <id> | reject <id> | preempt <path> | audit verify"
                .to_string()
        }
        ["status"] => match ctrl.status() {
            Ok(s) => format!(
                "OK mode={} agents={} frozen={} pending_approvals={} audit_records={} head_hash={}",
                s.system_mode,
                s.agent_count,
                s.frozen_count,
                s.pending_approval_count,
                s.audit_records,
                s.audit_head_hash
            ),
            Err(e) => format!("ERR {e}"),
        },
        ["agent", "list"] => match ctrl.list_agents() {
            Ok((agents, mode)) => {
                let items: Vec<String> = agents
                    .iter()
                    .map(|a| match &a.frozen_reason {
                        Some(r) => format!("{}(frozen:{r})", a.principal.agent_id),
                        None => format!("{}(active)", a.principal.agent_id),
                    })
                    .collect();
                format!("OK mode={} agents=[{}]", mode, items.join(","))
            }
            Err(e) => format!("ERR {e}"),
        },
        ["agent", "freeze", id, rest @ ..] => {
            let reason = if rest.is_empty() {
                "oob-console-freeze".to_string()
            } else {
                rest.join(" ")
            };
            match ctrl.freeze_agent(id, &reason) {
                Ok(frozen) => format!("OK frozen agent={frozen}"),
                Err(e) => format!("ERR {e}"),
            }
        }
        ["agent", "unfreeze", id] => match ctrl.unfreeze_agent(id) {
            Ok(id) => format!("OK unfrozen agent={id}"),
            Err(e) => format!("ERR {e}"),
        },
        ["agent", "revoke", id, rest @ ..] => {
            let reason = if rest.is_empty() {
                "oob-console-revoke".to_string()
            } else {
                rest.join(" ")
            };
            match ctrl.revoke_agent(id, &reason) {
                Ok(revoked) => format!("OK revoked agent={revoked}"),
                Err(e) => format!("ERR {e}"),
            }
        }
        ["mode", mode_str, rest @ ..] => match SystemMode::from_str(mode_str) {
            Ok(mode) => {
                let reason = if rest.is_empty() {
                    "oob-console".to_string()
                } else {
                    rest.join(" ")
                };
                match ctrl.set_mode(mode, &reason) {
                    Ok(updated) => format!("OK mode={updated}"),
                    Err(e) => format!("ERR {e}"),
                }
            }
            Err(e) => format!("ERR {e}"),
        },
        ["approvals"] => match ctrl.list_approvals() {
            Ok(list) => {
                let items: Vec<String> = list
                    .iter()
                    .map(|a| format!("{}:{:?}:{}", a.approval_id, a.status, a.proposal.target_path))
                    .collect();
                format!("OK approvals=[{}]", items.join(","))
            }
            Err(e) => format!("ERR {e}"),
        },
        ["approve", id, rest @ ..] => {
            let note = if rest.is_empty() {
                "approved via oob-console".to_string()
            } else {
                rest.join(" ")
            };
            match ctrl.resolve_approval(id, true, &note, now_unix_ms()) {
                Ok(a) => format!("OK approval={} status={:?}", a.approval_id, a.status),
                Err(e) => format!("ERR {e}"),
            }
        }
        ["reject", id, rest @ ..] => {
            let note = if rest.is_empty() {
                "rejected via oob-console".to_string()
            } else {
                rest.join(" ")
            };
            match ctrl.resolve_approval(id, false, &note, now_unix_ms()) {
                Ok(a) => format!("OK approval={} status={:?}", a.approval_id, a.status),
                Err(e) => format!("ERR {e}"),
            }
        }
        ["preempt", path] => match ctrl.preempt_lease(path, 60_000, now_unix_ms()) {
            Ok((lease, prev)) => format!(
                "OK lease={} path={} preempted={prev:?}",
                lease.lease_id, lease.resource_path
            ),
            Err(e) => format!("ERR {e}"),
        },
        ["audit", "verify"] => match ctrl.verify_audit() {
            Ok(r) => format!(
                "OK records={} head_seq={} head_hash={}",
                r.record_count, r.head_seq, r.head_hash
            ),
            Err(e) => format!("ERR {e}"),
        },
        _ => "ERR unknown console command (try 'help')".to_string(),
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
    use std::sync::{Arc, Mutex};

    #[test]
    fn serial_console_handles_freeze_and_mode_switch() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(format!(
            "/tmp/hal_con_{}_{}",
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
                token_secret: b"oob-console-test-secret-key-32b!".to_vec(),
            }),
            matrix,
            audit,
        )));
        let euid = unsafe { libc::geteuid() } as u32;
        let oob_sock = dir.join("oob.sock");
        let mut handle = BusServer::spawn(
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

        let ctrl = OobController::new(oob_sock, audit_path);
        assert!(handle_oob_console_line(&ctrl, "status").starts_with("OK mode=autonomous"));
        assert!(handle_oob_console_line(&ctrl, "agent freeze agent-research bad")
            .contains("OK frozen agent=agent-research"));
        assert!(handle_oob_console_line(&ctrl, "mode frozen emergency")
            .contains("OK mode=frozen"));
        assert!(handle_oob_console_line(&ctrl, "audit verify").starts_with("OK records=2"));

        handle.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
