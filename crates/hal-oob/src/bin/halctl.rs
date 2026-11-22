use hal_oob::OobController;
use hal_proto::SystemMode;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn print_usage() {
    println!(
        "Usage: halctl [--bus-socket <path>] [--audit-log <path>] [--workspace-root <path>] [--json] [--check] <command>
Commands:
  status
  agent list
  agent freeze <id> [--reason <text>]
  agent unfreeze <id>
  agent revoke <id> [--reason <text>]
  agent rollback <id> <episode_id> <snapshot_tag> [--workspace-root <path>]
  mode <autonomous|advisory|frozen|lockdown> [--reason <text>]
  approvals list
  approvals approve <id> [--note <text>]
  approvals reject <id> [--note <text>]
  lease preempt <resource_path> [--ttl-ms <ms>]
  audit verify [<path>]"
    );
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut bus_socket = PathBuf::from("/var/run/hal/bus/oob.sock");
    let mut audit_log = PathBuf::from("/pool/audit/hal-audit.log");
    let mut workspace_root = PathBuf::from("/");
    let mut reason: Option<String> = None;
    let mut note: Option<String> = None;
    let mut ttl_ms: u64 = 60_000;
    let mut json_out = false;
    let mut check_only = false;
    let mut pos: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bus-socket" if i + 1 < args.len() => {
                bus_socket = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--audit-log" if i + 1 < args.len() => {
                audit_log = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--workspace-root" if i + 1 < args.len() => {
                workspace_root = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--reason" if i + 1 < args.len() => {
                reason = Some(args[i + 1].clone());
                i += 2;
            }
            "--note" if i + 1 < args.len() => {
                note = Some(args[i + 1].clone());
                i += 2;
            }
            "--ttl-ms" if i + 1 < args.len() => {
                ttl_ms = args[i + 1]
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --ttl-ms: {e}"))?;
                i += 2;
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(ExitCode::SUCCESS);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag '{other}'"));
            }
            other => {
                pos.push(other.to_string());
                i += 1;
            }
        }
    }

    if check_only && pos.is_empty() {
        println!("HALCTL_READY check_only=true");
        return Ok(ExitCode::SUCCESS);
    }

    let refs: Vec<&str> = pos.iter().map(String::as_str).collect();
    if refs.is_empty() {
        print_usage();
        return Ok(ExitCode::from(2));
    }

    let ctrl = OobController::new(&bus_socket, &audit_log);
    let now_ms = now_unix_ms();

    match refs.as_slice() {
        ["status"] => {
            let s = ctrl.status().map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?
                );
            } else {
                println!(
                    "STATUS mode={} agents={} frozen={} pending_approvals={} audit_records={} head_hash={}",
                    s.system_mode,
                    s.agent_count,
                    s.frozen_count,
                    s.pending_approval_count,
                    s.audit_records,
                    s.audit_head_hash
                );
            }
        }
        ["agent", "list"] => {
            let (agents, mode) = ctrl.list_agents().map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"system_mode": mode, "agents": agents}))
                        .map_err(|e| e.to_string())?
                );
            } else {
                println!("AGENTS mode={mode} count={}", agents.len());
                for a in agents {
                    let st = a.frozen_reason.unwrap_or_else(|| "active".to_string());
                    println!("  - {} domain={} status={st}", a.principal.agent_id, a.principal.trust_domain);
                }
            }
        }
        ["agent", "freeze", id] => {
            let r = reason.as_deref().unwrap_or("halctl agent freeze");
            let frozen = ctrl.freeze_agent(id, r).map_err(|e| e.to_string())?;
            if json_out {
                println!("{}", json!({"agent_id": frozen, "frozen": true}));
            } else {
                println!("AGENT_FROZEN id={frozen}");
            }
        }
        ["agent", "unfreeze", id] => {
            let unfrozen = ctrl.unfreeze_agent(id).map_err(|e| e.to_string())?;
            if json_out {
                println!("{}", json!({"agent_id": unfrozen, "frozen": false}));
            } else {
                println!("AGENT_UNFROZEN id={unfrozen}");
            }
        }
        ["agent", "revoke", id] => {
            let r = reason.as_deref().unwrap_or("halctl agent revoke");
            let revoked = ctrl.revoke_agent(id, r).map_err(|e| e.to_string())?;
            if json_out {
                println!("{}", json!({"agent_id": revoked, "revoked": true}));
            } else {
                println!("AGENT_REVOKED id={revoked}");
            }
        }
        ["agent", "rollback", id, episode_id, tag] => {
            ctrl.rollback_agent_workspace(&workspace_root, id, episode_id, tag)
                .map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    json!({"agent_id": id, "episode_id": episode_id, "tag": tag, "rolled_back": true})
                );
            } else {
                println!("AGENT_ROLLED_BACK id={id} episode={episode_id} tag={tag}");
            }
        }
        ["mode", mode_str] => {
            let mode = SystemMode::from_str(mode_str)?;
            let r = reason.as_deref().unwrap_or("halctl mode update");
            let updated = ctrl.set_mode(mode, r).map_err(|e| e.to_string())?;
            if json_out {
                println!("{}", json!({"mode": updated}));
            } else {
                println!("MODE_UPDATED mode={updated}");
            }
        }
        ["approvals", "list"] => {
            let approvals = ctrl.list_approvals().map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"approvals": approvals}))
                        .map_err(|e| e.to_string())?
                );
            } else {
                println!("APPROVALS count={}", approvals.len());
                for a in approvals {
                    println!(
                        "  - {} status={:?} agent={} path={} summary={}",
                        a.approval_id, a.status, a.principal.agent_id, a.proposal.target_path, a.summary
                    );
                }
            }
        }
        ["approvals", "approve", id] => {
            let n = note.as_deref().unwrap_or("approved via halctl");
            let resolved = ctrl
                .resolve_approval(id, true, n, now_ms)
                .map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resolved).map_err(|e| e.to_string())?
                );
            } else {
                println!("APPROVAL_RESOLVED id={} status={:?}", resolved.approval_id, resolved.status);
            }
        }
        ["approvals", "reject", id] => {
            let n = note.as_deref().unwrap_or("rejected via halctl");
            let resolved = ctrl
                .resolve_approval(id, false, n, now_ms)
                .map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resolved).map_err(|e| e.to_string())?
                );
            } else {
                println!("APPROVAL_RESOLVED id={} status={:?}", resolved.approval_id, resolved.status);
            }
        }
        ["lease", "preempt", resource_path] => {
            let (lease, preempted) = ctrl
                .preempt_lease(resource_path, ttl_ms, now_ms)
                .map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    json!({"lease": lease, "preempted_lease_id": preempted})
                );
            } else {
                println!(
                    "LEASE_PREEMPTED lease={} path={} preempted={preempted:?}",
                    lease.lease_id, lease.resource_path
                );
            }
        }
        ["audit", "verify"] => {
            let r = ctrl.verify_audit().map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    json!({"record_count": r.record_count, "head_seq": r.head_seq, "head_hash": r.head_hash})
                );
            } else {
                println!(
                    "AUDIT_VERIFIED path={} records={} head_seq={} head_hash={}",
                    audit_log.display(),
                    r.record_count,
                    r.head_seq,
                    r.head_hash
                );
            }
        }
        ["audit", "verify", custom_path] => {
            let c = OobController::new(&bus_socket, custom_path);
            let r = c.verify_audit().map_err(|e| e.to_string())?;
            if json_out {
                println!(
                    "{}",
                    json!({"record_count": r.record_count, "head_seq": r.head_seq, "head_hash": r.head_hash})
                );
            } else {
                println!(
                    "AUDIT_VERIFIED path={custom_path} records={} head_seq={} head_hash={}",
                    r.record_count, r.head_seq, r.head_hash
                );
            }
        }
        _ => {
            print_usage();
            return Ok(ExitCode::from(2));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("halctl error: {err}");
            ExitCode::from(1)
        }
    }
}
