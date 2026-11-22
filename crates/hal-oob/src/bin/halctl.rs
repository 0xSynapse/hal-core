use hal_oob::{enroll_peer, mint_token, OobController, PeerEnrollRequest, TokenMintRequest};
use hal_proto::{parse_duration_ms, RiskTier, SystemMode};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_PEERS_CONFIG: &str = "/usr/local/etc/hal-os/gateway-peers.toml";
const DEFAULT_SECRETS_FILE: &str = "/usr/local/etc/hal-os/secrets.env";
const DEFAULT_GATEWAY_ADDR: &str = "10.99.0.1:9443";

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
  audit verify [<path>]
  peer enroll --agent-id <id> --ip <ip_or_cidr>... [--gateway-addr <ip:port>] [--bundle-out <path>] [--peers-config <path>] [--secrets-file <path>] [--token-secret-env <ENV>] [--peer-key-env <ENV>] [--cert-sha256 <hex64>] [--paths <p1,p2>] [--ops <op1,op2>] [--max-tier <L0|L1|L2>] [--ttl <dur>] [--rate-limit <rpm>] [--token-budget <n>] [--wg-pubkey <key>] [--replace] [--json]
  token mint --agent-id <id> [--out <path>] [--peers-config <path>] [--secrets-file <path>] [--token-secret-env <ENV>] [--paths <p1,p2>] [--ops <op1,op2>] [--max-tier <L0|L1|L2>] [--ttl <dur>] [--rate-limit <rpm>] [--token-budget <n>] [--json]"
    );
}

fn take_opt(args: &[String], i: &mut usize) -> Result<String, String> {
    if *i + 1 >= args.len() {
        return Err(format!("missing value after '{}'", args[*i]));
    }
    let val = args[*i + 1].clone();
    *i += 2;
    Ok(val)
}

fn append_csv(dst: &mut Vec<String>, raw: &str) {
    for part in raw.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() {
            dst.push(trimmed.to_string());
        }
    }
}

fn match_subcommand<'a>(
    args: &'a [String],
    first: &str,
    second: &str,
) -> Option<(bool, &'a [String])> {
    if args.len() >= 3 && args[1] == first && args[2] == second {
        Some((false, &args[3..]))
    } else if args.len() >= 4 && args[1] == "--json" && args[2] == first && args[3] == second {
        Some((true, &args[4..]))
    } else {
        None
    }
}

fn run_peer_enroll(args: &[String], initial_json: bool) -> Result<ExitCode, String> {
    let mut json_out = initial_json;
    let mut agent_id: Option<String> = None;
    let mut allowed_ips: Vec<String> = Vec::new();
    let mut gateway_addr = DEFAULT_GATEWAY_ADDR.to_string();
    let mut peers_config_path = PathBuf::from(DEFAULT_PEERS_CONFIG);
    let mut secrets_file_path = PathBuf::from(DEFAULT_SECRETS_FILE);
    let mut bundle_out_path: Option<PathBuf> = None;
    let mut token_secret_env = "HAL_TOKEN_SECRET".to_string();
    let mut peer_key_env: Option<String> = None;
    let mut cert_sha256: Option<String> = None;
    let mut custom_paths: Vec<String> = Vec::new();
    let mut custom_ops: Vec<String> = Vec::new();
    let mut max_risk_tier = RiskTier::L1ReversibleCow;
    let mut ttl_ms: u64 = 24 * 3_600_000;
    let mut rate_limit_per_min: u32 = 60;
    let mut token_budget: Option<u64> = Some(10_000);
    let mut wg_pubkey: Option<String> = None;
    let mut replace = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--agent-id" => agent_id = Some(take_opt(args, &mut i)?),
            "--ip" => {
                let raw = take_opt(args, &mut i)?;
                append_csv(&mut allowed_ips, &raw);
            }
            "--gateway-addr" => gateway_addr = take_opt(args, &mut i)?,
            "--peers-config" => peers_config_path = PathBuf::from(take_opt(args, &mut i)?),
            "--secrets-file" => secrets_file_path = PathBuf::from(take_opt(args, &mut i)?),
            "--bundle-out" => bundle_out_path = Some(PathBuf::from(take_opt(args, &mut i)?)),
            "--token-secret-env" => token_secret_env = take_opt(args, &mut i)?,
            "--peer-key-env" => peer_key_env = Some(take_opt(args, &mut i)?),
            "--cert-sha256" => cert_sha256 = Some(take_opt(args, &mut i)?),
            "--paths" => {
                let raw = take_opt(args, &mut i)?;
                append_csv(&mut custom_paths, &raw);
            }
            "--ops" => {
                let raw = take_opt(args, &mut i)?;
                append_csv(&mut custom_ops, &raw);
            }
            "--max-tier" => {
                let raw = take_opt(args, &mut i)?;
                max_risk_tier = RiskTier::from_short_str(&raw)
                    .ok_or_else(|| format!("invalid --max-tier '{raw}': expected L0, L1, or L2"))?;
            }
            "--ttl" => {
                let raw = take_opt(args, &mut i)?;
                ttl_ms = parse_duration_ms(&raw)?;
            }
            "--rate-limit" => {
                let raw = take_opt(args, &mut i)?;
                rate_limit_per_min = raw
                    .parse::<u32>()
                    .map_err(|e| format!("invalid --rate-limit '{raw}': {e}"))?;
            }
            "--token-budget" => {
                let raw = take_opt(args, &mut i)?;
                let parsed = raw
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --token-budget '{raw}': {e}"))?;
                token_budget = Some(parsed);
            }
            "--wg-pubkey" => wg_pubkey = Some(take_opt(args, &mut i)?),
            "--replace" => {
                replace = true;
                i += 1;
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(ExitCode::SUCCESS);
            }
            other => return Err(format!("unknown flag in 'peer enroll': {other}")),
        }
    }

    let agent_id = agent_id.ok_or_else(|| "peer enroll requires --agent-id <id>".to_string())?;
    let bundle_out_path = bundle_out_path
        .unwrap_or_else(|| PathBuf::from(format!("./{agent_id}.pairing-bundle.json")));
    let path_patterns = if custom_paths.is_empty() {
        vec![
            "/vault/**".to_string(),
            "/habitat/**".to_string(),
            "/work/**".to_string(),
        ]
    } else {
        custom_paths
    };
    let allowed_ops = if custom_ops.is_empty() {
        vec!["read".to_string(), "write".to_string(), "lock".to_string()]
    } else {
        custom_ops
    };

    let res = enroll_peer(&PeerEnrollRequest {
        agent_id,
        allowed_ips,
        gateway_addr,
        peers_config_path,
        secrets_file_path,
        bundle_out_path,
        token_secret_env,
        peer_key_env,
        cert_sha256,
        path_patterns,
        allowed_ops,
        max_risk_tier,
        ttl_ms,
        rate_limit_per_min,
        token_budget,
        wg_pubkey,
        replace,
        now_ms: now_unix_ms(),
    })
    .map_err(|e| e.to_string())?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "PEER_ENROLLED agent_id={} max_risk_tier={} replaced={} peer_key_env={} peers_config={} secrets_file={} bundle={} token_id={} expires_at_ms={}",
            res.agent_id,
            res.max_risk_tier,
            res.replaced,
            res.peer_key_env,
            res.peers_config_path.display(),
            res.secrets_file_path.display(),
            res.bundle_out_path.display(),
            res.token_id,
            res.token_expires_at_ms
        );
        if let Some(snippet) = &res.wg_peer_snippet {
            println!("\n{snippet}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_token_mint(args: &[String], initial_json: bool) -> Result<ExitCode, String> {
    let mut json_out = initial_json;
    let mut agent_id: Option<String> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut peers_config_path = PathBuf::from(DEFAULT_PEERS_CONFIG);
    let mut secrets_file_path = Some(PathBuf::from(DEFAULT_SECRETS_FILE));
    let mut token_secret_env = "HAL_TOKEN_SECRET".to_string();
    let mut custom_paths: Vec<String> = Vec::new();
    let mut custom_ops: Vec<String> = Vec::new();
    let mut requested_tier = RiskTier::L1ReversibleCow;
    let mut ttl_ms: u64 = 3_600_000;
    let mut rate_limit_per_min: u32 = 60;
    let mut token_budget: Option<u64> = Some(10_000);

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--agent-id" => agent_id = Some(take_opt(args, &mut i)?),
            "--out" => out_path = Some(PathBuf::from(take_opt(args, &mut i)?)),
            "--peers-config" => peers_config_path = PathBuf::from(take_opt(args, &mut i)?),
            "--secrets-file" => secrets_file_path = Some(PathBuf::from(take_opt(args, &mut i)?)),
            "--token-secret-env" => token_secret_env = take_opt(args, &mut i)?,
            "--paths" => {
                let raw = take_opt(args, &mut i)?;
                append_csv(&mut custom_paths, &raw);
            }
            "--ops" => {
                let raw = take_opt(args, &mut i)?;
                append_csv(&mut custom_ops, &raw);
            }
            "--max-tier" => {
                let raw = take_opt(args, &mut i)?;
                requested_tier = RiskTier::from_short_str(&raw)
                    .ok_or_else(|| format!("invalid --max-tier '{raw}': expected L0, L1, or L2"))?;
            }
            "--ttl" => {
                let raw = take_opt(args, &mut i)?;
                ttl_ms = parse_duration_ms(&raw)?;
            }
            "--rate-limit" => {
                let raw = take_opt(args, &mut i)?;
                rate_limit_per_min = raw
                    .parse::<u32>()
                    .map_err(|e| format!("invalid --rate-limit '{raw}': {e}"))?;
            }
            "--token-budget" => {
                let raw = take_opt(args, &mut i)?;
                let parsed = raw
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --token-budget '{raw}': {e}"))?;
                token_budget = Some(parsed);
            }
            "--json" => {
                json_out = true;
                i += 1;
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(ExitCode::SUCCESS);
            }
            other => return Err(format!("unknown flag in 'token mint': {other}")),
        }
    }

    let agent_id = agent_id.ok_or_else(|| "token mint requires --agent-id <id>".to_string())?;
    let out_path = out_path.unwrap_or_else(|| PathBuf::from(format!("./{agent_id}.cap.json")));
    let path_patterns = if custom_paths.is_empty() {
        vec![
            "/vault/**".to_string(),
            "/habitat/**".to_string(),
            "/work/**".to_string(),
        ]
    } else {
        custom_paths
    };
    let allowed_ops = if custom_ops.is_empty() {
        vec!["read".to_string(), "write".to_string(), "lock".to_string()]
    } else {
        custom_ops
    };

    let res = mint_token(&TokenMintRequest {
        agent_id,
        peers_config_path,
        secrets_file_path,
        token_secret_env,
        out_path,
        path_patterns,
        allowed_ops,
        requested_tier,
        ttl_ms,
        rate_limit_per_min,
        token_budget,
        now_ms: now_unix_ms(),
    })
    .map_err(|e| e.to_string())?;

    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "TOKEN_MINTED agent_id={} token_id={} max_risk_tier={} expires_at_ms={} out={}",
            res.agent_id,
            res.token_id,
            res.max_risk_tier,
            res.expires_at_ms,
            res.out_path.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().collect();
    if let Some((json_out, rest)) = match_subcommand(&args, "peer", "enroll") {
        return run_peer_enroll(rest, json_out);
    }
    if let Some((json_out, rest)) = match_subcommand(&args, "token", "mint") {
        return run_token_mint(rest, json_out);
    }

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
