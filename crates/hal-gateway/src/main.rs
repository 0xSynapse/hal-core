use hal_audit::AuditLog;
use hal_gateway::{GatewayConfig, GatewayServer, GatewayState};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn take_arg(args: &[String], i: &mut usize) -> Result<String, String> {
    if *i + 1 >= args.len() {
        return Err(format!("missing value after '{}'", args[*i]));
    }
    let val = args[*i + 1].clone();
    *i += 2;
    Ok(val)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path: Option<PathBuf> = None;
    let mut bind_addr: Option<String> = None;
    let mut bus_socket: Option<PathBuf> = None;
    let mut audit_log: Option<PathBuf> = None;
    let mut token_secret_env = "HAL_TOKEN_SECRET".to_string();
    let mut peer_key_envs: Vec<(String, String)> = Vec::new();
    let mut duration_ms: Option<u64> = None;
    let mut check_only = false;
    let mut serve = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => match take_arg(&args, &mut i) {
                Ok(v) => cfg_path = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--bind" => match take_arg(&args, &mut i) {
                Ok(v) => bind_addr = Some(v),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--bus-socket" => match take_arg(&args, &mut i) {
                Ok(v) => bus_socket = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--audit-log" => match take_arg(&args, &mut i) {
                Ok(v) => audit_log = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--token-secret-env" => match take_arg(&args, &mut i) {
                Ok(v) => token_secret_env = v,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--peer-key-env" => match take_arg(&args, &mut i) {
                Ok(v) => {
                    let Some((agent, env_name)) = v.split_once('=') else {
                        eprintln!("--peer-key-env must be '<agent_id>=<ENV>'");
                        return ExitCode::from(2);
                    };
                    peer_key_envs.push((agent.trim().to_string(), env_name.trim().to_string()));
                }
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--duration-ms" => match take_arg(&args, &mut i) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(ms) => duration_ms = Some(ms),
                    Err(e) => {
                        eprintln!("hal-gateway invalid --duration-ms '{v}': {e}");
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--serve" => {
                serve = true;
                i += 1;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: hal-gateway --config <path> [--bind <addr>] [--bus-socket <path>] [--audit-log <path>] [--token-secret-env <ENV>] [--peer-key-env <agent=ENV>]... [--serve] [--duration-ms <ms>] [--check]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let path = cfg_path.unwrap_or_else(|| PathBuf::from("config/policy/gateway-peers.toml"));
    let cfg = match GatewayConfig::from_file(&path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("hal-gateway config error ({}): {err}", path.display());
            return ExitCode::from(1);
        }
    };
    let peer_count = cfg.peers.len();

    if check_only || !serve {
        println!(
            "HAL_GATEWAY_READY peers={peer_count} default_policy={} check_only={check_only}",
            cfg.default_policy
        );
        return ExitCode::SUCCESS;
    }

    let bind_raw = bind_addr.unwrap_or_else(|| "127.0.0.1:9443".to_string());
    let addr: SocketAddr = match bind_raw.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hal-gateway invalid --bind '{bind_raw}': {e}");
            return ExitCode::from(2);
        }
    };

    let token_secret = match std::env::var(&token_secret_env) {
        Ok(v) if !v.trim().is_empty() => v.into_bytes(),
        _ => {
            eprintln!("hal-gateway --serve requires non-empty env var '{token_secret_env}'");
            return ExitCode::from(2);
        }
    };

    let audit_path = audit_log.unwrap_or_else(|| PathBuf::from("/pool/audit/hal-gateway.jsonl"));
    if let Some(parent) = audit_path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "hal-gateway cannot create audit dir ({}): {err}",
                    parent.display()
                );
                return ExitCode::from(1);
            }
        }
    }
    let audit = match AuditLog::open(&audit_path) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("hal-gateway audit error ({}): {err}", audit_path.display());
            return ExitCode::from(1);
        }
    };

    let peers_snapshot = cfg.peers.clone();
    let mut state = GatewayState::new(cfg, token_secret, audit);
    let mut explicit_agents = std::collections::BTreeSet::new();
    for (agent_id, env_name) in peer_key_envs {
        explicit_agents.insert(agent_id.clone());
        match std::env::var(&env_name) {
            Ok(val) if !val.trim().is_empty() => {
                state.set_peer_key(agent_id, val.into_bytes());
            }
            _ => {
                eprintln!(
                    "hal-gateway missing or empty peer proof key env '{env_name}' for '{agent_id}'"
                );
                return ExitCode::from(2);
            }
        }
    }

    for peer in peers_snapshot {
        if !peer.enabled || explicit_agents.contains(&peer.agent_id) {
            continue;
        }
        let derived_env = hal_proto::env_var_name_for_peer(&peer.agent_id);
        if let Ok(val) = std::env::var(&derived_env) {
            if !val.trim().is_empty() {
                state.set_peer_key(peer.agent_id, val.into_bytes());
            }
        }
    }

    let bus_sock = bus_socket.unwrap_or_else(|| PathBuf::from("/var/run/hal/bus/gateway.sock"));
    let mut handle = match GatewayServer::spawn(addr, bus_sock, Arc::new(Mutex::new(state))) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("hal-gateway serve failed: {err}");
            return ExitCode::from(1);
        }
    };

    println!(
        "HAL_GATEWAY_SERVING bind={} peers={peer_count}",
        handle.local_addr()
    );
    let _ = std::io::stdout().flush();

    let started = Instant::now();
    loop {
        if let Some(limit) = duration_ms {
            if started.elapsed() >= Duration::from_millis(limit) {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    handle.shutdown();
    ExitCode::SUCCESS
}
