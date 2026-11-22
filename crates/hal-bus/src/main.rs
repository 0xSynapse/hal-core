use hal_audit::AuditLog;
use hal_bus::{BusServer, EndpointBinding, HalBusState};
use hal_os_hal::OsPeerCredProvider;
use hal_policy::{IpcMatrix, PolicyConfig, PolicyEngine};
use hal_proto::{AgentAuthKind, AgentPrincipal, TrustDomain};
use std::io::Write;
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

fn resident_binding(
    agent_id: &str,
    trust_domain: TrustDomain,
    expected_uid: u32,
    is_oob: bool,
    is_watchdog: bool,
    is_gateway: bool,
) -> EndpointBinding {
    EndpointBinding {
        principal: AgentPrincipal {
            agent_id: agent_id.to_string(),
            trust_domain,
            auth_kind: if is_gateway {
                AgentAuthKind::RemoteGatewayMtls
            } else {
                AgentAuthKind::LocalNoIpJail
            },
            parent_agent_id: None,
            peer_cred_or_cert_fp: "unbound".to_string(),
        },
        expected_uid: Some(expected_uid),
        is_oob,
        is_watchdog,
        is_gateway,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut matrix_path: Option<PathBuf> = None;
    let mut audit_path: Option<PathBuf> = None;
    let mut socket_dir: Option<PathBuf> = None;
    let mut token_secret_env = "HAL_TOKEN_SECRET".to_string();
    let mut duration_ms: Option<u64> = None;
    let mut check_only = false;
    let mut serve = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ipc-matrix" => match take_arg(&args, &mut i) {
                Ok(v) => matrix_path = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--audit-log" => match take_arg(&args, &mut i) {
                Ok(v) => audit_path = Some(PathBuf::from(v)),
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--socket-dir" => match take_arg(&args, &mut i) {
                Ok(v) => socket_dir = Some(PathBuf::from(v)),
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
            "--duration-ms" => match take_arg(&args, &mut i) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(ms) => duration_ms = Some(ms),
                    Err(e) => {
                        eprintln!("hal-bus invalid --duration-ms '{v}': {e}");
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
                    "Usage: hal-bus --ipc-matrix <path> --audit-log <path> [--socket-dir <dir>] [--token-secret-env <ENV>] [--serve] [--duration-ms <ms>] [--check]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let matrix_path = matrix_path.unwrap_or_else(|| PathBuf::from("config/policy/ipc-matrix.toml"));
    let audit_path = audit_path.unwrap_or_else(|| PathBuf::from("/pool/audit/hal-audit.log"));

    let matrix = match IpcMatrix::from_file(&matrix_path) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("hal-bus ipc-matrix error ({}): {err}", matrix_path.display());
            return ExitCode::from(1);
        }
    };

    if let Some(parent) = audit_path.parent() {
        if !parent.as_os_str().is_empty() && serve {
            if let Err(err) = std::fs::create_dir_all(parent) {
                eprintln!("hal-bus cannot create audit dir ({}): {err}", parent.display());
                return ExitCode::from(1);
            }
        }
    }

    let audit = match AuditLog::open(&audit_path) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("hal-bus audit-log error ({}): {err}", audit_path.display());
            return ExitCode::from(1);
        }
    };

    if check_only || !serve {
        println!(
            "HAL_BUS_READY ipc_rules={} deny_asserts={} audit_next_seq={} check_only={check_only}",
            matrix.allow.len(),
            matrix.deny_assert.len(),
            audit.next_seq()
        );
        return ExitCode::SUCCESS;
    }

    let secret = match std::env::var(&token_secret_env) {
        Ok(val) if !val.trim().is_empty() => val.into_bytes(),
        _ => {
            eprintln!("hal-bus --serve requires non-empty env var '{token_secret_env}'");
            return ExitCode::from(2);
        }
    };

    let sock_dir = socket_dir.unwrap_or_else(|| PathBuf::from("/var/run/hal/bus"));
    if let Err(err) = std::fs::create_dir_all(&sock_dir) {
        eprintln!("hal-bus cannot create socket-dir ({}): {err}", sock_dir.display());
        return ExitCode::from(1);
    }

    let mut bus_state = HalBusState::new(PolicyEngine::new(PolicyConfig { token_secret: secret }), matrix, audit);
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

    let euid = unsafe { libc::geteuid() } as u32;
    let endpoints = vec![
        (sock_dir.join("oob.sock"), resident_binding("hal-oob", TrustDomain::ResidentCore, euid, true, false, false)),
        (sock_dir.join("gateway.sock"), resident_binding("hal-gateway", TrustDomain::RemoteExternal, euid, false, false, true)),
        (sock_dir.join("watchdog.sock"), resident_binding("hal-watchdog", TrustDomain::ResidentCore, euid, false, true, false)),
        (sock_dir.join("vault.sock"), resident_binding("agent-vault", TrustDomain::ResidentCore, euid, false, false, false)),
        (sock_dir.join("coder.sock"), resident_binding("agent-coder", TrustDomain::WorkspaceWorker, euid, false, false, false)),
        (sock_dir.join("habitat.sock"), resident_binding("agent-habitat", TrustDomain::ResidentCore, euid, false, false, false)),
        (sock_dir.join("netmon.sock"), resident_binding("adapter-netmon", TrustDomain::ResidentCore, euid, false, false, false)),
        (sock_dir.join("research.sock"), resident_binding("agent-research", TrustDomain::UntrustedResearch, euid, false, false, false)),
    ];
    let socket_count = endpoints.len();

    let mut handle = match BusServer::spawn(Arc::new(Mutex::new(bus_state)), endpoints, Arc::new(OsPeerCredProvider)) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("hal-bus serve failed: {err}");
            return ExitCode::from(1);
        }
    };

    println!(
        "HAL_BUS_SERVING socket_dir={} sockets={socket_count}",
        sock_dir.display()
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
