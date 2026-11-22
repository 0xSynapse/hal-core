use hal_oob::{validate_oob_bind_addr, OobController, OobHttpServer};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut bind_addr: Option<String> = None;
    let mut bus_socket: Option<PathBuf> = None;
    let mut audit_log: Option<PathBuf> = None;
    let mut token: Option<String> = None;
    let mut check_only = false;
    let mut serve = false;
    let mut duration_ms: Option<u64> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" if i + 1 < args.len() => {
                bind_addr = Some(args[i + 1].clone());
                i += 2;
            }
            "--bus-socket" if i + 1 < args.len() => {
                bus_socket = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--audit-log" if i + 1 < args.len() => {
                audit_log = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--token" if i + 1 < args.len() => {
                token = Some(args[i + 1].clone());
                i += 2;
            }
            "--duration-ms" if i + 1 < args.len() => {
                match args[i + 1].parse::<u64>() {
                    Ok(v) => duration_ms = Some(v),
                    Err(e) => {
                        eprintln!("hal-oob invalid --duration-ms '{}': {e}", args[i + 1]);
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
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
                    "Usage: hal-oob --bind <addr> --bus-socket <path> --audit-log <path> [--token <secret>] [--serve] [--duration-ms <ms>] [--check]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let bind_raw = bind_addr.unwrap_or_else(|| "127.0.0.1:8443".to_string());
    let addr: SocketAddr = match bind_raw.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hal-oob invalid --bind '{bind_raw}': {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = validate_oob_bind_addr(addr) {
        eprintln!("hal-oob bind error: {err}");
        return ExitCode::from(1);
    }

    let bus = bus_socket.unwrap_or_else(|| PathBuf::from("/var/run/hal/bus/oob.sock"));
    let audit = audit_log.unwrap_or_else(|| PathBuf::from("/pool/audit/hal-audit.log"));

    if check_only || !serve {
        println!("HAL_OOB_READY bind={addr} check_only={check_only}");
        return ExitCode::SUCCESS;
    }

    let auth_token = token
        .or_else(|| std::env::var("HAL_OOB_TOKEN").ok())
        .unwrap_or_default();
    if auth_token.trim().is_empty() {
        eprintln!("hal-oob --serve requires --token <secret> or HAL_OOB_TOKEN");
        return ExitCode::from(2);
    }

    let ctrl = Arc::new(OobController::new(bus, audit));
    let mut handle = match OobHttpServer::spawn(addr, auth_token, ctrl) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("hal-oob serve failed: {e}");
            return ExitCode::from(1);
        }
    };

    println!("HAL_KEY_SERVING url=http://{}/", handle.local_addr());
    let _ = std::io::Write::flush(&mut std::io::stdout());
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
