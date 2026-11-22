use hal_watchdog::{WatchdogConfig, WatchdogEngine, WatchdogRunner};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
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
    let mut audit_log: Option<PathBuf> = None;
    let mut bus_socket: Option<PathBuf> = None;
    let mut interval_ms = 250u64;
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
            "--audit-log" => match take_arg(&args, &mut i) {
                Ok(v) => audit_log = Some(PathBuf::from(v)),
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
            "--interval-ms" => match take_arg(&args, &mut i) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(ms) if ms > 0 => interval_ms = ms,
                    Ok(_) => {
                        eprintln!("hal-watchdog --interval-ms must be > 0");
                        return ExitCode::from(2);
                    }
                    Err(e) => {
                        eprintln!("hal-watchdog invalid --interval-ms '{v}': {e}");
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            "--duration-ms" => match take_arg(&args, &mut i) {
                Ok(v) => match v.parse::<u64>() {
                    Ok(ms) => duration_ms = Some(ms),
                    Err(e) => {
                        eprintln!("hal-watchdog invalid --duration-ms '{v}': {e}");
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
                    "Usage: hal-watchdog --config <path> [--audit-log <path>] [--bus-socket <path>] [--interval-ms <ms>] [--serve] [--duration-ms <ms>] [--check]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let path = cfg_path.unwrap_or_else(|| PathBuf::from("config/policy/watchdog.toml"));
    let cfg = match WatchdogConfig::from_file(&path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("hal-watchdog config error ({}): {err}", path.display());
            return ExitCode::from(1);
        }
    };

    if check_only || !serve {
        println!(
            "HAL_WATCHDOG_READY denial_threshold={} lease_threshold={} pf_threshold={} check_only={check_only}",
            cfg.denial_burst_threshold, cfg.lease_conflict_threshold, cfg.pf_drop_burst_threshold
        );
        return ExitCode::SUCCESS;
    }

    let audit = audit_log.unwrap_or_else(|| PathBuf::from("/pool/audit/hal-audit.log"));
    let bus_sock = bus_socket.unwrap_or_else(|| PathBuf::from("/var/run/hal/bus/watchdog.sock"));
    let mut runner = WatchdogRunner::new(&audit, &bus_sock, WatchdogEngine::new(cfg));

    println!(
        "HAL_WATCHDOG_SERVING audit_log={} interval_ms={interval_ms}",
        audit.display()
    );
    let _ = std::io::stdout().flush();

    let started = Instant::now();
    loop {
        if audit.exists() {
            match runner.tick() {
                Ok(report) => {
                    for action in &report.actions {
                        eprintln!("hal-watchdog action dispatched: {action:?}");
                    }
                }
                Err(err) => {
                    eprintln!("hal-watchdog tick warning: {err}");
                }
            }
        }
        if let Some(limit) = duration_ms {
            if started.elapsed() >= Duration::from_millis(limit) {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
    ExitCode::SUCCESS
}
