use hal_watchdog::WatchdogConfig;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path: Option<PathBuf> = None;
    let mut check_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" if i + 1 < args.len() => {
                cfg_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: hal-watchdog --config <path> [--check]");
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

    println!(
        "HAL_WATCHDOG_READY denial_threshold={} lease_threshold={} pf_threshold={} check_only={check_only}",
        cfg.denial_burst_threshold, cfg.lease_conflict_threshold, cfg.pf_drop_burst_threshold
    );
    ExitCode::SUCCESS
}
