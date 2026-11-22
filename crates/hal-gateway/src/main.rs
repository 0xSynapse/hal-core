use hal_gateway::GatewayConfig;
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
                println!("Usage: hal-gateway --config <path> [--check]");
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

    println!(
        "HAL_GATEWAY_READY peers={} default_policy={} check_only={check_only}",
        cfg.peers.len(),
        cfg.default_policy
    );
    ExitCode::SUCCESS
}
