use hal_net_broker::EgressAllowlist;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut allowlist_path: Option<PathBuf> = None;
    let mut check_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--allowlist" if i + 1 < args.len() => {
                allowlist_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: hal-net-broker --allowlist <path> [--check]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let path = allowlist_path.unwrap_or_else(|| PathBuf::from("config/policy/egress-allowlist.toml"));
    match EgressAllowlist::from_file(&path) {
        Ok(list) => {
            println!(
                "HAL_NET_BROKER_READY services={} max_req_per_min={} min_entropy_len={} check_only={check_only}",
                list.allow.len(),
                list.quotas.max_requests_per_min,
                list.dlp.min_entropy_len
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("hal-net-broker allowlist error ({}): {err}", path.display());
            ExitCode::from(1)
        }
    }
}
