use hal_oob::validate_oob_bind_addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut bind_addr: Option<String> = None;
    let mut bus_socket: Option<PathBuf> = None;
    let mut audit_log: Option<PathBuf> = None;
    let mut _token: Option<String> = None;
    let mut check_only = false;

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
                _token = Some(args[i + 1].clone());
                i += 2;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: hal-oob --bind <addr> --bus-socket <path> --audit-log <path> [--token <secret>] [--check]"
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

    let _bus = bus_socket.unwrap_or_else(|| PathBuf::from("/var/run/hal/bus/oob.sock"));
    let _audit = audit_log.unwrap_or_else(|| PathBuf::from("/pool/audit/hal-audit.log"));

    println!("HAL_OOB_READY bind={addr} check_only={check_only}");
    ExitCode::SUCCESS
}
