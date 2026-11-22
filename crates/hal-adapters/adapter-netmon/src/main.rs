use adapter_netmon::NetmonAdapter;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let check_only = args.iter().any(|a| a == "--check");
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: adapter-netmon [--check]");
        return ExitCode::SUCCESS;
    }

    let nodes = NetmonAdapter::descriptors().len();
    println!("ADAPTER_NETMON_READY nodes={nodes} check_only={check_only}");
    ExitCode::SUCCESS
}
