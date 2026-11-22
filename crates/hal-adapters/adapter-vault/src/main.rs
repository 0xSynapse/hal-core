use adapter_vault::VaultAdapter;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let check_only = args.iter().any(|a| a == "--check");
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: adapter-vault [--check]");
        return ExitCode::SUCCESS;
    }

    let nodes = VaultAdapter::descriptors().len();
    println!("ADAPTER_VAULT_READY nodes={nodes} locked_default=true check_only={check_only}");
    ExitCode::SUCCESS
}
