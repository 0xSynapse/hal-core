use adapter_digest::DigestAdapter;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: adapter-digest [--check]");
        return ExitCode::SUCCESS;
    }
    let sensors = DigestAdapter::descriptors().len();
    println!("ADAPTER_DIGEST_READY sensors={sensors} default_taint=UntrustedWeb");
    ExitCode::SUCCESS
}
