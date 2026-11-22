use hal_audit::verify_file;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "verify" {
        eprintln!("Usage: hal-audit verify <audit-log.jsonl>");
        return ExitCode::from(2);
    }
    let path = &args[2];
    match verify_file(path) {
        Ok(report) => {
            println!(
                "AUDIT_VERIFIED path={} records={} head_seq={} head_hash={}",
                path, report.record_count, report.head_seq, report.head_hash
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("AUDIT_VERIFY_FAILED path={path}: {err}");
            ExitCode::from(1)
        }
    }
}
