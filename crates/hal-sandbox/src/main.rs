use hal_audit::AuditLog;
use hal_os_hal::MockSandboxBackend;
use hal_sandbox::SandboxOrchestrator;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let check_only = args.iter().any(|a| a == "--check");
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: hal-sandbox [--check]");
        return ExitCode::SUCCESS;
    }

    let audit_path = std::env::temp_dir().join("hal-sandbox-check.jsonl");
    let audit = match AuditLog::open(&audit_path) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("hal-sandbox audit init failed: {err}");
            return ExitCode::from(1);
        }
    };
    let orch = SandboxOrchestrator::new(
        MockSandboxBackend::default(),
        b"hal-sandbox-startup-check-key".to_vec(),
        audit,
    );
    println!(
        "HAL_SANDBOX_READY active_sandboxes={} check_only={check_only}",
        orch.active_count()
    );
    let _ = std::fs::remove_file(audit_path);
    ExitCode::SUCCESS
}
