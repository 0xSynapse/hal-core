use hal_audit::AuditLog;
use hal_workspace::{LocalDirWorkspaceBackend, WorkspaceManager};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let check_only = args.iter().any(|a| a == "--check");
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: hal-workspace [--check]");
        return ExitCode::SUCCESS;
    }

    let tmp_root = std::env::temp_dir().join("hal-workspace-check");
    let backend = match LocalDirWorkspaceBackend::new(&tmp_root) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("hal-workspace backend init failed: {err}");
            return ExitCode::from(1);
        }
    };
    let audit = match AuditLog::open(tmp_root.join("hal-audit.jsonl")) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("hal-workspace audit init failed: {err}");
            return ExitCode::from(1);
        }
    };
    let _mgr = WorkspaceManager::new(backend, audit);
    println!("HAL_WORKSPACE_READY check_only={check_only}");
    let _ = std::fs::remove_dir_all(tmp_root);
    ExitCode::SUCCESS
}
