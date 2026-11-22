use hal_audit::AuditLog;
use hal_policy::IpcMatrix;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut matrix_path: Option<PathBuf> = None;
    let mut audit_path: Option<PathBuf> = None;
    let mut check_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ipc-matrix" if i + 1 < args.len() => {
                matrix_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--audit-log" if i + 1 < args.len() => {
                audit_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: hal-bus --ipc-matrix <path> --audit-log <path> [--check]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let matrix_path = matrix_path.unwrap_or_else(|| PathBuf::from("config/policy/ipc-matrix.toml"));
    let audit_path = audit_path.unwrap_or_else(|| PathBuf::from("/pool/audit/hal-audit.log"));

    let matrix = match IpcMatrix::from_file(&matrix_path) {
        Ok(m) => m,
        Err(err) => {
            eprintln!("hal-bus ipc-matrix error ({}): {err}", matrix_path.display());
            return ExitCode::from(1);
        }
    };

    let audit = match AuditLog::open(&audit_path) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("hal-bus audit-log error ({}): {err}", audit_path.display());
            return ExitCode::from(1);
        }
    };

    println!(
        "HAL_BUS_READY ipc_rules={} deny_asserts={} audit_next_seq={} check_only={check_only}",
        matrix.allow.len(),
        matrix.deny_assert.len(),
        audit.next_seq()
    );
    ExitCode::SUCCESS
}
