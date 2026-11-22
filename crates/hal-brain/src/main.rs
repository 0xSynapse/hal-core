use hal_brain::AgentRole;
use std::process::ExitCode;
use std::str::FromStr;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut role_str = String::from("coder");
    let mut check_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--role" if i + 1 < args.len() => {
                role_str = args[i + 1].clone();
                i += 2;
            }
            "--check" => {
                check_only = true;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: hal-brain --role <netsec|vault|coder|habitat|research> [--check]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    let role = match AgentRole::from_str(&role_str) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("hal-brain invalid role: {err}");
            return ExitCode::from(1);
        }
    };

    println!(
        "HAL_BRAIN_READY role={} agent_id={} no_ip_jail=true secretless=true check_only={check_only}",
        role,
        role.default_agent_id()
    );
    ExitCode::SUCCESS
}
