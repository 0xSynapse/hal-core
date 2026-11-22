use adapter_sim_ship::ShipSimulator;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let check_only = args.iter().any(|a| a == "--check");
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: adapter-sim-ship [--check]");
        return ExitCode::SUCCESS;
    }

    let mut ship = ShipSimulator::default();
    for _ in 0..5 {
        ship.spinal_tick(1.0);
    }
    let nodes = ShipSimulator::descriptors().len();
    println!(
        "ADAPTER_SIM_SHIP_READY nodes={nodes} temp_c={:.2} interlock={} check_only={check_only}",
        ship.state().cabin_temp_c,
        ship.state().human_emergency_interlock
    );
    ExitCode::SUCCESS
}
