//! Cyber-physical "Discovery One" ship simulator & spinal-cord safety interlocks (`adapter-sim-ship`).

pub mod ship;

pub use ship::{ShipCommand, ShipCommandOutcome, ShipError, ShipSimulator, ShipState};
