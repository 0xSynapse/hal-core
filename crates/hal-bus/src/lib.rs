//! HAL-OS UDS capability bus, kernel peer identity binding, IPC matrix routing,
//! transitive taint propagation, and physical/workspace resource lease arbitration.

pub mod client;
pub mod lease;
pub mod registry;
pub mod server;

pub use client::BusClient;
pub use lease::{LeaseArbiter, LeaseError};
pub use registry::{AgentRegistry, EndpointBinding};
pub use server::{BusServer, BusServerHandle, HalBusState};
