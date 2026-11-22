//! Zero-trust remote/guest agent authentication & admission gateway ("AI SSH", `hal-gateway`).

pub mod config;
pub mod protocol;
pub mod server;

pub use config::{GatewayConfig, GatewayConfigError, Ipv4Cidr, RemotePeerRule};
pub use protocol::{
    compute_cert_proof, verify_cert_proof, GatewayRequest, GatewayResponse, RemoteAuthHandshake,
};
pub use server::{GatewayClient, GatewayError, GatewayServer, GatewayServerHandle, GatewayState};
