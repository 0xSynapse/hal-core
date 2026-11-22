//! Unprivileged, secretless multi-agent cognitive runtime template (`hal-brain`).
//! Runs inside No-IP FreeBSD Jails or remote mTLS clients and interacts exclusively through
//! `hal-bus` / `hal-gateway` and `hal-net-broker`.

use hal_gateway::GatewayError;
use hal_net_broker::BrokerError;
use std::fmt;
use std::io;

pub mod agent;
pub mod memory;
pub mod planner;

pub use agent::{
    AgentRole, CognitiveAgent, CognitiveTransport, LocalBusTransport, RemoteGatewayTransport,
};
pub use memory::{EpisodicMemoryStore, MemoryEntry};
pub use planner::{
    extract_json_array_payload, BrokeredLlmClient, LlmPlanConfig, MockLlmHttpServer,
    MockLlmHttpServerHandle, PlannedStep,
};

#[derive(Debug)]
pub enum BrainError {
    Io(io::Error),
    Bus { code: String, reason: String },
    Broker(BrokerError),
    Gateway(GatewayError),
    Json(serde_json::Error),
    Parse(String),
}

impl fmt::Display for BrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "brain I/O error: {e}"),
            Self::Bus { code, reason } => write!(f, "hal-bus denied ({code}): {reason}"),
            Self::Broker(e) => write!(f, "hal-net-broker error: {e}"),
            Self::Gateway(e) => write!(f, "hal-gateway error: {e}"),
            Self::Json(e) => write!(f, "brain JSON error: {e}"),
            Self::Parse(msg) => write!(f, "brain parse error: {msg}"),
        }
    }
}

impl std::error::Error for BrainError {}

impl From<io::Error> for BrainError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<BrokerError> for BrainError {
    fn from(value: BrokerError) -> Self {
        Self::Broker(value)
    }
}

impl From<GatewayError> for BrainError {
    fn from(value: GatewayError) -> Self {
        Self::Gateway(value)
    }
}

impl From<serde_json::Error> for BrainError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
