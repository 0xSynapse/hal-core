//! Laptop-side bridge (`hal-bridge`) connecting Aegis OS coding agents to `HAL Core`
//! via `hal-gateway` (CLI + JSON-RPC 2.0 MCP stdio server + tri-node demo runtime).

pub mod client;
pub mod config;
pub mod demo;
pub mod mcp;

pub use client::{validate_vault_path, BridgeError, BridgeSession};
pub use config::{BridgeConfig, BridgeConfigError};
pub use demo::{
    run_self_test, TriNodeDemoCluster, TriNodeDemoConfig, DEMO_LAPTOP_AGENT_ID,
    DEMO_LAPTOP_CERT_FP,
};
pub use mcp::{mcp_tool_schemas, McpBridgeServer};
