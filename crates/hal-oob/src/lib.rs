//! Out-of-band human sovereignty control plane (`hal-oob`), management HTTP/serial APIs,
//! and `halctl` operator CLI.

pub mod console;
pub mod enroll;
pub mod http;
pub mod pwa;
pub mod service;

pub use console::handle_oob_console_line;
pub use enroll::{
    enroll_peer, mint_token, read_secret_from_env_or_file, upsert_secrets_env_0600,
    write_file_0600_atomic, EnrollError, PeerEnrollRequest, PeerEnrollResult, TokenMintRequest,
    TokenMintResult,
};
pub use http::{validate_oob_bind_addr, OobHttpClient, OobHttpServer, OobHttpServerHandle};
pub use service::{OobController, OobError, OobStatusSummary};
