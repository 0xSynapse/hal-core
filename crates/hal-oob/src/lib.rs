//! Out-of-band human sovereignty control plane (`hal-oob`), management HTTP/serial APIs,
//! and `halctl` operator CLI.

pub mod console;
pub mod http;
pub mod service;

pub use console::handle_oob_console_line;
pub use http::{validate_oob_bind_addr, OobHttpClient, OobHttpServer, OobHttpServerHandle};
pub use service::{OobController, OobError, OobStatusSummary};
