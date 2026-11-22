//! Zero-trust, secretless outbound HTTP/API egress proxy (`hal-net-broker`) with
//! default-deny domain allowlist, header/body DLP scanning, credential injection, and per-agent budgets.

pub mod allowlist;
pub mod broker;
pub mod dlp;
pub mod quota;
pub mod secrets;
pub mod transport;

pub use allowlist::{
    DlpConfig, EgressAllowRule, EgressAllowlist, EgressAllowlistError, QuotaConfig,
};
pub use broker::{BrokerError, EgressRequest, EgressResponse, NetBroker};
pub use dlp::{DlpScanner, DlpViolation};
pub use quota::{AgentQuotaTracker, QuotaError};
pub use secrets::{SealedSecret, SecretStore};
pub use transport::{
    EgressTransport, LoopbackHttpTransport, MockTransport, UpstreamHttpRequest,
    UpstreamHttpResponse,
};
