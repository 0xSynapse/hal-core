//! Encrypted personal data vault adapter enforcing `PRIVATE_VAULT` tainting (`adapter-vault`).

pub mod vault;

pub use vault::{VaultAdapter, VaultError};
