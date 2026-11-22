//! HAL-OS shared protocol contracts, canonical hashing, HMAC capability tokens,
//! and length-prefixed IPC framing.

pub mod canonical;
pub mod token;
pub mod types;
pub mod wire;

pub use canonical::{
    canonical_json_bytes, compute_audit_entry_hash, hex_decode, hex_encode, sha256_hex,
    GENESIS_PREV_HASH,
};
pub use token::{
    delegate_token, path_matches_pattern, pattern_is_subset, sign_token, verify_attenuation,
    verify_token_signature, AttenuationError, DelegationSpec,
};
pub use types::*;
