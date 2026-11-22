//! HAL-OS shared protocol contracts, canonical hashing, HMAC capability tokens,
//! and length-prefixed IPC framing.

pub mod canonical;
pub mod pairing;
pub mod token;
pub mod types;
pub mod wire;

pub use canonical::{
    canonical_json_bytes, compute_audit_entry_hash, hex_decode, hex_encode, sha256_hex,
    GENESIS_PREV_HASH,
};
pub use pairing::{
    env_var_name_for_peer, is_valid_agent_id, is_valid_env_name, is_valid_hex_64,
    parse_duration_ms, random_hex_bytes, PairingBundle, PAIRING_BUNDLE_VERSION,
};
pub use token::{
    delegate_token, is_valid_path_pattern, path_matches_pattern, pattern_is_subset, sign_token,
    verify_attenuation, verify_token_signature, AttenuationError, DelegationSpec,
};
pub use types::*;
