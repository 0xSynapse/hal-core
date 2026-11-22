use crate::types::AuditRecord;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// 64-character lowercase hex zero hash anchoring sequence #1 of every audit log.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Encodes raw bytes as lowercase hexadecimal.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes an even-length hexadecimal string into bytes.
#[must_use]
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Computes lowercase SHA-256 hex digest of an arbitrary byte slice.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn canonicalize_value(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

/// Serializes any JSON value with recursively sorted object keys and zero whitespace.
pub fn canonical_json_bytes(val: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let canonical = canonicalize_value(val);
    serde_json::to_vec(&canonical)
}

/// Computes `SHA256(prev_hash || canonical_json(record without entry_hash))`.
pub fn compute_audit_entry_hash(
    prev_hash: &str,
    record: &AuditRecord,
) -> Result<String, serde_json::Error> {
    let mut val = serde_json::to_value(record)?;
    if let Value::Object(ref mut obj) = val {
        obj.remove("entry_hash");
    }
    let body = canonical_json_bytes(&val)?;
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(&body);
    Ok(hex_encode(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AgentAuthKind, AgentPrincipal, TrustDomain};

    #[test]
    fn canonical_json_sorts_nested_keys_deterministically() {
        let a = serde_json::json!({"z": 1, "a": {"y": true, "b": [1, {"d": 2, "c": 3}]}});
        let b = serde_json::json!({"a": {"b": [1, {"c": 3, "d": 2}], "y": true}, "z": 1});
        assert_eq!(
            canonical_json_bytes(&a).unwrap(),
            canonical_json_bytes(&b).unwrap()
        );
    }

    #[test]
    fn audit_entry_hash_ignores_existing_entry_hash_field_and_chains_prev_hash() {
        let mut rec = AuditRecord {
            seq: 1,
            ts_ms: 1_700_000_000_000,
            principal: AgentPrincipal {
                agent_id: "agent-coder".to_string(),
                trust_domain: TrustDomain::WorkspaceWorker,
                auth_kind: AgentAuthKind::LocalNoIpJail,
                parent_agent_id: None,
                peer_cred_or_cert_fp: "uid:1003".to_string(),
            },
            episode_id: "ep_01".to_string(),
            target_path: "/work/agents/coder/episodes/ep_01/fs".to_string(),
            action: "write".to_string(),
            trigger_event_ids: vec!["evt_1".to_string()],
            proposal_id: Some("prop_1".to_string()),
            decision_summary: "Allow".to_string(),
            workspace_snapshot_id: Some("snap_1".to_string()),
            prev_hash: GENESIS_PREV_HASH.to_string(),
            entry_hash: String::new(),
        };
        let h1 = compute_audit_entry_hash(GENESIS_PREV_HASH, &rec).unwrap();
        rec.entry_hash = "tampered_placeholder".to_string();
        let h2 = compute_audit_entry_hash(GENESIS_PREV_HASH, &rec).unwrap();
        assert_eq!(h1, h2);
        let h3 = compute_audit_entry_hash("f".repeat(64).as_str(), &rec).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn hex_roundtrip_and_invalid_rejected() {
        let raw = [0x00, 0x0f, 0xa5, 0xff];
        let encoded = hex_encode(&raw);
        assert_eq!(encoded, "000fa5ff");
        assert_eq!(hex_decode(&encoded).as_deref(), Some(raw.as_slice()));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zzzz"), None);
    }
}
