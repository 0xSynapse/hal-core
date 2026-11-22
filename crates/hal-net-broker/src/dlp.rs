use crate::allowlist::DlpConfig;
use std::fmt;

const KNOWN_KEY_PREFIXES: &[&str] = &["ghp_", "github_pat_", "xoxb-", "xoxp-", "AIza", "sk-"];

/// Violation reported when outbound data matches a secret pattern or high-entropy credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpViolation {
    pub rule: &'static str,
    pub detail: String,
}

impl fmt::Display for DlpViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.rule, self.detail)
    }
}

/// Outbound payload scanner executed before writing bytes to any network socket.
#[derive(Debug, Clone)]
pub struct DlpScanner {
    min_entropy_len: usize,
    entropy_threshold: f64,
    blocked_literals: Vec<String>,
}

impl DlpScanner {
    #[must_use]
    pub fn from_config(cfg: &DlpConfig) -> Self {
        Self {
            min_entropy_len: cfg.min_entropy_len,
            entropy_threshold: cfg.shannon_entropy_threshold,
            blocked_literals: cfg.blocked_literals.clone(),
        }
    }

    /// Scans `text` for sealed secret leaks, blocked literals, PEM keys, token prefixes, or high-entropy blobs.
    pub fn scan_text(
        &self,
        field: &str,
        text: &str,
        sealed_secrets: &[&str],
    ) -> Result<(), DlpViolation> {
        for &secret in sealed_secrets {
            if !secret.is_empty() && text.contains(secret) {
                return Err(DlpViolation {
                    rule: "DLP_SEALED_SECRET_MATCH",
                    detail: format!("outbound {field} contains a sealed broker secret"),
                });
            }
        }

        for lit in &self.blocked_literals {
            if !lit.is_empty() && text.contains(lit) {
                return Err(DlpViolation {
                    rule: "DLP_BLOCKED_LITERAL",
                    detail: format!("outbound {field} contains blocked literal '{lit}'"),
                });
            }
        }

        if text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----") {
            return Err(DlpViolation {
                rule: "DLP_PEM_PRIVATE_KEY",
                detail: format!("outbound {field} contains a PEM private key block"),
            });
        }

        if has_aws_access_key(text) {
            return Err(DlpViolation {
                rule: "DLP_KNOWN_SECRET_PREFIX",
                detail: format!("outbound {field} contains AWS access key signature"),
            });
        }

        for &prefix in KNOWN_KEY_PREFIXES {
            if has_prefixed_token(text, prefix) {
                return Err(DlpViolation {
                    rule: "DLP_KNOWN_SECRET_PREFIX",
                    detail: format!("outbound {field} contains credential prefix '{prefix}'"),
                });
            }
        }

        for token in text.split(|c: char| !is_token_char(c)) {
            if token.len() < self.min_entropy_len {
                continue;
            }
            if count_char_classes(token) >= 3 && shannon_entropy(token) >= self.entropy_threshold {
                return Err(DlpViolation {
                    rule: "DLP_HIGH_ENTROPY_SECRET",
                    detail: format!(
                        "outbound {field} contains high-entropy token (len={})",
                        token.len()
                    ),
                });
            }
        }

        Ok(())
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')
}

fn count_char_classes(token: &str) -> u8 {
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    let mut sym = false;
    for b in token.bytes() {
        if b.is_ascii_uppercase() {
            upper = true;
        } else if b.is_ascii_lowercase() {
            lower = true;
        } else if b.is_ascii_digit() {
            digit = true;
        } else {
            sym = true;
        }
    }
    u8::from(upper) + u8::from(lower) + u8::from(digit) + u8::from(sym)
}

fn shannon_entropy(token: &str) -> f64 {
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in counts {
        if count > 0 {
            let p = f64::from(count) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn has_aws_access_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 20 <= bytes.len() {
        if &bytes[i..i + 4] == b"AKIA"
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
            && bytes[i + 4..i + 20]
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return true;
        }
        i += 1;
    }
    false
}

fn has_prefixed_token(text: &str, prefix: &str) -> bool {
    let bytes = text.as_bytes();
    let p_bytes = prefix.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(prefix) {
        let idx = search_from + rel;
        let boundary_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        let after = idx + p_bytes.len();
        let tail_len = bytes[after..]
            .iter()
            .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            .count();
        if boundary_ok && tail_len >= 12 {
            return true;
        }
        search_from = idx + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> DlpScanner {
        DlpScanner::from_config(&DlpConfig {
            min_entropy_len: 24,
            shannon_entropy_threshold: 4.3,
            blocked_literals: vec!["VAULT_SECRET_CANARY".to_string()],
        })
    }

    #[test]
    fn dlp_blocks_secrets_and_allows_normal_json_payloads() {
        let s = scanner();
        let sealed = ["real-secret-token-value-12345"];

        assert!(s
            .scan_text("body", r#"{"model":"gpt-4","status":"nominal","temp_c":22.4}"#, &sealed)
            .is_ok());

        // Sealed secret match
        assert_eq!(
            s.scan_text("body", "leak=real-secret-token-value-12345", &sealed)
                .unwrap_err()
                .rule,
            "DLP_SEALED_SECRET_MATCH"
        );

        // PEM private key
        assert_eq!(
            s.scan_text(
                "body",
                "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
                &sealed
            )
            .unwrap_err()
            .rule,
            "DLP_PEM_PRIVATE_KEY"
        );

        // AWS key
        assert_eq!(
            s.scan_text("body", "cred=AKIAIOSFODNN7EXAMPLE", &sealed)
                .unwrap_err()
                .rule,
            "DLP_KNOWN_SECRET_PREFIX"
        );

        // High-entropy token without known prefix
        assert_eq!(
            s.scan_text("body", "blob=K9mQ7zR2pX8vN4wL1jT6cB3yH5dF0sG9", &sealed)
                .unwrap_err()
                .rule,
            "DLP_HIGH_ENTROPY_SECRET"
        );
    }
}
