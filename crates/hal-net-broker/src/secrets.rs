use std::collections::BTreeMap;
use std::fmt;

/// Credential sealed inside `hal-net-broker`; redacts secret material in `Debug` and never serializes.
#[derive(Clone)]
pub struct SealedSecret {
    pub header_name: String,
    pub header_prefix: String,
    value: String,
}

impl SealedSecret {
    #[must_use]
    pub fn new(
        header_name: impl Into<String>,
        header_prefix: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            header_name: header_name.into(),
            header_prefix: header_prefix.into(),
            value: value.into(),
        }
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSecret")
            .field("header_name", &self.header_name)
            .field("header_prefix", &self.header_prefix)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Isolated credential store owned exclusively by `hal-net-broker` (`_hal_broker`).
#[derive(Debug, Default, Clone)]
pub struct SecretStore {
    secrets: BTreeMap<String, SealedSecret>,
}

impl SecretStore {
    pub fn insert(&mut self, secret_ref: impl Into<String>, secret: SealedSecret) {
        self.secrets.insert(secret_ref.into(), secret);
    }

    #[must_use]
    pub fn inject_header(&self, secret_ref: &str) -> Option<(String, String)> {
        let s = self.secrets.get(secret_ref)?;
        Some((
            s.header_name.clone(),
            format!("{}{}", s.header_prefix, s.value),
        ))
    }

    #[must_use]
    pub fn all_secret_values(&self) -> Vec<&str> {
        self.secrets
            .values()
            .map(|s| s.value.as_str())
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// Removes any accidentally echoed sealed secret strings before responses enter cognitive Jails.
    #[must_use]
    pub fn scrub_secrets(&self, raw: &str) -> String {
        let mut out = raw.to_string();
        for secret in self.all_secret_values() {
            if secret.len() >= 4 && out.contains(secret) {
                out = out.replace(secret, "[REDACTED_SECRET]");
            }
        }
        out
    }
}
