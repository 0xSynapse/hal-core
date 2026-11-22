use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

/// Per-agent egress quota thresholds configured in `egress-allowlist.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct QuotaConfig {
    pub max_requests_per_min: u32,
    pub max_egress_bytes: u64,
    pub max_ingress_bytes: u64,
}

/// Outbound Data Loss Prevention (DLP) scanner thresholds.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DlpConfig {
    pub min_entropy_len: usize,
    pub shannon_entropy_threshold: f64,
    #[serde(default)]
    pub blocked_literals: Vec<String>,
}

/// Single permitted upstream service entry in `egress-allowlist.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EgressAllowRule {
    pub service_id: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub allowed_agents: Vec<String>,
    #[serde(default)]
    pub secret_ref: Option<String>,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    #[serde(default = "default_true")]
    pub require_tls: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug)]
pub enum EgressAllowlistError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    Validation(String),
}

impl fmt::Display for EgressAllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read egress-allowlist: {e}"),
            Self::Toml(e) => write!(f, "invalid egress-allowlist TOML: {e}"),
            Self::Validation(msg) => write!(f, "egress-allowlist validation failed: {msg}"),
        }
    }
}

impl std::error::Error for EgressAllowlistError {}

impl From<std::io::Error> for EgressAllowlistError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for EgressAllowlistError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

/// Default-deny outbound service allowlist parsed from `config/policy/egress-allowlist.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct EgressAllowlist {
    pub version: u32,
    pub default_policy: String,
    pub quotas: QuotaConfig,
    pub dlp: DlpConfig,
    #[serde(default)]
    pub allow: Vec<EgressAllowRule>,
}

impl EgressAllowlist {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, EgressAllowlistError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Self, EgressAllowlistError> {
        let parsed: Self = toml::from_str(toml_str)?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), EgressAllowlistError> {
        if self.version != 1 {
            return Err(EgressAllowlistError::Validation(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.default_policy != "deny" {
            return Err(EgressAllowlistError::Validation(format!(
                "default_policy must be 'deny', got '{}'",
                self.default_policy
            )));
        }
        if self.quotas.max_requests_per_min == 0
            || self.quotas.max_egress_bytes == 0
            || self.quotas.max_ingress_bytes == 0
        {
            return Err(EgressAllowlistError::Validation(
                "quota limits must all be > 0".to_string(),
            ));
        }
        if self.dlp.min_entropy_len == 0 || self.dlp.shannon_entropy_threshold <= 0.0 {
            return Err(EgressAllowlistError::Validation(
                "DLP entropy config must be positive".to_string(),
            ));
        }

        let mut seen = BTreeSet::new();
        for rule in &self.allow {
            if rule.service_id.is_empty() || !seen.insert(rule.service_id.as_str()) {
                return Err(EgressAllowlistError::Validation(format!(
                    "duplicate or empty service_id '{}'",
                    rule.service_id
                )));
            }
            if rule.host.is_empty()
                || rule.host.contains(['\r', '\n', ' '])
                || rule.port == 0
                || rule.methods.is_empty()
                || rule.path_prefixes.is_empty()
                || rule.max_request_bytes == 0
                || rule.max_response_bytes == 0
            {
                return Err(EgressAllowlistError::Validation(format!(
                    "invalid allowlist fields on service '{}'",
                    rule.service_id
                )));
            }
            for p in &rule.path_prefixes {
                if !p.starts_with('/') || p.contains("..") || p.contains(['\r', '\n', '\0']) {
                    return Err(EgressAllowlistError::Validation(format!(
                        "unsafe path_prefix '{p}' on service '{}'",
                        rule.service_id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Authorizes `(agent_id, service_id, method, path, body_len)` against the allowlist.
    pub fn authorize(
        &self,
        agent_id: &str,
        service_id: &str,
        method: &str,
        path: &str,
        body_len: usize,
    ) -> Result<&EgressAllowRule, String> {
        if !path.starts_with('/')
            || path.contains(['\r', '\n', '\0', ' '])
            || path
                .split(['/', '?'])
                .any(|seg| seg == "..")
        {
            return Err(format!("invalid or unsafe HTTP path '{path}'"));
        }

        let rule = self
            .allow
            .iter()
            .find(|r| r.service_id == service_id)
            .ok_or_else(|| {
                format!("service '{service_id}' is not permitted by default-deny egress allowlist")
            })?;

        if !rule.allowed_agents.is_empty() && !rule.allowed_agents.iter().any(|a| a == agent_id) {
            return Err(format!(
                "agent '{agent_id}' is not authorized to invoke service '{service_id}'"
            ));
        }

        if !rule.methods.iter().any(|m| m == method) {
            return Err(format!(
                "HTTP method '{method}' not permitted on service '{service_id}'"
            ));
        }

        let path_only = path.split('?').next().unwrap_or(path);
        let prefix_ok = rule.path_prefixes.iter().any(|prefix| {
            path_only == prefix
                || (prefix.ends_with('/') && path_only.starts_with(prefix))
                || path_only
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/'))
        });
        if !prefix_ok {
            return Err(format!(
                "HTTP path '{path}' is outside allowed path_prefixes for '{service_id}'"
            ));
        }

        if body_len > rule.max_request_bytes {
            return Err(format!(
                "request body size ({body_len}) exceeds max_request_bytes ({}) on '{service_id}'",
                rule.max_request_bytes
            ));
        }

        Ok(rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_egress_allowlist_validates_and_enforces_agent_and_path_bounds() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/egress-allowlist.toml");
        let list = EgressAllowlist::from_file(path).unwrap();
        assert_eq!(list.allow.len(), 3);

        assert!(list
            .authorize(
                "agent-coder",
                "github_api",
                "GET",
                "/repos/0xSynapse/hal-os",
                0
            )
            .is_ok());

        // agent-research cannot access github_api
        assert!(list
            .authorize("agent-research", "github_api", "GET", "/repos/foo/bar", 0)
            .is_err());

        // CRLF / traversal injection rejected
        assert!(list
            .authorize(
                "agent-coder",
                "github_api",
                "GET",
                "/repos/a/b\r\nX-Inject: 1",
                0
            )
            .is_err());
        assert!(list
            .authorize("agent-coder", "github_api", "GET", "/repos/../admin", 0)
            .is_err());

        // Unknown service denied
        assert!(list
            .authorize("agent-coder", "evil_exfil", "POST", "/steal", 10)
            .is_err());
    }
}
