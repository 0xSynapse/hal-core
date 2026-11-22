use hal_bus::BusClient;
use hal_proto::wire::{BusRequest, BusResponse};
use hal_proto::{EventEnvelope, NodeDescriptor, NodeKind, RiskTier, TaintTag, TrustLevel};
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultError {
    pub code: &'static str,
    pub reason: String,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(value: io::Error) -> Self {
        let code = if value.kind() == io::ErrorKind::NotFound {
            "VAULT_NOT_FOUND"
        } else {
            "VAULT_IO_ERROR"
        };
        Self {
            code,
            reason: value.to_string(),
        }
    }
}

/// Layer 2 encrypted vault adapter mapping `halpool/vault` onto `/vault/*` capability nodes.
/// Starts locked by default until unlocked out-of-band by human operator.
#[derive(Debug, Clone)]
pub struct VaultAdapter {
    root: PathBuf,
    locked: bool,
    seq: u64,
}

impl VaultAdapter {
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            locked: true,
            seq: 0,
        }
    }

    #[must_use]
    pub fn descriptors() -> Vec<NodeDescriptor> {
        vec![
            NodeDescriptor {
                path: "/vault/docs".to_string(),
                kind: NodeKind::Sensor,
                risk_tier: RiskTier::L0ReadOnly,
                default_taint: Some(TaintTag::PrivateVault),
                reversible: true,
                description: "Encrypted personal financial/legal documents (always marks PRIVATE_VAULT)"
                    .to_string(),
            },
            NodeDescriptor {
                path: "/vault/notes".to_string(),
                kind: NodeKind::Sensor,
                risk_tier: RiskTier::L0ReadOnly,
                default_taint: Some(TaintTag::PrivateVault),
                reversible: true,
                description: "Encrypted private notes & keys archive (always marks PRIVATE_VAULT)"
                    .to_string(),
            },
        ]
    }

    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn unlock(&mut self, is_oob: bool) -> Result<(), VaultError> {
        if !is_oob {
            return Err(VaultError {
                code: "UNAUTHORIZED",
                reason: "unlocking halpool/vault requires out-of-band human authorization"
                    .to_string(),
            });
        }
        self.locked = false;
        Ok(())
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    fn resolve_vault_path(&self, vault_path: &str) -> Result<PathBuf, VaultError> {
        let Some(rel) = vault_path.strip_prefix("/vault/") else {
            return Err(VaultError {
                code: "INVALID_VAULT_PATH",
                reason: format!("path '{vault_path}' must start with '/vault/'"),
            });
        };
        if rel.is_empty()
            || rel.ends_with('/')
            || rel.contains('\0')
            || rel
                .split('/')
                .any(|seg| seg.is_empty() || seg == "." || seg == ".." || seg.contains('*'))
        {
            return Err(VaultError {
                code: "INVALID_VAULT_PATH",
                reason: format!("path '{vault_path}' contains forbidden traversal or wildcards"),
            });
        }
        Ok(self.root.join(rel))
    }

    /// Provisions a document into the backing encrypted dataset root.
    pub fn seed_document(&self, vault_path: &str, content: &str) -> Result<(), VaultError> {
        let disk_path = self.resolve_vault_path(vault_path)?;
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(disk_path, content)?;
        Ok(())
    }

    /// Reads an unlocked vault document and wraps access metadata in a `PrivateVault`-tainted event.
    pub fn read_document(
        &mut self,
        vault_path: &str,
        ts_ms: u64,
    ) -> Result<(String, EventEnvelope), VaultError> {
        if self.locked {
            return Err(VaultError {
                code: "VAULT_LOCKED",
                reason: "vault dataset is locked; unlock via OOB before reading".to_string(),
            });
        }
        let disk_path = self.resolve_vault_path(vault_path)?;
        let content = std::fs::read_to_string(disk_path)?;
        self.seq += 1;
        let event = EventEnvelope {
            event_id: format!("vault_read_{}", self.seq),
            ts_ms,
            source_path: vault_path.to_string(),
            producer_actor: "adapter-vault".to_string(),
            trust_level: TrustLevel::PrivateLocal,
            taint_tags: BTreeSet::from([TaintTag::PrivateVault]),
            payload: serde_json::json!({
                "path": vault_path,
                "bytes": content.len(),
            }),
        };
        Ok((content, event))
    }

    /// Reads a vault document and immediately publishes its `PrivateVault` event onto `hal-bus`.
    pub fn read_and_publish(
        &mut self,
        bus: &mut BusClient,
        episode_id: &str,
        vault_path: &str,
        ts_ms: u64,
    ) -> Result<(String, BTreeSet<TaintTag>), VaultError> {
        let (content, event) = self.read_document(vault_path, ts_ms)?;
        match bus.call(&BusRequest::PublishEvent {
            event,
            episode_id: episode_id.to_string(),
        })? {
            BusResponse::EventRecorded { episode_taints } => Ok((content, episode_taints)),
            BusResponse::Error { code, reason } => Err(VaultError {
                code: "BUS_ERROR",
                reason: format!("{code}: {reason}"),
            }),
            other => Err(VaultError {
                code: "BUS_ERROR",
                reason: format!("unexpected bus response: {other:?}"),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn vault_locks_by_default_blocks_traversal_and_tags_private_vault() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hal_vault_unit_{}_{}",
            std::process::id(),
            nanos % 1_000_000_000
        ));
        let mut vault = VaultAdapter::new(&root);
        assert!(vault.is_locked());

        vault
            .seed_document("/vault/docs/secret_plan.txt", "TOP_SECRET_PLAN")
            .unwrap();

        assert_eq!(
            vault
                .read_document("/vault/docs/secret_plan.txt", 1000)
                .unwrap_err()
                .code,
            "VAULT_LOCKED"
        );
        assert_eq!(vault.unlock(false).unwrap_err().code, "UNAUTHORIZED");
        vault.unlock(true).unwrap();

        assert_eq!(
            vault
                .read_document("/vault/../etc/passwd", 1001)
                .unwrap_err()
                .code,
            "INVALID_VAULT_PATH"
        );

        let (content, ev) = vault
            .read_document("/vault/docs/secret_plan.txt", 1002)
            .unwrap();
        assert_eq!(content, "TOP_SECRET_PLAN");
        assert!(ev.taint_tags.contains(&TaintTag::PrivateVault));
        assert_eq!(ev.trust_level, TrustLevel::PrivateLocal);

        vault.lock();
        assert!(vault.is_locked());
        let _ = std::fs::remove_dir_all(&root);
    }
}
