//! Hash-chained append-only black-box audit log (`hal-audit`).

use hal_os_hal::AppendOnlyGuard;
use hal_proto::{compute_audit_entry_hash, AgentPrincipal, AuditRecord, GENESIS_PREV_HASH};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Errors produced when opening, appending to, or verifying `hal-audit` logs.
#[derive(Debug)]
pub enum AuditError {
    Io(io::Error),
    Serde(serde_json::Error),
    TamperDetected {
        line: usize,
        seq: u64,
        reason: String,
    },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "audit I/O error: {e}"),
            Self::Serde(e) => write!(f, "audit JSON error: {e}"),
            Self::TamperDetected { line, seq, reason } => {
                write!(f, "audit tamper detected at line {line} (seq {seq}): {reason}")
            }
        }
    }
}

impl std::error::Error for AuditError {}

impl From<io::Error> for AuditError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(value)
    }
}

/// Unchained event details supplied by `hal-bus` / `hal-policy` to record a new `AuditRecord`.
#[derive(Debug, Clone)]
pub struct AuditInput {
    pub ts_ms: u64,
    pub principal: AgentPrincipal,
    pub episode_id: String,
    pub target_path: String,
    pub action: String,
    pub trigger_event_ids: Vec<String>,
    pub proposal_id: Option<String>,
    pub decision_summary: String,
    pub workspace_snapshot_id: Option<String>,
}

/// Summary returned after verifying an entire JSONL audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub record_count: u64,
    pub head_seq: u64,
    pub head_hash: String,
}

/// Append-only SHA-256 hash-chained audit writer backed by `hal-audit` JSONL files.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: File,
    next_seq: u64,
    last_hash: String,
}

impl AuditLog {
    /// Opens an existing audit log (verifying its entire hash chain first!) or creates a new one.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let (next_seq, last_hash) = if path.exists() {
            let report = verify_file(&path)?;
            (report.head_seq + 1, report.head_hash)
        } else {
            (1, GENESIS_PREV_HASH.to_string())
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file,
            next_seq,
            last_hash,
        })
    }

    /// Applies kernel append-only protection (`chflags sappnd` on FreeBSD) via `AppendOnlyGuard`.
    pub fn lock_append_only(&self, guard: &dyn AppendOnlyGuard) -> io::Result<()> {
        guard.enable_append_only(&self.path)
    }

    /// Path to the backing JSONL audit file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Most recently committed hash (or `GENESIS_PREV_HASH` if empty).
    #[must_use]
    pub fn head_hash(&self) -> &str {
        &self.last_hash
    }

    /// Next sequence number to be written.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Appends and fsyncs one hash-chained `AuditRecord`.
    pub fn append(&mut self, input: AuditInput) -> Result<AuditRecord, AuditError> {
        let mut record = AuditRecord {
            seq: self.next_seq,
            ts_ms: input.ts_ms,
            principal: input.principal,
            episode_id: input.episode_id,
            target_path: input.target_path,
            action: input.action,
            trigger_event_ids: input.trigger_event_ids,
            proposal_id: input.proposal_id,
            decision_summary: input.decision_summary,
            workspace_snapshot_id: input.workspace_snapshot_id,
            prev_hash: self.last_hash.clone(),
            entry_hash: String::new(),
        };
        let entry_hash = compute_audit_entry_hash(&record.prev_hash, &record)?;
        record.entry_hash = entry_hash.clone();

        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()?;

        self.next_seq += 1;
        self.last_hash = entry_hash;
        Ok(record)
    }
}

/// Verifies every record sequence number, `prev_hash` pointer, and SHA-256 `entry_hash` in `path`.
pub fn verify_file(path: impl AsRef<Path>) -> Result<VerifyReport, AuditError> {
    let (report, _) = verify_and_collect(path.as_ref(), None)?;
    Ok(report)
}

/// Verifies the full audit chain in `path` and returns records with `seq > after_seq`.
/// Returns an empty vector if `path` does not exist yet.
pub fn read_records_from_seq(
    path: impl AsRef<Path>,
    after_seq: u64,
) -> Result<Vec<AuditRecord>, AuditError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let (_, records) = verify_and_collect(path, Some(after_seq))?;
    Ok(records)
}

fn verify_and_collect(
    path: &Path,
    collect_after_seq: Option<u64>,
) -> Result<(VerifyReport, Vec<AuditRecord>), AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut expected_seq = 1u64;
    let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();
    let mut record_count = 0u64;
    let mut collected = Vec::new();

    for (idx, line_res) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let line = line_res?;
        if line.is_empty() {
            return Err(AuditError::TamperDetected {
                line: line_no,
                seq: expected_seq,
                reason: "unexpected blank line inside audit chain".to_string(),
            });
        }
        let record: AuditRecord = serde_json::from_str(&line).map_err(|e| AuditError::TamperDetected {
            line: line_no,
            seq: expected_seq,
            reason: format!("corrupted record JSON: {e}"),
        })?;
        if record.seq != expected_seq {
            return Err(AuditError::TamperDetected {
                line: line_no,
                seq: record.seq,
                reason: format!("expected seq {expected_seq}, got {}", record.seq),
            });
        }
        if record.prev_hash != expected_prev_hash {
            return Err(AuditError::TamperDetected {
                line: line_no,
                seq: record.seq,
                reason: format!(
                    "prev_hash mismatch: expected {expected_prev_hash}, got {}",
                    record.prev_hash
                ),
            });
        }
        let recomputed = compute_audit_entry_hash(&expected_prev_hash, &record)?;
        if record.entry_hash != recomputed {
            return Err(AuditError::TamperDetected {
                line: line_no,
                seq: record.seq,
                reason: format!(
                    "entry_hash mismatch: expected {recomputed}, got {}",
                    record.entry_hash
                ),
            });
        }

        expected_prev_hash = record.entry_hash.clone();
        if let Some(after_seq) = collect_after_seq {
            if record.seq > after_seq {
                collected.push(record);
            }
        }
        expected_seq += 1;
        record_count += 1;
    }

    Ok((
        VerifyReport {
            record_count,
            head_seq: record_count,
            head_hash: expected_prev_hash,
        },
        collected,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_os_hal::MockAppendOnlyGuard;
    use hal_proto::{AgentAuthKind, TrustDomain};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_tmp_file(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hal_audit_{label}_{}_{}.jsonl",
            std::process::id(),
            nanos
        ))
    }

    fn sample_input(action: &str) -> AuditInput {
        AuditInput {
            ts_ms: 1_700_000_000_000,
            principal: AgentPrincipal {
                agent_id: "agent-coder".to_string(),
                trust_domain: TrustDomain::WorkspaceWorker,
                auth_kind: AgentAuthKind::LocalNoIpJail,
                parent_agent_id: None,
                peer_cred_or_cert_fp: "uid:1001".to_string(),
            },
            episode_id: "ep_01".to_string(),
            target_path: "/work/agents/coder/episodes/ep_01/fs".to_string(),
            action: action.to_string(),
            trigger_event_ids: vec!["evt_1".to_string()],
            proposal_id: Some("prop_1".to_string()),
            decision_summary: "Allow(L1)".to_string(),
            workspace_snapshot_id: Some("ep_01_step1".to_string()),
        }
    }

    #[test]
    fn append_reopen_verify_and_detect_single_byte_tampering() {
        let path = unique_tmp_file("chain");
        let guard = MockAppendOnlyGuard::default();

        let head_hash_after_3 = {
            let mut log = AuditLog::open(&path).unwrap();
            log.lock_append_only(&guard).unwrap();
            assert!(guard.is_append_only(&path).unwrap());
            let r1 = log.append(sample_input("read")).unwrap();
            let r2 = log.append(sample_input("write")).unwrap();
            assert_eq!(r1.seq, 1);
            assert_eq!(r1.prev_hash, GENESIS_PREV_HASH);
            assert_eq!(r2.seq, 2);
            assert_eq!(r2.prev_hash, r1.entry_hash);
            drop(log);

            let mut reopened = AuditLog::open(&path).unwrap();
            let r3 = reopened.append(sample_input("snapshot")).unwrap();
            assert_eq!(r3.seq, 3);
            assert_eq!(r3.prev_hash, r2.entry_hash);
            r3.entry_hash
        };

        let report = verify_file(&path).unwrap();
        assert_eq!(report.record_count, 3);
        assert_eq!(report.head_seq, 3);
        assert_eq!(report.head_hash, head_hash_after_3);

        let all = read_records_from_seq(&path, 0).unwrap();
        assert_eq!(all.len(), 3);
        let tail = read_records_from_seq(&path, 2).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].seq, 3);
        let missing = unique_tmp_file("missing");
        assert!(read_records_from_seq(&missing, 0).unwrap().is_empty());

        let original = std::fs::read_to_string(&path).unwrap();
        let mutated = original.replacen("\"write\"", "\"Write\"", 1);
        assert_ne!(original, mutated);
        std::fs::write(&path, &mutated).unwrap();

        let err = verify_file(&path).unwrap_err();
        assert!(matches!(err, AuditError::TamperDetected { line: 2, seq: 2, .. }));
        assert!(matches!(
            AuditLog::open(&path),
            Err(AuditError::TamperDetected { line: 2, seq: 2, .. })
        ));

        let lines: Vec<&str> = original.lines().collect();
        let skipped = format!("{}\n{}\n", lines[0], lines[2]);
        std::fs::write(&path, skipped).unwrap();
        let err = verify_file(&path).unwrap_err();
        assert!(matches!(err, AuditError::TamperDetected { line: 2, seq: 3, .. }));

        let _ = std::fs::remove_file(&path);
    }
}
