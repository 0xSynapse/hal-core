use hal_proto::{ActionProposal, AgentPrincipal};

const IMMUTABLE_TCB_PATHS: &[&str] = &[
    "/etc/pf.conf",
    "/boot/loader.conf",
    "/usr/local/etc/hal-os",
    "/sys/policy",
    "/sys/ipc-matrix",
    "/net/broker/secrets",
    "/net/broker/allowlist",
    "/net/policy",
];

const PROTECTED_SUBSYSTEM_PATHS: &[&str] = &["/pool/audit", "/sys/audit", "/sys/watchdog"];

fn is_valid_concrete_path(path: &str) -> bool {
    if !path.starts_with('/') || path.contains('\0') {
        return false;
    }
    if path == "/" {
        return true;
    }
    let Some(trimmed) = path.strip_prefix('/') else {
        return false;
    };
    if trimmed.ends_with('/') {
        return false;
    }
    !trimmed
        .split('/')
        .any(|seg| seg.is_empty() || seg == "." || seg == ".." || seg.contains('*'))
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn is_read_only_op(action: &str) -> bool {
    matches!(
        action,
        "read" | "list" | "stat" | "query" | "inspect" | "verify" | "subscribe"
    )
}

/// Hard non-overridable security invariants checked before any capability/risk tier approval.
#[must_use]
pub fn check_hard_invariants(
    _principal: &AgentPrincipal,
    proposal: &ActionProposal,
    is_oob: bool,
) -> Option<(String, String)> {
    if !is_valid_concrete_path(&proposal.target_path) {
        return Some((
            "INVALID_TARGET_PATH".to_string(),
            format!(
                "target_path '{}' failed strict namespace path validation",
                proposal.target_path
            ),
        ));
    }

    if is_oob {
        return None;
    }

    let path = proposal.target_path.as_str();
    let action = proposal.action.as_str();

    if path_matches_prefix(path, "/net/broker/secrets") {
        return Some((
            "HARD_INVARIANT_IMMUTABLE_TCB".to_string(),
            "sealed broker secrets are strictly inaccessible outside hal-net-broker".to_string(),
        ));
    }

    for &tcb in IMMUTABLE_TCB_PATHS {
        if path_matches_prefix(path, tcb) && !is_read_only_op(action) {
            return Some((
                "HARD_INVARIANT_IMMUTABLE_TCB".to_string(),
                format!(
                    "non-OOB mutation of immutable TCB/policy path '{path}' (action '{action}') is forbidden"
                ),
            ));
        }
    }

    for &sub in PROTECTED_SUBSYSTEM_PATHS {
        if path_matches_prefix(path, sub) && !is_read_only_op(action) {
            return Some((
                "HARD_INVARIANT_PROTECTED_SUBSYSTEM".to_string(),
                format!(
                    "non-OOB tampering/stopping of protected audit/watchdog subsystem '{path}' is forbidden"
                ),
            ));
        }
    }

    if path_matches_prefix(path, "/sys/mode") && !is_read_only_op(action) {
        return Some((
            "HARD_INVARIANT_UNIDIRECTIONAL_LOCK".to_string(),
            "system mode mutation via agent proposal is forbidden; only hal-oob or watchdog controls mode".to_string(),
        ));
    }

    None
}
