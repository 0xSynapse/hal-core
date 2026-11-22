use hal_audit::verify_file;
use hal_bridge::{BridgeConfig, BridgeError, BridgeSession};
use hal_proto::{sign_token, CapabilityToken, PairingBundle, RiskTier};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TOKEN_SECRET_VAL: &str = "hal-phase5c-e2e-signing-secret-32b";
const OOB_TOK_VAL: &str = "hal-key-phase5c-operator-token";

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct DirGuard(PathBuf);

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unique_tmp_dir(label: &str) -> DirGuard {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!(
        "/tmp/hal_p5c_{label}_{}_{}",
        std::process::id(),
        nanos % 1_000_000_000
    ));
    std::fs::create_dir_all(&dir).unwrap();
    DirGuard(dir)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn workspace_bin_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
    let needed = ["hal-bus", "hal-gateway", "hal-oob", "halctl", "hal-bridge"];
    if needed.iter().any(|name| !dir.join(name).is_file()) {
        let out = Command::new("cargo")
            .current_dir(repo_root())
            .args([
                "build",
                "--offline",
                "-p",
                "hal-bus",
                "-p",
                "hal-gateway",
                "-p",
                "hal-oob",
                "-p",
                "hal-bridge",
                "--bins",
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "cargo build workspace bins failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    dir
}

fn spawn_and_wait_banner(mut cmd: Command, prefix: &str) -> (ChildGuard, String) {
    cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = cmd.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let banner = loop {
        line.clear();
        let n = reader.read_line(&mut line).unwrap();
        assert!(
            n > 0 && Instant::now() < deadline,
            "daemon exited or timed out waiting for '{prefix}'"
        );
        if line.starts_with(prefix) {
            break line.trim().to_string();
        }
    };
    std::thread::spawn(move || {
        let mut sink = String::new();
        while reader.read_line(&mut sink).unwrap_or(0) > 0 {
            sink.clear();
        }
    });
    (ChildGuard(Some(child)), banner)
}

fn parse_env_file(path: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

#[test]
fn phase5c_oob_pairing_auto_discovery_renewal_ceiling_and_revoke_e2e() {
    let tmp = unique_tmp_dir("e2e");
    let root_dir = &tmp.0;
    let host_dir = root_dir.join("host_etc");
    let laptop_dir = root_dir.join("laptop_cfg");
    let sock_dir = root_dir.join("bus");
    let audit_log = root_dir.join("hal-audit.jsonl");
    let gw_audit = root_dir.join("hal-gateway.jsonl");
    let peers_cfg = host_dir.join("gateway-peers.toml");
    let secrets_env = host_dir.join("secrets.env");
    let laptop_bundle = host_dir.join("remote-laptop-e2e.pairing-bundle.json");
    let guest_bundle = host_dir.join("remote-guest-ro.pairing-bundle.json");

    std::fs::create_dir_all(&host_dir).unwrap();
    let repo = repo_root();
    let bin_dir = workspace_bin_dir();

    // Seed initial host secrets.env (0600) with signing key (simulating HAL Core Day-0 host setup).
    std::fs::write(&secrets_env, format!("HAL_TOKEN_SECRET={TOKEN_SECRET_VAL}\n")).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(&secrets_env, std::fs::Permissions::from_mode(0o600)).unwrap();

    // 1. Run real `halctl peer enroll` for an L2-capable developer laptop & an L0-capped guest peer.
    let enroll_laptop = Command::new(bin_dir.join("halctl"))
        .args([
            "peer",
            "enroll",
            "--agent-id",
            "remote-laptop-e2e",
            "--ip",
            "127.0.0.1/32",
            "--gateway-addr",
            "127.0.0.1:9443",
            "--peers-config",
            peers_cfg.to_str().unwrap(),
            "--secrets-file",
            secrets_env.to_str().unwrap(),
            "--bundle-out",
            laptop_bundle.to_str().unwrap(),
            "--paths",
            "/vault/**,/habitat/**",
            "--ops",
            "read,write,lock",
            "--max-tier",
            "L2",
            "--ttl",
            "24h",
            "--wg-pubkey",
            "LaptopWgPublicKeyDemo123=",
        ])
        .output()
        .unwrap();
    assert!(
        enroll_laptop.status.success(),
        "halctl peer enroll laptop failed: {}",
        String::from_utf8_lossy(&enroll_laptop.stderr)
    );
    let enroll_stdout = String::from_utf8_lossy(&enroll_laptop.stdout);
    assert!(enroll_stdout.contains("PEER_ENROLLED agent_id=remote-laptop-e2e"));
    assert!(enroll_stdout.contains("[Peer]"));
    assert!(enroll_stdout.contains("PublicKey = LaptopWgPublicKeyDemo123="));

    let enroll_guest = Command::new(bin_dir.join("halctl"))
        .args([
            "peer",
            "enroll",
            "--agent-id",
            "remote-guest-ro",
            "--ip",
            "127.0.0.1/32",
            "--gateway-addr",
            "127.0.0.1:9443",
            "--peers-config",
            peers_cfg.to_str().unwrap(),
            "--secrets-file",
            secrets_env.to_str().unwrap(),
            "--bundle-out",
            guest_bundle.to_str().unwrap(),
            "--paths",
            "/vault/**",
            "--ops",
            "read",
            "--max-tier",
            "L0",
            "--ttl",
            "1h",
        ])
        .output()
        .unwrap();
    assert!(
        enroll_guest.status.success(),
        "halctl peer enroll guest failed: {}",
        String::from_utf8_lossy(&enroll_guest.stderr)
    );

    // Secrets & bundles must be 0600, and stdout must never print raw proof keys or signing secrets.
    let parsed_env = parse_env_file(&secrets_env);
    let laptop_proof_key = parsed_env
        .get("HAL_PEER_KEY_REMOTE_LAPTOP_E2E")
        .expect("secrets.env must contain HAL_PEER_KEY_REMOTE_LAPTOP_E2E")
        .clone();
    let guest_proof_key = parsed_env
        .get("HAL_PEER_KEY_REMOTE_GUEST_RO")
        .expect("secrets.env must contain HAL_PEER_KEY_REMOTE_GUEST_RO")
        .clone();
    assert!(!enroll_stdout.contains(&laptop_proof_key));
    assert!(!enroll_stdout.contains(TOKEN_SECRET_VAL));
    assert!(!String::from_utf8_lossy(&enroll_guest.stdout).contains(&guest_proof_key));

    #[cfg(unix)]
    {
        assert_eq!(
            std::fs::metadata(&secrets_env).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&laptop_bundle).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&guest_bundle).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // 2. Spawn live `hal-bus`, `hal-gateway` (WITHOUT `--peer-key-env`, testing auto-discovery), and `hal-oob`.
    let mut bus_cmd = Command::new(bin_dir.join("hal-bus"));
    bus_cmd
        .args([
            "--ipc-matrix",
            repo.join("config/policy/ipc-matrix.toml").to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--socket-dir",
            sock_dir.to_str().unwrap(),
            "--token-secret-env",
            "HAL_TOKEN_SECRET",
            "--serve",
        ])
        .env("HAL_TOKEN_SECRET", TOKEN_SECRET_VAL);
    let (_bus_guard, bus_banner) = spawn_and_wait_banner(bus_cmd, "HAL_BUS_SERVING");
    assert!(bus_banner.contains("HAL_BUS_SERVING"));

    let mut gw_cmd = Command::new(bin_dir.join("hal-gateway"));
    gw_cmd
        .args([
            "--config",
            peers_cfg.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--bus-socket",
            sock_dir.join("gateway.sock").to_str().unwrap(),
            "--audit-log",
            gw_audit.to_str().unwrap(),
            "--token-secret-env",
            "HAL_TOKEN_SECRET",
            "--serve",
        ])
        .env("HAL_TOKEN_SECRET", TOKEN_SECRET_VAL)
        .env("HAL_PEER_KEY_REMOTE_LAPTOP_E2E", &laptop_proof_key)
        .env("HAL_PEER_KEY_REMOTE_GUEST_RO", &guest_proof_key);
    let (_gw_guard, gw_banner) = spawn_and_wait_banner(gw_cmd, "HAL_GATEWAY_SERVING");
    let gw_bind = gw_banner
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("bind="))
        .unwrap()
        .to_string();
    let gw_addr: SocketAddr = gw_bind.parse().unwrap();

    let mut oob_cmd = Command::new(bin_dir.join("hal-oob"));
    oob_cmd
        .args([
            "--bind",
            "127.0.0.1:0",
            "--bus-socket",
            sock_dir.join("oob.sock").to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--serve",
        ])
        .env("HAL_OOB_TOKEN", OOB_TOK_VAL);
    let (_oob_guard, oob_banner) = spawn_and_wait_banner(oob_cmd, "HAL_KEY_SERVING");
    assert!(oob_banner.contains("HAL_KEY_SERVING"));

    // 3. Unpaired stranger cannot authenticate even if it holds an HMAC-signed token.
    let mut stranger_tok = CapabilityToken {
        token_id: "tok-stranger".to_string(),
        subject_agent_id: "unpaired-stranger".to_string(),
        path_patterns: vec!["/vault/**".to_string()],
        allowed_ops: vec!["read".to_string()],
        max_risk_tier: RiskTier::L0ReadOnly,
        delegation_depth: 0,
        max_delegation_depth: 0,
        expires_at_ms: now_unix_ms().saturating_add(3_600_000),
        rate_limit_per_min: 10,
        token_budget: None,
        hmac_sha256: String::new(),
    };
    sign_token(&mut stranger_tok, TOKEN_SECRET_VAL.as_bytes());
    let stranger_cfg = BridgeConfig::from_toml_str(&format!(
        "version = 1\ngateway_addr = \"{gw_addr}\"\nagent_id = \"unpaired-stranger\"\ncert_sha256 = \"{}\"\npeer_proof_key = \"arbitrary\"\ncap_token_json = '''{}'''\n",
        "f".repeat(64),
        serde_json::to_string(&stranger_tok).unwrap()
    ))
    .unwrap();
    match BridgeSession::connect(stranger_cfg) {
        Err(BridgeError::Gateway { code, .. }) => assert_eq!(code, "GATEWAY_PEER_DENIED"),
        Err(other) => panic!("expected GATEWAY_PEER_DENIED for unpaired peer, got: {other:?}"),
        Ok(_) => panic!("unpaired peer unexpectedly connected"),
    }

    // 4. Pair laptop using real `hal-bridge pair --bundle ... --out-dir ... --gateway-addr ...`
    let pair_out = Command::new(bin_dir.join("hal-bridge"))
        .args([
            "pair",
            "--bundle",
            laptop_bundle.to_str().unwrap(),
            "--out-dir",
            laptop_dir.to_str().unwrap(),
            "--gateway-addr",
            &gw_addr.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        pair_out.status.success(),
        "hal-bridge pair failed: {}",
        String::from_utf8_lossy(&pair_out.stderr)
    );
    let pair_stdout = String::from_utf8_lossy(&pair_out.stdout);
    assert!(pair_stdout.contains("BRIDGE_PAIRED agent_id=remote-laptop-e2e"));
    assert!(!pair_stdout.contains(&laptop_proof_key));

    let bridge_toml = laptop_dir.join("laptop-bridge.toml");
    let proof_key_file = laptop_dir.join("remote-laptop-e2e.proof.key");
    let cap_token_file = laptop_dir.join("remote-laptop-e2e.cap.json");
    #[cfg(unix)]
    {
        assert_eq!(
            std::fs::metadata(&laptop_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for sensitive in [&proof_key_file, &cap_token_file, &bridge_toml] {
            assert_eq!(
                std::fs::metadata(sensitive).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    // Ensure the pairing bundle can still be parsed and checked cleanly.
    let bundle_parsed: PairingBundle =
        serde_json::from_str(&std::fs::read_to_string(&laptop_bundle).unwrap()).unwrap();
    bundle_parsed.validate().unwrap();

    // 5. Real `hal-bridge --check`, `ping`, L2 `propose`, and `halctl approvals approve`.
    let check_out = Command::new(bin_dir.join("hal-bridge"))
        .args(["--config", bridge_toml.to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    assert!(check_out.status.success());
    assert!(String::from_utf8_lossy(&check_out.stdout)
        .contains("HAL_BRIDGE_READY agent=remote-laptop-e2e"));

    let ping_out = Command::new(bin_dir.join("hal-bridge"))
        .args(["--config", bridge_toml.to_str().unwrap(), "ping"])
        .output()
        .unwrap();
    assert!(
        ping_out.status.success(),
        "paired hal-bridge ping failed: {}",
        String::from_utf8_lossy(&ping_out.stderr)
    );
    let ping_json: Value = serde_json::from_slice(&ping_out.stdout).unwrap();
    assert_eq!(ping_json["type"], "Pong");
    assert_eq!(ping_json["principal"]["agent_id"], "remote-laptop-e2e");

    let propose_l2 = Command::new(bin_dir.join("hal-bridge"))
        .args([
            "--config",
            bridge_toml.to_str().unwrap(),
            "propose",
            "--target",
            "/habitat/entry/lock",
            "--action",
            "lock",
            "--args",
            r#"{"locked":true}"#,
            "--reason",
            "phase5c paired L2 check",
        ])
        .output()
        .unwrap();
    assert!(
        propose_l2.status.success(),
        "paired L2 propose failed: {}",
        String::from_utf8_lossy(&propose_l2.stderr)
    );
    let propose_json: Value = serde_json::from_slice(&propose_l2.stdout).unwrap();
    assert_eq!(propose_json["type"], "ProposalDecision");
    let approval_id = propose_json["decision"]["approval_id"]
        .as_str()
        .expect("L2 action must require OOB approval")
        .to_string();

    let approve_out = Command::new(bin_dir.join("halctl"))
        .args([
            "--bus-socket",
            sock_dir.join("oob.sock").to_str().unwrap(),
            "approvals",
            "approve",
            &approval_id,
            "--note",
            "approved via halctl e2e",
        ])
        .output()
        .unwrap();
    assert!(
        approve_out.status.success(),
        "halctl approve failed: {}",
        String::from_utf8_lossy(&approve_out.stderr)
    );
    let approve_stdout = String::from_utf8_lossy(&approve_out.stdout);
    assert!(approve_stdout.contains("APPROVAL_RESOLVED"));
    assert!(approve_stdout.contains("Approved"));

    // 6. Short-TTL token expiry -> `TOKEN_EXPIRED` -> `halctl token mint` + `hal-bridge pair --token` recovery.
    let short_tok = host_dir.join("short.cap.json");
    let mint_short = Command::new(bin_dir.join("halctl"))
        .args([
            "token",
            "mint",
            "--agent-id",
            "remote-laptop-e2e",
            "--peers-config",
            peers_cfg.to_str().unwrap(),
            "--secrets-file",
            secrets_env.to_str().unwrap(),
            "--out",
            short_tok.to_str().unwrap(),
            "--paths",
            "/vault/**,/habitat/**",
            "--ops",
            "read,lock",
            "--max-tier",
            "L2",
            "--ttl",
            "500ms",
        ])
        .output()
        .unwrap();
    assert!(
        mint_short.status.success(),
        "short token mint failed: {}",
        String::from_utf8_lossy(&mint_short.stderr)
    );

    let swap_short = Command::new(bin_dir.join("hal-bridge"))
        .args([
            "pair",
            "--token",
            short_tok.to_str().unwrap(),
            "--out-dir",
            laptop_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(swap_short.status.success());

    std::thread::sleep(Duration::from_millis(750));
    let expired_ping = Command::new(bin_dir.join("hal-bridge"))
        .args(["--config", bridge_toml.to_str().unwrap(), "ping"])
        .output()
        .unwrap();
    assert!(!expired_ping.status.success());
    let expired_stderr = String::from_utf8_lossy(&expired_ping.stderr);
    assert!(
        expired_stderr.contains("TOKEN_EXPIRED"),
        "expected TOKEN_EXPIRED on stderr, got: {expired_stderr}"
    );

    let renewed_tok = host_dir.join("renewed.cap.json");
    let mint_renew = Command::new(bin_dir.join("halctl"))
        .args([
            "token",
            "mint",
            "--agent-id",
            "remote-laptop-e2e",
            "--peers-config",
            peers_cfg.to_str().unwrap(),
            "--secrets-file",
            secrets_env.to_str().unwrap(),
            "--out",
            renewed_tok.to_str().unwrap(),
            "--paths",
            "/vault/**,/habitat/**",
            "--ops",
            "read,lock",
            "--max-tier",
            "L2",
            "--ttl",
            "1h",
        ])
        .output()
        .unwrap();
    assert!(mint_renew.status.success());

    let renew_pair = Command::new(bin_dir.join("hal-bridge"))
        .args([
            "pair",
            "--token",
            renewed_tok.to_str().unwrap(),
            "--out-dir",
            laptop_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(renew_pair.status.success());

    let ping_recovered = Command::new(bin_dir.join("hal-bridge"))
        .args(["--config", bridge_toml.to_str().unwrap(), "ping"])
        .output()
        .unwrap();
    assert!(
        ping_recovered.status.success(),
        "ping after token renewal failed: {}",
        String::from_utf8_lossy(&ping_recovered.stderr)
    );

    // 7. Tier ceiling enforcement: L0 guest peer cannot be minted an L1 token.
    let escalated_tok = host_dir.join("guest-escalated.cap.json");
    let mint_escalate = Command::new(bin_dir.join("halctl"))
        .args([
            "token",
            "mint",
            "--agent-id",
            "remote-guest-ro",
            "--peers-config",
            peers_cfg.to_str().unwrap(),
            "--secrets-file",
            secrets_env.to_str().unwrap(),
            "--out",
            escalated_tok.to_str().unwrap(),
            "--max-tier",
            "L1",
            "--ttl",
            "1h",
        ])
        .output()
        .unwrap();
    assert!(!mint_escalate.status.success());
    let escalate_stderr = String::from_utf8_lossy(&mint_escalate.stderr);
    assert!(
        escalate_stderr.contains("ceiling"),
        "expected ceiling error, got: {escalate_stderr}"
    );
    assert!(!escalated_tok.exists());

    // 8. Live revocation: `halctl agent revoke` freezes the agent on `hal-bus`, blocking further proposals.
    let revoke_out = Command::new(bin_dir.join("halctl"))
        .args([
            "--bus-socket",
            sock_dir.join("oob.sock").to_str().unwrap(),
            "agent",
            "revoke",
            "remote-laptop-e2e",
            "--reason",
            "phase5c stolen laptop drill",
        ])
        .output()
        .unwrap();
    assert!(
        revoke_out.status.success(),
        "halctl agent revoke failed: {}",
        String::from_utf8_lossy(&revoke_out.stderr)
    );
    assert!(String::from_utf8_lossy(&revoke_out.stdout).contains("AGENT_REVOKED"));

    let post_revoke = Command::new(bin_dir.join("hal-bridge"))
        .args([
            "--config",
            bridge_toml.to_str().unwrap(),
            "propose",
            "--target",
            "/vault/notes.md",
            "--action",
            "read",
            "--reason",
            "post revoke attempt",
        ])
        .output()
        .unwrap();
    let pr_stdout = String::from_utf8_lossy(&post_revoke.stdout);
    let pr_stderr = String::from_utf8_lossy(&post_revoke.stderr);
    assert!(
        (!post_revoke.status.success() && pr_stderr.contains("AGENT_FROZEN"))
            || pr_stdout.contains("AGENT_FROZEN"),
        "expected AGENT_FROZEN rejection after revoke; status={} stdout={pr_stdout} stderr={pr_stderr}",
        post_revoke.status
    );

    // 9. Both `hal-bus` and `hal-gateway` hash-chained audit logs remain cryptographically valid.
    verify_file(&audit_log).unwrap();
    verify_file(&gw_audit).unwrap();
}
