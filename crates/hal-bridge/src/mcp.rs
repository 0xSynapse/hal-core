use crate::client::BridgeSession;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// Pure stdlib JSON-RPC 2.0 MCP stdio server bridging laptop agents (`Aegis OS`) to `HAL Core`.
pub struct McpBridgeServer {
    session: BridgeSession,
}

impl McpBridgeServer {
    #[must_use]
    pub fn new(session: BridgeSession) -> Self {
        Self { session }
    }

    #[must_use]
    pub fn session(&self) -> &BridgeSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut BridgeSession {
        &mut self.session
    }

    /// Processes a single JSON-RPC 2.0 request/notification line and returns an optional reply line.
    pub fn handle_json_line(&mut self, line: &str) -> Option<String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return Some(json_rpc_err(Value::Null, -32700, &format!("Parse error: {e}")));
            }
        };

        let Some(obj) = req.as_object() else {
            return Some(json_rpc_err(Value::Null, -32600, "Invalid Request"));
        };
        let id = obj.get("id").cloned();
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            return id.map(|req_id| json_rpc_err(req_id, -32600, "Invalid Request: missing method"));
        };

        if let Some(version) = obj.get("jsonrpc").and_then(Value::as_str) {
            if version != "2.0" {
                return id.map(|req_id| json_rpc_err(req_id, -32600, "Unsupported jsonrpc version"));
            }
        }

        // Notifications omit `id` and expect no JSON-RPC response line.
        let req_id = id?;

        let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));
        let reply = match method {
            "initialize" => json_rpc_ok(
                req_id,
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": { "listChanged": false }
                    },
                    "serverInfo": {
                        "name": "hal-bridge",
                        "version": env!("CARGO_PKG_VERSION"),
                    }
                }),
            ),
            "ping" => json_rpc_ok(req_id, json!({})),
            "tools/list" => json_rpc_ok(req_id, json!({ "tools": mcp_tool_schemas() })),
            "tools/call" => self.handle_tool_call(req_id, &params),
            other => json_rpc_err(req_id, -32601, &format!("Method not found: {other}")),
        };
        Some(reply)
    }

    pub fn run_stdio<R: BufRead, W: Write>(&mut self, reader: R, mut writer: W) -> io::Result<()> {
        for line_res in reader.lines() {
            let line = line_res?;
            if let Some(reply) = self.handle_json_line(&line) {
                writer.write_all(reply.as_bytes())?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
        }
        Ok(())
    }

    fn handle_tool_call(&mut self, req_id: Value, params: &Value) -> String {
        let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
            return json_rpc_err(req_id, -32602, "Invalid params: missing tool 'name'");
        };
        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let Some(args_obj) = args.as_object() else {
            return json_rpc_err(req_id, -32602, "Invalid params: 'arguments' must be a JSON object");
        };

        let call_res = match tool_name {
            "hal_ping" => self
                .session
                .ping()
                .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null)),
            "hal_vault_read" => {
                let Some(path) = args_obj.get("path").and_then(Value::as_str) else {
                    return json_rpc_err(req_id, -32602, "Invalid params: missing string 'path'");
                };
                let Some(reason) = args_obj.get("reason").and_then(Value::as_str) else {
                    return json_rpc_err(req_id, -32602, "Invalid params: missing string 'reason'");
                };
                let episode_id = args_obj.get("episode_id").and_then(Value::as_str);
                self.session
                    .vault_read(path, reason, episode_id)
                    .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
            }
            "hal_propose_action" => {
                let Some(target_path) = args_obj.get("target_path").and_then(Value::as_str) else {
                    return json_rpc_err(
                        req_id,
                        -32602,
                        "Invalid params: missing string 'target_path'",
                    );
                };
                let Some(action) = args_obj.get("action").and_then(Value::as_str) else {
                    return json_rpc_err(req_id, -32602, "Invalid params: missing string 'action'");
                };
                let Some(reason) = args_obj.get("reason").and_then(Value::as_str) else {
                    return json_rpc_err(req_id, -32602, "Invalid params: missing string 'reason'");
                };
                let prop_args = args_obj.get("args").cloned().unwrap_or_else(|| json!({}));
                let episode_id = args_obj.get("episode_id").and_then(Value::as_str);
                let triggers = args_obj
                    .get("trigger_event_ids")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                self.session
                    .submit_proposal(episode_id, target_path, action, prop_args, reason, triggers)
                    .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
            }
            "hal_send_ipc" => {
                let Some(to_agent) = args_obj.get("to_agent").and_then(Value::as_str) else {
                    return json_rpc_err(req_id, -32602, "Invalid params: missing string 'to_agent'");
                };
                let Some(schema_id) = args_obj.get("schema_id").and_then(Value::as_str) else {
                    return json_rpc_err(
                        req_id,
                        -32602,
                        "Invalid params: missing string 'schema_id'",
                    );
                };
                let Some(payload) = args_obj.get("payload").cloned() else {
                    return json_rpc_err(req_id, -32602, "Invalid params: missing 'payload'");
                };
                let from_ep = args_obj.get("from_episode_id").and_then(Value::as_str);
                let to_ep = args_obj
                    .get("to_episode_id")
                    .and_then(Value::as_str)
                    .unwrap_or("default");
                self.session
                    .send_ipc(to_agent, schema_id, payload, from_ep, to_ep)
                    .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
            }
            "hal_publish_event" => {
                let Some(source_path) = args_obj.get("source_path").and_then(Value::as_str) else {
                    return json_rpc_err(
                        req_id,
                        -32602,
                        "Invalid params: missing string 'source_path'",
                    );
                };
                let Some(payload) = args_obj.get("payload").cloned() else {
                    return json_rpc_err(req_id, -32602, "Invalid params: missing 'payload'");
                };
                let ep = args_obj.get("episode_id").and_then(Value::as_str);
                self.session
                    .publish_event(source_path, payload, ep)
                    .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
            }
            unknown => {
                return json_rpc_err(req_id, -32602, &format!("Unknown MCP tool '{unknown}'"));
            }
        };

        match call_res {
            Ok(val) => {
                let text = serde_json::to_string_pretty(&val).unwrap_or_else(|_| "{}".to_string());
                json_rpc_ok(
                    req_id,
                    json!({
                        "content": [{ "type": "text", "text": text }],
                        "isError": false
                    }),
                )
            }
            Err(err) => json_rpc_ok(
                req_id,
                json!({
                    "content": [{ "type": "text", "text": err.to_string() }],
                    "isError": true
                }),
            ),
        }
    }
}

fn json_rpc_ok(id: Value, result: Value) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"serialize error"}}"#.to_string())
}

fn json_rpc_err(id: Value, code: i64, message: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    }))
    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"serialize error"}}"#.to_string())
}

#[must_use]
pub fn mcp_tool_schemas() -> Vec<Value> {
    vec![
        json!({
            "name": "hal_ping",
            "description": "Check HAL Core connectivity and current SystemMode over hal-gateway.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "hal_vault_read",
            "description": "Propose an L0 read on /vault/** inside HAL Core's encrypted personal vault.",
            "inputSchema": {
                "type": "object",
                "required": ["path", "reason"],
                "properties": {
                    "path": { "type": "string", "description": "Habitat path starting with /vault/" },
                    "reason": { "type": "string" },
                    "episode_id": { "type": "string" }
                }
            }
        }),
        json!({
            "name": "hal_propose_action",
            "description": "Submit a typed ActionProposal (L0/L1/L2) through HAL Core's deterministic policy gate.",
            "inputSchema": {
                "type": "object",
                "required": ["target_path", "action", "reason"],
                "properties": {
                    "target_path": { "type": "string" },
                    "action": { "type": "string" },
                    "reason": { "type": "string" },
                    "args": { "type": "object" },
                    "episode_id": { "type": "string" },
                    "trigger_event_ids": { "type": "array", "items": { "type": "string" } }
                }
            }
        }),
        json!({
            "name": "hal_send_ipc",
            "description": "Send a schema-validated IPC message via hal-bus IPC Matrix with transitive taint propagation.",
            "inputSchema": {
                "type": "object",
                "required": ["to_agent", "schema_id", "payload"],
                "properties": {
                    "to_agent": { "type": "string" },
                    "schema_id": { "type": "string" },
                    "payload": { "type": "object" },
                    "from_episode_id": { "type": "string" },
                    "to_episode_id": { "type": "string" }
                }
            }
        }),
        json!({
            "name": "hal_publish_event",
            "description": "Record an external untrusted input event into the remote episode taint tracker.",
            "inputSchema": {
                "type": "object",
                "required": ["source_path", "payload"],
                "properties": {
                    "source_path": { "type": "string" },
                    "payload": { "type": "object" },
                    "episode_id": { "type": "string" }
                }
            }
        }),
    ]
}
