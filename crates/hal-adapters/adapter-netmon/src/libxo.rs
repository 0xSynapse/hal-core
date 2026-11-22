use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Structured active socket summary extracted from FreeBSD `netstat -an --libxo json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketSummary {
    pub proto: String,
    pub local_addr: String,
    pub foreign_addr: String,
    pub state: Option<String>,
}

fn format_endpoint(obj: &Value, nested_key: &str, flat_key: &str) -> String {
    if let Some(ep) = obj.get(nested_key) {
        if let Some(s) = ep.as_str() {
            return s.to_string();
        }
        let addr = ep
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or("*");
        if let Some(port) = ep.get("port").and_then(|v| v.as_str()) {
            return format!("{addr}:{port}");
        }
        if let Some(port_num) = ep.get("port").and_then(|v| v.as_u64()) {
            return format!("{addr}:{port_num}");
        }
        return addr.to_string();
    }
    obj.get(flat_key)
        .and_then(|v| v.as_str())
        .unwrap_or("*")
        .to_string()
}

/// Parses JSON emitted by FreeBSD `netstat -an --libxo json`.
pub fn parse_netstat_libxo_json(json_str: &str) -> Result<Vec<SocketSummary>, serde_json::Error> {
    let val: Value = serde_json::from_str(json_str)?;
    let Some(sockets) = val
        .get("statistics")
        .and_then(|s| s.get("socket"))
        .and_then(|v| v.as_array())
    else {
        return Ok(Vec::new());
    };

    let mut out = Vec::with_capacity(sockets.len());
    for sock in sockets {
        let proto = sock
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let local_addr = format_endpoint(sock, "local", "local-address");
        let foreign_addr = format_endpoint(sock, "foreign", "foreign-address");
        let state = sock
            .get("tcp-state")
            .or_else(|| sock.get("state"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(SocketSummary {
            proto,
            local_addr,
            foreign_addr,
            state,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_freebsd_netstat_libxo_json() {
        let sample = r#"{
          "statistics": {
            "socket": [
              {
                "protocol": "tcp4",
                "local": { "address": "192.168.100.10", "port": "8443" },
                "foreign": { "address": "*", "port": "*" },
                "tcp-state": "LISTEN"
              },
              {
                "protocol": "udp4",
                "local": { "address": "10.0.2.15", "port": "5353" },
                "foreign": { "address": "*", "port": "*" }
              }
            ]
          }
        }"#;
        let parsed = parse_netstat_libxo_json(sample).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].proto, "tcp4");
        assert_eq!(parsed[0].local_addr, "192.168.100.10:8443");
        assert_eq!(parsed[0].state.as_deref(), Some("LISTEN"));
        assert_eq!(parsed[1].state, None);
    }
}
