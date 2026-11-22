use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PfAction {
    Pass,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PfDirection {
    In,
    Out,
}

/// Structured flow record parsed from FreeBSD `tcpdump -n -e -ttt -i pflog0` lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PfLogEvent {
    pub ts_ms: u64,
    pub rule_nr: u32,
    pub action: PfAction,
    pub direction: PfDirection,
    pub iface: String,
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub proto: String,
}

fn parse_ts_ms(token: &str) -> Option<u64> {
    if token.contains(':') {
        let mut hms = token.split(':');
        let h: u64 = hms.next()?.parse().ok()?;
        let m: u64 = hms.next()?.parse().ok()?;
        let s_part = hms.next()?;
        if hms.next().is_some() {
            return None;
        }
        let sec_ms = parse_sec_millis(s_part)?;
        Some((h * 3600 + m * 60) * 1000 + sec_ms)
    } else {
        parse_sec_millis(token)
    }
}

fn parse_sec_millis(s: &str) -> Option<u64> {
    let (sec_str, frac_str) = match s.split_once('.') {
        Some((a, b)) => (a, b),
        None => (s, "0"),
    };
    let secs: u64 = sec_str.parse().ok()?;
    let padded = format!("{frac_str}000");
    let ms: u64 = padded[..3].parse().ok()?;
    Some(secs.saturating_mul(1000).saturating_add(ms))
}

fn split_ip_port(addr: &str) -> (String, Option<u16>) {
    let trimmed = addr.trim().trim_end_matches(':');
    if let Some((host, port_str)) = trimmed.rsplit_once('.') {
        if let Ok(port) = port_str.parse::<u16>() {
            if host.parse::<std::net::Ipv4Addr>().is_ok() {
                return (host.to_string(), Some(port));
            }
        }
    }
    (trimmed.to_string(), None)
}

/// Parses a single `pflog0` text line from `tcpdump -n -e -ttt -i pflog0`.
#[must_use]
pub fn parse_pflog_line(line: &str) -> Option<PfLogEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (ts_tok, rest) = trimmed.split_once(' ')?;
    let ts_ms = parse_ts_ms(ts_tok)?;

    let rule_after = rest.split_once("rule ")?.1;
    let rule_digits: String = rule_after
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let rule_nr: u32 = rule_digits.parse().ok()?;

    let (action, after_action) = if let Some(idx) = rest.find(": block ") {
        (PfAction::Block, &rest[idx + ": block ".len()..])
    } else if let Some(idx) = rest.find(": pass ") {
        (PfAction::Pass, &rest[idx + ": pass ".len()..])
    } else {
        return None;
    };

    let (direction, after_dir) = if let Some(r) = after_action.strip_prefix("out on ") {
        (PfDirection::Out, r)
    } else if let Some(r) = after_action.strip_prefix("in on ") {
        (PfDirection::In, r)
    } else {
        return None;
    };

    let (iface_raw, flow_rest) = after_dir.split_once(':')?;
    let iface = iface_raw.trim().to_string();
    let flow_rest = flow_rest.trim();

    let (src_raw, after_gt) = flow_rest.split_once(" > ")?;
    let (dst_raw, detail) = after_gt.split_once(':')?;

    let (src_ip, src_port) = split_ip_port(src_raw);
    let (dst_ip, dst_port) = split_ip_port(dst_raw);

    let proto = if detail.contains("UDP") {
        "UDP"
    } else if detail.contains("ICMP") {
        "ICMP"
    } else {
        "TCP"
    }
    .to_string();

    Some(PfLogEvent {
        ts_ms,
        rule_nr,
        action,
        direction,
        iface,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pflog_block_dns_and_pass_tcp_lines() {
        let blocked_dns = "1700000001.123456 rule 4/0(match): block out on wan0: 10.0.2.15.54321 > 1.1.1.1.53: UDP, length 42";
        let ev1 = parse_pflog_line(blocked_dns).unwrap();
        assert_eq!(ev1.action, PfAction::Block);
        assert_eq!(ev1.direction, PfDirection::Out);
        assert_eq!(ev1.iface, "wan0");
        assert_eq!(ev1.rule_nr, 4);
        assert_eq!(ev1.src_ip, "10.0.2.15");
        assert_eq!(ev1.src_port, Some(54321));
        assert_eq!(ev1.dst_ip, "1.1.1.1");
        assert_eq!(ev1.dst_port, Some(53));
        assert_eq!(ev1.proto, "UDP");
        assert_eq!(ev1.ts_ms, 1_700_000_001_123);

        let passed_tls = "00:00:02.500000 rule 2/0(match): pass out on wan0: 192.168.100.10.43210 > 93.184.216.34.443: Flags [S], seq 1, length 0";
        let ev2 = parse_pflog_line(passed_tls).unwrap();
        assert_eq!(ev2.action, PfAction::Pass);
        assert_eq!(ev2.dst_port, Some(443));
        assert_eq!(ev2.proto, "TCP");
        assert_eq!(ev2.ts_ms, 2_500);
    }
}
