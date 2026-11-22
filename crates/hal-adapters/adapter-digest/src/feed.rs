use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Normalized feed entry extracted from RSS 2.0, Atom (e.g. arXiv), or GitHub JSON API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestItem {
    pub id: String,
    pub title: String,
    pub link: String,
    pub summary: String,
    pub published: Option<String>,
}

/// Sanitizes an arbitrary untrusted string into a single-line UTF-8-bounded field (`<= max_bytes`)
/// suitable for `hal-policy`'s strict declassification schema gate.
#[must_use]
pub fn sanitize_declassified_field(input: &str, max_bytes: usize) -> String {
    let mut collapsed = String::with_capacity(input.len().min(max_bytes));
    let mut prev_space = true;
    for ch in input.chars() {
        let normalized = if ch.is_control() || ch.is_whitespace() {
            ' '
        } else {
            ch
        };
        if normalized == ' ' {
            if !prev_space {
                if collapsed.len() + 1 > max_bytes {
                    break;
                }
                collapsed.push(' ');
                prev_space = true;
            }
        } else {
            let len = normalized.len_utf8();
            if collapsed.len() + len > max_bytes {
                break;
            }
            collapsed.push(normalized);
            prev_space = false;
        }
    }
    collapsed.trim().to_string()
}

fn decode_xml_entities(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
}

fn strip_cdata(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("<![CDATA[") {
        if let Some(inner) = rest.strip_suffix("]]>") {
            return inner.trim();
        }
    }
    trimmed
}

fn split_tag_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open_prefix = format!("<{tag}");
    let close_tag = format!("</{tag}>");
    let mut blocks = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open_prefix) {
        let after = &rest[start + open_prefix.len()..];
        let Some(first_ch) = after.chars().next() else {
            break;
        };
        if first_ch != '>' && !first_ch.is_whitespace() {
            rest = after;
            continue;
        }
        let Some(gt_rel) = after.find('>') else {
            break;
        };
        let body_start = &after[gt_rel + 1..];
        let Some(end_rel) = body_start.find(&close_tag) else {
            break;
        };
        blocks.push(&body_start[..end_rel]);
        rest = &body_start[end_rel + close_tag.len()..];
    }
    blocks
}

fn extract_tag_text(block: &str, tag: &str) -> Option<String> {
    let open_prefix = format!("<{tag}");
    let close_tag = format!("</{tag}>");
    let mut rest = block;
    while let Some(start) = rest.find(&open_prefix) {
        let after = &rest[start + open_prefix.len()..];
        let next_ch = after.chars().next()?;
        if next_ch != '>' && !next_ch.is_whitespace() && next_ch != '/' {
            rest = after;
            continue;
        }
        let gt_rel = after.find('>')?;
        if after[..gt_rel].trim_end().ends_with('/') {
            rest = &after[gt_rel + 1..];
            continue;
        }
        let content_start = &after[gt_rel + 1..];
        let end_rel = content_start.find(&close_tag)?;
        let raw = strip_cdata(&content_start[..end_rel]);
        return Some(decode_xml_entities(raw));
    }
    None
}

fn extract_link(block: &str) -> String {
    if let Some(txt) = extract_tag_text(block, "link") {
        let t = txt.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    let mut rest = block;
    while let Some(start) = rest.find("<link") {
        let after = &rest[start + "<link".len()..];
        let Some(gt) = after.find('>') else {
            break;
        };
        let attrs = &after[..gt];
        if let Some(href_pos) = attrs.find("href=") {
            let val_part = attrs[href_pos + "href=".len()..].trim_start();
            if let Some(quote) = val_part.chars().next().filter(|c| *c == '"' || *c == '\'') {
                let inner = &val_part[quote.len_utf8()..];
                if let Some(end_q) = inner.find(quote) {
                    return decode_xml_entities(&inner[..end_q]);
                }
            }
        }
        rest = &after[gt + 1..];
    }
    String::new()
}

/// Parses RSS 2.0 (`<item>`) or Atom (`<entry>`) XML feeds without external XML crate deps.
#[must_use]
pub fn parse_rss_or_atom_xml(xml: &str) -> Vec<DigestItem> {
    let mut blocks = split_tag_blocks(xml, "item");
    if blocks.is_empty() {
        blocks = split_tag_blocks(xml, "entry");
    }
    let mut out = Vec::with_capacity(blocks.len());
    for (idx, blk) in blocks.into_iter().enumerate() {
        let title = extract_tag_text(blk, "title").unwrap_or_default();
        let link = extract_link(blk);
        let id = extract_tag_text(blk, "guid")
            .or_else(|| extract_tag_text(blk, "id"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if !link.is_empty() {
                    link.clone()
                } else {
                    format!("item_{}", idx + 1)
                }
            });
        let summary = extract_tag_text(blk, "description")
            .or_else(|| extract_tag_text(blk, "summary"))
            .or_else(|| extract_tag_text(blk, "content"))
            .unwrap_or_default();
        let published = extract_tag_text(blk, "pubDate")
            .or_else(|| extract_tag_text(blk, "published"))
            .or_else(|| extract_tag_text(blk, "updated"));
        out.push(DigestItem {
            id: id.trim().to_string(),
            title: title.trim().to_string(),
            link,
            summary: summary.trim().to_string(),
            published: published.map(|s| s.trim().to_string()),
        });
    }
    out
}

/// Parses a GitHub REST Issues/PRs/Releases JSON array (or search `{items: [...]}`) response.
pub fn parse_github_items_json(json_str: &str) -> Result<Vec<DigestItem>, String> {
    let val: Value = serde_json::from_str(json_str)
        .map_err(|e| format!("invalid GitHub JSON payload: {e}"))?;
    let arr = val
        .as_array()
        .or_else(|| val.get("items").and_then(Value::as_array))
        .ok_or_else(|| "GitHub JSON payload must be an array or contain 'items'".to_string())?;
    let mut items = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let id = entry
            .get("number")
            .and_then(Value::as_u64)
            .map(|n| format!("#{n}"))
            .or_else(|| entry.get("tag_name").and_then(Value::as_str).map(str::to_string))
            .or_else(|| entry.get("id").and_then(Value::as_u64).map(|n| n.to_string()))
            .unwrap_or_else(|| format!("gh_{}", idx + 1));
        let title = entry
            .get("title")
            .or_else(|| entry.get("name"))
            .or_else(|| entry.get("tag_name"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let link = entry
            .get("html_url")
            .or_else(|| entry.get("url"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let summary = entry
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let published = entry
            .get("updated_at")
            .or_else(|| entry.get("published_at"))
            .or_else(|| entry.get("created_at"))
            .and_then(Value::as_str)
            .map(str::to_string);
        items.push(DigestItem {
            id,
            title,
            link,
            summary,
            published,
        });
    }
    Ok(items)
}
