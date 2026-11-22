//! Brokered digital intelligence adapter (`RSS/Atom` & `GitHub` read-only feeds) that
//! stamps all ingested external payloads with `UntrustedWeb` taint before cognition sees them.

pub mod adapter;
pub mod feed;

pub use adapter::{DigestAdapter, DigestError, FeedRequest};
pub use feed::{
    parse_github_items_json, parse_rss_or_atom_xml, sanitize_declassified_field, DigestItem,
};
