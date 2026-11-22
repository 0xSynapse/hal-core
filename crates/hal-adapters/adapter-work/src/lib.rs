//! Transactional per-agent Copy-on-Write workspace adapter (`adapter-work`).

pub mod work;

pub use work::{WorkAdapter, WorkError};
