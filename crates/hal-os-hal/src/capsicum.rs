use std::io;

/// Enters OS capability sandbox mode (`cap_enter(2)` on FreeBSD) after initialization.
pub trait CapsicumGuard: Send + Sync {
    /// Returns `Ok(true)` if capability mode was entered, `Ok(false)` if unsupported on host OS.
    fn enter_capability_mode(&self) -> io::Result<bool>;
}

/// Native Capsicum implementation on FreeBSD; returns `Ok(false)` on Linux dev hosts.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsCapsicumGuard;

impl CapsicumGuard for OsCapsicumGuard {
    #[cfg(target_os = "freebsd")]
    fn enter_capability_mode(&self) -> io::Result<bool> {
        let rc = unsafe { libc::cap_enter() };
        if rc == 0 {
            Ok(true)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(target_os = "freebsd"))]
    fn enter_capability_mode(&self) -> io::Result<bool> {
        Ok(false)
    }
}
