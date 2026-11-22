use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Guard enforcing kernel append-only protection (`chflags sappnd` on FreeBSD) on audit logs.
pub trait AppendOnlyGuard: Send + Sync {
    fn enable_append_only(&self, path: &Path) -> io::Result<()>;
    fn is_append_only(&self, path: &Path) -> io::Result<bool>;
}

/// Native FreeBSD `chflags(SF_APPEND)` implementation (safe no-op on non-FreeBSD hosts).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsAppendOnlyGuard;

impl AppendOnlyGuard for OsAppendOnlyGuard {
    #[cfg(target_os = "freebsd")]
    fn enable_append_only(&self, path: &Path) -> io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(c_path.as_ptr(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let new_flags = st.st_flags | libc::SF_APPEND;
        if unsafe { libc::chflags(c_path.as_ptr(), new_flags) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(target_os = "freebsd"))]
    fn enable_append_only(&self, path: &Path) -> io::Result<()> {
        let _ = std::fs::metadata(path)?;
        Ok(())
    }

    #[cfg(target_os = "freebsd")]
    fn is_append_only(&self, path: &Path) -> io::Result<bool> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(c_path.as_ptr(), &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((st.st_flags & libc::SF_APPEND) != 0)
    }

    #[cfg(not(target_os = "freebsd"))]
    fn is_append_only(&self, path: &Path) -> io::Result<bool> {
        let _ = std::fs::metadata(path)?;
        Ok(false)
    }
}

/// In-memory append-only state tracker for unit tests.
#[derive(Debug, Default)]
pub struct MockAppendOnlyGuard {
    locked: Mutex<BTreeSet<PathBuf>>,
}

impl AppendOnlyGuard for MockAppendOnlyGuard {
    fn enable_append_only(&self, path: &Path) -> io::Result<()> {
        self.locked
            .lock()
            .expect("MockAppendOnlyGuard mutex poisoned")
            .insert(path.to_path_buf());
        Ok(())
    }

    fn is_append_only(&self, path: &Path) -> io::Result<bool> {
        Ok(self
            .locked
            .lock()
            .expect("MockAppendOnlyGuard mutex poisoned")
            .contains(path))
    }
}
