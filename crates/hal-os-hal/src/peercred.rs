use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Kernel-verified Unix domain socket peer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    pub groups: Vec<u32>,
}

impl PeerCred {
    /// Deterministic identity fingerprint stored in `AgentPrincipal.peer_cred_or_cert_fp`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        match self.pid {
            Some(pid) => format!("uid:{}:gid:{}:pid:{}", self.uid, self.gid, pid),
            None => format!("uid:{}:gid:{}", self.uid, self.gid),
        }
    }
}

/// Strategy trait for extracting authenticated socket peer credentials.
pub trait PeerCredProvider: Send + Sync {
    fn peer_cred(&self, stream: &UnixStream) -> io::Result<PeerCred>;
}

/// Native kernel `LOCAL_PEERCRED` (FreeBSD) / `SO_PEERCRED` (Linux) provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsPeerCredProvider;

impl PeerCredProvider for OsPeerCredProvider {
    #[cfg(target_os = "freebsd")]
    fn peer_cred(&self, stream: &UnixStream) -> io::Result<PeerCred> {
        let mut cred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                (&mut cred as *mut libc::xucred).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if cred.cr_version != libc::XUCRED_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected xucred version {}", cred.cr_version),
            ));
        }
        let ngroups = (cred.cr_ngroups.max(0) as usize).min(cred.cr_groups.len());
        let groups: Vec<u32> = cred.cr_groups[..ngroups]
            .iter()
            .map(|&g| g as u32)
            .collect();
        let gid = groups.first().copied().unwrap_or(0);
        Ok(PeerCred {
            uid: cred.cr_uid as u32,
            gid,
            pid: None,
            groups,
        })
    }

    #[cfg(target_os = "linux")]
    fn peer_cred(&self, stream: &UnixStream) -> io::Result<PeerCred> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let uid = cred.uid as u32;
        let gid = cred.gid as u32;
        Ok(PeerCred {
            uid,
            gid,
            pid: Some(cred.pid as i32),
            groups: vec![gid],
        })
    }

    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    fn peer_cred(&self, _stream: &UnixStream) -> io::Result<PeerCred> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OsPeerCredProvider is only implemented for FreeBSD and Linux",
        ))
    }
}

/// Deterministic mock provider for unit tests needing distinct synthetic UIDs.
#[derive(Debug, Clone)]
pub struct MockPeerCredProvider {
    pub fixed: PeerCred,
}

impl PeerCredProvider for MockPeerCredProvider {
    fn peer_cred(&self, _stream: &UnixStream) -> io::Result<PeerCred> {
        Ok(self.fixed.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_peercred_returns_real_euid_on_unix_socket_pair() {
        let (a, _b) = UnixStream::pair().unwrap();
        let cred = OsPeerCredProvider.peer_cred(&a).unwrap();
        let expected_uid = unsafe { libc::geteuid() } as u32;
        let expected_gid = unsafe { libc::getegid() } as u32;
        assert_eq!(cred.uid, expected_uid);
        assert_eq!(cred.gid, expected_gid);
        assert!(cred.fingerprint().starts_with(&format!("uid:{expected_uid}:")));
    }
}
