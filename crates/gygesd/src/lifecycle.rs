//! Single-instance enforcement through `gygesd.pid` (DATA_MODEL.md §1: "PID
//! of the running daemon, advisory-locked").

use std::fs::{self, File, TryLockError};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Holds the advisory lock on the pid file for the life of the daemon and
/// removes the file on drop.
#[derive(Debug)]
pub struct PidLock {
    file: File,
    path: PathBuf,
}

/// Why the lock could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum PidLockError {
    #[error("gygesd is already running (pid {pid}); stop it with `gyges daemon stop`")]
    AlreadyRunning { pid: String },
    #[error("cannot lock {path}: {source}", path = .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl PidLock {
    /// Take the lock, writing our pid. Fails with [`PidLockError::AlreadyRunning`]
    /// when another process holds it.
    pub fn acquire(path: &Path) -> Result<Self, PidLockError> {
        let io = |source| PidLockError::Io {
            path: path.to_path_buf(),
            source,
        };
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let mut pid = String::new();
                let _ = file.read_to_string(&mut pid);
                let pid = pid.trim().to_string();
                let pid = if pid.is_empty() {
                    "unknown".to_string()
                } else {
                    pid
                };
                return Err(PidLockError::AlreadyRunning { pid });
            }
            Err(TryLockError::Error(source)) => return Err(io(source)),
        }
        file.set_len(0).map_err(io)?;
        file.rewind().map_err(io)?;
        writeln!(file, "{}", std::process::id()).map_err(io)?;
        file.sync_all().map_err(io)?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The pid recorded in a lock file, if any; `None` when the file is absent.
    pub fn read_pid(path: &Path) -> Option<u32> {
        fs::read_to_string(path).ok()?.trim().parse().ok()
    }
}

impl Drop for PidLock {
    fn drop(&mut self) {
        // Remove before the lock is released with the file handle.
        let _ = fs::remove_file(&self.path);
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_in_process_is_refused_and_release_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gygesd.pid");
        let lock = PidLock::acquire(&path).unwrap();
        assert_eq!(PidLock::read_pid(&path), Some(std::process::id()));
        let err = PidLock::acquire(&path).unwrap_err();
        assert!(matches!(err, PidLockError::AlreadyRunning { .. }), "{err}");
        assert!(err.to_string().contains(&std::process::id().to_string()));
        drop(lock);
        assert!(!path.exists());
        assert_eq!(PidLock::read_pid(&path), None);
        let _again = PidLock::acquire(&path).unwrap();
    }
}
