//! Startup permission enforcement (DATA_MODEL.md §1, THREAT_MODEL.md Q-S7).
//!
//! Every directory under `GYGES_HOME` must be `0700` and every file `0600`
//! (more precisely: no group or other bits). The daemon refuses to start on
//! anything wider and names the one-line `chmod` that fixes it.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// A path whose permissions are wider than the design allows.
#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    #[error("{path} is mode {mode:04o}, which lets other users read it; fix: chmod {want:o} {path}", path = .path.display())]
    TooWide {
        path: PathBuf,
        /// The permission bits found.
        mode: u32,
        /// `0o700` for directories, `0o600` for files.
        want: u32,
    },
    #[error("cannot inspect {path}: {source}", path = .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Bits that must be clear on everything under `GYGES_HOME`.
const GROUP_OTHER: u32 = 0o077;

/// `TooWide` when `mode` has group or other bits.
fn private(path: &Path, mode: u32, want: u32) -> Result<(), PermissionError> {
    if mode & GROUP_OTHER != 0 {
        return Err(PermissionError::TooWide {
            path: path.to_path_buf(),
            mode,
            want,
        });
    }
    Ok(())
}

/// Walk `root` (itself included) and fail on the first directory or regular
/// file readable by group or other. Symlinks are inspected, not followed;
/// sockets are skipped because `gygesd.sock` has its own rule (0660 with
/// `daemon.socket_group`).
pub fn check_tree(root: &Path) -> Result<(), PermissionError> {
    let io_err = |source| PermissionError::Io {
        path: root.to_path_buf(),
        source,
    };
    let meta = fs::symlink_metadata(root).map_err(io_err)?;
    let ft = meta.file_type();
    let mode = meta.mode() & 0o7777;
    if ft.is_dir() {
        private(root, mode, 0o700)?;
        for entry in fs::read_dir(root).map_err(io_err)? {
            check_tree(&entry.map_err(io_err)?.path())?;
        }
        Ok(())
    } else if ft.is_socket() || ft.is_fifo() {
        Ok(())
    } else {
        private(root, mode, 0o600)
    }
}

/// Create `dir` (and its parents) with mode `0700`, or verify an existing
/// one is no wider.
pub fn ensure_private_dir(dir: &Path) -> Result<(), PermissionError> {
    let io_err = |source| PermissionError::Io {
        path: dir.to_path_buf(),
        source,
    };
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(io_err)?;
    }
    let meta = fs::symlink_metadata(dir).map_err(io_err)?;
    if !meta.is_dir() {
        return Err(io_err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "not a directory",
        )));
    }
    private(dir, meta.mode() & 0o7777, 0o700)
}

/// Open (create or truncate) a file with mode `0600`.
pub fn create_private_file(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

/// Set a path to exactly `mode`.
pub fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        set_mode(dir.path(), 0o700).unwrap();
        dir
    }

    #[test]
    fn clean_tree_passes() {
        let dir = tmp();
        ensure_private_dir(&dir.path().join("keys/main")).unwrap();
        let f = dir.path().join("keys/main/seed.age");
        create_private_file(&f).unwrap();
        check_tree(dir.path()).unwrap();
    }

    #[test]
    fn wide_file_is_named_with_its_fix() {
        let dir = tmp();
        ensure_private_dir(&dir.path().join("keys/main")).unwrap();
        let f = dir.path().join("keys/main/seed.age");
        create_private_file(&f).unwrap();
        set_mode(&f, 0o644).unwrap();
        let err = check_tree(dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("0644"), "{msg}");
        assert!(msg.contains(&format!("chmod 600 {}", f.display())), "{msg}");
    }

    #[test]
    fn wide_directory_is_refused() {
        let dir = tmp();
        let d = dir.path().join("logs");
        ensure_private_dir(&d).unwrap();
        set_mode(&d, 0o750).unwrap();
        let err = check_tree(dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("chmod 700 {}", d.display()))
        );
        // ensure_private_dir on the existing wide dir also refuses.
        assert!(ensure_private_dir(&d).is_err());
    }

    #[test]
    fn read_only_owner_modes_are_fine() {
        let dir = tmp();
        let f = dir.path().join("profile.json");
        create_private_file(&f).unwrap();
        set_mode(&f, 0o400).unwrap();
        check_tree(dir.path()).unwrap();
    }
}
