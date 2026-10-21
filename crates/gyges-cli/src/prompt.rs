//! Terminal input: passphrases, confirmations and the non-interactive rules
//! of CLI_SPEC.md §1.2.
//!
//! Nothing here blocks when stdin is not a TTY or `--non-interactive` is
//! set; the caller gets `CliError::Daemon(CONFIRMATION_REQUIRED)` /
//! `VAULT_LOCKED` (exit 4) instead, with a message naming the flag that
//! would have avoided the prompt.

use std::fs::File;
use std::io::{self, BufRead as _, BufReader, IsTerminal as _, Read as _, Write as _};

use gyges_proto::v1::{ErrorReason, GygesError};
use zeroize::Zeroizing;

use crate::exit::CliError;

/// Path to a file holding the passphrase (`--passphrase-fd` for scripts
/// that cannot pass a descriptor).
pub const PASSPHRASE_FILE_ENV: &str = "GYGES_PASSPHRASE_FILE";

/// How the CLI may talk to the user, resolved once from the global flags.
#[derive(Clone, Debug)]
pub struct Prompter {
    pub non_interactive: bool,
    pub passphrase_fd: Option<u32>,
}

impl Prompter {
    /// Whether a prompt may be shown at all.
    pub fn interactive(&self) -> bool {
        !self.non_interactive && io::stdin().is_terminal() && io::stderr().is_terminal()
    }

    /// Where a non-prompted passphrase would come from, if anywhere.
    fn passphrase_source(&self) -> Option<PassphraseSource> {
        if let Some(fd) = self.passphrase_fd {
            return Some(PassphraseSource::Fd(fd));
        }
        std::env::var_os(PASSPHRASE_FILE_ENV)
            .filter(|p| !p.is_empty())
            .map(PassphraseSource::File)
    }

    /// Whether a passphrase can be obtained without a prompt.
    pub fn has_passphrase_source(&self) -> bool {
        self.passphrase_source().is_some()
    }

    /// A passphrase from `--passphrase-fd` / `GYGES_PASSPHRASE_FILE`, else a
    /// hidden prompt on the terminal. `confirm` asks for it twice (new
    /// passphrases) and fails on a mismatch.
    pub fn passphrase(&self, prompt: &str, confirm: bool) -> Result<Zeroizing<String>, CliError> {
        if let Some(src) = self.passphrase_source() {
            let p = src.read()?;
            if p.is_empty() {
                return Err(CliError::Other(anyhow::anyhow!(
                    "the passphrase source is empty"
                )));
            }
            return Ok(p);
        }
        if !self.interactive() {
            return Err(CliError::Daemon(GygesError::new(
                ErrorReason::VaultLocked,
                format!(
                    "a passphrase is needed and no terminal is available; pass --passphrase-fd N \
                     or set {PASSPHRASE_FILE_ENV}"
                ),
            )));
        }
        let first = Zeroizing::new(rpassword::prompt_password(format!("{prompt}: "))?);
        if first.is_empty() {
            return Err(CliError::Other(anyhow::anyhow!(
                "the passphrase must not be empty"
            )));
        }
        if confirm {
            let again = Zeroizing::new(rpassword::prompt_password(format!("{prompt} (again): "))?);
            if *first != *again {
                return Err(CliError::Other(anyhow::anyhow!(
                    "the passphrases do not match"
                )));
            }
        }
        Ok(first)
    }

    /// A hidden single-line input (mnemonics), or an error when there is no
    /// terminal.
    pub fn hidden_line(&self, prompt: &str) -> Result<Zeroizing<String>, CliError> {
        if !self.interactive() {
            return Err(CliError::Daemon(GygesError::new(
                ErrorReason::ConfirmationRequired,
                format!("{prompt} needs a terminal; pass --stdin to read it from standard input"),
            )));
        }
        Ok(Zeroizing::new(rpassword::prompt_password(format!(
            "{prompt}: "
        ))?))
    }

    /// A visible single-line input.
    pub fn line(&self, prompt: &str) -> Result<String, CliError> {
        if !self.interactive() {
            return Err(CliError::Daemon(GygesError::new(
                ErrorReason::ConfirmationRequired,
                format!("{prompt} needs a terminal"),
            )));
        }
        let mut err = io::stderr();
        write!(err, "{prompt}: ")?;
        err.flush()?;
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(CliError::Cancelled);
        }
        Ok(line.trim().to_string())
    }

    /// `question [y/N]`. `assume_yes` (a `--yes` flag) skips the prompt; a
    /// missing terminal yields `CONFIRMATION_REQUIRED` naming the flag.
    pub fn confirm(&self, question: &str, assume_yes: bool, flag: &str) -> Result<(), CliError> {
        if assume_yes {
            return Ok(());
        }
        if !self.interactive() {
            return Err(CliError::Daemon(GygesError::new(
                ErrorReason::ConfirmationRequired,
                format!("{question} (pass {flag} to confirm non-interactively)"),
            )));
        }
        let answer = self.line(&format!("{question} [y/N]"))?;
        if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
            Ok(())
        } else {
            Err(CliError::Cancelled)
        }
    }

    /// All of standard input, for `--stdin` mnemonics.
    pub fn read_stdin(&self) -> Result<Zeroizing<String>, CliError> {
        let mut s = Zeroizing::new(String::new());
        io::stdin().lock().read_to_string(&mut s)?;
        Ok(s)
    }
}

enum PassphraseSource {
    Fd(u32),
    File(std::ffi::OsString),
}

impl PassphraseSource {
    /// The first line, without its terminator.
    fn read(self) -> Result<Zeroizing<String>, CliError> {
        let reader: Box<dyn io::Read> = match self {
            PassphraseSource::Fd(fd) => {
                let fd = i32::try_from(fd).map_err(|_| {
                    CliError::Other(anyhow::anyhow!("--passphrase-fd {fd} is out of range"))
                })?;
                // `File::from_raw_fd` is unsafe (and the crate forbids
                // unsafe); /dev/fd opens the descriptor like any path on
                // both macOS and Linux.
                Box::new(File::open(format!("/dev/fd/{fd}")).map_err(|e| {
                    CliError::Other(anyhow::anyhow!("cannot read --passphrase-fd {fd}: {e}"))
                })?)
            }
            PassphraseSource::File(path) => Box::new(File::open(&path).map_err(|e| {
                CliError::Other(anyhow::anyhow!(
                    "cannot read {PASSPHRASE_FILE_ENV}={}: {e}",
                    path.to_string_lossy()
                ))
            })?),
        };
        let mut line = Zeroizing::new(String::new());
        BufReader::new(reader).read_line(&mut line)?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_file_source_reads_the_first_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, "hunter2\r\nsecond line\n").unwrap();
        let p = PassphraseSource::File(path.into()).read().unwrap();
        assert_eq!(p.as_str(), "hunter2");
    }

    #[test]
    fn non_interactive_passphrase_is_exit_4_with_the_fix() {
        let pr = Prompter {
            non_interactive: true,
            passphrase_fd: None,
        };
        // Only when no file source is configured in the environment.
        if std::env::var_os(PASSPHRASE_FILE_ENV).is_some() {
            return;
        }
        let err = pr.passphrase("Enter passphrase", true).unwrap_err();
        assert_eq!(err.exit(), crate::exit::Exit::AuthorizationRequired);
        assert!(
            err.message().contains("--passphrase-fd"),
            "{}",
            err.message()
        );
        let err = pr.confirm("Continue?", false, "--yes").unwrap_err();
        assert_eq!(err.exit(), crate::exit::Exit::AuthorizationRequired);
        assert!(err.message().contains("--yes"));
        pr.confirm("Continue?", true, "--yes").unwrap();
    }
}
