//! `seed.age` and the mnemonic (DATA_MODEL.md §4, OVERVIEW.md Q-S5).
//!
//! What is on disk is an ordinary armored age file with a single scrypt
//! passphrase recipient, holding the 32-byte BIP 39 **entropy** of the
//! 24-word mnemonic (not the 64-byte derived seed), so that `rage -d` can
//! recover exactly the words the user wrote down. The work factor comes from
//! `vault.scrypt_work_factor` and is recorded in `profile.json` as
//! `seed_format = "age-scrypt-v1"`.
//!
//! The signing sessions, idle TTLs and unlock rate limiting that make up the
//! rest of the `VaultManager` (ARCHITECTURE.md §2.1) are the next ROADMAP.md
//! item; this module is only the file format and the key derivation that
//! `key init` / `key restore` need.

use std::io::{self, Read as _, Write as _};
use std::path::Path;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::secrecy::SecretString;
use bip0039::{English, Mnemonic};
use rand::Rng as _;
use secrecy::{ExposeSecret as _, Secret, SecretVec};
use zeroize::Zeroizing;

/// 32 bytes of BIP 39 entropy, zeroized on drop.
pub type Entropy = Secret<[u8; 32]>;

/// Why a seed file could not be produced or opened.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("seed.age is not a Gyges seed file: {0}")]
    Corrupt(String),
    #[error(
        "seed.age uses a scrypt work factor above the configured maximum ({0}); raise vault.scrypt_work_factor"
    )]
    ExcessiveWork(u8),
    #[error("cannot encrypt the seed: {0}")]
    Encrypt(String),
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },
}

/// Fresh entropy from the operating system (`getrandom`).
pub fn generate_entropy() -> Entropy {
    let mut bytes = [0u8; 32];
    rand::rand_core::UnwrapErr(rand::rngs::SysRng).fill_bytes(&mut bytes);
    Secret::new(bytes)
}

/// The 24 English words for `entropy`.
pub fn mnemonic_phrase(entropy: &Entropy) -> Zeroizing<String> {
    let mut m = Mnemonic::<English>::from_entropy(entropy.expose_secret().to_vec())
        .expect("32 bytes is a valid entropy length");
    let phrase = Zeroizing::new(m.phrase().to_string());
    zeroize::Zeroize::zeroize(&mut m);
    phrase
}

/// Parse a 24-word mnemonic back into its entropy. Whitespace is normalised;
/// anything but 24 valid words with a correct checksum is refused.
pub fn entropy_from_phrase(phrase: &str) -> Result<Entropy, VaultError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 24 {
        return Err(VaultError::Mnemonic(format!(
            "expected 24 words, got {}",
            words.len()
        )));
    }
    let normalised = Zeroizing::new(words.join(" "));
    // `bip0039::Error::UnknownWord` carries the word itself; never let a
    // piece of the mnemonic into an error message or a log line.
    let mut m = Mnemonic::<English>::from_phrase(normalised.as_str()).map_err(|e| {
        VaultError::Mnemonic(match e {
            bip0039::Error::UnknownWord(_) => "a word is not in the English word list".to_string(),
            bip0039::Error::InvalidChecksum => "checksum mismatch; check the words".to_string(),
            other => other.to_string(),
        })
    })?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(m.entropy());
    zeroize::Zeroize::zeroize(&mut m);
    Ok(Secret::new(bytes))
}

/// The 64-byte BIP 39 seed (empty BIP 39 passphrase) that ZIP 32 derives
/// from.
pub fn seed_from_entropy(entropy: &Entropy) -> SecretVec<u8> {
    let mut m = Mnemonic::<English>::from_entropy(entropy.expose_secret().to_vec())
        .expect("32 bytes is a valid entropy length");
    let mut seed = m.to_seed("");
    let out = SecretVec::new(seed.to_vec());
    zeroize::Zeroize::zeroize(&mut seed);
    zeroize::Zeroize::zeroize(&mut m);
    out
}

/// Number of words [`mnemonic_phrase`] produces.
pub const WORD_COUNT: u32 = 24;

/// Encrypt `entropy` to an armored age file with one scrypt recipient at
/// work factor `2^log_n`.
pub fn seal(entropy: &Entropy, passphrase: SecretString, log_n: u8) -> Result<Vec<u8>, VaultError> {
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(log_n);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| VaultError::Encrypt(e.to_string()))?;
    let io = |source| VaultError::Io {
        context: "encrypting seed.age",
        source,
    };
    let mut out = Vec::with_capacity(512);
    let armor = ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor).map_err(io)?;
    let mut writer = encryptor.wrap_output(armor).map_err(io)?;
    writer.write_all(entropy.expose_secret()).map_err(io)?;
    writer.finish().and_then(|a| a.finish()).map_err(io)?;
    Ok(out)
}

/// Decrypt an armored seed file. Work factors above `max_log_n` are refused
/// before any work is done (a tampered header cannot pin the CPU).
pub fn open(
    armored: &[u8],
    passphrase: SecretString,
    max_log_n: u8,
) -> Result<Entropy, VaultError> {
    let mut identity = age::scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(max_log_n);
    let decryptor = age::Decryptor::new_buffered(ArmoredReader::new(armored))
        .map_err(|e| VaultError::Corrupt(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed | age::DecryptError::NoMatchingKeys => {
                VaultError::WrongPassphrase
            }
            age::DecryptError::ExcessiveWork { .. } => VaultError::ExcessiveWork(max_log_n),
            other => VaultError::Corrupt(other.to_string()),
        })?;
    let mut bytes = Zeroizing::new([0u8; 32]);
    reader
        .read_exact(&mut bytes[..])
        .map_err(|e| VaultError::Corrupt(e.to_string()))?;
    let mut rest = [0u8; 1];
    match reader.read(&mut rest) {
        Ok(0) => {}
        Ok(_) => return Err(VaultError::Corrupt("payload longer than 32 bytes".into())),
        Err(e) => return Err(VaultError::Corrupt(e.to_string())),
    }
    Ok(Secret::new(*bytes))
}

/// Write a new seed file: `O_EXCL` and `0600` on a temporary name in the
/// same directory, `fsync`, then rename into place. Fails if `path` exists.
pub fn write_new(path: &Path, armored: &[u8]) -> Result<(), VaultError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |source| VaultError::Io {
        context: "writing seed.age",
        source,
    };
    if path.exists() {
        return Err(io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", path.display()),
        )));
    }
    let tmp = path.with_extension("age.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io)?;
    f.write_all(armored).map_err(io)?;
    f.sync_all().map_err(io)?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(io)?;
    if let Ok(dir) = std::fs::File::open(path.parent().unwrap_or(Path::new("."))) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast enough for tests; production uses `vault.scrypt_work_factor`.
    const LOG_N: u8 = 10;

    fn pass(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn mnemonic_round_trips_and_is_24_words() {
        let e = generate_entropy();
        let phrase = mnemonic_phrase(&e);
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(WORD_COUNT, 24);
        let back = entropy_from_phrase(&phrase).unwrap();
        assert_eq!(back.expose_secret(), e.expose_secret());
        // Whitespace is normalised.
        let messy = format!("  {}  ", phrase.replace(' ', "\n  "));
        assert_eq!(
            entropy_from_phrase(&messy).unwrap().expose_secret(),
            e.expose_secret()
        );
    }

    #[test]
    fn bad_mnemonics_are_refused() {
        assert!(entropy_from_phrase("abandon abandon").is_err());
        let twelve = "abandon ".repeat(11) + "about";
        assert!(entropy_from_phrase(&twelve).is_err(), "12 words");
        let bad_checksum = "abandon ".repeat(23) + "abandon";
        assert!(entropy_from_phrase(&bad_checksum).is_err());
        let unknown = "abandon ".repeat(23) + "zzzzq";
        let err = entropy_from_phrase(&unknown).unwrap_err();
        assert!(!err.to_string().contains("zzzzq"), "no word leaks: {err}");
    }

    /// The BIP 39 test vector: 23×abandon + art has all-zero entropy.
    #[test]
    fn known_vector() {
        let phrase = "abandon ".repeat(23) + "art";
        let e = entropy_from_phrase(&phrase).unwrap();
        assert_eq!(e.expose_secret(), &[0u8; 32]);
        assert_eq!(mnemonic_phrase(&e).as_str(), phrase);
        let seed = seed_from_entropy(&e);
        assert_eq!(seed.expose_secret().len(), 64);
        assert_eq!(hex::encode(&seed.expose_secret()[..8]), "408b285c12383600");
    }

    #[test]
    fn seal_and_open_is_an_armored_age_file() {
        let e = generate_entropy();
        let file = seal(&e, pass("correct horse"), LOG_N).unwrap();
        let text = std::str::from_utf8(&file).unwrap();
        assert!(
            text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
            "{text}"
        );
        assert!(
            text.trim_end()
                .ends_with("-----END AGE ENCRYPTED FILE-----")
        );
        let back = open(&file, pass("correct horse"), LOG_N + 2).unwrap();
        assert_eq!(back.expose_secret(), e.expose_secret());
        assert!(matches!(
            open(&file, pass("wrong"), LOG_N + 2),
            Err(VaultError::WrongPassphrase)
        ));
        assert!(matches!(
            open(&file, pass("correct horse"), LOG_N - 1),
            Err(VaultError::ExcessiveWork(_))
        ));
        assert!(matches!(
            open(b"not an age file", pass("x"), LOG_N),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn write_new_is_exclusive_and_private() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::profile::SEED_FILE);
        write_new(&path, b"x").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(!path.with_extension("age.tmp").exists());
        assert!(write_new(&path, b"y").is_err(), "never overwritten");
        assert_eq!(std::fs::read(&path).unwrap(), b"x");
    }
}
