//! `gyges key …` (CLI_SPEC.md §2.2, API.md §7).
//!
//! Implemented: `list`, `init`, `restore`. The rest of the group is declared
//! so that `--help` matches the spec and exits 1 ("not implemented").

use std::ffi::OsString;

use clap::{Args, Subcommand};
use gyges_proto::v1::{
    GetInfoResponse, InitKeyRequest, KeySummary, ListKeysRequest, Network, RestoreKeyRequest,
    SigningMode,
};
use zeroize::Zeroizing;

use crate::client::Ctx;
use crate::exit::CliError;
use crate::output::{format_unix, to_json};

#[derive(Debug, Subcommand)]
pub enum KeyCmd {
    /// List key profiles: signing mode, lock state, birthday, scanned tip.
    List,
    /// Generate a new 24-word seed, encrypt it with a passphrase, show the words once.
    Init(InitArgs),
    /// Restore a 24-word mnemonic; --birthday avoids a full rescan.
    Restore(RestoreArgs),
    /// Register a Keystone 3 Pro profile from its UR export.
    ImportKeystone(Unimplemented),
    /// Create a watch-only profile from a UFVK.
    ImportUfvk(Unimplemented),
    /// Unlock a key for a limited time (daemon-scoped session).
    Unlock(Unimplemented),
    /// Lock a key, or every key.
    Lock(Unimplemented),
    /// Print the uview1… UFVK.
    ExportUfvk(Unimplemented),
    /// Print the 24-word mnemonic (TTY only).
    ExportSeed(Unimplemented),
    /// Archive profile.json and seed.age (and optionally the wallet).
    Backup(Unimplemented),
    /// Restore an archive written by `key backup`.
    ImportBackup(Unimplemented),
    /// Remove a profile.
    Delete(Unimplemented),
}

/// Accepts any arguments so that the command is "not implemented" (exit 1)
/// rather than a usage error (exit 2).
#[derive(Debug, Args)]
pub struct Unimplemented {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    _rest: Vec<OsString>,
}

#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    /// Key id: ^[a-z0-9][a-z0-9_-]{0,31}$.
    #[arg(long, value_name = "KEY_ID")]
    pub id: String,
    /// Make this the daemon's default key for this run (set `default_key` in config.toml to persist).
    #[arg(long)]
    pub set_default: bool,
}

#[derive(Debug, Clone, Args)]
pub struct RestoreArgs {
    /// Key id: ^[a-z0-9][a-z0-9_-]{0,31}$.
    #[arg(long, value_name = "KEY_ID")]
    pub id: String,
    /// Block height the key was created at; strongly recommended. Default: Sapling activation (full rescan).
    #[arg(long, value_name = "HEIGHT")]
    pub birthday: Option<u32>,
    /// Read the mnemonic from standard input instead of prompting.
    #[arg(long)]
    pub stdin: bool,
    /// Confirm a backfill below the node's retention window without prompting.
    #[arg(long)]
    pub yes: bool,
    /// Make this the daemon's default key for this run (set `default_key` in config.toml to persist).
    #[arg(long)]
    pub set_default: bool,
}

pub async fn run(ctx: &Ctx, cmd: KeyCmd) -> Result<(), CliError> {
    match cmd {
        KeyCmd::List => list(ctx).await,
        KeyCmd::Init(args) => init(ctx, args).await,
        KeyCmd::Restore(args) => restore(ctx, args).await,
        KeyCmd::ImportKeystone(_) => Err(CliError::NotImplemented("key import-keystone")),
        KeyCmd::ImportUfvk(_) => Err(CliError::NotImplemented("key import-ufvk")),
        KeyCmd::Unlock(_) => Err(CliError::NotImplemented("key unlock")),
        KeyCmd::Lock(_) => Err(CliError::NotImplemented("key lock")),
        KeyCmd::ExportUfvk(_) => Err(CliError::NotImplemented("key export-ufvk")),
        KeyCmd::ExportSeed(_) => Err(CliError::NotImplemented("key export-seed")),
        KeyCmd::Backup(_) => Err(CliError::NotImplemented("key backup")),
        KeyCmd::ImportBackup(_) => Err(CliError::NotImplemented("key import-backup")),
        KeyCmd::Delete(_) => Err(CliError::NotImplemented("key delete")),
    }
}

async fn list(ctx: &Ctx) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let resp = conn
        .client
        .list_keys(ListKeysRequest {})
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else {
        print!("{}", render_list(&resp.keys));
    }
    Ok(())
}

/// Human-readable `key list`.
pub fn render_list(keys: &[KeySummary]) -> String {
    use std::fmt::Write as _;
    if keys.is_empty() {
        return "no keys; create one with `gyges key init --id main`\n".to_string();
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<18} {:<12} {:<9} {:>10} {:>10}",
        "KEY", "MODE", "STATE", "BIRTHDAY", "SCANNED"
    );
    for k in keys {
        let state = if k.locked {
            "locked".to_string()
        } else if k.unlock_expires_at > 0 {
            format!("UNLOCKED until {}", format_unix(k.unlock_expires_at))
        } else {
            "UNLOCKED".to_string()
        };
        let birthday = if k.signing_mode() == SigningMode::SignerOnly {
            "-".to_string()
        } else {
            k.birthday_height.to_string()
        };
        let scanned = if k.signing_mode() == SigningMode::SignerOnly {
            "-".to_string()
        } else {
            k.scanned_tip.to_string()
        };
        let _ = writeln!(
            s,
            "{:<18} {:<12} {:<9} {:>10} {:>10}{}",
            k.key_id,
            mode_name(k.signing_mode()),
            state,
            birthday,
            scanned,
            if k.is_default { "  (default)" } else { "" }
        );
    }
    s
}

pub fn mode_name(mode: SigningMode) -> &'static str {
    match mode {
        SigningMode::Unspecified => "unknown",
        SigningMode::LocalSeed => "local-seed",
        SigningMode::KeystoneQr => "keystone-qr",
        SigningMode::WatchOnly => "watch-only",
        SigningMode::SignerOnly => "signer-only",
    }
}

/// `key init`: passphrase twice, `InitKey`, mnemonic shown once, three words
/// typed back (OVERVIEW.md Q-S4).
///
/// Scripted form: with `--json` and a passphrase source
/// (`--passphrase-fd` / `GYGES_PASSPHRASE_FILE`) no terminal is needed; the
/// mnemonic is in the JSON and nothing is typed back. Otherwise a TTY is
/// required (exit 4).
async fn init(ctx: &Ctx, args: InitArgs) -> Result<(), CliError> {
    let scripted = ctx.json && ctx.prompter.has_passphrase_source();
    if !scripted && !ctx.prompter.interactive() {
        return Err(CliError::Daemon(gyges_proto::v1::GygesError::new(
            gyges_proto::v1::ErrorReason::ConfirmationRequired,
            "key init shows the mnemonic on a terminal; run it interactively, or use --json with \
             --passphrase-fd for a scripted setup",
        )));
    }
    let mut conn = ctx.connect().await?;
    let passphrase = ctx
        .prompter
        .passphrase(&format!("Enter a passphrase for key '{}'", args.id), true)?;
    let resp = conn
        .client
        .init_key(InitKeyRequest {
            key_id: args.id.clone(),
            passphrase: passphrase.to_string(),
            set_default: args.set_default,
            word_count: 0,
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    drop(passphrase);
    let mnemonic = Zeroizing::new(resp.mnemonic.clone());

    if scripted {
        println!("{}", to_json(&resp)?);
        return Ok(());
    }

    eprintln!();
    eprintln!(
        "Write down these 24 words in order. They are the only backup of key '{}':",
        resp.key_id
    );
    eprintln!();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    for (i, chunk) in words.chunks(6).enumerate() {
        let line: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(j, w)| format!("{:>2}. {:<10}", i * 6 + j + 1, w))
            .collect();
        eprintln!("  {}", line.join(" "));
    }
    eprintln!();
    if conn.info.airgapped {
        eprintln!("Signer-only profile (air-gapped): no wallet database, no birthday.");
    } else {
        eprintln!("Birthday height: {}", resp.birthday_height);
    }
    eprintln!();
    ctx.prompter
        .line("Press Enter once you have written them down")?;
    eprint!("\x1b[2J\x1b[H");

    for idx in pick_three(words.len()) {
        let answer = ctx
            .prompter
            .line(&format!("Word #{}", idx + 1))?
            .to_lowercase();
        if answer != words[idx] {
            return Err(CliError::Other(anyhow::anyhow!(
                "word #{} did not match; the key '{}' was created, but verify your backup with \
                 `gyges key export-seed` before funding it",
                idx + 1,
                resp.key_id
            )));
        }
    }
    drop(mnemonic);
    if !ctx.quiet {
        eprintln!("key '{}' created; backup verified", resp.key_id);
        if args.set_default {
            eprintln!(
                "note: --set-default lasts until the daemon restarts; set default_key = \"{}\" in config.toml to persist it",
                resp.key_id
            );
        }
    }
    Ok(())
}

/// Three distinct word positions, ascending.
fn pick_three(n: usize) -> [usize; 3] {
    use rand::seq::SliceRandom as _;
    let mut idx: Vec<usize> = (0..n).collect();
    idx.shuffle(&mut rand::rng());
    let mut out = [idx[0], idx[1], idx[2]];
    out.sort_unstable();
    out
}

/// `key restore`: mnemonic from `--stdin` or a hidden prompt, passphrase
/// twice, backfill consent computed from `GetInfo` (API.md §4,
/// `RestoreKey.allow_backfill`).
async fn restore(ctx: &Ctx, args: RestoreArgs) -> Result<(), CliError> {
    let mut conn = ctx.connect().await?;
    let mnemonic = if args.stdin {
        ctx.prompter.read_stdin()?
    } else {
        ctx.prompter.hidden_line("Enter the 24-word mnemonic")?
    };
    let words = mnemonic.split_whitespace().count();
    if words != 24 {
        return Err(CliError::Daemon(gyges_proto::v1::GygesError::new(
            gyges_proto::v1::ErrorReason::InvalidArgument,
            format!("expected a 24-word mnemonic, got {words} words"),
        )));
    }
    let network = conn.info.network();
    let birthday = match args.birthday {
        Some(h) => h,
        None => {
            let h = sapling_activation(network);
            if !ctx.quiet {
                eprintln!(
                    "warning: no --birthday given; using the Sapling activation height ({h}), \
                     which means scanning the whole chain (and a Tor backfill below the node's \
                     retention window)"
                );
            }
            h
        }
    };
    let allow_backfill = backfill_consent(ctx, &conn.info, birthday, args.yes)?;
    let passphrase = ctx
        .prompter
        .passphrase(&format!("Enter a passphrase for key '{}'", args.id), true)?;
    let resp = conn
        .client
        .restore_key(RestoreKeyRequest {
            key_id: args.id.clone(),
            mnemonic: mnemonic.to_string(),
            passphrase: passphrase.to_string(),
            birthday_height: birthday,
            set_default: args.set_default,
            allow_backfill,
        })
        .await
        .map_err(CliError::from_status)?
        .into_inner();
    drop(passphrase);
    drop(mnemonic);
    if ctx.json {
        println!("{}", to_json(&resp)?);
    } else if !ctx.quiet {
        eprintln!(
            "key '{}' restored with birthday {}{}",
            resp.key_id,
            resp.birthday_height,
            if resp.backfill_blocks > 0 {
                format!("; {} blocks will be backfilled", resp.backfill_blocks)
            } else {
                String::new()
            }
        );
        if args.set_default {
            eprintln!(
                "note: --set-default lasts until the daemon restarts; set default_key = \"{}\" in config.toml to persist it",
                resp.key_id
            );
        }
    }
    Ok(())
}

/// Ask (or `--yes`) when the birthday is below the node's retention height
/// and a fallback endpoint exists. Without a fallback the daemon's own
/// `FALLBACK_UNAVAILABLE` says what is missing, so no question is asked.
fn backfill_consent(
    ctx: &Ctx,
    info: &GetInfoResponse,
    birthday: u32,
    yes: bool,
) -> Result<bool, CliError> {
    let node = info.node.clone().unwrap_or_default();
    let fallback = info.fallback.clone().unwrap_or_default();
    if !node.connected || birthday >= node.retained_from || !fallback.enabled {
        return Ok(yes);
    }
    let blocks = node.retained_from - birthday;
    ctx.prompter.confirm(
        &format!(
            "{blocks} blocks below the node's retention height must be fetched {} from {}; continue?",
            if fallback.use_tor {
                "over Tor"
            } else {
                "directly"
            },
            fallback.grpc_url
        ),
        yes,
        "--yes",
    )?;
    Ok(true)
}

/// Default restore birthday per network (DATA_MODEL.md §3). Duplicated
/// from `gyges-core` on purpose: the CLI does not link the wallet stack.
pub fn sapling_activation(network: Network) -> u32 {
    match network {
        Network::Mainnet | Network::Unspecified => 419_200,
        Network::Testnet => 280_000,
        Network::Regtest => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_rendering() {
        assert!(render_list(&[]).contains("no keys"));
        let keys = [
            KeySummary {
                key_id: "main".into(),
                signing_mode: SigningMode::LocalSeed as i32,
                is_default: true,
                locked: true,
                birthday_height: 2_650_000,
                scanned_tip: 2_700_000,
                ..Default::default()
            },
            KeySummary {
                key_id: "box".into(),
                signing_mode: SigningMode::SignerOnly as i32,
                locked: true,
                ..Default::default()
            },
        ];
        let s = render_list(&keys);
        assert!(s.contains("main"), "{s}");
        assert!(s.contains("local-seed"), "{s}");
        assert!(s.contains("(default)"), "{s}");
        assert!(s.contains("2650000"), "{s}");
        let box_line = s.lines().find(|l| l.starts_with("box")).unwrap();
        assert!(
            box_line.contains("signer-only") && box_line.contains('-'),
            "{box_line}"
        );
    }

    #[test]
    fn three_distinct_ascending_positions() {
        for _ in 0..50 {
            let [a, b, c] = pick_three(24);
            assert!(a < b && b < c && c < 24, "{a} {b} {c}");
        }
    }

    #[test]
    fn sapling_defaults_match_data_model() {
        assert_eq!(sapling_activation(Network::Mainnet), 419_200);
        assert_eq!(sapling_activation(Network::Regtest), 1);
    }
}
