//! `Debug` for the messages that carry a secret.
//!
//! `proto/gyges.proto` marks passphrases, mnemonics and session tokens
//! `[debug_redact = true]`, but prost 0.14 does not act on that option: the
//! `Debug` it derives prints every field. So `build.rs` skips the derived
//! `Debug` of each message with such a field, and this module writes it by
//! hand with the secret left out. Three lists have to agree, and each
//! disagreement is caught:
//!
//! * a message listed here but not in `build.rs` has two `Debug`
//!   implementations and does not compile;
//! * a field added to a listed message does not compile until it is named
//!   here (the implementation destructures the message exhaustively);
//! * a field marked in the `.proto` but not listed here fails
//!   `tests::every_marked_field_is_redacted`.

use std::fmt;

use crate::v1;

/// What `Debug` prints in place of a secret, set or not.
const REDACTED: fmt::Arguments<'static> = format_args!("[REDACTED]");

macro_rules! redacted_debug {
    ($( $message:ident { $($field:ident),* $(,)? ; redacted: $($secret:ident),+ $(,)? } )*) => {
        $(
            impl fmt::Debug for v1::$message {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    let Self { $($field,)* $($secret: _,)+ } = self;
                    f.debug_struct(stringify!($message))
                        $(.field(stringify!($field), $field))*
                        $(.field(stringify!($secret), &REDACTED))+
                        .finish()
                }
            }
        )*

        /// `(message, field)` of every redacted field.
        #[cfg(test)]
        const REDACTED_FIELDS: &[(&str, &str)] = &[
            $($((stringify!($message), stringify!($secret)),)+)*
        ];

        /// The `Debug` text of every message above with `secret` in each of
        /// its redacted fields.
        #[cfg(test)]
        fn debug_with_secrets(secret: &str) -> Vec<String> {
            vec![$({
                let mut message = v1::$message::default();
                $(message.$secret = secret.into();)+
                format!("{message:?}")
            },)*]
        }
    };
}

redacted_debug! {
    InitKeyRequest { key_id, set_default, word_count; redacted: passphrase }
    InitKeyResponse { key_id, birthday_height, ufvk; redacted: mnemonic }
    RestoreKeyRequest {
        key_id, birthday_height, set_default, allow_backfill;
        redacted: mnemonic, passphrase
    }
    UnlockKeyRequest { key_id, ttl_secs, session_id, scope; redacted: passphrase }
    UnlockKeyResponse { expires_at, scope; redacted: session_token }
    ExportSeedRequest { key_id, confirmation; redacted: passphrase }
    ExportSeedResponse { birthday_height; redacted: mnemonic }
    SendTransactionRequest {
        key_id, to, amount, memo, via_tor, dry_run, min_confirmations, wait_for_mined, options;
        redacted: session_token
    }
    ShieldFundsRequest { key_id, threshold, dry_run, wait_for_mined; redacted: session_token }
    ResumeTexTransferRequest { key_id, step1_txid; redacted: session_token }
    ProvePcztRequest { pczt, key_id; redacted: session_token }
    SignPcztRequest { pczt, key_id; redacted: session_token }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// `(message, field)` of every `[debug_redact = true]` field in the
    /// `.proto`, read from its text: the option does not survive into
    /// anything prost generates.
    fn marked_in_proto() -> BTreeSet<(String, String)> {
        let proto = include_str!("../../../proto/gyges.proto");
        let mut message = None;
        let mut marked = BTreeSet::new();
        for line in proto.lines() {
            if let Some(rest) = line.strip_prefix("message ") {
                message = rest.split_whitespace().next();
            }
            if line.contains("debug_redact = true") {
                assert!(
                    line.starts_with("  ") && !line.starts_with("   "),
                    "a redacted field outside a top-level message needs its own Debug: {line}"
                );
                let field = line
                    .split('=')
                    .next()
                    .and_then(|declaration| declaration.split_whitespace().last())
                    .expect("a field name before `=`");
                let message = message.expect("a field inside a message");
                marked.insert((message.to_string(), field.to_string()));
            }
        }
        marked
    }

    #[test]
    fn every_marked_field_is_redacted() {
        let redacted: BTreeSet<(String, String)> = REDACTED_FIELDS
            .iter()
            .map(|(m, f)| (m.to_string(), f.to_string()))
            .collect();
        assert_eq!(redacted, marked_in_proto());
        assert!(!redacted.is_empty());
    }

    #[test]
    fn debug_leaves_the_secrets_out() {
        let shown = debug_with_secrets("correct horse battery staple");
        assert_eq!(shown.len(), 12);
        for text in shown {
            assert!(text.contains("[REDACTED]"), "{text}");
            // Neither as text nor as the bytes of a token.
            assert!(!text.contains("correct horse"), "{text}");
            assert!(!text.contains("99, 111, 114, 114"), "{text}");
        }
        // The other fields still print.
        let request = v1::UnlockKeyRequest {
            key_id: "main".into(),
            passphrase: "hunter2".into(),
            ..Default::default()
        };
        let text = format!("{request:?}");
        assert!(text.contains(r#"key_id: "main""#), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }
}
