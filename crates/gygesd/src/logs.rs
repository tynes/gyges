//! Logging: the layer stack behind `logs/gygesd.<date>.log` and
//! `logs/audit.log`, and the in-process hub behind `StreamLogs`
//! (API.md §4.5, DATA_MODEL.md §1, OVERVIEW.md Q-O1).
//!
//! Three layers see every event:
//!
//! * the **main file** layer writes the human-readable line to the daily
//!   rotated `gygesd.<date>.log` (seven files kept), filtered by
//!   `daemon.log_level` (or `RUST_LOG`);
//! * the **audit** layer writes events whose target is
//!   [`AUDIT_TARGET`] to `audit.log` as one JSON object per line, *regardless*
//!   of the configured level, so a `log_level = "warn"` daemon still audits;
//!   the file is never rotated (it must survive a database wipe and a
//!   migration, DATA_MODEL.md §7) and carries only what the events do: a
//!   timestamp, the level, the event name, the key id and, where applicable,
//!   the unlock scope or the signing path;
//! * the **capture** layer keeps the last [`RING_CAPACITY`] entries of each
//!   log in memory and fans new ones out to `StreamLogs` followers, so the
//!   CLI never tails a file.
//!
//! Redaction happens upstream of all three: values are wrapped in
//! [`gyges_core::Sensitive`] at the call site, so every writer below sees
//! `[redacted]`. Tests install the same stack over in-memory writers
//! ([`layers`]) and assert the rendered lines.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use gyges_core::perms;
use gyges_proto::v1::{LogEntry, LogLevel, StreamLogsRequest};
use tokio::sync::broadcast;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::BroadcastStream;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, FilterExt as _, FilterFn, LevelFilter};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::keys::AUDIT_TARGET;

/// How many entries of each log `StreamLogs` can replay.
pub const RING_CAPACITY: usize = 1000;
/// How far a slow follower may fall behind before it skips entries.
const FOLLOW_CAPACITY: usize = 256;
/// The file beside the rotated main log (DATA_MODEL.md §1).
pub const AUDIT_FILE: &str = "audit.log";

/// What the generated service returns for `StreamLogs`.
pub type LogStream = tonic::codegen::BoxStream<LogEntry>;

/// One captured entry with its position in its ring, so that a follower
/// started during a replay delivers each entry exactly once.
#[derive(Clone, Debug)]
struct Numbered {
    seq: u64,
    entry: LogEntry,
}

struct Ring {
    state: Mutex<RingState>,
    live: broadcast::Sender<Numbered>,
}

struct RingState {
    entries: VecDeque<Numbered>,
    next_seq: u64,
}

impl Default for Ring {
    fn default() -> Self {
        Self {
            state: Mutex::new(RingState {
                entries: VecDeque::with_capacity(RING_CAPACITY),
                next_seq: 0,
            }),
            live: broadcast::channel(FOLLOW_CAPACITY).0,
        }
    }
}

impl fmt::Debug for Ring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.state.lock().map(|s| s.entries.len()).unwrap_or(0);
        f.debug_struct("Ring").field("entries", &len).finish()
    }
}

impl Ring {
    fn push(&self, entry: LogEntry) {
        let numbered = {
            let mut s = crate::lock(&self.state);
            let numbered = Numbered {
                seq: s.next_seq,
                entry,
            };
            s.next_seq += 1;
            if s.entries.len() == RING_CAPACITY {
                s.entries.pop_front();
            }
            s.entries.push_back(numbered.clone());
            numbered
        };
        // No follower is not an error.
        let _ = self.live.send(numbered);
    }

    /// The last `lines` entries and the sequence number the next entry gets.
    fn snapshot(&self, lines: usize) -> (Vec<Numbered>, u64) {
        let s = crate::lock(&self.state);
        let skip = s.entries.len().saturating_sub(lines);
        (s.entries.iter().skip(skip).cloned().collect(), s.next_seq)
    }
}

/// The in-memory tail of both logs, shared by the capture layer and the
/// `StreamLogs` handler.
#[derive(Debug, Default)]
pub struct LogHub {
    main: Ring,
    audit: Ring,
}

impl LogHub {
    /// Store one entry, routed by target.
    pub fn record(&self, entry: LogEntry) {
        if entry.target == AUDIT_TARGET {
            self.audit.push(entry);
        } else {
            self.main.push(entry);
        }
    }

    /// The `tracing` layer that feeds this hub.
    pub fn layer(self: &Arc<Self>) -> CaptureLayer {
        CaptureLayer { hub: self.clone() }
    }

    /// The last `lines` entries of one log, oldest first.
    pub fn recent(&self, audit: bool, lines: usize) -> Vec<LogEntry> {
        let ring = if audit { &self.audit } else { &self.main };
        ring.snapshot(lines)
            .0
            .into_iter()
            .map(|n| n.entry)
            .collect()
    }

    /// `StreamLogs`: replay the last `lines` entries, then (with `follow`)
    /// every new one until the client goes away. A follower subscribes
    /// before the snapshot is taken and skips what the snapshot covered, so
    /// nothing is lost or repeated at the seam.
    pub fn stream(&self, req: &StreamLogsRequest) -> LogStream {
        let ring = if req.audit { &self.audit } else { &self.main };
        let min_level = req.min_level();
        let passes = move |e: &LogEntry| level_passes(e.level(), min_level);
        let live = req.follow.then(|| ring.live.subscribe());
        let (replay, next_seq) = ring.snapshot(req.lines as usize);
        let replay = tokio_stream::iter(
            replay
                .into_iter()
                .map(|n| n.entry)
                .filter(move |e| passes(e))
                .map(Ok),
        );
        match live {
            None => Box::pin(replay),
            Some(rx) => {
                let live = BroadcastStream::new(rx).filter_map(move |item| match item {
                    Ok(n) if n.seq >= next_seq && passes(&n.entry) => Some(Ok(n.entry)),
                    // Replayed already, filtered out, or `Lagged`: the ring
                    // still has what a lagging follower missed.
                    _ => None,
                });
                Box::pin(replay.chain(live))
            }
        }
    }
}

/// `min_level` is the least severe level to deliver; `UNSPECIFIED` delivers
/// everything the daemon's filter let through.
fn level_passes(level: LogLevel, min_level: LogLevel) -> bool {
    match min_level {
        LogLevel::Unspecified => true,
        min => (level as i32) <= (min as i32) && level != LogLevel::Unspecified,
    }
}

fn proto_level(level: &tracing::Level) -> LogLevel {
    match *level {
        tracing::Level::ERROR => LogLevel::Error,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::TRACE => LogLevel::Trace,
    }
}

pub(crate) fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A `tracing` layer that turns every event into a [`LogEntry`] in the hub.
#[derive(Clone, Debug)]
pub struct CaptureLayer {
    hub: Arc<LogHub>,
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let meta = event.metadata();
        self.hub.record(LogEntry {
            timestamp_unix_ms: unix_now_ms(),
            level: proto_level(meta.level()) as i32,
            target: meta.target().to_string(),
            message: fields.message,
            fields: fields.fields,
        });
    }
}

/// Collects an event's fields as strings. `%value` and `?value` arrive
/// through `record_debug`, which is where a [`gyges_core::Sensitive`] prints
/// its placeholder.
#[derive(Default)]
struct Fields {
    message: String,
    fields: HashMap<String, String>,
}

impl Fields {
    fn set(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.set(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.set(field, value.to_string());
    }

    // Integers, bools and errors use the defaults: their `Debug` is their
    // `Display`. A float's is not (`1.0`, not `1`), nor a string's (quoted).
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.set(field, value.to_string());
    }
}

/// Upstream targets that put txids or addresses in their messages, capped
/// under `daemon.log_level` so the main log keeps none (THREAT_MODEL.md log
/// redaction, TESTING.md §5).
/// - `ll::wallet`: `store_decrypted_tx` logs every txid it stores at `info`
///   (the mempool loop stores each transaction of ours), and its `warn`s
///   about unsupported scripts and unknown recipients name the txid too.
/// - `zcash_client_sqlite`: `put_received_transparent_utxo` logs the txid of
///   a spender it attributes at `info`.
const QUIET_UPSTREAM: &[&str] = &[
    "zcash_client_backend::data_api::ll::wallet=error",
    "zcash_client_sqlite=warn",
];

/// The effective filter: `RUST_LOG` when set and non-empty (the operator's
/// own choice, taken as given), else `daemon.log_level` with
/// [`QUIET_UPSTREAM`] appended.
pub fn filter_spec(configured: &str) -> String {
    std::env::var("RUST_LOG")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            std::iter::once(configured)
                .chain(QUIET_UPSTREAM.iter().copied())
                .collect::<Vec<_>>()
                .join(",")
        })
}

fn audit_only() -> FilterFn {
    FilterFn::new(|meta: &tracing::Metadata<'_>| meta.target() == AUDIT_TARGET)
}

/// The production layer stack over arbitrary writers: the main log through
/// `main_writer`, `audit.log` through `audit_writer`, and the capture layer
/// into `hub`. `filter` is a `tracing` directive string such as `info` or
/// `gygesd=debug,info`; it governs the main log and the main ring, never the
/// audit log.
pub fn layers<S, M, A>(
    hub: &Arc<LogHub>,
    filter: &str,
    main_writer: M,
    audit_writer: A,
) -> anyhow::Result<impl Layer<S> + use<S, M, A>>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    M: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    A: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let env = || {
        EnvFilter::try_new(filter)
            .with_context(|| format!("{filter:?} is not a valid tracing filter"))
    };
    let main_file = tracing_subscriber::fmt::layer::<S>()
        .with_ansi(false)
        .with_writer(main_writer)
        .with_filter(env()?);
    let audit_file = tracing_subscriber::fmt::layer::<S>()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_ansi(false)
        .with_writer(audit_writer)
        .with_filter(audit_only().with_max_level_hint(LevelFilter::INFO));
    let capture = hub.layer().with_filter(audit_only().or(env()?));
    Ok(main_file.and_then(audit_file).and_then(capture))
}

/// Keeps the non-blocking appenders flushing; drop it last.
pub struct Guards {
    _main: tracing_appender::non_blocking::WorkerGuard,
    _audit: tracing_appender::non_blocking::WorkerGuard,
}

impl fmt::Debug for Guards {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Guards")
    }
}

/// Install the global subscriber for a daemon: the stack from [`layers`]
/// over `logs_dir/gygesd.<date>.log` (daily, seven kept) and
/// `logs_dir/audit.log` (never rotated), plus stderr when `to_stderr`.
/// Files are created 0600 under the daemon's umask.
pub fn init(
    hub: &Arc<LogHub>,
    logs_dir: &Path,
    filter: &str,
    to_stderr: bool,
) -> anyhow::Result<Guards> {
    perms::ensure_private_dir(logs_dir)?;
    let main = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("gygesd")
        .filename_suffix("log")
        .max_log_files(7)
        .build(logs_dir)
        .with_context(|| format!("cannot open log directory {}", logs_dir.display()))?;
    let audit = tracing_appender::rolling::never(logs_dir, AUDIT_FILE);
    let (main_writer, main_guard) = tracing_appender::non_blocking(main);
    let (audit_writer, audit_guard) = tracing_appender::non_blocking(audit);

    let stderr = if to_stderr {
        Some(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(EnvFilter::try_new(filter)?),
        )
    } else {
        None
    };
    tracing_subscriber::registry()
        .with(layers(hub, filter, main_writer, audit_writer)?)
        .with(stderr)
        .try_init()
        .context("a global tracing subscriber is already installed")?;
    Ok(Guards {
        _main: main_guard,
        _audit: audit_guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gyges_core::Sensitive;
    use std::io::Write;

    /// A `MakeWriter` over a shared buffer.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            BufWriter(self.0.clone())
        }
    }

    fn stack(filter: &str) -> (Arc<LogHub>, Buf, Buf, impl Subscriber) {
        let hub = Arc::new(LogHub::default());
        let main = Buf::default();
        let audit = Buf::default();
        let subscriber = tracing_subscriber::registry()
            .with(layers(&hub, filter, main.clone(), audit.clone()).expect("valid filter"));
        (hub, main, audit, subscriber)
    }

    const ADDRESS: &str = "t1SecretRecipientAddressXYZ";
    const TXID: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    /// Everything the daemon logs about a send, through the production
    /// layers: the sensitive values print as `[redacted]` in the file, on
    /// stderr-style output and in the `StreamLogs` fields.
    #[test]
    fn sensitive_fields_render_redacted_everywhere() {
        let (hub, main, audit, subscriber) = stack("info");
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                key_id = "main",
                to = %Sensitive::new(ADDRESS),
                txid = ?Sensitive::new(TXID),
                zatoshis = %Sensitive::new(123_456_789u64),
                height = 42,
                "transaction broadcast"
            );
            tracing::debug!(dropped = %Sensitive::new(ADDRESS), "below the filter");
            tracing::info!(target: AUDIT_TARGET, key_id = "main", event = "broadcast");
        });

        let text = main.text();
        assert!(text.contains("transaction broadcast"), "{text}");
        assert!(text.contains("to=[redacted]"), "{text}");
        assert!(text.contains("txid=[redacted]"), "{text}");
        assert!(text.contains("zatoshis=[redacted]"), "{text}");
        assert!(text.contains("height=42"), "{text}");
        assert!(!text.contains(ADDRESS), "{text}");
        assert!(!text.contains(TXID), "{text}");
        assert!(!text.contains("123456789"), "{text}");
        assert!(!text.contains("below the filter"), "{text}");
        // The audit event also appears in the main log, as an ordinary line.
        assert!(text.contains("gyges::audit"), "{text}");

        let entries = hub.recent(false, 10);
        assert_eq!(entries.len(), 1, "{entries:?}");
        let e = &entries[0];
        assert_eq!(e.message, "transaction broadcast");
        assert_eq!(e.level(), LogLevel::Info);
        assert_eq!(e.fields["to"], "[redacted]");
        assert_eq!(e.fields["txid"], "[redacted]");
        assert_eq!(e.fields["height"], "42");
        assert_eq!(e.fields["key_id"], "main");
        assert!(e.timestamp_unix_ms > 1_700_000_000_000);

        let audit_text = audit.text();
        assert_eq!(audit_text.lines().count(), 1, "{audit_text}");
        assert!(!audit_text.contains(ADDRESS), "{audit_text}");
    }

    /// `audit.log` is JSON lines carrying only timestamp, level, event, key
    /// id and the event's own small fields; it ignores the configured level.
    #[test]
    fn audit_log_is_json_lines_independent_of_the_level() {
        let (hub, main, audit, subscriber) = stack("warn");
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(key_id = "main", "key unlocked");
            tracing::info!(target: AUDIT_TARGET, key_id = "main", event = "unlock", scope = ?"Daemon");
            tracing::info!(target: AUDIT_TARGET, key_id = "main", event = "sign", via = "session");
            tracing::warn!("a warning");
        });

        // `warn` keeps the info lines out of the main log and the main ring.
        let text = main.text();
        assert!(!text.contains("key unlocked"), "{text}");
        assert!(text.contains("a warning"), "{text}");
        let main_entries = hub.recent(false, 10);
        assert_eq!(main_entries.len(), 1, "{main_entries:?}");
        assert_eq!(main_entries[0].message, "a warning");

        // ... but never the audit events.
        let lines: Vec<serde_json::Value> = audit
            .text()
            .lines()
            .map(|l| serde_json::from_str(l).expect("JSON line"))
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[0]["event"], "unlock");
        assert_eq!(lines[0]["key_id"], "main");
        assert_eq!(lines[0]["scope"], "\"Daemon\"");
        assert_eq!(lines[0]["level"], "INFO");
        assert!(lines[0]["timestamp"].is_string(), "{}", lines[0]);
        assert_eq!(lines[1]["event"], "sign");
        assert_eq!(lines[1]["via"], "session");
        let allowed = ["timestamp", "level", "event", "key_id", "scope", "via"];
        for line in &lines {
            for key in line.as_object().unwrap().keys() {
                assert!(
                    allowed.contains(&key.as_str()),
                    "unexpected key {key} in {line}"
                );
            }
        }
        let audit_entries = hub.recent(true, 10);
        assert_eq!(audit_entries.len(), 2);
        assert_eq!(audit_entries[1].fields["event"], "sign");
    }

    /// Replay, the level filter, and a follower that joins during a replay.
    #[test]
    fn stream_replays_then_follows_without_gaps_or_repeats() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (hub, _main, _audit, subscriber) = stack("debug");
        tracing::subscriber::with_default(subscriber, || {
            for i in 0..5 {
                tracing::info!(i, "replayed");
            }
            tracing::debug!("quiet");

            // Replay only, capped by `lines`.
            let mut s = hub.stream(&StreamLogsRequest {
                lines: 3,
                follow: false,
                ..Default::default()
            });
            let got: Vec<LogEntry> = rt.block_on(async {
                let mut v = Vec::new();
                while let Some(e) = s.next().await {
                    v.push(e.unwrap());
                }
                v
            });
            assert_eq!(got.len(), 3);
            assert_eq!(got[0].fields["i"], "3");
            assert_eq!(got[2].message, "quiet");

            // `min_level = INFO` drops the debug entry.
            let mut s = hub.stream(&StreamLogsRequest {
                lines: 10,
                min_level: LogLevel::Info as i32,
                ..Default::default()
            });
            let got: Vec<LogEntry> = rt.block_on(async {
                let mut v = Vec::new();
                while let Some(e) = s.next().await {
                    v.push(e.unwrap());
                }
                v
            });
            assert_eq!(got.len(), 5, "{got:?}");

            // Follow: two replayed, then exactly the new ones.
            let mut s = hub.stream(&StreamLogsRequest {
                lines: 2,
                follow: true,
                ..Default::default()
            });
            tracing::info!("after subscribe");
            tracing::info!(target: AUDIT_TARGET, event = "unlock", "not this log");
            tracing::info!("and another");
            let got: Vec<String> = rt.block_on(async {
                let mut v = Vec::new();
                for _ in 0..4 {
                    v.push(s.next().await.unwrap().unwrap().message);
                }
                v
            });
            assert_eq!(got, ["replayed", "quiet", "after subscribe", "and another"]);

            // The audit stream saw its own entry only.
            let audit = hub.recent(true, 10);
            assert_eq!(audit.len(), 1);
            assert_eq!(audit[0].message, "not this log");
        });
    }

    #[test]
    fn the_ring_is_bounded() {
        let hub = Arc::new(LogHub::default());
        for i in 0..(RING_CAPACITY as u64 + 7) {
            hub.record(LogEntry {
                message: i.to_string(),
                ..Default::default()
            });
        }
        let all = hub.recent(false, usize::MAX);
        assert_eq!(all.len(), RING_CAPACITY);
        assert_eq!(all[0].message, "7");
    }

    #[test]
    fn filter_spec_prefers_a_non_empty_rust_log() {
        // Not touching the process environment: only the fallback is tested.
        if std::env::var_os("RUST_LOG").is_none_or(|v| v.is_empty()) {
            assert_eq!(
                filter_spec("info"),
                "info,zcash_client_backend::data_api::ll::wallet=error,zcash_client_sqlite=warn"
            );
        }
        assert!(
            layers::<tracing_subscriber::Registry, _, _>(
                &Arc::new(LogHub::default()),
                "not a filter ===",
                Buf::default(),
                Buf::default()
            )
            .is_err()
        );
    }
}
