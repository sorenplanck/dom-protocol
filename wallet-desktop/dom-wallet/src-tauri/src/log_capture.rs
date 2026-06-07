//! Live log capture for the Node tab (the headline V1 feature).
//!
//! A custom `tracing_subscriber` `Layer` intercepts every event emitted by the
//! embedded node (and the app itself), formats it into a structured
//! [`LogLine`], and does two things:
//!
//!   1. Pushes it into a bounded ring buffer (the last [`BACKEND_BUFFER`] lines)
//!      so the Node tab can show recent history the moment it opens.
//!   2. Broadcasts it on a `tokio::sync::broadcast` channel. Tauri command
//!      handlers subscribe and re-emit each line to the frontend as a
//!      `log://line` event.
//!
//! SECURITY: this layer formats whatever `tracing` emits. The protocol crates
//! are written never to log secrets, and the app wraps passwords/seeds in
//! `Zeroizing` and never logs them. The layer adds no new exposure — it only
//! forwards. We still apply a defensive redaction pass on the rendered message
//! as a belt-and-braces measure (see [`redact`]).

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Lines retained in the backend ring buffer (UI keeps fewer; export uses this).
pub const BACKEND_BUFFER: usize = 10_000;
/// Broadcast channel capacity. If the UI lags, oldest queued lines are dropped
/// for that receiver only (the buffer still holds them for replay).
const CHANNEL_CAPACITY: usize = 4_096;

/// A single rendered log line, as delivered to the frontend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogLine {
    /// Unix milliseconds.
    pub timestamp: u64,
    /// "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE".
    pub level: String,
    /// Emitting target, e.g. "dom_node::miner".
    pub target: String,
    /// The formatted message (fields folded in), redacted defensively.
    pub message: String,
}

/// Shared handle to the capture machinery. Cloneable; cheap.
#[derive(Clone)]
pub struct LogBus {
    tx: broadcast::Sender<LogLine>,
    ring: Arc<Mutex<VecDeque<LogLine>>>,
}

impl LogBus {
    /// Create a new bus plus the `tracing` layer that feeds it.
    pub fn new() -> (LogBus, LogLayer) {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        let ring = Arc::new(Mutex::new(VecDeque::with_capacity(BACKEND_BUFFER)));
        let bus = LogBus {
            tx,
            ring: ring.clone(),
        };
        let layer = LogLayer { bus: bus.clone() };
        (bus, layer)
    }

    /// Subscribe to the live stream. Each subscriber gets every line emitted
    /// after it subscribes.
    pub fn subscribe(&self) -> broadcast::Receiver<LogLine> {
        self.tx.subscribe()
    }

    /// Snapshot the recent buffer (oldest first), capped at `max` lines.
    pub fn snapshot(&self, max: usize) -> Vec<LogLine> {
        let ring = self.ring.lock().expect("log ring poisoned");
        let len = ring.len();
        let start = len.saturating_sub(max);
        ring.iter().skip(start).cloned().collect()
    }

    fn push(&self, line: LogLine) {
        {
            let mut ring = self.ring.lock().expect("log ring poisoned");
            if ring.len() == BACKEND_BUFFER {
                ring.pop_front();
            }
            ring.push_back(line.clone());
        }
        // A send error only means there are no live subscribers — fine.
        let _ = self.tx.send(line);
    }
}

/// The `tracing` layer that turns events into [`LogLine`]s on the [`LogBus`].
pub struct LogLayer {
    bus: LogBus,
}

impl<S> Layer<S> for LogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let line = LogLine {
            timestamp,
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message: redact(visitor.into_message()),
        };
        self.bus.push(line);
    }
}

/// Collects the `message` field plus any structured fields into one string.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    extra: String,
}

impl MessageVisitor {
    fn into_message(self) -> String {
        if self.extra.is_empty() {
            self.message
        } else if self.message.is_empty() {
            self.extra
        } else {
            format!("{} {}", self.message, self.extra.trim())
        }
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
            // strip the surrounding quotes Debug adds to bare strings
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            let _ = write!(self.extra, " {}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.extra, " {}={}", field.name(), value);
        }
    }
}

/// Defensive redaction: even though the crates never log secrets, scrub any
/// `password=`, `seed=`, `mnemonic=`, or `token=` style fields if they ever
/// appear. Belt-and-braces; not a substitute for not-logging-secrets.
fn redact(mut s: String) -> String {
    const KEYS: [&str; 6] = [
        "password=",
        "passphrase=",
        "mnemonic=",
        "seed_phrase=",
        "bearer=",
        "token=",
    ];
    for key in KEYS {
        if let Some(idx) = s.to_ascii_lowercase().find(key) {
            // Redact from the key to the next whitespace.
            let start = idx + key.len();
            let end = s[start..]
                .find(char::is_whitespace)
                .map(|o| start + o)
                .unwrap_or(s.len());
            s.replace_range(start..end, "[REDACTED]");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_caps_and_orders() {
        let (bus, _layer) = LogBus::new();
        for i in 0..(BACKEND_BUFFER + 50) {
            bus.push(LogLine {
                timestamp: i as u64,
                level: "INFO".into(),
                target: "t".into(),
                message: format!("line {i}"),
            });
        }
        let snap = bus.snapshot(BACKEND_BUFFER);
        assert_eq!(snap.len(), BACKEND_BUFFER);
        // Oldest 50 dropped; first retained line is #50.
        assert_eq!(snap.first().unwrap().timestamp, 50);
        assert_eq!(snap.last().unwrap().timestamp, (BACKEND_BUFFER + 49) as u64);
    }

    #[test]
    fn snapshot_respects_max() {
        let (bus, _layer) = LogBus::new();
        for i in 0..100 {
            bus.push(LogLine {
                timestamp: i,
                level: "INFO".into(),
                target: "t".into(),
                message: "x".into(),
            });
        }
        let snap = bus.snapshot(10);
        assert_eq!(snap.len(), 10);
        assert_eq!(snap.first().unwrap().timestamp, 90);
    }

    #[test]
    fn subscribers_receive_pushed_lines() {
        let (bus, _layer) = LogBus::new();
        let mut rx = bus.subscribe();
        bus.push(LogLine {
            timestamp: 1,
            level: "WARN".into(),
            target: "t".into(),
            message: "hello".into(),
        });
        let got = rx.try_recv().expect("should have a line");
        assert_eq!(got.message, "hello");
        assert_eq!(got.level, "WARN");
    }

    #[test]
    fn redact_scrubs_sensitive_fields() {
        assert_eq!(redact("auth bearer=abc123 ok".into()), "auth bearer=[REDACTED] ok");
        assert_eq!(redact("password=hunter2".into()), "password=[REDACTED]");
        assert_eq!(redact("nothing here".into()), "nothing here");
    }
}
