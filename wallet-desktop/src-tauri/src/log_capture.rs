//! Live log capture for the embedded DOM node.
//!
//! The node emits all of its diagnostics through the `tracing` crate. Because
//! the node runs *in the same process* as this Tauri backend, we install a
//! custom `tracing_subscriber` layer that captures every event into a bounded
//! broadcast channel. The frontend subscribes to that channel via a Tauri
//! event ("node-log"), giving the Node / Logs tab a real-time stream.
//!
//! SECURITY: the node code is careful never to log secrets (passwords/seeds are
//! redacted at the source — see `dom-node` `main.rs`, which prints
//! "[REDACTED]"). We additionally run a defensive scrub here so that even a
//! future regression cannot leak a secret-looking line to the UI.

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// A single structured log line delivered to the UI.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LogLine {
    /// Milliseconds since UNIX epoch (frontend formats locally).
    pub ts_ms: u64,
    /// Level: "ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE".
    pub level: String,
    /// Module path / target that emitted the event.
    pub target: String,
    /// Rendered message.
    pub message: String,
}

/// Shared sender; clone freely. Capacity is bounded so a slow UI can never
/// cause unbounded memory growth — laggy receivers simply drop old lines.
#[derive(Clone)]
pub struct LogBus {
    tx: broadcast::Sender<LogLine>,
}

impl LogBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogLine> {
        self.tx.subscribe()
    }

    fn emit(&self, line: LogLine) {
        // Ignore send errors: they only mean there are currently no receivers.
        let _ = self.tx.send(line);
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn level_str(l: &Level) -> &'static str {
    match *l {
        Level::ERROR => "ERROR",
        Level::WARN => "WARN",
        Level::INFO => "INFO",
        Level::DEBUG => "DEBUG",
        Level::TRACE => "TRACE",
    }
}

/// Visitor that extracts the `message` field (and other fields) into a string.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    extra: Vec<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
            // Strip the surrounding quotes Debug adds to plain messages.
            if self.message.starts_with('"') && self.message.ends_with('"') && self.message.len() >= 2
            {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            self.extra.push(format!("{}={value:?}", field.name()));
        }
    }
}

/// Defensive secret scrubber. The node never logs secrets, but if a line ever
/// contains a password/seed-looking key we redact the value before it reaches
/// the UI or any in-memory ring buffer.
fn scrub(mut s: String) -> String {
    const NEEDLES: [&str; 6] = [
        "password", "passphrase", "seed", "mnemonic", "private_key", "secret",
    ];
    let lower = s.to_lowercase();
    if NEEDLES.iter().any(|n| lower.contains(n)) {
        // Replace any value after `=` or `:` on the line with a marker.
        // Keep the key visible for debugging, hide the value.
        let mut out = String::with_capacity(s.len());
        let mut redact_rest = false;
        for ch in s.chars() {
            if redact_rest {
                continue;
            }
            out.push(ch);
            if ch == '=' || ch == ':' {
                let l = out.to_lowercase();
                if NEEDLES.iter().any(|n| l.contains(n)) {
                    out.push_str(" [REDACTED]");
                    redact_rest = true;
                }
            }
        }
        s = out;
    }
    s
}

/// A `tracing` layer that forwards every event to the `LogBus`.
pub struct BroadcastLayer {
    bus: Arc<LogBus>,
}

impl BroadcastLayer {
    pub fn new(bus: Arc<LogBus>) -> Self {
        Self { bus }
    }
}

impl<S: Subscriber> Layer<S> for BroadcastLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let mut message = visitor.message;
        if !visitor.extra.is_empty() {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(&visitor.extra.join(" "));
        }

        let line = LogLine {
            ts_ms: now_ms(),
            level: level_str(meta.level()).to_string(),
            target: meta.target().to_string(),
            message: scrub(message),
        };
        self.bus.emit(line);
    }
}
