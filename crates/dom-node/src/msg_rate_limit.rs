//! Per-peer, per-category inbound message rate limiting (anti-flood).
//!
//! Audit finding (P2P hardening): a connected peer can flood the node with
//! VALID but excessive messages (pings, GetHeaders, GetBlockData, relay) and
//! burn CPU/IO without ever violating the protocol. The write-timeout (PR #59)
//! protects the write side; this protects inbound processing.
//!
//! Design mirrors [`crate::pex::AddrFloodTracker`]: a cheap, allocation-free
//! fixed-window counter — but **per category** (a cheap ping and an expensive
//! GetBlockData cannot share one ceiling) and **per connection** (instantiated
//! in `message_loop`, so a flood from one peer never affects others).
//!
//! Limits were chosen with 2-70x headroom over the legitimate peak flows
//! measured during the audit (see the constants below). `GetAddr`/`Addr` are
//! deliberately NOT handled here — they already have dedicated limiters
//! (`GETADDR_COOLDOWN_SECS` serve-side and `AddrFloodTracker` for inbound Addr).

use dom_wire::message::Command;

/// Counting window. Shorter than the 600s Addr window so high-rate categories
/// (sync/relay) are policed responsively.
pub const RATE_WINDOW_SECS: u64 = 10;

/// Cheap, O(1) messages: Ping, Pong, and the ignored-by-default commands
/// (Inv, Headers, GetBlock). Honest peers send ~1 Ping + 1 Pong / 30s
/// (`PING_INTERVAL_SECS`), i.e. ~0.07/s — so 5/s is ~70x headroom.
pub const CHEAP_PER_WINDOW: u32 = 50;

/// Sync-serve requests: GetHeaders (≤2000-header response under the chain lock)
/// and GetBlockData (≤128 block-body reads). A serial honest syncer peaks at
/// ~8-13/s on a LAN; the target is public WAN, where it is far lower — 20/s.
pub const SYNC_PER_WINDOW: u32 = 200;

/// Transaction relay. Bursts during high mempool activity — 60/s.
pub const TX_PER_WINDOW: u32 = 600;

/// Block relay. The catch-up burst observed on the real network is ~30/s; 60/s
/// gives 2x headroom. Defense-in-depth: valid-block floods are already bounded
/// by PoW cost and the duplicate-relay window.
pub const BLOCK_PER_WINDOW: u32 = 600;

/// Cost/volume category a command is rate-limited under. `None` (via
/// [`category_for`]) means "not policed by this limiter".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateCategory {
    /// Ping, Pong, Inv, Headers, GetBlock.
    Cheap,
    /// GetHeaders, GetBlockData.
    Sync,
    /// Tx.
    Tx,
    /// Block.
    Block,
}

/// Map a command to its rate category, or `None` when it must not be policed
/// here. `Hello` self-terminates the connection (second Hello is a violation),
/// and `GetAddr`/`Addr` have their own limiters — all three are `None`.
pub fn category_for(cmd: Command) -> Option<RateCategory> {
    match cmd {
        Command::Ping | Command::Pong | Command::Inv | Command::Headers | Command::GetBlock => {
            Some(RateCategory::Cheap)
        }
        Command::GetHeaders | Command::GetBlockData => Some(RateCategory::Sync),
        Command::Tx => Some(RateCategory::Tx),
        Command::Block => Some(RateCategory::Block),
        Command::Hello | Command::GetAddr | Command::Addr => None,
    }
}

/// Per-category budgets and window, resolved once per connection. Production
/// uses the constants above; tests override via `DOM_TEST_RATELIMIT_*` (mirrors
/// the write-timeout's `DOM_TEST_WRITE_TIMEOUT_SECS`).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Window length in seconds.
    pub window_secs: u64,
    /// Per-window budget for [`RateCategory::Cheap`].
    pub cheap: u32,
    /// Per-window budget for [`RateCategory::Sync`].
    pub sync: u32,
    /// Per-window budget for [`RateCategory::Tx`].
    pub tx: u32,
    /// Per-window budget for [`RateCategory::Block`].
    pub block: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window_secs: RATE_WINDOW_SECS,
            cheap: CHEAP_PER_WINDOW,
            sync: SYNC_PER_WINDOW,
            tx: TX_PER_WINDOW,
            block: BLOCK_PER_WINDOW,
        }
    }
}

impl RateLimitConfig {
    /// Production defaults, with optional `DOM_TEST_RATELIMIT_*` overrides.
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            window_secs: env_override("DOM_TEST_RATELIMIT_WINDOW_SECS", d.window_secs),
            cheap: env_override("DOM_TEST_RATELIMIT_CHEAP", d.cheap as u64) as u32,
            sync: env_override("DOM_TEST_RATELIMIT_SYNC", d.sync as u64) as u32,
            tx: env_override("DOM_TEST_RATELIMIT_TX", d.tx as u64) as u32,
            block: env_override("DOM_TEST_RATELIMIT_BLOCK", d.block as u64) as u32,
        }
    }

    fn budget(&self, cat: RateCategory) -> u32 {
        match cat {
            RateCategory::Cheap => self.cheap,
            RateCategory::Sync => self.sync,
            RateCategory::Tx => self.tx,
            RateCategory::Block => self.block,
        }
    }
}

fn env_override(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One fixed-window counter. Same worst-case as `AddrFloodTracker`: a burst
/// straddling a window boundary tolerates up to 2x the limit, still bounded.
#[derive(Debug, Default, Clone, Copy)]
struct Window {
    start: u64,
    count: u32,
}

impl Window {
    fn allow_at(&mut self, now: u64, limit: u32, window_secs: u64) -> bool {
        if now.saturating_sub(self.start) >= window_secs {
            self.start = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= limit
    }
}

/// Per-connection, per-category inbound message rate limiter.
#[derive(Debug)]
pub struct MessageRateLimiter {
    cfg: RateLimitConfig,
    cheap: Window,
    sync: Window,
    tx: Window,
    block: Window,
}

impl MessageRateLimiter {
    /// Build with production defaults (+ `DOM_TEST_RATELIMIT_*` overrides).
    pub fn from_env() -> Self {
        Self::with_config(RateLimitConfig::from_env())
    }

    /// Build with an explicit config (used by tests).
    pub fn with_config(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            cheap: Window::default(),
            sync: Window::default(),
            tx: Window::default(),
            block: Window::default(),
        }
    }

    /// Register one inbound message of `cmd` and return whether it is within the
    /// category's per-window budget. Commands with no category are always
    /// allowed. Uses the wall clock.
    pub fn allow(&mut self, cmd: Command) -> bool {
        self.allow_at(cmd, unix_now())
    }

    /// Clock-injected variant for deterministic tests.
    pub fn allow_at(&mut self, cmd: Command, now: u64) -> bool {
        let Some(cat) = category_for(cmd) else {
            return true;
        };
        let limit = self.cfg.budget(cat);
        let window = self.cfg.window_secs;
        let slot = match cat {
            RateCategory::Cheap => &mut self.cheap,
            RateCategory::Sync => &mut self.sync,
            RateCategory::Tx => &mut self.tx,
            RateCategory::Block => &mut self.block,
        };
        slot.allow_at(now, limit, window)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> MessageRateLimiter {
        MessageRateLimiter::with_config(RateLimitConfig::default())
    }

    #[test]
    fn categories_map_as_specified() {
        assert_eq!(category_for(Command::Ping), Some(RateCategory::Cheap));
        assert_eq!(category_for(Command::Pong), Some(RateCategory::Cheap));
        assert_eq!(category_for(Command::Inv), Some(RateCategory::Cheap));
        assert_eq!(category_for(Command::Headers), Some(RateCategory::Cheap));
        assert_eq!(category_for(Command::GetBlock), Some(RateCategory::Cheap));
        assert_eq!(category_for(Command::GetHeaders), Some(RateCategory::Sync));
        assert_eq!(
            category_for(Command::GetBlockData),
            Some(RateCategory::Sync)
        );
        assert_eq!(category_for(Command::Tx), Some(RateCategory::Tx));
        assert_eq!(category_for(Command::Block), Some(RateCategory::Block));
        // Excluded: handled elsewhere / self-terminating.
        assert_eq!(category_for(Command::Hello), None);
        assert_eq!(category_for(Command::GetAddr), None);
        assert_eq!(category_for(Command::Addr), None);
    }

    #[test]
    fn block_flood_overflows_after_budget() {
        let mut rl = limiter();
        // First BLOCK_PER_WINDOW are allowed within the window...
        for i in 0..BLOCK_PER_WINDOW {
            assert!(rl.allow_at(Command::Block, 1_000), "block #{i} must pass");
        }
        // ...the next one overflows.
        assert!(
            !rl.allow_at(Command::Block, 1_000),
            "the message past the budget must be rejected"
        );
    }

    #[test]
    fn window_resets_after_window_secs() {
        let mut rl = limiter();
        for _ in 0..BLOCK_PER_WINDOW {
            assert!(rl.allow_at(Command::Block, 1_000));
        }
        assert!(!rl.allow_at(Command::Block, 1_000));
        // A new window restores the full budget.
        assert!(rl.allow_at(Command::Block, 1_000 + RATE_WINDOW_SECS));
    }

    #[test]
    fn categories_are_independent() {
        let mut rl = limiter();
        // Exhaust the cheap budget...
        for _ in 0..=CHEAP_PER_WINDOW {
            rl.allow_at(Command::Ping, 1_000);
        }
        assert!(!rl.allow_at(Command::Ping, 1_000), "cheap exhausted");
        // ...other categories are unaffected.
        assert!(
            rl.allow_at(Command::Block, 1_000),
            "block independent of cheap"
        );
        assert!(rl.allow_at(Command::GetHeaders, 1_000), "sync independent");
        assert!(rl.allow_at(Command::Tx, 1_000), "tx independent");
    }

    #[test]
    fn separate_peers_do_not_share_state() {
        // Each connection has its OWN limiter; one peer flooding must not consume
        // another peer's budget.
        let mut peer_a = limiter();
        let mut peer_b = limiter();
        for _ in 0..=BLOCK_PER_WINDOW {
            peer_a.allow_at(Command::Block, 1_000);
        }
        assert!(!peer_a.allow_at(Command::Block, 1_000), "peer A flooded");
        assert!(
            peer_b.allow_at(Command::Block, 1_000),
            "peer B must be unaffected by peer A's flood"
        );
    }

    /// Legitimate serve-side sync flow (a peer syncing FROM us) must never be
    /// punished. WAN peak is well under the LAN figure; we model a generous
    /// 13 sync requests/s sustained for a full minute.
    #[test]
    fn legitimate_sync_serve_flow_passes() {
        let mut rl = limiter();
        for sec in 0..60u64 {
            let now = 1_000 + sec;
            for _ in 0..13 {
                assert!(
                    rl.allow_at(Command::GetBlockData, now),
                    "honest sync ({sec}s) must not be rate-limited"
                );
            }
        }
    }

    /// Catch-up relay burst (~30 blocks/s, as seen on the real network) must
    /// pass — modeled sustained for a full minute.
    #[test]
    fn catch_up_block_burst_passes() {
        let mut rl = limiter();
        for sec in 0..60u64 {
            let now = 1_000 + sec;
            for _ in 0..30 {
                assert!(
                    rl.allow_at(Command::Block, now),
                    "30 blocks/s catch-up ({sec}s) must not be rate-limited"
                );
            }
        }
    }

    #[test]
    fn env_overrides_apply() {
        // Process-global env: use a unique key set/cleared here only.
        std::env::set_var("DOM_TEST_RATELIMIT_BLOCK", "2");
        let cfg = RateLimitConfig::from_env();
        std::env::remove_var("DOM_TEST_RATELIMIT_BLOCK");
        assert_eq!(cfg.block, 2);
        let mut rl = MessageRateLimiter::with_config(cfg);
        assert!(rl.allow_at(Command::Block, 1_000));
        assert!(rl.allow_at(Command::Block, 1_000));
        assert!(
            !rl.allow_at(Command::Block, 1_000),
            "overflow at the overridden budget"
        );
    }
}
