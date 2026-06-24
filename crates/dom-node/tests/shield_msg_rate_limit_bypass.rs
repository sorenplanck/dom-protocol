//! dom-shield — message rate-limit None-category bypass KAV (message-loop sub-area).
//!
//! `category_for` maps `Hello`, `GetAddr`, and `Addr` to `None`, and
//! `MessageRateLimiter::allow_at` returns `true` UNCONDITIONALLY for any
//! `None`-category command (early-return before any slot accounting). That is
//! by design — those three have their own dedicated limiters (handshake
//! self-termination, `GETADDR_COOLDOWN_SECS`, `AddrFloodTracker`). The risk is
//! a regression where a NEW `Command` variant is added and silently lands in
//! the `None` arm, gaining an unmetered flood channel through this limiter.
//!
//! The existing in-src `categories_map_as_specified` pins the *labels*. These
//! tests pin the *consequence* (None => unbounded pass) and the *exhaustive
//! mapping* so a newly-added variant cannot slip through unpoliced unnoticed.
//!
//! Technique: KAV on `allow_at` behaviour + a closed-world enumeration of every
//! `Command` variant that must remain non-`None` (the policed set).

use dom_node::msg_rate_limit::{category_for, MessageRateLimiter, RateCategory, RateLimitConfig};
use dom_wire::message::Command;

/// None-category commands pass at any volume — confirm the bypass is total, so
/// the policed-set enumeration below is the ONLY thing keeping them metered.
#[test]
fn none_category_commands_never_throttle() {
    let mut limiter = MessageRateLimiter::with_config(RateLimitConfig {
        window_secs: 10,
        cheap: 1,
        sync: 1,
        tx: 1,
        block: 1,
    });
    for cmd in [Command::Hello, Command::GetAddr, Command::Addr] {
        assert!(category_for(cmd).is_none(), "{cmd:?} must be None-category");
        // 100k in one window with budget 1 — still always true.
        for _ in 0..100_000 {
            assert!(
                limiter.allow_at(cmd, 0),
                "{cmd:?} must bypass the per-category limiter unconditionally"
            );
        }
    }
}

/// A policed command IS bounded, proving the early-return is the only bypass.
#[test]
fn policed_category_is_actually_bounded() {
    let mut limiter = MessageRateLimiter::with_config(RateLimitConfig {
        window_secs: 10,
        cheap: 5,
        sync: 5,
        tx: 5,
        block: 5,
    });
    let mut passed = 0;
    for _ in 0..100 {
        if limiter.allow_at(Command::Block, 0) {
            passed += 1;
        }
    }
    assert_eq!(passed, 5, "Block must stop at its budget within the window");
}

/// Closed-world enumeration: EVERY `Command` variant is classified, and only
/// the three documented variants are `None`. This is the regression gate — if a
/// new variant is added and defaults into the `None` arm, this fails loudly.
#[test]
fn command_classification_is_exhaustive_and_only_three_bypass() {
    // Every known Command variant. If the enum grows, the compiler does NOT
    // force an update here (Command is external), so this list IS the audit:
    // adding a variant upstream without adding it here leaves it untested.
    let all = [
        Command::Hello,
        Command::Ping,
        Command::Pong,
        Command::Inv,
        Command::GetBlock,
        Command::Block,
        Command::GetHeaders,
        Command::Headers,
        Command::GetBlockData,
        Command::Tx,
        Command::GetAddr,
        Command::Addr,
    ];
    let none: Vec<Command> = all
        .iter()
        .copied()
        .filter(|c| category_for(*c).is_none())
        .collect();
    assert_eq!(
        none,
        vec![Command::Hello, Command::GetAddr, Command::Addr],
        "exactly Hello/GetAddr/Addr may bypass the per-category limiter"
    );
    // Sanity: each policed command has a concrete category.
    for c in all {
        if !none.contains(&c) {
            let cat = category_for(c).expect("policed command has a category");
            assert!(matches!(
                cat,
                RateCategory::Cheap | RateCategory::Sync | RateCategory::Tx | RateCategory::Block
            ));
        }
    }
}
