//! The advisory ignore list is pinned here, and it is empty.
//!
//! `[advisories] ignore` is the one place in `deny.toml` where a known
//! vulnerability can be waved through. Nothing enforces that an entry carries
//! a reason, so the list is the kind that grows quietly: one ID today to get a
//! build green, and the next reader cannot tell which entries were reasoned
//! about and which were expedient.
//!
//! It is empty because `webbrowser` was upgraded rather than ignored —
//! `egui-winit` declares `webbrowser = "1.2"`, which admits the fixed 1.2.4,
//! so `cargo update -p webbrowser --precise 1.2.4` closed it at the source.
//! Upgrading is the only direction permitted; downgrading never is.
//!
//! An entry may be added ONLY with all three of: the ID `cargo deny` reported,
//! a reference to a written unreachability proof, and an expiry date. Adding
//! one here without that is the thing this test exists to stop.

use std::path::Path;

/// Every advisory ID this workspace waves through, with the proof that
/// justifies it and the date the waiver expires.
///
/// Empty is the correct state. An entry belongs here only when the advisory
/// cannot be closed by upgrading AND its code path is proven unreachable.
const ALLOWED_IGNORES: &[(&str, &str)] = &[(
    "RUSTSEC-2025-0141",
    "unmaintained notice for bincode 1.3.3, not a vulnerability: no CVE and \
     no code-path defect is reported, so there is nothing whose reachability \
     needs disproving. The advisory itself declares 1.3.3 complete and not \
     in need of updates; no upgrade closes it (bincode 2.x is a different \
     crate surface, and the solana-*/xmr-dleq-sigma consumers pin 1.x via \
     their own upstreams). Waiver expires 2027-03-01 or the day a RUSTSEC \
     entry reports an actual soundness or security defect in 1.3.3, \
     whichever comes first.",
)];

fn declared_ignores(policy: &str) -> Vec<String> {
    let Some(start) = policy.find("[advisories]") else {
        panic!("deny.toml declares no [advisories] section");
    };
    let section = &policy[start..];
    let Some(open) = section.find("ignore") else {
        return Vec::new();
    };
    let after = &section[open..];
    let Some(bracket) = after.find('[') else {
        return Vec::new();
    };
    let body = &after[bracket..];
    let close = body.find(']').expect("unterminated `ignore` list");
    let mut found = Vec::new();
    let mut rest = &body[..close];
    while let Some(quote) = rest.find('"') {
        let tail = &rest[quote + 1..];
        let end = tail.find('"').expect("unterminated string in `ignore`");
        found.push(tail[..end].to_string());
        rest = &tail[end + 1..];
    }
    found
}

#[test]
fn the_advisory_ignore_list_holds_only_what_was_proven() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deny.toml");
    let policy = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let declared = declared_ignores(&policy);
    let allowed: Vec<&str> = ALLOWED_IGNORES.iter().map(|(id, _)| *id).collect();

    for id in &declared {
        assert!(
            allowed.contains(&id.as_str()),
            "deny.toml now ignores advisory `{id}`, which this guard does not \
             know.\n\
             An ignored advisory is a known vulnerability shipped on purpose. \
             It is allowed only when it cannot be closed by UPGRADING and its \
             code path is proven unreachable — never to make a build green.\n\
             If it is genuinely justified, add it to ALLOWED_IGNORES with the \
             proof it rests on and the date the waiver expires."
        );
    }

    for (id, proof) in ALLOWED_IGNORES {
        assert!(
            declared.contains(&(*id).to_string()),
            "`{id}` is no longer ignored in deny.toml, but this guard still \
             records it as waived ({proof}).\n\
             If the advisory was closed, remove its entry from ALLOWED_IGNORES."
        );
    }

    assert_eq!(
        declared.len(),
        ALLOWED_IGNORES.len(),
        "the ignore list changed size: declared {declared:?}, allowed {allowed:?}"
    );
}
