# Patches

Both patches below are real unified diffs generated from a checkout in which
they were applied, compiled and tested. `git apply --check` accepts them.

- `dom-real-xmr-secret-forwarding.patch` — applied by the installer. It is the
  minimal real integration hook: the scalar the canonical real-DOM claim path
  has already verified is forwarded to an optional sink before the Kaystra
  outbox effect is completed. Without a sink installed, `dom-real` behaves
  exactly as before.
- `store-rustix-std-feature.patch` — applied by the installer. `crates/store`
  declares `rustix` without the `std` feature while `lib.rs` passes
  `std::os::fd::BorrowedFd` to `rustix::fs::flock`. That only ever compiled
  because the crate's own dev-dependency on `tempfile` enabled `rustix/std` in
  the same resolution unit. Building any XMR crate that reaches `store` through
  `kaystra-core` as a plain dependency produces a unit without `tempfile`, and
  the crate fails to compile. The fix makes the existing requirement explicit;
  it widens nothing.
- `kaystra-terms-v2-cross-curve.patch` — a ratification checklist, not a diff.
  It is deliberately not applied. See `docs/RATIFICATION_SHEET.md` for the
  measured list of everything that change actually has to touch.
