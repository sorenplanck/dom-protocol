#!/usr/bin/env python3
"""Adversarial tests for the absorbed layer-policy guard."""

from __future__ import annotations

import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import guard_layer_policy as guard  # noqa: E402


class RustLexicalPolicyTests(unittest.TestCase):
    def test_comments_and_literals_cannot_pose_as_product_code(self) -> None:
        source = r'''
fn product() {
    let live = value.unwrap();
    let normal = "onlyOwner println! PurposeV1::Sponsor /* not a comment */";
    let raw = r###"delegatecall .expect( // still a literal"###;
    // admin_key another.unwrap() eprintln!("not product");
    /* nested /* guardian dbg!(not_product); */ pause_all */
}
'''
        code = guard.sanitize_source(source, strip_strings=True)
        commentless = guard.sanitize_source(source, strip_strings=False)

        self.assertEqual(source.count("\n"), code.count("\n"))
        self.assertEqual(len(source), len(code))
        self.assertIn("value.unwrap()", code)
        self.assertNotIn("onlyOwner", code)
        self.assertNotIn("admin_key", code)
        self.assertNotIn("guardian", code)
        self.assertIn("onlyOwner println! PurposeV1::Sponsor", commentless)
        self.assertNotIn("admin_key", commentless)
        self.assertNotIn("guardian", commentless)

    def test_character_literals_do_not_blind_following_code(self) -> None:
        source = r"let a = '/'; let b = '\u{10ff}'; let value = item.unwrap();" + "\n"
        code = guard.sanitize_source(source, strip_strings=True)
        self.assertIn("item.unwrap()", code)
        self.assertEqual(len(source), len(code))

    def test_cfg_implication_is_conservative(self) -> None:
        self.assertTrue(guard.cfg_implies_test("test"))
        self.assertTrue(guard.cfg_implies_test("all(unix, test)"))
        self.assertTrue(guard.cfg_implies_test("any(test, all(test, unix))"))
        self.assertFalse(guard.cfg_implies_test('any(test, feature = "lab")'))
        self.assertFalse(guard.cfg_implies_test("not(test)"))
        self.assertFalse(guard.cfg_implies_test("fuzzing"))
        self.assertFalse(guard.cfg_implies_nonproduction("fuzzing"))

    def test_only_provably_nonproduction_items_are_masked(self) -> None:
        source = '''
fn product_one() { first.unwrap(); }
#[cfg(test)]
fn test_only() { second.unwrap(); }
#[cfg(all(unix, test))]
fn also_test_only() { third.unwrap(); }
#[cfg(any(test, feature = "laboratory"))]
fn may_be_product() { fourth.unwrap(); }
#[cfg(fuzzing)]
fn fuzz_only() { fifth.unwrap(); }
#[test]
fn harness_only() { sixth.unwrap(); }
fn host() {
    #[cfg(test)]
    test_hook(|| { eighth.unwrap(); });
    ninth.unwrap();
}
fn product_two() { seventh.unwrap(); }
'''
        code = guard.sanitize_source(source, strip_strings=True)
        masked = guard.test_only_line_numbers(code)
        numbered = {line.strip(): number for number, line in enumerate(source.splitlines(), 1)}

        self.assertNotIn(numbered["fn product_one() { first.unwrap(); }"], masked)
        self.assertIn(numbered["fn test_only() { second.unwrap(); }"], masked)
        self.assertIn(numbered["fn also_test_only() { third.unwrap(); }"], masked)
        self.assertNotIn(numbered["fn may_be_product() { fourth.unwrap(); }"], masked)
        self.assertNotIn(numbered["fn fuzz_only() { fifth.unwrap(); }"], masked)
        self.assertIn(numbered["fn harness_only() { sixth.unwrap(); }"], masked)
        self.assertIn(numbered["test_hook(|| { eighth.unwrap(); });"], masked)
        self.assertNotIn(numbered["ninth.unwrap();"], masked)
        self.assertNotIn(numbered["fn product_two() { seventh.unwrap(); }"], masked)

    def test_test_mask_does_not_hide_product_code_on_the_same_line(self) -> None:
        source = "#[cfg(test)] const ONLY_TEST: () = (); fn product() { live.unwrap (); }\n"
        sanitized = guard.sanitize_source(source, strip_strings=True)
        masked = guard.mask_test_only_items(sanitized)
        self.assertNotIn("ONLY_TEST", masked)
        self.assertIn("live.unwrap ()", masked)
        self.assertIsNotNone(guard.I14_PATTERN.search(masked))

    def test_product_member_path_filter_is_target_root_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            member = pathlib.Path(directory)
            product = member / "src" / "tests" / "backdoor.rs"
            integration = member / "tests" / "fixture.rs"
            build = member / "build.rs"
            product.parent.mkdir(parents=True)
            integration.parent.mkdir(parents=True)
            for path in (product, integration, build):
                path.write_text("fn marker() {}\n", encoding="utf-8")
            paths = set(guard._member_rust_paths(member))
            self.assertIn(product, paths)
            self.assertIn(build, paths)
            self.assertIn(integration, paths)

    def test_product_edge_wins_over_test_path_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            member = pathlib.Path(directory)
            source = member / "src"
            tests = member / "tests"
            source.mkdir()
            tests.mkdir()
            library = source / "lib.rs"
            production = source / "production_time_guard.rs"
            test_only = source / "independent_vector_comparison.rs"
            integration = tests / "production_time_guard.rs"
            library.write_text(
                "mod production_time_guard;\n"
                "#[cfg(test)]\nmod independent_vector_comparison;\n",
                encoding="utf-8",
            )
            production.write_text("fn live() { value.unwrap(); }\n", encoding="utf-8")
            test_only.write_text("fn fixture() { value.unwrap(); }\n", encoding="utf-8")
            integration.write_text(
                '#[path = "../src/production_time_guard.rs"]\nmod production_time_guard;\n',
                encoding="utf-8",
            )

            paths = guard._member_rust_paths(member)
            whole_test = guard._whole_test_only_paths(member, paths)
            self.assertNotIn(production.resolve(), whole_test)
            self.assertIn(test_only.resolve(), whole_test)
            self.assertIn(integration.resolve(), whole_test)

    def test_solidity_nested_comment_syntax_cannot_mask_live_code(self) -> None:
        source = '''/* fake nested opener /* */
contract Backdoor { function f() external { assembly { pop(delegatecall(0,0,0,0,0,0)) } }
string constant END = "*/"; }
'''
        code = guard.sanitize_solidity_source(source)
        self.assertIn("delegatecall", code)
        self.assertNotIn("fake nested opener", code)


class FrozenAllowanceTests(unittest.TestCase):
    def test_allowlist_fails_on_new_and_stale_exceptions(self) -> None:
        one = ("crates/example/src/lib.rs", "value.unwrap()")
        two = ("crates/example/src/lib.rs", "other.unwrap()")

        self.assertEqual(
            guard._exact_allowlist_findings(
                "example", collections.Counter({one: 1}), collections.Counter({one: 1})
            ),
            [],
        )
        added = guard._exact_allowlist_findings(
            "example", collections.Counter({one: 2}), collections.Counter({one: 1})
        )
        self.assertEqual(len(added), 1)
        self.assertIn("unreviewed production use", added[0].message)

        stale = guard._exact_allowlist_findings(
            "example", collections.Counter({one: 1}), collections.Counter({one: 1, two: 1})
        )
        self.assertEqual(len(stale), 1)
        self.assertIn("frozen allowance disappeared", stale[0].message)

    def test_contract_inventory_hash_rejects_renamed_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            contract = root / "contracts" / "src" / "Frozen.sol"
            contract.parent.mkdir(parents=True)
            contract.write_text(
                "contract Frozen { address private onlyOwner; }\n", encoding="utf-8"
            )
            expected = {
                "contracts/src/Frozen.sol": (
                    "94340d38d5d0669d420465bd9fc1413558e6e3493d35b9ad9eee60514e01e254"
                )
            }
            self.assertEqual(
                guard._frozen_sha256_findings(
                    root, "contract", expected, expected.keys()
                ),
                [],
            )

            # The denylist no longer sees the renamed authority, but the
            # approved whole-file digest must still reject the body change.
            contract.write_text(
                "contract Frozen { address private soleGovernor; }\n", encoding="utf-8"
            )
            sanitized = guard.sanitize_solidity_source(
                contract.read_text(encoding="utf-8")
            )
            self.assertIsNone(guard.ANTI_POWER.search(sanitized))
            findings = guard._frozen_sha256_findings(
                root, "contract", expected, expected.keys()
            )
            self.assertEqual(len(findings), 1)
            self.assertIn("SHA-256 changed", findings[0].message)

            extra = root / "contracts" / "src" / "Extra.sol"
            extra.write_text("contract Extra {}\n", encoding="utf-8")
            findings = guard._frozen_sha256_findings(
                root,
                "contract",
                expected,
                (*expected.keys(), "contracts/src/Extra.sol"),
            )
            self.assertTrue(any("unreviewed file" in item.message for item in findings))

            missing = guard._frozen_sha256_findings(root, "contract", expected, ())
            self.assertEqual(len(missing), 1)
            self.assertIn("frozen file is absent", missing[0].message)

    def test_sponsor_source_hash_rejects_body_change_with_same_arm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "crate.rs"
            frozen = (
                "match purpose { PurposeV1::Sponsor => Err(Error::Denied), "
                "_ => Ok(()) }\n"
            )
            source.write_text(frozen, encoding="utf-8")
            expected = {
                "crate.rs": (
                    "1f46b26da7cd1999d316589f1ce3e884785073385c755bb99c09f39c0594d3e2"
                )
            }
            sponsor_at = frozen.index("PurposeV1::Sponsor")
            self.assertTrue(
                guard._sponsor_context_is_rejection_or_registry(
                    "crate.rs", frozen, sponsor_at
                )
            )
            self.assertEqual(
                guard._frozen_sha256_findings(
                    root, "Sponsor", expected, expected.keys()
                ),
                [],
            )

            source.write_text(
                frozen
                + "fn newly_authorized_body(purpose: PurposeV1) -> Result<(), Error> {\n"
                + "    if purpose.to_byte() == 4 { Ok(()) } else { Err(Error::Denied) }\n"
                + "}\n",
                encoding="utf-8",
            )
            findings = guard._frozen_sha256_findings(
                root, "Sponsor", expected, expected.keys()
            )
            self.assertEqual(len(findings), 1)
            self.assertIn("SHA-256 changed", findings[0].message)

    def test_unresolved_frozen_digest_is_a_failure_not_a_wildcard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "pending.rs"
            source.write_text("fn pending() {}\n", encoding="utf-8")
            findings = guard._frozen_sha256_findings(
                root, "pending", {"pending.rs": None}, ("pending.rs",)
            )
            self.assertEqual(len(findings), 1)
            self.assertIn("awaits explicit post-handoff review", findings[0].message)


class ManifestBoundaryTests(unittest.TestCase):
    def test_fault_features_are_dev_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "crates" / "member").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/member"]\n', encoding="utf-8"
            )
            manifest = root / "crates" / "member" / "Cargo.toml"
            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[dependencies]
relay = { version = "1", features = ["relay-fault-injection"] }
''',
                encoding="utf-8",
            )
            failed = guard.check_f2_feature_boundaries(root)
            self.assertFalse(failed.passed)
            self.assertIn("not dev-dependencies", failed.findings[0].message)

            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[features]
production = ["relay/relay-fault-injection"]

[dev-dependencies]
relay = { version = "1", features = ["relay-fault-injection"] }
''',
                encoding="utf-8",
            )
            forwarded = guard.check_f2_feature_boundaries(root)
            self.assertFalse(forwarded.passed)
            self.assertIn("forwards laboratory feature", forwarded.findings[0].message)

            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[dev-dependencies]
relay = { version = "1", features = ["relay-fault-injection"] }
''',
                encoding="utf-8",
            )
            self.assertTrue(guard.check_f2_feature_boundaries(root).passed)

    def test_evidence_only_store_surface_never_ships(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "crates" / "member").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/member"]\n', encoding="utf-8"
            )
            manifest = root / "crates" / "member" / "Cargo.toml"

            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[dependencies]
dom-scriptless-store = { version = "1", features = ["evidence-only"] }
''',
                encoding="utf-8",
            )
            normal = guard.check_evidence_only_isolation(root)
            self.assertFalse(normal.passed)
            self.assertIn("not dev-dependencies", normal.findings[0].message)

            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[features]
laboratory = ["dom-scriptless-store?/evidence-only"]
production = ["laboratory"]
''',
                encoding="utf-8",
            )
            neutral = guard.check_evidence_only_isolation(root)
            self.assertFalse(neutral.passed)
            messages = " | ".join(finding.message for finding in neutral.findings)
            self.assertIn("under a neutral name", messages)
            self.assertIn("shipped feature production reaches", messages)

            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[features]
production = []
evidence-only-ancestry-tests = ["dom-scriptless-store?/evidence-only"]

[dev-dependencies]
dom-scriptless-store = { version = "1", features = ["evidence-only"] }
''',
                encoding="utf-8",
            )
            self.assertTrue(guard.check_evidence_only_isolation(root).passed)

    def test_derived_evidence_only_feature_names_cannot_ship_via_dependencies(self) -> None:
        """Rule (a) mints names such as `evidence-only-ancestry-tests`; rule (c) must see them."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "crates" / "member").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/member"]\n', encoding="utf-8"
            )
            manifest = root / "crates" / "member" / "Cargo.toml"
            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[dependencies]
dom-interopd = { version = "1", features = ["production", "evidence-only-ancestry-tests"] }
''',
                encoding="utf-8",
            )
            derived = guard.check_evidence_only_isolation(root)
            self.assertFalse(derived.passed)
            self.assertIn("not dev-dependencies", derived.findings[0].message)

            manifest.write_text(
                '''
[package]
name = "member"
version = "0.1.0"

[dev-dependencies]
dom-interopd = { version = "1", features = ["production", "evidence-only-ancestry-tests"] }
''',
                encoding="utf-8",
            )
            self.assertTrue(guard.check_evidence_only_isolation(root).passed)

    def test_out_of_workspace_manifests_are_still_scanned_for_evidence_only(self) -> None:
        """A per-crate fuzz workspace enabling the laboratory feature must not hide from the guard."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "crates" / "member" / "fuzz").mkdir(parents=True)
            (root / "target" / "debug").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/member"]\n', encoding="utf-8"
            )
            (root / "crates" / "member" / "Cargo.toml").write_text(
                '[package]\nname = "member"\nversion = "0.1.0"\n\n[features]\nevidence-only = []\n',
                encoding="utf-8",
            )
            (root / "target" / "debug" / "Cargo.toml").write_text(
                '[dependencies]\nmember = { path = "../../crates/member", features = ["evidence-only"] }\n',
                encoding="utf-8",
            )
            self.assertTrue(guard.check_evidence_only_isolation(root).passed)

            (root / "crates" / "member" / "fuzz" / "Cargo.toml").write_text(
                '''[package]
name = "member-fuzz"
version = "0.0.0"

[workspace]

[dependencies.member]
path = ".."
features = ["evidence-only"]
''',
                encoding="utf-8",
            )
            result = guard.check_evidence_only_isolation(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("crates/member/fuzz/Cargo.toml" in item.path for item in result.findings))

    def test_store_never_extracts_adaptor_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source_root = root / "crates" / "dom-scriptless-store" / "src"
            source_root.mkdir(parents=True)
            module = source_root / "session_store.rs"

            module.write_text(
                "fn prove(pre: &AdaptorPreSignatureV1) -> Result<(), Error> {\n"
                "    pre.verify_final_signature_opens_adaptor_point_v1(&signature, &context)\n"
                "}\n",
                encoding="utf-8",
            )
            self.assertTrue(guard.check_store_never_extracts_adaptor_secret(root).passed)

            module.write_text(
                "/// Never calls `extract_revealed_secret_be_bytes`; the proof returns unit.\n"
                "fn prove(pre: &AdaptorPreSignatureV1) -> Result<(), Error> {\n"
                "    pre.verify_final_signature_opens_adaptor_point_v1(&signature, &context)\n"
                "}\n",
                encoding="utf-8",
            )
            self.assertTrue(guard.check_store_never_extracts_adaptor_secret(root).passed)

            module.write_text(
                "fn leak(pre: &AdaptorPreSignatureV1) -> Result<[u8; 32], Error> {\n"
                "    pre.extract_revealed_secret_be_bytes(&signature, &context)\n"
                "}\n",
                encoding="utf-8",
            )
            extracted = guard.check_store_never_extracts_adaptor_secret(root)
            self.assertFalse(extracted.passed)
            self.assertIn("extract_revealed_secret_be_bytes", extracted.findings[0].message)

            module.write_text(
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    fn leak(pre: &AdaptorPreSignatureV1) -> Result<Secret, Error> {\n"
                "        pre.verify_and_extract(&signature, &context)\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            in_tests = guard.check_store_never_extracts_adaptor_secret(root)
            self.assertFalse(in_tests.passed)
            self.assertIn("verify_and_extract", in_tests.findings[0].message)

    def _store_source(self, body: str) -> guard.RustSource:
        """Build one masked Store source the way `load_rust_sources` does."""

        relative = "crates/dom-scriptless-store/src/runtime/linux/session_store.rs"
        raw_code = guard.sanitize_source(body, strip_strings=True)
        spans = guard._test_only_spans(raw_code)
        code = guard._mask_spans(raw_code, spans)
        commentless = guard._mask_spans(
            guard.sanitize_source(body, strip_strings=False), spans
        )
        return guard.RustSource(
            path=pathlib.Path(relative),
            relative_path=relative,
            original_lines=tuple(body.splitlines()),
            code=code,
            commentless=commentless,
            code_lines=tuple(code.splitlines()),
            commentless_lines=tuple(commentless.splitlines()),
        )

    def test_store_custody_traits_stay_out_of_the_laboratory(self) -> None:
        root = pathlib.Path("/nonexistent")
        check = guard.check_store_custody_traits_stay_out_of_the_laboratory

        # A pinned product implementation is the normal case and passes.
        pinned = self._store_source(
            "impl SharedBlindingVaultV1 for ContractsNonceVaultV1 {\n}\n"
        )
        self.assertTrue(check(root, _sources=(pinned,)).passed)

        # A double under `cfg(test)` alone is masked and therefore invisible.
        in_tests = self._store_source(
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    struct TestSharedBlindingVault;\n"
            "    impl SharedBlindingVaultV1 for TestSharedBlindingVault {\n"
            "    }\n"
            "}\n"
        )
        self.assertTrue(check(root, _sources=(in_tests,)).passed)

        # The exact transition this guard exists to refuse: the same double,
        # moved to a cfg the evidence-only feature can satisfy.
        laboratory = self._store_source(
            '#[cfg(any(test, feature = "evidence-only"))]\n'
            "struct TestSharedBlindingVault;\n"
            '#[cfg(any(test, feature = "evidence-only"))]\n'
            "impl SharedBlindingVaultV1 for TestSharedBlindingVault {\n"
            "}\n"
        )
        escaped = check(root, _sources=(laboratory,))
        self.assertFalse(escaped.passed)
        self.assertIn("TestSharedBlindingVault", escaped.findings[0].message)
        self.assertIn("SharedBlindingVaultV1", escaped.findings[0].message)

        # An unpinned implementation with no cfg at all is a custody decision
        # too, and is refused for the same reason.
        unpinned = self._store_source(
            "impl OperationalClaimTransactionSinkV1 for SomethingNew {\n}\n"
        )
        self.assertFalse(check(root, _sources=(unpinned,)).passed)

        # Prose about the rule is not itself a violation.
        prose = self._store_source(
            "// impl SharedBlindingVaultV1 for TestSharedBlindingVault is forbidden.\n"
        )
        self.assertTrue(check(root, _sources=(prose,)).passed)

        # A trait outside the custody set is none of this guard's business.
        unrelated = self._store_source("impl fmt::Display for Whatever {\n}\n")
        self.assertTrue(check(root, _sources=(unrelated,)).passed)

    def test_evidence_dependency_alias_and_target_table_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            crate = root / "crates" / "adapters" / "btc-evidence"
            (crate / "src").mkdir(parents=True)
            (crate / "src" / "lib.rs").write_text("pub fn verify() {}\n", encoding="utf-8")
            (crate / "Cargo.toml").write_text(
                '''[package]
name = "btc-evidence"
version = "0.1.0"

[target.'cfg(unix)'.dependencies]
custody_alias = { package = "btc-live", version = "1" }
''',
                encoding="utf-8",
            )
            result = guard.check_f5_evidence_boundary(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("custody/signing dependency btc-live" in item.message for item in result.findings))

    def test_sponsor_arm_requires_local_rejection_shape(self) -> None:
        rejected = "match purpose { PurposeV1::Sponsor => Err(Error::Denied), _ => Ok(()) }"
        accepted = "match purpose { PurposeV1::Sponsor => Ok(()), _ => Ok(()) }"
        rejected_at = rejected.index("PurposeV1::Sponsor")
        accepted_at = accepted.index("PurposeV1::Sponsor")
        self.assertTrue(guard._sponsor_context_is_rejection_or_registry("crate.rs", rejected, rejected_at))
        self.assertFalse(guard._sponsor_context_is_rejection_or_registry("crate.rs", accepted, accepted_at))

    def test_literal_secp_randomization_is_not_unpredictable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "crates" / "adapters" / "btc-live" / "src"
            source.mkdir(parents=True)
            (source / "nested.rs").write_text(
                "fn bad() {\nlet mut secp = Secp256k1::new();\nsecp.seeded_randomize(&[0; 32]);\n}\n",
                encoding="utf-8",
            )
            result = guard.check_f1_secp_contexts(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("fresh_entropy provenance" in item.message for item in result.findings))

    def test_fresh_entropy_substring_or_context_alias_cannot_bypass_f1(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "crates" / "adapters" / "btc-live" / "src"
            source.mkdir(parents=True)
            (source / "nested.rs").write_text(
                "type Hidden = Secp256k1<All>;\n"
                "fn bad() {\n"
                "let mut secp = Secp256k1::new();\n"
                "secp.seeded_randomize(&not_fresh_entropy());\n"
                "}\n",
                encoding="utf-8",
            )
            result = guard.check_f1_secp_contexts(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("fresh_entropy provenance" in item.message for item in result.findings))
            self.assertTrue(any("aliases are forbidden" in item.message for item in result.findings))

    def test_signet_support_is_absent_or_complete_never_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            absent = guard.check_f5_signet_static(root)
            self.assertTrue(absent.passed)
            self.assertIn("support bundle absent", absent.note)

            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "f5-signet-custom-e2e.sh").write_text(
                "#!/usr/bin/env bash\n", encoding="utf-8"
            )
            partial = guard.check_f5_signet_static(root)
            self.assertFalse(partial.passed)
            self.assertIn("partial Signet bundle", partial.findings[0].message)

    def test_complete_signet_bundle_is_bounded_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            infra = root / "infra" / "signet"
            scripts.mkdir()
            infra.mkdir(parents=True)
            (scripts / "f5-signet-custom-e2e.sh").write_text(
                """#!/usr/bin/env bash
set -Eeuo pipefail
if ! git diff --quiet --; then
    exit 1
fi
if ! git diff --cached --quiet --; then
    exit 1
fi
if git ls-files --error-unmatch -- signer.wif; then
    exit 1
fi
""",
                encoding="utf-8",
            )
            (scripts / "f5-signet-public-e2e.sh").write_text(
                "#!/usr/bin/env bash\nexit 1\n", encoding="utf-8"
            )

            challenge = bytes.fromhex(
                "21030f293b15c1014a5a747712be70543883a204e546fef03fea9ea6d939f6e9f4e0ac"
            )
            magic = hashlib.sha256(
                hashlib.sha256(bytes([len(challenge)]) + challenge).digest()
            ).digest()[:4]
            network = {
                "schema": "dom-interop/f5-custom-signet-network/v1",
                "bitcoin_core": {
                    "version": "31.0.0",
                    "binary_sha256": "1" * 64,
                    "source_sha256": "2" * 64,
                    "official_signet_miner_sha256": "3" * 64,
                },
                "network": {
                    "challenge_type": "p2pk-1-of-1",
                    "challenge": challenge.hex(),
                    "challenge_hash_sha256": hashlib.sha256(challenge).hexdigest(),
                    "message_magic": magic.hex(),
                },
                "topology": {
                    "miner": {
                        "rpc": "127.0.0.1:39443",
                        "p2p": "127.0.0.1:39444",
                        "config": "infra/signet/miner.conf",
                    },
                    "observer": {
                        "rpc": "127.0.0.1:39453",
                        "p2p": "127.0.0.1:39454",
                        "config": "infra/signet/observer.conf",
                    },
                },
                "policy": {
                    "public_signet_required": False,
                    "mainnet_allowed": False,
                    "minimum_confirmations": 2,
                    "conformance_csv_blocks": 17,
                    "production_csv_blocks": 144,
                    "mempool_persistence": False,
                    "wallet_rebroadcast": False,
                },
            }
            terms = {
                "schema": "dom-interop/f5-custom-signet-conformance-terms/v1",
                "network_identity": "infra/signet/network.json",
                "network_kind": "custom-signet-bip325",
                "csv_profile": {
                    "scope": "conformance-only",
                    "blocks": 17,
                    "production_blocks": 144,
                    "production_profile_changed": False,
                },
                "finality_policy": {
                    "minimum_confirmations": 2,
                    "reorg_rows_require_reconfirmation": True,
                },
                "rows": {f"E{index:02d}": {} for index in range(1, 17)},
            }
            network_path = infra / "network.json"
            network_path.write_text(json.dumps(network), encoding="utf-8")
            (infra / "conformance-terms.json").write_text(
                json.dumps(terms), encoding="utf-8"
            )
            (infra / "miner.conf").write_text(
                "signet=1\n"
                f"signetchallenge={guard.CUSTOM_SIGNET_CHALLENGE_HEX}\n"
                "server=1\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n"
                "persistmempool=0\nwalletbroadcast=0\ndnsseed=0\nlistenonion=0\n"
                "rpcport=39443\nport=39444\nconnect=127.0.0.1:39454\n",
                encoding="utf-8",
            )
            (infra / "observer.conf").write_text(
                "signet=1\n"
                f"signetchallenge={guard.CUSTOM_SIGNET_CHALLENGE_HEX}\n"
                "server=1\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n"
                "persistmempool=0\nwalletbroadcast=0\ndnsseed=0\nlistenonion=0\n"
                "rpcport=39453\nport=39454\nconnect=127.0.0.1:39444\n",
                encoding="utf-8",
            )

            result = guard.check_f5_signet_static(root)
            self.assertTrue(result.passed, result.findings)
            self.assertIn("structure checked", result.note)
            self.assertIn("not provenance proof", result.note)

            network["policy"]["minimum_confirmations"] = 1
            network_path.write_text(json.dumps(network), encoding="utf-8")
            weakened = guard.check_f5_signet_static(root)
            self.assertFalse(weakened.passed)
            self.assertIn("confirmation policy drift", weakened.findings[0].message)

    def test_token_only_signet_safety_script_is_rejected(self) -> None:
        insecure = """#!/usr/bin/env bash
git diff --quiet --
git diff --cached --quiet --
git ls-files --error-unmatch -- signer.wif
"""
        self.assertFalse(guard._script_refuses_dirty_or_tracked_signer(insecure))

    def test_signet_safety_tokens_in_comments_are_rejected(self) -> None:
        insecure = """#!/usr/bin/env bash
set -Eeuo pipefail
if ! git diff --quiet --; then
    # exit 1
fi
if ! git diff --cached --quiet --; then
    # exit 1
fi
if git ls-files --error-unmatch -- signer.wif; then
    # exit 1
fi
"""
        self.assertFalse(guard._script_refuses_dirty_or_tracked_signer(insecure))

    def test_signet_safety_rejects_git_override_or_errexit_disable(self) -> None:
        base = """#!/usr/bin/env bash
set -Eeuo pipefail
if ! git diff --quiet --; then
    exit 1
fi
if ! git diff --cached --quiet --; then
    exit 1
fi
if git ls-files --error-unmatch -- signer.wif; then
    exit 1
fi
"""
        self.assertFalse(guard._script_refuses_dirty_or_tracked_signer(base + "git() { :; }\n"))
        self.assertFalse(guard._script_refuses_dirty_or_tracked_signer(base + "set +e\n"))

    def test_duplicate_signet_config_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "miner.conf"
            path.write_text("persistmempool=0\npersistmempool=1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                guard._parse_unique_config(path)

    def test_automation_closure_follows_wrappers_to_manual_signet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "ci_local.sh").write_text(
                '#!/usr/bin/env bash\n"$script_dir/wrapper.sh"\n', encoding="utf-8"
            )
            (scripts / "wrapper.sh").write_text(
                "#!/usr/bin/env bash\n./scripts/f5-signet-public-e2e.sh\n",
                encoding="utf-8",
            )
            result = guard.check_f5_signet_automation(root)
            self.assertFalse(result.passed)
            self.assertTrue(
                any("manual Signet runner" in finding.message for finding in result.findings)
            )

    def test_automation_closure_canonicalizes_same_directory_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "ci_local.sh").write_text(
                "#!/usr/bin/env bash\n./wrapper.sh\n", encoding="utf-8"
            )
            (scripts / "wrapper.sh").write_text(
                "#!/usr/bin/env bash\n./f5-signet-public-e2e.sh\n",
                encoding="utf-8",
            )
            result = guard.check_f5_signet_automation(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("Signet" in item.message for item in result.findings))

    def test_dynamic_repository_automation_dispatch_is_rejected(self) -> None:
        cases = (
            '#!/usr/bin/env bash\nrunner="scripts/$TARGET"\n"$runner"\n',
            '#!/usr/bin/env bash\nrunner="$TARGET"\n"$runner"\n',
        )
        for source in cases:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                scripts = root / "scripts"
                scripts.mkdir()
                (scripts / "ci_local.sh").write_text(source, encoding="utf-8")
                result = guard.check_f5_signet_automation(root)
                self.assertFalse(result.passed)
                self.assertTrue(
                    any("dynamic repository" in item.message for item in result.findings)
                )

    def test_repo_root_dynamic_dispatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "ci_local.sh").write_text(
                '#!/usr/bin/env bash\nrunner="$repo/$TARGET"\n"$runner"\n',
                encoding="utf-8",
            )
            result = guard.check_f5_signet_automation(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("dynamic repository" in item.message for item in result.findings))

    def test_python_process_alias_cannot_hide_signet_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "ci_local.sh").write_text(
                "#!/usr/bin/env bash\npython3 scripts/wrapper.py\n", encoding="utf-8"
            )
            (scripts / "wrapper.py").write_text(
                "from subprocess import run as execute\n"
                'execute(["scripts/f5-signet-public-e2e.sh"], check=True)\n',
                encoding="utf-8",
            )
            result = guard.check_f5_signet_automation(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("Signet" in item.message for item in result.findings))

    def test_python_dynamic_process_alias_is_rejected(self) -> None:
        commands, errors = guard._python_process_commands(
            pathlib.Path("wrapper.py"),
            "import subprocess as process\nprocess.run(command)\n",
        )
        self.assertEqual(commands, [])
        self.assertTrue(any("dynamic process dispatch" in item for item in errors))

        commands, errors = guard._python_process_commands(
            pathlib.Path("wrapper.py"),
            '__import__("subprocess").run(["true"])\n',
        )
        self.assertEqual(commands, [])
        self.assertTrue(any("dynamic process" in item for item in errors))

        commands, errors = guard._python_process_commands(
            pathlib.Path("wrapper.py"),
            "import subprocess\nprocess = subprocess\nexecute = process.run\nexecute(command)\n",
        )
        self.assertEqual(commands, [])
        self.assertTrue(any("dynamic process dispatch" in item for item in errors))

    def test_shell_quote_concatenation_cannot_hide_signet_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "ci_local.sh").write_text(
                '#!/usr/bin/env bash\n./scripts/f5-"sig""net"-public-e2e.sh\n',
                encoding="utf-8",
            )
            result = guard.check_f5_signet_automation(root)
            self.assertFalse(result.passed)
            self.assertTrue(any("Signet" in item.message for item in result.findings))

    def test_rust_signet_support_is_not_an_automation_sink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scripts = root / "scripts"
            rust = root / "crates" / "verifier" / "src"
            scripts.mkdir(parents=True)
            rust.mkdir(parents=True)
            (scripts / "ci_local.sh").write_text("#!/usr/bin/env bash\ntrue\n", encoding="utf-8")
            (rust / "lib.rs").write_text(
                "pub const NETWORK: Network = Network::Signet;\n", encoding="utf-8"
            )
            self.assertTrue(guard.check_f5_signet_automation(root).passed)


class RepositoryContractTests(unittest.TestCase):
    def test_publication_gate_has_independent_official_node_snapshot(self) -> None:
        ci = (ROOT / "scripts" / "ci_local.sh").read_text(encoding="utf-8")
        match = re.search(
            r"readonly -a OFFICIAL_NODE_MEMBERS=\(\n(?P<body>.*?)\n\)",
            ci,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        snapshot = tuple(line.strip() for line in match.group("body").splitlines())
        self.assertEqual(snapshot, tuple(sorted(guard.NODE_MEMBERS)))
        self.assertIn('merge-base --is-ancestor "$publication_ref" HEAD', ci)
        self.assertIn('cat-file -e "$publication_ref:$node_member/Cargo.toml"', ci)

    def test_offline_and_production_cargo_surfaces_are_fail_closed(self) -> None:
        ci = (ROOT / "scripts" / "ci_local.sh").read_text(encoding="utf-8")
        self.assertRegex(
            ci,
            re.compile(
                r'if \[\[ "\$mode" == "--static" \]\]; then\n'
                r'\s+for command_name in cargo rustc rustup forge anvil cast '
                r'bitcoin-cli bitcoind;',
            ),
        )

        for cargo_subcommand in ("check", "clippy", "test"):
            self.assertRegex(
                ci,
                re.compile(
                    rf'cargo {cargo_subcommand} --locked --offline '
                    rf'"\$\{{package_args\[@\]\}}" --all-targets'
                ),
            )

        # Each production gate is a bare `run_gate` invocation: the function
        # counts the failure and the script's exit status carries it.  The
        # former trailing `|| true` neutralised exactly that, and this test
        # once matched on it; it now refuses it.
        blocks = re.findall(
            r'run_gate "production daemon (?P<label>check|clippy|tests)" \\\n'
            r'(?P<command>(?:[ \t]+.*\\\n)*[ \t]+.*)\n',
            ci,
        )
        self.assertEqual([label for label, _ in blocks], ["check", "clippy", "tests"])
        for label, command in blocks:
            expected_subcommand = "test" if label == "tests" else label
            self.assertIn(f"cargo {expected_subcommand} --locked --offline", command)
            self.assertIn("--package dom-interopd", command)
            self.assertIn("--no-default-features --features production", command)
            self.assertIn("--lib --bins", command)
            self.assertNotIn("--all-targets", command)
            self.assertNotIn("|| true", command)
        production_region = ci[ci.index('run_gate "production daemon check"') :]
        production_region = production_region[: production_region.index("Store release-surface")]
        self.assertNotIn("|| true", production_region)

    def test_current_workspace_satisfies_every_absorbed_guard(self) -> None:
        results = guard.validate(ROOT)
        failures = [
            f"{result.name}: {finding.path}:{finding.line}: {finding.message}"
            for result in results
            for finding in result.findings
        ]
        self.assertEqual(failures, [])
        # Pin the exact set, not the count.  A count catches a check that is
        # silently dropped but says nothing about which one, and it has to be
        # edited by hand every time a check is added -- which is how it came to
        # read 9 while validate() returned 12.  It also sat behind the
        # `failures` assertion, so while the two F1 sentinels were failing this
        # line was never reached and the drift was invisible.  Naming them makes
        # a removal fail with the name and an addition fail with the diff.
        self.assertEqual(
            [result.name for result in results],
            [
                "I2 anti-power",
                "I14 unwrap/expect outside tests",
                "I6 println/eprintln/dbg outside tests",
                "F1 Sponsor is frozen with local rejection/registry shape",
                "F2 failpoints/fault injection remain dev-only",
                "F5 C1a stays a dev-only conformance harness",
                "F5 btc-evidence remains verify-only",
                "F5 Signet policy is static-only and disabled",
                "evidence-only Store surface is never a normal dependency"
                " or shipped feature",
                "Store custody traits are implemented only by pinned product types",
                "Store never extracts the adaptor secret",
                "F1 secp contexts use syntactically bound fresh entropy",
            ],
        )


class AuthorshipPolicyTests(unittest.TestCase):
    def _repository(self, directory: str) -> tuple[pathlib.Path, str]:
        root = pathlib.Path(directory)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        subprocess.run(
            ["git", "config", "user.name", "Soren Planck"], cwd=root, check=True
        )
        subprocess.run(
            ["git", "config", "user.email", "sorenplanck@tutamail.com"],
            cwd=root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "commit.gpgsign", "false"], cwd=root, check=True
        )
        marker = root / "marker"
        marker.write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "add", "marker"], cwd=root, check=True)
        subprocess.run(
            ["git", "commit", "--quiet", "-m", "baseline"], cwd=root, check=True
        )
        baseline = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        return root, baseline

    @staticmethod
    def _check(root: pathlib.Path, baseline: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["DOM_AUTHORSHIP_BASELINE"] = baseline
        environment["GIT_DIR"] = str(root / ".git")
        environment["GIT_WORK_TREE"] = str(root)
        return subprocess.run(
            ["scripts/check-authorship.sh", "HEAD"],
            cwd=ROOT,
            env=environment,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_exact_author_and_committer_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, baseline = self._repository(directory)
            (root / "marker").write_text("exact\n", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "commit",
                    "--quiet",
                    "-m",
                    "exact identity\n\n"
                    "Signed-off-by: Soren Planck <sorenplanck@tutamail.com>",
                ],
                cwd=root,
                check=True,
            )
            self.assertEqual(self._check(root, baseline).returncode, 0)

    def test_lowercase_author_or_github_merge_committer_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, baseline = self._repository(directory)
            (root / "marker").write_text("lowercase\n", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=root, check=True)
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_AUTHOR_NAME": "sorenplanck",
                    "GIT_AUTHOR_EMAIL": "sorenplanck@tutamail.com",
                    "GIT_COMMITTER_NAME": "Soren Planck",
                    "GIT_COMMITTER_EMAIL": "sorenplanck@tutamail.com",
                }
            )
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "wrong author"],
                cwd=root,
                env=environment,
                check=True,
            )
            result = self._check(root, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized author name", result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            root, baseline = self._repository(directory)
            (root / "marker").write_text("github\n", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=root, check=True)
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_AUTHOR_NAME": "Soren Planck",
                    "GIT_AUTHOR_EMAIL": "sorenplanck@tutamail.com",
                    "GIT_COMMITTER_NAME": "GitHub",
                    "GIT_COMMITTER_EMAIL": "noreply@github.com",
                }
            )
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "wrong committer"],
                cwd=root,
                env=environment,
                check=True,
            )
            result = self._check(root, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized committer", result.stderr)

    def test_obfuscated_coauthor_trailer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, baseline = self._repository(directory)
            (root / "marker").write_text("trailer\n", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "commit",
                    "--quiet",
                    "-m",
                    "subject\n\nCo-AUTHORED-by : Other <other@example.invalid>",
                ],
                cwd=root,
                check=True,
            )
            result = self._check(root, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("forbidden Co-authored-by trailer", result.stderr)

    def test_self_coauthor_and_third_party_identity_trailers_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, baseline = self._repository(directory)
            (root / "marker").write_text("self coauthor\n", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "commit",
                    "--quiet",
                    "-m",
                    "subject\n\n"
                    "Co-authored-by: Soren Planck <sorenplanck@tutamail.com>",
                ],
                cwd=root,
                check=True,
            )
            result = self._check(root, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("forbidden Co-authored-by trailer", result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            root, baseline = self._repository(directory)
            (root / "marker").write_text("third-party review\n", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "commit",
                    "--quiet",
                    "-m",
                    "subject\n\nReviewed-by: Other Reviewer",
                ],
                cwd=root,
                check=True,
            )
            result = self._check(root, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized identity trailer", result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            root, baseline = self._repository(directory)
            (root / "marker").write_text("wrong signoff\n", encoding="utf-8")
            subprocess.run(["git", "add", "marker"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "commit",
                    "--quiet",
                    "-m",
                    "subject\n\n"
                    "Signed-off-by: soren planck <sorenplanck@tutamail.com>",
                ],
                cwd=root,
                check=True,
            )
            result = self._check(root, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized identity trailer", result.stderr)


if __name__ == "__main__":
    unittest.main()
