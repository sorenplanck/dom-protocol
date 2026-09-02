# README Visual Identity Report

**Input commit:** `32b152bd81394d4236f6a43630b54aaa37354245`
**Initial branch:** `main`
**Initial working tree:** clean
**Result:** README_VISUAL_IDENTITY_COMPLETE

## Scope and repository integrity

Only `README.md`, `assets/dom-wallet-v3-banner.svg`, and this report were written. The initial `git status --short` and `git diff --stat` were empty. The final file-set check is limited to these same three paths. No specification, Cargo, workflow, source, test, script, DOM Protocol, or reference-study file was edited.

## Inputs read

* `README.md` at the input commit and its README history.
* `specs/README.md`.
* `reports/FOUNDATIONAL_SPECIFICATIONS_PASS1.md`.
* `reports/FOUNDATIONAL_SPECIFICATIONS_PASS2.md`.
* `docs/ARCHITECTURE.md`, `docs/ENGINEERING_SOURCES.md`, `docs/REFERENCE_BASELINE.md`, `docs/EPIC_DOM_ADOPTION_MATRIX.md`, `docs/CONFIRMED_DESIGN_INPUTS.md`, and `docs/SPECIFICATION_GATE.md`.
* `/home/leonardov/dom-protocol/wallet-desktop/ui/index.html`, `wallet-desktop/ui/assets/dom-coin.png`, and `wallet-desktop/ui/styles.css` as visual-reference evidence only.

## README baseline and copied-content diagnosis

The selected substantive baseline is commit `69fe8f1` (`Align README with DOM visual identity`), the latest local README revision containing all required markers: `Why V3 Exists`, `DOM-W2-SYNC-001`, `Target Architecture`, and `Planned Workspace`. Its predecessor `062822c` has the same wallet-focused structure; the diff between those revisions changes badge colors only.

The restored README is wallet-specific. It excludes website-only and protocol-only categories: supply, issuance, mining, monetary-ledger data, genesis claims, protocol navigation, landing-page slogans, consensus marketing, and general protocol README prose. The retained DOM references are limited to wallet governing constraints. The substantive correction updates stale status text from five first-pass specifications to the repository-proven state: specifications `0001` through `0012` completed first pass and all indexed specifications remain DRAFT.

## Substantive-content result

The README preserves the required wallet sections: Why V3 Exists, DOM Sovereignty, Current Project Status, Core Design Principles, DOM-W2-SYNC-001, Target Architecture, Planned Workspace, Target Capabilities, Security Model, Verification Strategy, Implementation Gates, Specifications and Documentation, Engineering References, Building, Contributing, Authorship, and License.

It states the governing rule exactly: **DOM semantics > Epic strategy.** DOM Wallet V3 remains an independent DOM-native implementation. DOM Wallet V1 and V2 contribute DOM-specific experience and validated properties; Epic Wallet contributes protected properties and engineering lessons only. No Epic implementation or protocol behavior is copied or authoritative.

## Repository-status evidence

`specs/README.md` lists `0000` as DRAFT and `0001` through `0012` as DRAFT with completed first passes. It states that Gate 1 remains IN PROGRESS until adversarial cross-review, blocking-decision closure, REVIEW promotion, and ACCEPTED status. The README status notice, table, and Gate 1 evidence now match that source. No functional wallet, completed crate, audit, production readiness, mainnet readiness, or real-fund authorization is claimed.

## Official DOM visual identity

### Symbol evidence

The current DOM desktop web header and onboarding surface reference `wallet-desktop/ui/assets/dom-coin.png` from `/home/leonardov/dom-protocol/wallet-desktop/ui/index.html` at the two DOM image references in the brand surface. That raster medallion is the local official DOM symbol evidence available in the DOM Protocol repository. No authoritative reusable vector or separate website source was present in that checkout.

The banner uses a proportional vector rendering of the medallion form: concentric circular relief, radial marks, central DOM legend, and engraved bronze treatment. The medallion is rendered with equal `cx` and `cy` radii inside one translated group; no nonuniform transform, stretch, alternate token symbol, or recoloring outside the official dark-bronze-paper material treatment is used. No raster was extracted or embedded because the official local source is a 499074-byte PNG and no reusable vector source exists.

### Palette

| Token | Hex | Banner use |
|---|---|---|
| black | `#0a0807` | field and medallion interior |
| black-soft | `#14100d` | relief field |
| line | `#2a2018` | ledger grid and rules |
| line-bright | `#3d2f22` | secondary geometry |
| bronze | `#b87333` | medallion and controlled accents |
| bronze-bright | `#d4914a` | restrained emphasis |
| bronze-deep | `#7a4a22` | radial marks and continuity lines |
| patina | `#8a6a3f` | small medallion markers |
| paper | `#e6ddd0` | wordmark and major title |
| paper-dim | `#b8aa97` | subtitle |
| fog | `#7d7060` | technical metadata |

### Typography and geometry

The major title and medallion legend use `Cinzel, Georgia, Times New Roman, serif`; technical labels use `IBM Plex Mono, SFMono-Regular, Consolas, Liberation Mono, monospace`; supporting copy uses `Inter, Arial, Helvetica, sans-serif`. These are local fallback stacks only. The banner has `width="1600"`, `height="480"`, and `viewBox="0 0 1600 480"`; its title and subtitle remain readable at the README render width of 760 pixels.

## Badge validation

The centered badge row retains only accurate labels: Specification First Pass, Rust, DOM Wallet V3, and Specification Driven. Its colors are limited to the DOM dark-bronze palette: `#b87333`, `#7a4a22`, `#3d2f22`, and `#8a6a3f`. No audit, production, mainnet, release, build, coverage, or license badge was added.

## Safety and link validation

The SVG contains no remote URL, remote font import, script, foreignObject, event handler, JavaScript, animation, external image, stylesheet link, or data-image dependency. It uses only SVG geometry, text, local font fallback names, and the XML namespace. The README relative links target repository files listed in the specifications and documentation section, including both foundational-pass reports. The README excludes prohibited automated-tool attribution and excludes unsupported audited, production-ready, live-mainnet, bug-free, completed-wallet, and real-fund authorization claims.

## Validation commands

```text
git status --short
git diff --check
git diff --name-only
git diff -- README.md assets/dom-wallet-v3-banner.svg reports/README_VISUAL_IDENTITY_REPORT.md
rg -n "DOM Wallet V3|Why V3 Exists|DOM Sovereignty|DOM semantics > Epic strategy|DOM-W2-SYNC-001|Target Architecture|Planned Workspace|Security Model|Verification Strategy|Implementation Gates" README.md
rg -n -i "supply|issuance|mining|monetary ledger|genesis|protocol navigation|landing-page thesis" README.md
rg -n -i "<script\b|<foreignObject\b|javascript:|[[:space:]]on[a-z]+[[:space:]]*=|@import|<image\b|<animate\b" assets/dom-wallet-v3-banner.svg
```

The dedicated XML parser command could not run in this session because the managed sandbox returned `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` before reading the file. The complete SVG was inspected as XML source; its element nesting and quoted attributes are well formed. This environmental limitation did not modify repository content.

## Verdict

README_VISUAL_IDENTITY_COMPLETE
