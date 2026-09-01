#!/usr/bin/env python3
from __future__ import annotations
import json,re,sys,tomllib
from pathlib import Path

ROOT=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
# The metadata sits beside this script in the delivered package, and under
# docs/interop/xmr-v6 once the installer has copied it into a DOM checkout.
# Crate paths always resolve against ROOT; only the metadata moves. Without
# this the script could only ever run from inside the zip, which is not where
# the gate script calls it from.
META=ROOT
if not (META/'ACTIVE_COMPONENTS.json').is_file():
    installed=ROOT/'docs/interop/xmr-v6'
    if (installed/'ACTIVE_COMPONENTS.json').is_file():META=installed
    else:raise SystemExit(f'ACTIVE_COMPONENTS.json not found under {ROOT}')
meta=json.loads((META/'ACTIVE_COMPONENTS.json').read_text())
active=[ROOT/path for path in meta['workspace_members']]
sidecar=ROOT/meta['external_sidecar']
errors=[];warnings=[];packages={}
allowed_external={'kaystra-core','adapter-dom-real','counterparty-api'}

manifests=[path/'Cargo.toml' for path in active]+[sidecar/'Cargo.toml']
for manifest in manifests:
    if not manifest.is_file():errors.append(f'missing manifest: {manifest.relative_to(ROOT)}');continue
    try:data=tomllib.loads(manifest.read_text())
    except Exception as exc:errors.append(f'TOML parse {manifest.relative_to(ROOT)}: {exc}');continue
    name=data.get('package',{}).get('name')
    if name:
        if name in packages:errors.append(f'duplicate package {name}')
        packages[name]=str(manifest.relative_to(ROOT))
    for section in ('dependencies','dev-dependencies','build-dependencies'):
        for dep,spec in data.get(section,{}).items():
            if isinstance(spec,dict) and 'path' in spec:
                target=(manifest.parent/spec['path']).resolve()
                if not target.exists() and dep not in allowed_external:
                    errors.append(f'missing path dependency {dep}: {manifest.relative_to(ROOT)} -> {spec["path"]}')

sources=[]
for base in active+[sidecar]:
    sources.extend(sorted((base/'src').rglob('*.rs')) if (base/'src').exists() else [])
for rust in sources:
    text=rust.read_text(errors='replace')
    # A test module is not always spelled `#[cfg(test)]`: a module that needs
    # Unix sockets is `#[cfg(all(test, unix))]`. Matching only the bare form
    # made every `unwrap` in such a module look like production code. Only
    # these two shapes count as the start of test code — a `#[cfg(feature =
    # "test-...")]` block is production and stays subject to the checks below.
    cut=re.search(r'#\[cfg\((?:test\)|all\(test[,)])',text)
    production=text[:cut.start()] if cut else text
    rel=rust.relative_to(ROOT)
    for macro in ('todo!(','unimplemented!(','dbg!(','println!('):
        if macro in production:errors.append(f'production placeholder/debug macro {macro}: {rel}')
    if '.unwrap()' in production: errors.append(f'production unwrap: {rel}')
    if '.expect(' in production: errors.append(f'production expect: {rel}')

api=(ROOT/'crates/adapters/xmr-live-sidecar-api/src/lib.rs').read_text()
if 'SecretScalarBytes(<redacted>)' not in api:errors.append('sidecar secret Debug is not redacted')
if re.search(r'pub\s+(spend_scalar|view_scalar|private_view_key)\s*:\s*\[u8;\s*32\]',api):
    errors.append('sidecar API exposes a secret as a raw public array')
if 'auth_tag' not in api or 'API_VERSION_V2' not in api:errors.append('sidecar V2 authentication fields missing')

dleq=(ROOT/'crates/adapters/xmr-dleq-sigma/src/lib.rs').read_text()
for required in ('CrossCurveDLEQ','CrossCurveSecret252','ROLE_XMR_SHARED_SPEND','revealed_dom_secret_to_xmr_scalar','MAX_PROOF_BYTES'):
    if required not in dleq:errors.append(f'DLEQ requirement missing: {required}')
if 'from_bytes_mod_order' in dleq:errors.append('DLEQ setup must not reduce an arbitrary secp scalar modulo ed25519')


registry=(ROOT/'crates/adapters/xmr-claim-registry/src/lib.rs').read_text()
for required in ('TransactionBehavior::Immediate','ClaimReused','SettlementConflict','CLAIM_ID_DOMAIN'):
    if required not in registry:errors.append(f'claim-registry requirement missing: {required}')

bridge=(ROOT/'crates/adapters/xmr-kaystra-bridge/src/lib.rs').read_text()
for required in ('RevealedSecretSinkV1','prepare_exact','delete_secrets_after_durability','submit_exact'):
    if required not in bridge:errors.append(f'bridge requirement missing: {required}')
patch=(META/'patches/dom-real-xmr-secret-forwarding.patch').read_text()
for required in ('pub trait RevealedSecretSinkV1','with_revealed_secret_sink','Ok(revealed)'):
    if required not in patch:errors.append(f'dom-real patch requirement missing: {required}')
store_patch=(META/'patches/store-rustix-std-feature.patch').read_text()
if '"fs", "process", "std"' not in store_patch:errors.append('store rustix patch does not add the std feature')

raw=(ROOT/'crates/adapters/xmr-raw-tx-verify/src/lib.rs').read_text()
for required in ('Transaction::read','transaction.serialize()','transaction.hash()'):
    if required not in raw:errors.append(f'raw tx verification requirement missing: {required}')

license_file=sidecar/'LICENSE'
if not license_file.is_file() or 'GNU GENERAL PUBLIC LICENSE' not in license_file.read_text(errors='ignore'):
    errors.append('full GPL license missing from live sidecar')
source_lock=json.loads((META/'SOURCE_LOCK.json').read_text())
if source_lock['dom_protocol']['commit']!='7ea7f96836730a2b79fb4eaf1f3b8c34b1b511ff':errors.append('DOM source lock changed')
if source_lock['eigenwallet_core']['commit']!='0e17c7f7cd8f0657af176c8852aa4c9949586051':errors.append('Eigenwallet source lock changed')

report={'root':str(ROOT),'metadata_root':str(META),'active_components':len(active),'manifests_parsed':len(manifests),
        'packages':packages,'errors':sorted(set(errors)),'warnings':sorted(set(warnings)),
        'status':'PASS' if not errors else 'FAIL'}
(META/'VALIDATION_REPORT.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
raise SystemExit(0 if not errors else 1)
