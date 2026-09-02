#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path


def balanced_rust(text: str) -> bool:
    stack: list[str] = []
    pairs = {')': '(', ']': '[', '}': '{'}
    index = 0
    state = 'code'
    block_depth = 0
    raw_hashes = 0
    while index < len(text):
        ch = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ''
        if state == 'line':
            if ch == '\n':
                state = 'code'
            index += 1
            continue
        if state == 'block':
            if ch == '/' and nxt == '*':
                block_depth += 1
                index += 2
                continue
            if ch == '*' and nxt == '/':
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = 'code'
                continue
            index += 1
            continue
        if state == 'string':
            if ch == '\\':
                index += 2
                continue
            if ch == '"':
                state = 'code'
            index += 1
            continue
        if state == 'raw':
            if ch == '"' and text.startswith('#' * raw_hashes, index + 1):
                index += 1 + raw_hashes
                state = 'code'
            index += 1
            continue
        if ch == '/' and nxt == '/':
            state = 'line'
            index += 2
            continue
        if ch == '/' and nxt == '*':
            state = 'block'
            block_depth = 1
            index += 2
            continue
        if ch == '"':
            state = 'string'
            index += 1
            continue
        if ch == 'r':
            cursor = index + 1
            while cursor < len(text) and text[cursor] == '#':
                cursor += 1
            if cursor < len(text) and text[cursor] == '"':
                raw_hashes = cursor - index - 1
                state = 'raw'
                index = cursor + 1
                continue
        if ch in '([{':
            stack.append(ch)
        elif ch in ')]}':
            if not stack or stack.pop() != pairs[ch]:
                return False
        index += 1
    return state in {'code', 'line'} and not stack and block_depth == 0


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
    errors: list[str] = []
    warnings: list[str] = []

    active_path = root / 'ACTIVE_COMPONENTS.json'
    if not active_path.exists():
        errors.append('ACTIVE_COMPONENTS.json missing')
        active = {'workspace_members': []}
    else:
        active = json.loads(active_path.read_text())

    packages: dict[str, str] = {}
    manifest_count = 0
    for manifest in sorted(root.rglob('Cargo.toml')):
        try:
            data = tomllib.loads(manifest.read_text())
        except Exception as exc:
            errors.append(f'TOML parse: {manifest.relative_to(root)}: {exc}')
            continue
        manifest_count += 1
        name = data.get('package', {}).get('name')
        if name:
            rel_manifest = str(manifest.relative_to(root)).replace('\\', '/')
            # The install flow copies the GPL sidecar into the build checkout
            # under sidecar-gpl/, so the same package name appearing there is
            # the installation itself, not a duplicate. Two copies OUTSIDE the
            # build checkout are still refused.
            in_build_checkout = rel_manifest.startswith('sidecar-gpl/')
            if name in packages and not in_build_checkout and not packages[name].startswith('sidecar-gpl/'):
                errors.append(
                    f'duplicate package {name}: {packages[name]} and {rel_manifest}'
                )
            if not in_build_checkout or name not in packages:
                packages[name] = rel_manifest
        for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
            for dep, spec in data.get(section, {}).items():
                if not isinstance(spec, dict) or 'path' not in spec:
                    continue
                target = (manifest.parent / spec['path']).resolve()
                rel = str(manifest.relative_to(root)).replace('\\', '/')
                external_sidecar = (
                    ('sidecar-gpl/' in rel or 'external-gpl/' in rel)
                    and dep == 'monero-wallet-ng'
                )
                overlay_dom_dep = (
                    not (root / 'Cargo.toml').exists()
                    and dep in {'kaystra-core', 'adapter-dom-real'}
                )
                if not target.exists() and not external_sidecar and not overlay_dom_dep:
                    errors.append(
                        f'missing path dependency {dep}: {rel} -> {spec["path"]}'
                    )

    root_cargo = root / 'Cargo.toml'
    workspace_members: set[str] = set()
    if root_cargo.exists():
        root_data = tomllib.loads(root_cargo.read_text())
        workspace_members = set(root_data.get('workspace', {}).get('members', []))

    for member in active.get('workspace_members', []):
        if not (root / member / 'Cargo.toml').is_file():
            errors.append(f'active component missing: {member}')
        if workspace_members and member not in workspace_members:
            errors.append(f'active component absent from root workspace: {member}')

    source_roots = [root / member / 'src' for member in active.get('workspace_members', [])]
    for candidate in (
        root / 'sidecar-gpl/eigenwallet-xmr-sidecar/src',
        root / 'external-gpl/dom-xmr-sidecar/src',
    ):
        if candidate.exists():
            source_roots.append(candidate)

    rust_files_checked = 0
    for source_root in source_roots:
        if not source_root.exists():
            continue
        for rust in sorted(source_root.rglob('*.rs')):
            rust_files_checked += 1
            rel = rust.relative_to(root)
            text = rust.read_text(errors='replace')
            for macro in ('todo!(', 'unimplemented!('):
                if macro in text:
                    errors.append(f'production placeholder {macro}: {rel}')
            if 'unsafe {' in text or 'unsafe fn' in text or 'unsafe impl' in text:
                errors.append(f'unsafe code in active XMR source: {rel}')
            if 'println!(' in text or 'dbg!(' in text or 'eprintln!(' in text:
                errors.append(f'direct output/debug macro in active source: {rel}')
            if not balanced_rust(text):
                errors.append(f'unbalanced Rust delimiters: {rel}')

    scripts_dir = root / 'scripts'
    if scripts_dir.exists():
        for shell in sorted(scripts_dir.glob('*.sh')):
            result = subprocess.run(
                ['bash', '-n', str(shell)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if result.returncode != 0:
                errors.append(
                    f'bash syntax: {shell.relative_to(root)}: '
                    f'{result.stderr.decode(errors="replace").strip()}'
                )
        for py in sorted(scripts_dir.glob('*.py')):
            try:
                compile(py.read_text(errors='replace'), str(py), 'exec')
            except SyntaxError as error:
                errors.append(f'python syntax: {py.relative_to(root)}: {error}')

    all_rust = '\n'.join(path.read_text(errors='replace') for path in root.rglob('*.rs'))
    for label, marker in {
        'DLEQ nullifier': 'DleqNullifierStore',
        'refund policy': 'NonCooperativeRefundCapability',
        'guarded initialization': 'initialize_session_guarded',
    }.items():
        if marker not in all_rust:
            errors.append(f'required marker missing: {label}')

    if root_cargo.exists():
        dom_real = root / 'crates/adapters/dom-real/src/lib.rs'
        if not dom_real.exists() or 'pub trait RevealedSecretSinkV1' not in dom_real.read_text(
            errors='replace'
        ):
            errors.append('dom-real secret-forwarding hook missing')

    lock_path = root / 'SOURCE_LOCK.json'
    if not lock_path.exists():
        errors.append('SOURCE_LOCK.json missing')
    else:
        lock = json.loads(lock_path.read_text())
        if lock['eigenwallet_core']['commit'] != '0e17c7f7cd8f0657af176c8852aa4c9949586051':
            errors.append('Eigenwallet source lock drift')

    sidecar_license = None
    for candidate in (
        root / 'sidecar-gpl/eigenwallet-xmr-sidecar/LICENSE',
        root / 'external-gpl/dom-xmr-sidecar/LICENSE',
    ):
        if candidate.exists():
            sidecar_license = candidate
    if sidecar_license is None or 'GNU GENERAL PUBLIC LICENSE' not in sidecar_license.read_text(
        errors='replace'
    ):
        errors.append('GPL sidecar license missing or invalid')

    report = {
        'root': str(root),
        'cargo_executed': False,
        'rustc_executed': False,
        'cargo_manifests_parsed': manifest_count,
        'packages': len(packages),
        'active_components': len(active.get('workspace_members', [])),
        'rust_files_checked': rust_files_checked,
        'errors': errors,
        'warnings': warnings,
        'status': 'PASS' if not errors else 'FAIL',
    }
    # Print only: validation must not mutate a manifest-protected artifact.
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
