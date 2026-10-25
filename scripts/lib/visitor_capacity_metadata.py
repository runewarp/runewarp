"""Portable benchmark provenance, without machine-local invocation paths."""

import hashlib
import json
from pathlib import Path


def portable_invocation(argv, binary):
    # Output and executable locations are local bookkeeping, not reproduction inputs.
    # Retain only the two workload options, whose values come from parsed argparse input.
    command = ['python3', 'scripts/benchmark-visitor-capacity', '--output', '<output-directory>']
    for option in ['--cooldown-seconds', '--scenarios']:
        if option in argv:
            start = argv.index(option)
            end = start + 1
            while end < len(argv) and not argv[end].startswith('--'):
                end += 1
            command.extend(argv[start:end])
    with Path(binary).open('rb') as executable:
        digest = hashlib.file_digest(executable, 'sha256').hexdigest()
    return {'command': command, 'test_binary_sha256': digest}


def rust_source_sha256(root):
    """Fingerprint compiled Rust inputs, including archived source outside Git's file list."""
    root = Path(root)
    files = [root / 'Cargo.toml', root / 'Cargo.lock', *sorted((root / 'src').rglob('*.rs'))]
    digest = hashlib.sha256()
    for file in files:
        digest.update(file.relative_to(root).as_posix().encode() + b'\0')
        digest.update(file.read_bytes() + b'\0')
    return digest.hexdigest()


def verify_binary_provenance(directory, expected):
    actual = json.loads((Path(directory) / 'build-provenance.json').read_text())
    if actual.get('rust_source_sha256') != expected:
        raise ValueError('benchmark binary source mismatch; rebuild in a separate CARGO_TARGET_DIR')
