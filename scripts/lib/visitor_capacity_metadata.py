"""Portable benchmark provenance, without machine-local invocation paths."""

import hashlib
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
