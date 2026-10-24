#!/usr/bin/env python3
"""Generate the reviewable local patch after mechanical import and formatting.

Usage: python3 scripts/prototype_webtransport/vendor_diff.py /path/to/h3-checkout
Uses temporary files, leaves the checkout and vendored source unchanged.
"""
import difflib
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='runewarp-wt-vendor-') as scratch:
    baseline = pathlib.Path(scratch) / 'src/vendor'
    subprocess.run([sys.executable, str(root / 'scripts/prototype_webtransport/import_vendor.py'), sys.argv[1], str(baseline)], check=True)
    subprocess.run(['rustfmt', '--edition', '2024', str(baseline / 'mod.rs')], check=True)
    patch = []
    for old in sorted(baseline.rglob('*.rs')):
        relative = old.relative_to(baseline)
        new = root / 'src/vendor' / relative
        path = f'src/vendor/{relative}'
        patch.extend(difflib.unified_diff(old.read_text().splitlines(keepends=True), new.read_text().splitlines(keepends=True), fromfile=f'a/{path}', tofile=f'b/{path}'))
    output = root / 'scripts/prototype_webtransport/vendor.patch'
    # Git accepts empty context lines without a prefix; avoid trailing whitespace.
    output.write_text(''.join(patch).replace('\n \n', '\n\n'))
    subprocess.run(['git', 'apply', '--check', str(output)], cwd=scratch, check=True)
    subprocess.run(['git', 'apply', str(output)], cwd=scratch, check=True)
    for old in baseline.rglob('*.rs'):
        assert old.read_bytes() == (root / 'src/vendor' / old.relative_to(baseline)).read_bytes(), str(old)
    print(f'{output.relative_to(root)}: exact replay verified')
