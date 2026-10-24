#!/usr/bin/env python3
"""THROWAWAY: import hyperium/h3 source as modules; never reads project secrets."""
import pathlib
import re
import shutil
import subprocess
import sys

revision = sys.argv[3] if len(sys.argv) > 3 else '43745ad87e95b0c035ac9c547aad467303213425'
upstream = pathlib.Path(sys.argv[1]).resolve()
actual = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True).strip()
if actual != revision:
    raise SystemExit(f'expected {revision}, got {actual}')
root = pathlib.Path(__file__).resolve().parents[2]
destination = pathlib.Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else root / 'src/vendor'
destination.mkdir(parents=True, exist_ok=True)
for package in ['h3', 'h3-quinn', 'h3-datagram', 'h3-webtransport']:
    module = package.replace('-', '_')
    target = destination / module
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(upstream / package / 'src', target)
    shutil.copy(upstream / 'LICENSE', target / 'LICENSE-MIT')
    (target / 'lib.rs').rename(target / 'mod.rs')
    for path in target.rglob('*.rs'):
        source = path.read_text()
        # Expose the extension/backend internals inside this package only.
        source = re.sub(r'#\[cfg\(not\(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"\)\)\)\]\n(?:#\[[^\n]+\]\n)*[^\n]+\n', '', source)
        source = source.replace('#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]\n', '')
        source = source.replace('#[cfg(feature = "datagram")]\n', '')
        source = source.replace('#[cfg(test)]', '#[cfg(any())]')
        source = source.replace('#[cfg(not(test))]', '#[cfg(all())]')
        source = source.replace('feature = "tracing"', 'any()')
        source = source.replace('feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"', 'all()')
        source = source.replace('Some(ref n)', 'Some(n)')
        source = source.replace('pub struct StreamId(#[cfg(all())] u64, #[cfg(any())] pub(crate) u64);', 'pub struct StreamId(u64);')
        source = source.replace('pub(crate) mod connection_error_creators;', 'pub mod connection_error_creators;')
        source = source.replace('#[cfg(any())]\nextern crate self as h3;', '')
        source = re.sub(r'#\[cfg\(not\(feature = [^\n]+\n(?:#\[[^\n]+\]\n)*(?:pub(?:\(crate\))? )?mod [^\n]+\n', '', source)
        source = re.sub(r'\bcrate::', f'crate::vendor::{module}::', source)
        source = re.sub(r'\bcrate\{', f'crate::vendor::{module}' + '{', source)
        source = source.replace('use crate::{', f'use crate::vendor::{module}::' + '{')
        for dep in ['h3_quinn', 'h3_datagram', 'h3_webtransport', 'h3']:
            source = re.sub(r'(?<![\w:])' + dep + r'::', f'crate::vendor::{dep}::', source)
        # Doctests are separate crates, so their references need the host package name.
        source = ''.join(line.replace('crate::vendor::', 'runewarp::vendor::')
                         if line.lstrip().startswith(('///', '//!')) else line
                         for line in source.splitlines(keepends=True))
        if path.name == 'varint.rs':
            source = source.replace('/// # Safety', '/// Range invariant')
            source = source.replace('pub const unsafe fn from_u64_unchecked(x: u64) -> Self {\n        VarInt(x)', 'pub const fn from_u64_unchecked(x: u64) -> Self {\n        assert!(x < (1 << 62));\n        VarInt(x)')
        source = source.replace('../../../h3-quinn/src/lib.rs', '../../h3_quinn/mod.rs')
        # Preserve Rust 2021 opaque-return capture rules inside the 2024 host crate.
        source = source.replace('Option<impl Buf>', 'Option<impl Buf + use<S, B>>')
        path.write_text(source)
(destination / 'mod.rs').write_text('''//! THROWAWAY vendored HTTP/3 stack. MIT notices accompany each module.
#![forbid(unsafe_code)]
pub mod h3;
pub mod h3_quinn;
pub mod h3_datagram;
pub mod h3_webtransport;
''')
