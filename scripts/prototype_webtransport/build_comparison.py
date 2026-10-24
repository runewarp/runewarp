#!/usr/bin/env python3
"""THROWAWAY warm-dependency build/link comparison. No other checkout is modified."""
import io
import os
import pathlib
import subprocess
import tarfile
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]
base = 'f3e9a3aa599b3a85e820d2d329bb650fe194579f'
with tempfile.TemporaryDirectory(prefix='runewarp-wt-build-') as scratch:
    baseline = pathlib.Path(scratch)
    archive = subprocess.check_output(['git', 'archive', base, 'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', 'src'], cwd=root)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(baseline, filter='data')
    fixture = (root / 'src/prototype_webtransport/fixture.rs').read_text()
    measure = (root / 'src/prototype_webtransport/measure.rs').read_text()
    measure = measure.replace('experiment::pair, ', '')
    start = measure.index('pub(super) async fn wt(')
    end = measure.index('async fn slots(', start)
    measure = measure[:start] + measure[end:]
    measure = measure.replace('            tokio::time::timeout(STEP, wt(count)).await??;\n', '')
    module = baseline / 'src/prototype_slot_baseline'
    module.mkdir()
    (module / 'fixture.rs').write_text(fixture)
    (module / 'measure.rs').write_text(measure)
    (module / 'mod.rs').write_text('''mod fixture;
mod measure;
type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;
const SERVER: &str = "tunnel.example.test";
const STEP: std::time::Duration = std::time::Duration::from_secs(5);
pub async fn run() -> Result<()> { measure::run().await }
''')
    with (baseline / 'src/lib.rs').open('a') as file:
        file.write('\n#[allow(dead_code)] pub mod prototype_slot_baseline;\n')
    (baseline / 'examples').mkdir()
    (baseline / 'examples/prototype_slot_timing.rs').write_text('''#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    runewarp::prototype_slot_baseline::run().await
}
''')
    env = dict(os.environ, CARGO_TARGET_DIR=str(root / 'target'), RUNEWARP_BUILD_COMMIT=base)
    commands = [
        ('git-pin slots', baseline, 'prototype_slot_timing'),
        ('vendored WT', root, 'prototype_webtransport_timing'),
    ]
    for name, directory, example in commands:
        os.utime(directory / 'src/lib.rs', None)
        print(name, flush=True)
        subprocess.run(['perl', '-e', 'alarm 300; exec @ARGV', '/usr/bin/time', '-p', 'cargo', 'build', '--release', '--locked', '--manifest-path', str(directory / 'Cargo.toml'), '--example', example], cwd=root, env=env, check=True)
        binary = root / 'target/release/examples' / example
        print(f'{name}: {binary.stat().st_size} bytes', flush=True)
