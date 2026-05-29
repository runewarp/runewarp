use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn run_validator(repo_root: &Path, args: &[&str]) -> Output {
    run_validator_with_path(repo_root, args, None)
}

fn run_validator_with_path(
    repo_root: &Path,
    args: &[&str],
    extra_path_dir: Option<&Path>,
) -> Output {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("validate-install-surfaces.sh");

    let mut command = Command::new("bash");
    command
        .arg(script_path)
        .args(args)
        .arg("--repo-root")
        .arg(repo_root);

    if let Some(extra_path_dir) = extra_path_dir {
        let current_path = std::env::var("PATH").unwrap();
        command.env(
            "PATH",
            format!("{}:{}", extra_path_dir.display(), current_path),
        );
    }

    command.output().unwrap()
}

fn write_minimal_binary_crate(repo_root: &Path, version: &str) {
    fs::create_dir_all(repo_root.join("src")).unwrap();
    fs::write(
        repo_root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"install-surface-fixture\"\nversion = \"{version}\"\nedition = \"2024\"\nlicense = \"Apache-2.0\"\n"
        ),
    )
    .unwrap();
    fs::write(
        repo_root.join("src").join("main.rs"),
        "fn main() {\n    if std::env::args().nth(1).as_deref() == Some(\"--version\") {\n        println!(\"install-surface-fixture {}\", env!(\"CARGO_PKG_VERSION\"));\n        return;\n    }\n\n    println!(\"fixture\");\n}\n",
    )
    .unwrap();

    let status = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(repo_root)
        .status()
        .unwrap();
    assert!(status.success());
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[test]
fn cargo_install_mode_installs_the_binary_and_checks_its_version() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let output = run_validator(
        temp_dir.path(),
        &[
            "cargo-install",
            "--bin-name",
            "install-surface-fixture",
            "--expected-version",
            "0.3.1",
        ],
    );

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn package_readiness_mode_uses_the_sparse_crates_io_protocol() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let fake_bin_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin_dir).unwrap();
    let observed_protocol = temp_dir.path().join("observed-protocol.txt");
    write_executable(
        &fake_bin_dir.join("cargo"),
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"${{CARGO_REGISTRIES_CRATES_IO_PROTOCOL:-}}\" > \"{}\"\nexit 0\n",
            observed_protocol.display()
        ),
    );

    let output =
        run_validator_with_path(temp_dir.path(), &["package-readiness"], Some(&fake_bin_dir));

    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read_to_string(observed_protocol).unwrap(), "sparse\n");
}

#[test]
fn registry_install_mode_retries_until_the_registry_surface_is_available() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let fake_bin_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin_dir).unwrap();
    let attempts_file = temp_dir.path().join("registry-install-attempts.txt");
    write_executable(
        &fake_bin_dir.join("cargo"),
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nattempts_file=\"{attempts_file}\"\ncount=0\nif [[ -f \"$attempts_file\" ]]; then\n  count=\"$(cat \"$attempts_file\")\"\nfi\ncount=$((count + 1))\nprintf '%s' \"$count\" > \"$attempts_file\"\nif [[ \"$1\" != \"install\" ]]; then\n  exit 1\nfi\nif (( count < 3 )); then\n  printf 'not yet available\\n' >&2\n  exit 1\nfi\nshift\nroot=''\ncrate=''\nwhile (($#)); do\n  case \"$1\" in\n    --root)\n      root=\"$2\"\n      shift 2\n      ;;\n    --version)\n      shift 2\n      ;;\n    --locked)\n      shift\n      ;;\n    *)\n      crate=\"$1\"\n      shift\n      ;;\n  esac\ndone\nmkdir -p \"$root/bin\"\nprintf '#!/usr/bin/env bash\\nprintf \"%%s\\\\n\" \"%%s 0.3.1\"\\n' \"$crate\" > \"$root/bin/$crate\"\nchmod +x \"$root/bin/$crate\"\n",
            attempts_file = attempts_file.display()
        ),
    );

    let output = run_validator_with_path(
        temp_dir.path(),
        &[
            "registry-install",
            "--crate-name",
            "install-surface-fixture",
            "--bin-name",
            "install-surface-fixture",
            "--expected-version",
            "0.3.1",
            "--retry-attempts",
            "3",
            "--retry-delay-seconds",
            "0",
        ],
        Some(&fake_bin_dir),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read_to_string(attempts_file).unwrap(), "3");
}

#[test]
fn docker_registry_image_mode_pulls_and_runs_the_released_image() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let fake_bin_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin_dir).unwrap();
    let commands_file = temp_dir.path().join("docker-commands.txt");
    write_executable(
        &fake_bin_dir.join("docker"),
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$*\" >> \"{}\"\nif [[ \"$1\" == \"pull\" ]]; then\n  exit 0\nfi\nif [[ \"$1\" == \"run\" ]]; then\n  printf 'Usage: runewarp\\n'\n  exit 0\nfi\nexit 1\n",
            commands_file.display()
        ),
    );

    let output = run_validator_with_path(
        temp_dir.path(),
        &[
            "docker-registry-image",
            "--image-ref",
            "docker.io/runewarp/runewarp:0.1.0",
            "--expected-text",
            "Usage: runewarp",
            "--probe-arg",
            "--help",
        ],
        Some(&fake_bin_dir),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(commands_file).unwrap(),
        "pull docker.io/runewarp/runewarp:0.1.0\nrun --rm docker.io/runewarp/runewarp:0.1.0 --help\n"
    );
}

#[test]
fn docker_registry_image_mode_retries_until_the_image_is_available() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let fake_bin_dir = temp_dir.path().join("fake-bin");
    fs::create_dir_all(&fake_bin_dir).unwrap();
    let attempts_file = temp_dir.path().join("docker-pull-attempts.txt");
    write_executable(
        &fake_bin_dir.join("docker"),
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nattempts_file=\"{attempts_file}\"\ncount=0\nif [[ -f \"$attempts_file\" ]]; then\n  count=\"$(cat \"$attempts_file\")\"\nfi\nif [[ \"$1\" == \"pull\" ]]; then\n  count=$((count + 1))\n  printf '%s' \"$count\" > \"$attempts_file\"\n  if (( count < 3 )); then\n    printf 'manifest unknown\\n' >&2\n    exit 1\n  fi\n  exit 0\nfi\nif [[ \"$1\" == \"run\" ]]; then\n  printf 'runewarp 0.1.0\\n'\n  exit 0\nfi\nexit 1\n",
            attempts_file = attempts_file.display()
        ),
    );

    let output = run_validator_with_path(
        temp_dir.path(),
        &[
            "docker-registry-image",
            "--image-ref",
            "docker.io/runewarp/runewarp:0.1.0",
            "--expected-version",
            "0.1.0",
            "--retry-attempts",
            "3",
            "--retry-delay-seconds",
            "0",
        ],
        Some(&fake_bin_dir),
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read_to_string(attempts_file).unwrap(), "3");
}

#[test]
fn package_readiness_mode_accepts_a_publishable_crate() {
    let temp_dir = TempDir::new().unwrap();
    write_minimal_binary_crate(temp_dir.path(), "0.3.1");

    let output = run_validator(temp_dir.path(), &["package-readiness"]);

    assert!(output.status.success(), "{output:?}");
}
