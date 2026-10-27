use std::process::{Command, Stdio};
use std::time::Duration;

use runewarp::CertificateOwner;

// A real child process verifies the OS lock, rather than a same-process mutex.
#[test]
fn owner_process() {
    let Some(directory) = std::env::var_os("RUNEWARP_TEST_OWNER_DIRECTORY") else {
        return;
    };
    match CertificateOwner::try_acquire(std::path::Path::new(&directory)).unwrap() {
        Some(_owner) => {
            println!("owner acquired");
            if std::env::var_os("RUNEWARP_TEST_OWNER_HOLD").is_some() {
                std::thread::sleep(Duration::from_secs(30));
            }
        }
        None => std::process::exit(42),
    }
}

#[test]
fn a_stable_process_lock_survives_handle_drop_and_dies_with_its_process() {
    use std::io::{BufRead, BufReader};
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let child = || {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "owner_process", "--nocapture"])
            .env("RUNEWARP_TEST_OWNER_DIRECTORY", directory.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    };
    let mut owner = child()
        .env("RUNEWARP_TEST_OWNER_HOLD", "1")
        .spawn()
        .unwrap();
    let mut output = BufReader::new(owner.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        if output.read_line(&mut line).unwrap() == 0 {
            let error = owner.wait_with_output().unwrap();
            panic!(
                "owner failed to start: {}",
                String::from_utf8_lossy(&error.stderr)
            );
        }
        if line.contains("owner acquired") {
            break;
        }
        line.clear();
    }
    assert_eq!(child().status().unwrap().code(), Some(42));
    owner.kill().unwrap();
    owner.wait().unwrap();
    assert!(child().status().unwrap().success());
    let acquired = CertificateOwner::try_acquire(directory.path())
        .unwrap()
        .unwrap();
    drop(acquired);
    assert_eq!(
        child().status().unwrap().code(),
        Some(42),
        "ownership lasts until process exit"
    );
}
