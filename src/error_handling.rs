use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::process::ExitCode;

pub(crate) enum RunError {
    Cli(clap::Error),
    Logged,
    Other(Box<dyn Error>),
}

#[derive(Debug)]
pub(crate) enum RunTermination {
    Clap(clap::Error),
    Exit(ExitCode),
}

#[derive(Debug)]
pub(crate) struct LoggedRuntimeError;

impl fmt::Display for LoggedRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("runtime failure already logged")
    }
}

impl Error for LoggedRuntimeError {}

pub(crate) fn classify_runtime_error(error: Box<dyn Error>) -> RunError {
    if error.downcast_ref::<LoggedRuntimeError>().is_some() {
        RunError::Logged
    } else {
        RunError::Other(error)
    }
}

pub(crate) fn finish_run(result: Result<(), RunError>, stderr: &mut impl Write) -> RunTermination {
    match result {
        Ok(()) => RunTermination::Exit(ExitCode::SUCCESS),
        Err(RunError::Cli(error)) => RunTermination::Clap(error),
        Err(RunError::Logged) => RunTermination::Exit(ExitCode::FAILURE),
        Err(RunError::Other(error)) => {
            let _ = writeln!(stderr, "{error}");
            RunTermination::Exit(ExitCode::FAILURE)
        }
    }
}

pub(crate) async fn finish_run_after<Fut, StderrFactory, Stderr>(
    run: Fut,
    stderr_factory: StderrFactory,
) -> RunTermination
where
    Fut: Future<Output = Result<(), RunError>>,
    StderrFactory: FnOnce() -> Stderr,
    Stderr: Write,
{
    match run.await {
        Ok(()) => RunTermination::Exit(ExitCode::SUCCESS),
        Err(RunError::Cli(error)) => RunTermination::Clap(error),
        Err(RunError::Logged) => RunTermination::Exit(ExitCode::FAILURE),
        Err(RunError::Other(error)) => {
            let mut stderr = stderr_factory();
            finish_run(Err(RunError::Other(error)), &mut stderr)
        }
    }
}

pub(crate) fn logged_runtime_failure(error: Box<dyn Error>) -> Box<dyn Error> {
    runewarp::runtime_log::emit(runewarp::runtime_log::EventLevel::Error, &error.to_string());
    Box::new(LoggedRuntimeError)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    use clap::{Command, error::ErrorKind};
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    use super::{
        RunError, RunTermination, classify_runtime_error, finish_run, finish_run_after,
        logged_runtime_failure,
    };

    #[derive(Default)]
    struct SharedStderrState {
        locked: bool,
        buffer: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct SharedStderr(Arc<(Mutex<SharedStderrState>, Condvar)>);

    struct HeldStderr(SharedStderr);

    impl SharedStderr {
        fn lock(&self) -> HeldStderr {
            let (state, ready) = &*self.0;
            let mut guard = state.lock().expect("stderr state mutex poisoned");
            while guard.locked {
                guard = ready
                    .wait(guard)
                    .expect("stderr state mutex poisoned while waiting");
            }
            guard.locked = true;
            HeldStderr(self.clone())
        }

        fn read(&self) -> String {
            let (state, _) = &*self.0;
            String::from_utf8(
                state
                    .lock()
                    .expect("stderr state mutex poisoned")
                    .buffer
                    .clone(),
            )
            .expect("stderr buffer must stay valid UTF-8")
        }
    }

    impl Write for HeldStderr {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let (state, _) = &*self.0.0;
            state
                .lock()
                .expect("stderr state mutex poisoned")
                .buffer
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for HeldStderr {
        fn drop(&mut self) {
            let (state, ready) = &*self.0.0;
            let mut guard = state.lock().expect("stderr state mutex poisoned");
            guard.locked = false;
            ready.notify_one();
        }
    }

    fn assert_exit_code(termination: RunTermination, expected: ExitCode) {
        match termination {
            RunTermination::Exit(code) => assert_eq!(code, expected),
            RunTermination::Clap(error) => {
                panic!(
                    "expected exit code {expected:?}, got clap error {:?}",
                    error.kind()
                )
            }
        }
    }

    #[test]
    fn finish_run_returns_success_for_ok_result() {
        let mut stderr = Vec::new();

        let termination = finish_run(Ok(()), &mut stderr);

        assert_exit_code(termination, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
    }

    #[test]
    fn finish_run_returns_failure_and_writes_message_for_other_error() {
        let mut stderr = Vec::new();

        let termination = finish_run(
            Err(RunError::Other(io::Error::other("boom").into())),
            &mut stderr,
        );

        assert_exit_code(termination, ExitCode::FAILURE);
        assert_eq!(String::from_utf8(stderr).unwrap(), "boom\n");
    }

    #[test]
    fn finish_run_returns_failure_without_writing_for_logged_error() {
        let mut stderr = Vec::new();

        let termination = finish_run(Err(RunError::Logged), &mut stderr);

        assert_exit_code(termination, ExitCode::FAILURE);
        assert!(stderr.is_empty());
    }

    #[test]
    fn finish_run_preserves_clap_errors_for_process_exit() {
        let mut stderr = Vec::new();

        let termination = finish_run(
            Err(RunError::Cli(
                Command::new("runewarp").error(ErrorKind::InvalidValue, "invalid"),
            )),
            &mut stderr,
        );

        match termination {
            RunTermination::Clap(error) => assert_eq!(error.kind(), ErrorKind::InvalidValue),
            RunTermination::Exit(code) => panic!("expected clap termination, got {code:?}"),
        }
        assert!(stderr.is_empty());
    }

    #[test]
    fn classify_runtime_error_detects_logged_runtime_failures() {
        let run_error =
            classify_runtime_error(logged_runtime_failure(io::Error::other("boom").into()));

        assert!(matches!(run_error, RunError::Logged));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finish_run_after_defers_stderr_lock_until_after_async_run_completes() {
        let stderr = SharedStderr::default();
        let stderr_for_background_log = stderr.clone();

        let termination = finish_run_after(
            async move {
                let (logged_tx, logged_rx) = oneshot::channel();
                std::thread::spawn(move || {
                    let mut stderr = stderr_for_background_log.lock();
                    writeln!(stderr, "background runtime log")
                        .expect("background runtime log write should succeed");
                    let _ = logged_tx.send(());
                });

                timeout(Duration::from_millis(200), logged_rx)
                    .await
                    .expect("background runtime log should not block on final stderr lock")
                    .expect("background runtime log completion signal should arrive");

                Ok(())
            },
            || stderr.lock(),
        )
        .await;

        assert_exit_code(termination, ExitCode::SUCCESS);
        assert_eq!(stderr.read(), "background runtime log\n");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finish_run_after_skips_stderr_factory_when_no_write_is_needed() {
        let stderr_factory_called = Arc::new(AtomicBool::new(false));
        let stderr_factory_called_for_run = stderr_factory_called.clone();

        let termination = finish_run_after(async { Ok(()) }, move || {
            stderr_factory_called_for_run.store(true, Ordering::Relaxed);
            Vec::<u8>::new()
        })
        .await;

        assert_exit_code(termination, ExitCode::SUCCESS);
        assert!(!stderr_factory_called.load(Ordering::Relaxed));
    }
}
