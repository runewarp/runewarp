use std::error::Error;
use std::fmt;
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

pub(crate) fn logged_runtime_failure(error: Box<dyn Error>) -> Box<dyn Error> {
    runewarp::runtime_log::emit(runewarp::runtime_log::EventLevel::Error, &error.to_string());
    Box::new(LoggedRuntimeError)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::process::ExitCode;

    use clap::{Command, error::ErrorKind};

    use super::{
        RunError, RunTermination, classify_runtime_error, finish_run, logged_runtime_failure,
    };

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
}
