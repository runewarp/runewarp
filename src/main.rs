mod cert_commands;
mod client_runtime;
mod commands;
mod config_hints;
mod error_handling;
mod reconnect_policy;

use std::env;
use std::io;
use std::process::ExitCode;

use error_handling::{RunTermination, finish_run};

mod cli;

#[tokio::main]
async fn main() -> ExitCode {
    let mut stderr = io::stderr().lock();
    match finish_run(commands::run(env::args().skip(1)).await, &mut stderr) {
        RunTermination::Exit(code) => code,
        RunTermination::Clap(error) => error.exit(),
    }
}
