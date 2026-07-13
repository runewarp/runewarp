mod client_runtime;
mod commands;
mod config_hints;
mod error_handling;

use std::env;
use std::io;
use std::process::ExitCode;

use error_handling::{RunTermination, finish_run_after};

mod cli;

#[tokio::main]
async fn main() -> ExitCode {
    match finish_run_after(commands::run(env::args().skip(1)), || io::stderr().lock()).await {
        RunTermination::Exit(code) => code,
        RunTermination::Clap(error) => error.exit(),
    }
}
