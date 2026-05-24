use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "runewarp",
    about = "Private tunneling for TLS passthrough",
    long_about = None,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<TopLevelCommand>,
}

#[derive(Debug, Subcommand)]
pub enum TopLevelCommand {
    Server(ServerArgs),
    Client(ClientArgs),
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<ServerSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum ServerSubcommand {
    Cert(ServerCertArgs),
}

#[derive(Debug, Args)]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct ServerCertArgs {
    #[command(subcommand)]
    pub command: ServerCertSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ServerCertSubcommand {
    Init(ServerCertInitArgs),
    Renew(ServerCertDirArgs),
    RotateCa(ServerCertInitArgs),
}

#[derive(Debug, Args)]
pub struct ServerCertInitArgs {
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
}

#[derive(Debug, Args)]
pub struct ServerCertDirArgs {
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ClientArgs {
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<ClientSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum ClientSubcommand {
    Identity(ClientIdentityArgs),
}

#[derive(Debug, Args)]
#[command(subcommand_required = true, arg_required_else_help = true)]
pub struct ClientIdentityArgs {
    #[command(subcommand)]
    pub command: ClientIdentitySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ClientIdentitySubcommand {
    Init(ClientIdentityDirArgs),
    Renew(ClientIdentityDirArgs),
    Rotate(ClientIdentityDirArgs),
}

#[derive(Debug, Args)]
pub struct ClientIdentityDirArgs {
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}
