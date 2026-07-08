use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

const TOP_LEVEL_EXAMPLES: &str = "\
Examples:
  runewarp server
  runewarp client";

const SERVER_EXAMPLES: &str = "\
Examples:
  runewarp server
  runewarp server cert init --hostname tunnel.example.com";

const SERVER_CERT_EXAMPLES: &str = "\
Examples:
  runewarp server cert init --hostname tunnel.example.com
  runewarp server cert renew";

const CLIENT_EXAMPLES: &str = "\
Examples:
  runewarp client
  runewarp client --server-address tunnel.example.com --backend-address 127.0.0.1:443
  runewarp client --server-address tunnel-a.example.com --server-address tunnel-b.example.com --backend-address 127.0.0.1:443";

const CLIENT_IDENTITY_EXAMPLES: &str = "\
Examples:
  runewarp client identity init
  runewarp client identity show";

const CLIENT_IDENTITY_LEAF_EXAMPLES: &str = "\
Examples:
  runewarp client identity init --dir ./client-identity
  runewarp client identity show";

const CLIENT_PUBLIC_CERT_EXAMPLES: &str = "\
Examples:
  runewarp client public-cert init --hostname app.example.com
  runewarp client public-cert renew --hostname app.example.com";

const CLIENT_PUBLIC_CERT_ROTATE_CA_EXAMPLES: &str = "\
Examples:
  runewarp client public-cert rotate-ca
  runewarp client -c client.toml public-cert rotate-ca";

const SERVER_HEADER: &str = "Runewarp Server";
const SERVER_CERT_HEADER: &str = "Runewarp Server Certificates";
const CLIENT_HEADER: &str = "Runewarp Client";
const CLIENT_IDENTITY_HEADER: &str = "Runewarp Client Identity";
const CLIENT_PUBLIC_CERT_HEADER: &str = "Runewarp Public Hostname Certificates";

#[derive(Debug, Parser)]
#[command(
    name = "runewarp",
    version = env!("RUNEWARP_CLI_VERSION"),
    about = "Runewarp: Public ingress. Private by design.",
    long_about = None,
    after_help = TOP_LEVEL_EXAMPLES
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<TopLevelCommand>,
}

#[derive(Debug, Subcommand)]
pub enum TopLevelCommand {
    /// Operate the Server runtime and setup commands.
    Server(ServerArgs),
    /// Operate the Client runtime and setup commands.
    Client(ClientArgs),
}

#[derive(Debug, Args)]
#[command(
    about = "Operate the Server runtime and setup commands",
    long_about = None,
    before_help = SERVER_HEADER,
    after_help = SERVER_EXAMPLES
)]
pub struct ServerArgs {
    /// Use an explicit config file instead of the default Runewarp config path.
    #[arg(short = 'c', long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    /// Override the configured Server hostname for the runtime Server command.
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
    #[command(subcommand)]
    pub command: Option<ServerSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum ServerSubcommand {
    /// Manage Server certificates.
    Cert(ServerCertArgs),
}

#[derive(Debug, Args)]
#[command(
    about = "Manage Server certificates",
    long_about = None,
    before_help = SERVER_CERT_HEADER,
    subcommand_required = true,
    arg_required_else_help = true,
    after_help = SERVER_CERT_EXAMPLES
)]
pub struct ServerCertArgs {
    #[command(subcommand)]
    pub command: ServerCertSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ServerCertSubcommand {
    /// Initialize Server certificates.
    Init(ServerCertInitArgs),
    /// Renew Server certificates.
    Renew(ServerCertDirArgs),
    /// Rotate the Server CA.
    RotateCa(ServerCertInitArgs),
}

#[derive(Debug, Args)]
#[command(before_help = SERVER_CERT_HEADER, after_help = SERVER_CERT_EXAMPLES)]
pub struct ServerCertInitArgs {
    /// Write certificate material into this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Use this Server hostname instead of reading it from config.
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
}

#[derive(Debug, Args)]
#[command(before_help = SERVER_CERT_HEADER, after_help = SERVER_CERT_EXAMPLES)]
pub struct ServerCertDirArgs {
    /// Read and write certificate material in this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    about = "Operate the Client runtime and setup commands",
    long_about = None,
    before_help = CLIENT_HEADER,
    after_help = CLIENT_EXAMPLES
)]
pub struct ClientArgs {
    /// Use an explicit config file instead of the default Runewarp config path.
    #[arg(short = 'c', long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    /// Override the configured Server address for the runtime Client command.
    #[arg(long, value_name = "HOSTNAME[:PORT]")]
    pub server_address: Vec<String>,
    /// Supply a catch-all backend address for the runtime Client command.
    #[arg(long, value_name = "ADDRESS")]
    pub backend_address: Option<String>,
    #[command(subcommand)]
    pub command: Option<ClientSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum ClientSubcommand {
    /// Manage Client identity.
    Identity(ClientIdentityArgs),
    /// Manage Public hostname certificates.
    PublicCert(ClientPublicCertArgs),
}

#[derive(Debug, Args)]
#[command(
    about = "Manage Public hostname certificates",
    long_about = None,
    before_help = CLIENT_PUBLIC_CERT_HEADER,
    subcommand_required = true,
    arg_required_else_help = true,
    after_help = CLIENT_PUBLIC_CERT_EXAMPLES
)]
pub struct ClientPublicCertArgs {
    #[command(subcommand)]
    pub command: ClientPublicCertSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ClientPublicCertSubcommand {
    /// Initialize Public hostname certificates.
    Init(ClientPublicCertInitArgs),
    /// Renew Public hostname certificates.
    Renew(ClientPublicCertRenewArgs),
    /// Rotate the Public hostname CA.
    RotateCa(ClientPublicCertDirArgs),
}

#[derive(Debug, Args)]
#[command(before_help = CLIENT_PUBLIC_CERT_HEADER, after_help = CLIENT_PUBLIC_CERT_EXAMPLES)]
pub struct ClientPublicCertInitArgs {
    /// Write Public hostname certificate material into this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Issue a certificate for this Public hostname.
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
}

#[derive(Debug, Args)]
#[command(before_help = CLIENT_PUBLIC_CERT_HEADER, after_help = CLIENT_PUBLIC_CERT_EXAMPLES)]
pub struct ClientPublicCertRenewArgs {
    /// Read and write Public hostname certificate material in this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Hostname whose leaf certificate should be renewed. When omitted, all
    /// terminating hostnames from the config file are renewed.
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
}

#[derive(Debug, Args)]
#[command(before_help = CLIENT_PUBLIC_CERT_HEADER, after_help = CLIENT_PUBLIC_CERT_ROTATE_CA_EXAMPLES)]
pub struct ClientPublicCertDirArgs {
    /// Read and write Public hostname certificate material in this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    about = "Manage Client identity",
    long_about = None,
    before_help = CLIENT_IDENTITY_HEADER,
    subcommand_required = true,
    arg_required_else_help = true,
    after_help = CLIENT_IDENTITY_EXAMPLES
)]
pub struct ClientIdentityArgs {
    #[command(subcommand)]
    pub command: ClientIdentitySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ClientIdentitySubcommand {
    /// Initialize Client identity.
    Init(ClientIdentityDirArgs),
    /// Renew Client identity certificates.
    Renew(ClientIdentityDirArgs),
    /// Rotate Client identity.
    Rotate(ClientIdentityDirArgs),
    /// Show the Client identity fingerprint.
    Show(ClientIdentityDirArgs),
}

#[derive(Debug, Args)]
#[command(before_help = CLIENT_IDENTITY_HEADER, after_help = CLIENT_IDENTITY_LEAF_EXAMPLES)]
pub struct ClientIdentityDirArgs {
    /// Read and write Client identity material in this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}
