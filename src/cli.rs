use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

const TOP_LEVEL_EXAMPLES: &str = "\
Examples:
  runewarp server
  runewarp client

Config defaults:
  Commands use the default Runewarp config path unless -c, --config is set.";

const SERVER_EXAMPLES: &str = "\
Examples:
  runewarp server
  runewarp server cert init --hostname tunnel.example.com

Config defaults:
  Commands use the default Runewarp config path unless -c, --config is set.";

const SERVER_CERT_EXAMPLES: &str = "\
Examples:
  runewarp server cert init --hostname tunnel.example.com
  runewarp server cert renew -c server.toml

Config defaults:
  Commands use the default Runewarp config path unless -c, --config is set.";

const CLIENT_EXAMPLES: &str = "\
Examples:
  runewarp client
  runewarp client --server-address tunnel.example.com --backend-address 127.0.0.1:443

Config defaults:
  Commands use the default Runewarp config path unless -c, --config is set.";

const CLIENT_IDENTITY_EXAMPLES: &str = "\
Examples:
  runewarp client identity init
  runewarp client identity renew -c client.toml

Config defaults:
  Commands use the default Runewarp config path unless -c, --config is set.";

const CLIENT_PUBLIC_CERT_EXAMPLES: &str = "\
Examples:
  runewarp client public-cert init --hostname app.example.com
  runewarp client public-cert renew -c client.toml

Config defaults:
  Commands use the default Runewarp config path unless -c, --config is set.";

#[derive(Debug, Parser)]
#[command(
    name = "runewarp",
    about = "Runewarp: Private tunneling for TLS passthrough",
    long_about = None,
    after_help = TOP_LEVEL_EXAMPLES
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<TopLevelCommand>,
}

#[derive(Debug, Subcommand)]
pub enum TopLevelCommand {
    /// Run the Server runtime and server-side setup commands.
    Server(ServerArgs),
    /// Run the Client runtime and client-side setup commands.
    Client(ClientArgs),
}

#[derive(Debug, Args)]
#[command(
    about = "Run the Server runtime and server-side setup commands",
    long_about = None,
    after_help = SERVER_EXAMPLES
)]
pub struct ServerArgs {
    /// Use an explicit config file instead of the default Runewarp config path.
    #[arg(short = 'c', long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<ServerSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum ServerSubcommand {
    /// Manage manual Server certificate material.
    Cert(ServerCertArgs),
}

#[derive(Debug, Args)]
#[command(
    about = "Manage manual Server certificate material",
    long_about = None,
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
    /// Initialize the manual Server CA and issue the first Server certificate.
    Init(ServerCertInitArgs),
    /// Renew the current manual Server certificate from the existing Server CA.
    Renew(ServerCertDirArgs),
    /// Rotate the Server CA and reissue the Server certificate.
    RotateCa(ServerCertInitArgs),
}

#[derive(Debug, Args)]
pub struct ServerCertInitArgs {
    /// Write certificate material into this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Use this Server hostname instead of reading it from config.
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
}

#[derive(Debug, Args)]
pub struct ServerCertDirArgs {
    /// Read and write certificate material in this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    about = "Run the Client runtime and client-side setup commands",
    long_about = None,
    after_help = CLIENT_EXAMPLES
)]
pub struct ClientArgs {
    /// Use an explicit config file instead of the default Runewarp config path.
    #[arg(short = 'c', long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    /// Override the configured Server address for the runtime Client command.
    #[arg(long, value_name = "HOSTNAME[:PORT]")]
    pub server_address: Option<String>,
    /// Supply a catch-all backend address for the runtime Client command.
    #[arg(long, value_name = "ADDRESS")]
    pub backend_address: Option<String>,
    #[command(subcommand)]
    pub command: Option<ClientSubcommand>,
}

#[derive(Debug, Subcommand)]
pub enum ClientSubcommand {
    /// Manage Client identity material and fingerprints.
    Identity(ClientIdentityArgs),
    /// Manage manual Public hostname certificates for terminate mode.
    PublicCert(ClientPublicCertArgs),
}

#[derive(Debug, Args)]
#[command(
    about = "Manage manual Public hostname certificates for terminate mode",
    long_about = None,
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
    /// Create the shared Public hostname CA and a leaf certificate for one
    /// hostname (--hostname) or for all config-derived terminating hostnames
    /// when --hostname is omitted. Requires --config when --hostname is not
    /// provided.
    Init(ClientPublicCertInitArgs),
    /// Renew the leaf certificate for one hostname (--hostname) or all
    /// config-derived terminating hostnames when --hostname is omitted.
    /// Requires --config when --hostname is not provided.
    Renew(ClientPublicCertRenewArgs),
    /// Rotate the shared Public hostname CA and reissue every managed leaf
    /// certificate. The managed hostname set is derived from
    /// client.services[].public-hostnames for tls-mode = "terminate" entries
    /// in the config file; --config is therefore required.
    RotateCa(ClientPublicCertDirArgs),
}

#[derive(Debug, Args)]
pub struct ClientPublicCertInitArgs {
    /// Write Public hostname certificate material into this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Issue a certificate for this Public hostname.
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
}

#[derive(Debug, Args)]
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
pub struct ClientPublicCertDirArgs {
    /// Read and write Public hostname certificate material in this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[command(
    about = "Manage Client identity material and fingerprints",
    long_about = None,
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
    /// Initialize Client identity material.
    Init(ClientIdentityDirArgs),
    /// Renew the Client certificate without changing the Client identity.
    Renew(ClientIdentityDirArgs),
    /// Rotate the Client keypair and issue a new Client identity.
    Rotate(ClientIdentityDirArgs),
}

#[derive(Debug, Args)]
pub struct ClientIdentityDirArgs {
    /// Read and write Client identity material in this directory.
    #[arg(long = "dir", value_name = "DIR")]
    pub dir: Option<PathBuf>,
}
