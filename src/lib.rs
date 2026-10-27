mod acme;
mod cert_file_ops;
mod client;
mod client_admission;
mod client_hello;
mod client_public_cert;
mod client_runtime;
pub mod config;
mod control_address;
mod fd_capacity;
mod hostname;
mod identity;
pub mod managed_session;
mod opaque_control_token;
mod paths;
mod proxy;
mod proxy_protocol;
mod quic;
pub mod reconnect_policy;
pub mod runtime_log;
mod server;
mod server_address;
mod server_admission;
mod server_cert;
pub mod server_certificate;
mod server_identity;
mod server_runtime;
mod shutdown;
mod sse;
mod startup;
mod tls_material;
mod trust;
pub mod tunnel;
mod tunnel_framing;
mod tunnel_id;

pub use client::{
    AddressController, AddressControllerShutdown, AddressControllerView, AddressWorkerBackoff,
    AddressWorkerControl, AddressWorkerDial, AddressWorkerFactory, AddressWorkerHooks,
    AssignmentConvergence, Client, ClientAssignmentAdapter, ClientConfigResolutionDefaults,
    ClientConfigResolutionError, ClientConnectConfig, ClientConnectError, ClientRuntimeArgs,
    ClientTunnelAttempt, FixedBackoff, MaintenanceIntent, SelectedClientConfig,
    SilentAddressWorkerHooks, TunnelAttemptFailure, TunnelAttemptOutcome, TunnelConnectionEnd,
    TunnelConnectionRun, resolve_client_config_from_cli, resolve_selected_client_config,
    run_address_worker, select_client_config,
};
pub use client_admission::ClientAdmission;
pub use client_hello::{
    CLIENT_HELLO_BUFFER_LIMIT, ClientHelloError, ParsedClientHello, read_client_hello,
};
pub use client_public_cert::{
    CLIENT_PUBLIC_CA_FILENAME, CLIENT_PUBLIC_CA_LIFETIME_DAYS, CLIENT_PUBLIC_CERT_FILENAME,
    CLIENT_PUBLIC_CERT_LIFETIME_DAYS, CLIENT_PUBLIC_KEY_FILENAME, ClientPublicCertError,
    client_public_cert_leaf_dir, initialize_manual_client_public_cert,
    renew_manual_client_public_cert, rotate_manual_client_public_cert_authority,
};
// Stable role-runtime seams used by the CLI/process adapters.
pub use client_runtime::ClientRuntime;
pub use config::{
    ClientConfig, ClientPublicCertConfig, ClientTlsMode, ConfigFileError, ControlConfig,
    ControlTrust, LogLevel, MaterialDirectoryError, SelectedTerminatingHostnames,
    ServerCertHostnameError, ServerCertificateConfig, ServerConfig, ServerConfigResolutionError,
    ServerIdentityConfig, ServerRuntimeArgs, ServerTunnelConfig, ServiceConfig,
    is_managed_client_config, is_managed_selected_client_config, load_client_config,
    load_server_config, resolve_client_identity_material_dir,
    resolve_client_identity_material_dir_from_config, resolve_client_public_cert_material_dir,
    resolve_client_public_cert_material_dir_from_config, resolve_selected_terminating_hostnames,
    resolve_server_cert_hostname, resolve_server_cert_material_dir,
    resolve_server_cert_material_dir_from_config, resolve_server_config_from_cli,
    resolve_server_hostname_from_config, resolve_server_hostname_runtime_override,
    resolve_terminating_hostnames_from_config,
};
pub use control_address::{ControlAddress, ControlAddressError};
pub use hostname::{PublicHostname, PublicHostnameError, ServerHostname, ServerHostnameError};
pub use identity::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME,
    ClientIdentity, ClientIdentityMaterialError, GeneratedClientIdentity,
    ParseClientIdentityCertificateError, ParseClientIdentityError,
    client_identity_from_certificate_der, generate_client_identity, read_client_identity,
    rotate_client_identity,
};
pub use managed_session::{
    ApplyError, ClientManagedInput, ControlClientIdentityMaterial, ControlTlsMaterialError,
    InputError, ManagedSession, ManagedSessionEvent, ManagedSessionLimitKind, ManagedSessionLimits,
    ManagedSessionRole, RoleAdapter, RoleState, ServerManagedInput, SessionMaterial, StateFields,
    TrustLoadError, parse_client_input, parse_server_input,
};
pub use opaque_control_token::OpaqueControlTokenError;
pub use paths::{
    XdgPathError, default_client_acme_state_dir, default_client_identity_material_dir,
    default_client_public_cert_material_dir, default_client_server_ca_path, default_config_path,
    default_control_ca_path, default_server_acme_state_dir, default_server_cert_material_dir,
    default_server_identity_material_dir,
};
pub use proxy_protocol::{ProxyProtocolVersion, TrustedNetwork, VisitorTcpAddresses};
pub use quic::{
    ClientIdentityAdmission, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT, KEEPALIVE_INTERVAL, QuicConfigError,
};
pub use server::{
    AuthorizationSnapshot, QUIC_CLOSE_FLUSH_DURATION, Server, ServerAuthorization,
    ServerAuthorizationAdapter, ServerBindConfig,
};
pub use server_address::{ServerAddress, ServerAddressError};
pub use server_admission::ServerAdmission;
pub use server_cert::{
    SERVER_CA_FILENAME, initialize_manual_server_certificate, inspect_manual_server_certificate,
    renew_manual_server_certificate, rotate_manual_server_certificate_authority,
};
pub use server_certificate::CertificateOwner;
pub use server_identity::{
    ParseServerIdentityError, SERVER_IDENTITY_CERT_FILENAME, SERVER_IDENTITY_FILENAME,
    SERVER_IDENTITY_KEY_FILENAME, ServerIdentity, ServerIdentityMaterialError,
    read_server_identity,
};
pub use server_runtime::ServerRuntime;
pub use shutdown::{OrderlyShutdown, ShutdownMode, ShutdownTransition};
pub use startup::{
    ClientInstancePrep, ClientStartupError, PreparedClient, PreparedServer, ServerStartupError,
};
pub use trust::ClientServerTrust;
pub use tunnel::{
    ProtocolFailure, ReplacementHint, ServerRuntimeGeneration, UnconfirmedDrain, WithdrawalOutcome,
    make_client_tunnel_h3_config, make_server_tunnel_h3_config,
    make_server_tunnel_h3_config_with_resolver,
};
pub use tunnel_id::TunnelId;

#[cfg(test)]
mod capacity_benchmark;

#[cfg(test)]
mod runtime_capacity_tests;

mod visitor_capacity;
