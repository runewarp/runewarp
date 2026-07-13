mod acme;
mod cert_file_ops;
mod client;
mod client_hello;
mod client_public_cert;
pub mod config;
mod hostname;
mod identity;
mod paths;
mod proxy;
mod quic;
pub mod runtime_log;
mod server;
mod server_address;
mod server_cert;
mod shutdown;
mod startup;
mod tls_material;
mod trust;

pub use client::{
    AddressController, AddressControllerShutdown, AddressWorkerControl, Client,
    ClientConfigResolutionDefaults, ClientConfigResolutionError, ClientConnectConfig,
    ClientConnectError, ClientRuntimeArgs, MaintenanceIntent, SelectedClientConfig,
    resolve_client_config_from_cli, resolve_selected_client_config, select_client_config,
};
pub use client_hello::{
    CLIENT_HELLO_BUFFER_LIMIT, ClientHelloError, ParsedClientHello, read_client_hello,
};
pub use client_public_cert::{
    CLIENT_PUBLIC_CA_FILENAME, CLIENT_PUBLIC_CA_LIFETIME_DAYS, CLIENT_PUBLIC_CERT_FILENAME,
    CLIENT_PUBLIC_CERT_LIFETIME_DAYS, CLIENT_PUBLIC_KEY_FILENAME, ClientPublicCertError,
    client_public_cert_leaf_dir, initialize_manual_client_public_cert,
    renew_manual_client_public_cert, rotate_manual_client_public_cert_authority,
};
pub use config::{
    ClientConfig, ClientPublicCertConfig, ClientTlsMode, ConfigFileError, LogLevel,
    ServerCertificateConfig, ServerConfig, ServerConfigResolutionError, ServerRuntimeArgs,
    ServerTunnelConfig, ServiceConfig, load_client_config, load_server_config,
    resolve_client_identity_material_dir_from_config,
    resolve_client_public_cert_material_dir_from_config,
    resolve_server_cert_material_dir_from_config, resolve_server_config_from_cli,
    resolve_server_hostname_from_config, resolve_server_hostname_runtime_override,
    resolve_terminating_hostnames_from_config,
};
pub use hostname::{PublicHostname, PublicHostnameError, ServerHostname, ServerHostnameError};
pub use identity::{
    CLIENT_CERT_FILENAME, CLIENT_CERT_LIFETIME_DAYS, CLIENT_IDENTITY_FILENAME, CLIENT_KEY_FILENAME,
    ClientIdentity, ClientIdentityMaterialError, GeneratedClientIdentity,
    ParseClientIdentityCertificateError, ParseClientIdentityError,
    client_identity_from_certificate_der, generate_client_identity, read_client_identity,
    rotate_client_identity,
};
pub use paths::{
    XdgPathError, default_client_acme_state_dir, default_client_identity_material_dir,
    default_client_public_cert_material_dir, default_client_server_ca_path, default_config_path,
    default_server_acme_state_dir, default_server_cert_material_dir,
};
pub use quic::{
    ClientIdentityAdmission, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT, KEEPALIVE_INTERVAL,
    MAX_SERVER_OPENED_BIDI_STREAMS, QuicConfigError, RUNEWARP_ALPN, make_client_quic_config,
    make_client_quic_config_with_client_auth, make_server_quic_config,
    make_server_quic_config_with_client_admission,
    make_server_quic_config_with_client_admission_resolver,
    make_server_quic_config_with_client_auth, make_server_quic_config_with_client_auth_resolver,
};
pub use server::{
    AuthorizationSnapshot, PreparedAuthorization, QUIC_CLOSE_FLUSH_DURATION, Server,
    ServerAuthorization, ServerBindConfig,
};
pub use server_address::{ServerAddress, ServerAddressError};
pub use server_cert::{
    SERVER_CA_FILENAME, initialize_manual_server_certificate, inspect_manual_server_certificate,
    renew_manual_server_certificate, rotate_manual_server_certificate_authority,
};
pub use shutdown::{OrderlyShutdown, ShutdownMode, ShutdownTransition};
pub use startup::{ClientStartupError, PreparedClient, PreparedServer, ServerStartupError};
