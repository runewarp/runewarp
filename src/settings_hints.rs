use std::error::Error;
use std::io;
use std::path::Path;

use runewarp::{
    ClientSettingsResolutionError, ServerSettingsResolutionError, SettingsError,
    default_config_path,
};

pub(crate) fn wrap_server_settings_resolution_error(
    error: ServerSettingsResolutionError,
) -> Box<dyn Error> {
    if error.settings_error().is_some_and(server_material_missing) {
        return Box::new(io::Error::other(format!(
            "{error}\nHint: {}",
            error.selected_config_path().map_or_else(
                || "runewarp server cert init".to_owned(),
                server_cert_init_hint,
            )
        )));
    }
    Box::new(error)
}

pub(crate) fn wrap_client_settings_resolution_error(
    error: ClientSettingsResolutionError,
) -> Box<dyn Error> {
    if error
        .validation_messages()
        .is_some_and(client_identity_messages_missing)
    {
        return Box::new(io::Error::other(format!(
            "{error}\nHint: {}",
            client_identity_init_hint_from_optional_path(error.selected_config_path()),
        )));
    }
    Box::new(error)
}

fn server_material_missing(error: &SettingsError) -> bool {
    any_message_starts_with(
        settings_messages(error),
        &[
            "server.cert-dir directory not found:",
            "server.cert-dir file not found:",
        ],
    )
}

fn settings_messages(error: &SettingsError) -> &[String] {
    match error {
        SettingsError::Validation { messages, .. } => messages,
        SettingsError::Read { .. } | SettingsError::Parse { .. } => &[],
    }
}

fn server_cert_init_hint(config_path: &Path) -> String {
    hint_command("runewarp server cert init", config_path)
}

fn client_identity_init_hint(config_path: &Path) -> String {
    hint_command("runewarp client identity init", config_path)
}

fn client_identity_init_hint_from_optional_path(config_path: Option<&Path>) -> String {
    config_path.map_or_else(
        || "runewarp client identity init".to_owned(),
        client_identity_init_hint,
    )
}

fn hint_command(base: &str, config_path: &Path) -> String {
    let default_config_path = default_config_path().ok();
    if is_nondefault_config_path(config_path, default_config_path.as_deref()) {
        format!("{base} --config {}", config_path.display())
    } else {
        base.to_owned()
    }
}

fn is_nondefault_config_path(config_path: &Path, default_config_path: Option<&Path>) -> bool {
    match default_config_path {
        Some(default_config_path) => default_config_path != config_path,
        None => true,
    }
}

fn client_identity_messages_missing(messages: &[String]) -> bool {
    any_message_starts_with(
        messages,
        &[
            "client.identity-dir directory not found:",
            "client.identity-dir file not found:",
        ],
    )
}

fn any_message_starts_with(messages: &[String], prefixes: &[&str]) -> bool {
    messages
        .iter()
        .any(|message| prefixes.iter().any(|prefix| message.starts_with(prefix)))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use runewarp::{ClientSettingsResolutionError, ServerSettingsResolutionError, SettingsError};

    #[test]
    fn server_wrapper_adds_hint_for_missing_server_material() {
        let wrapped = super::wrap_server_settings_resolution_error(
            ServerSettingsResolutionError::Settings(SettingsError::Validation {
                path: PathBuf::from("custom.toml"),
                section: "server",
                messages: vec!["server.cert-dir directory not found: custom-certs".to_owned()],
            }),
        );

        assert_eq!(
            wrapped.to_string(),
            "invalid server config in custom.toml:\n- server.cert-dir directory not found: custom-certs\nHint: runewarp server cert init --config custom.toml"
        );
    }

    #[test]
    fn client_wrapper_adds_hint_for_missing_client_identity_material() {
        let wrapped = super::wrap_client_settings_resolution_error(
            ClientSettingsResolutionError::Validation {
                path: Some(PathBuf::from("custom.toml")),
                messages: vec!["client.identity-dir file not found: client.pem".to_owned()],
            },
        );

        assert_eq!(
            wrapped.to_string(),
            "invalid client config in custom.toml:\n- client.identity-dir file not found: client.pem\nHint: runewarp client identity init --config custom.toml"
        );
    }
}
