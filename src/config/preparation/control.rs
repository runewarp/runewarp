use std::path::{Path, PathBuf};

use crate::config::{
    ConfigFileError, RawControlConfig, collect_control_unknown_field_messages,
    deserialize_selected_section, load_optional_selected_section_value,
};
use crate::trust::{ControlTrust, ResolveControlTrustError, resolve_control_trust_with_default};
use crate::{XdgPathError, default_control_ca_path};

use super::PreparedValue;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedControlTrust {
    System,
    CaFile(PreparedValue<PathBuf>),
    InvalidMode(String),
    UnexpectedCaFile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedControlSection {
    pub(crate) section_present: bool,
    pub(crate) address: Option<String>,
    pub(crate) trust: PreparedControlTrust,
    pub(crate) unknown_field_messages: Vec<String>,
}

pub(crate) fn prepare_control_section(
    path: &Path,
    runtime_control_address: Option<String>,
) -> Result<PreparedControlSection, ConfigFileError> {
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let Some(section_value) = load_optional_selected_section_value(path, "control")? else {
        return Ok(PreparedControlSection {
            section_present: false,
            address: runtime_control_address,
            trust: PreparedControlTrust::System,
            unknown_field_messages: Vec::new(),
        });
    };
    let unknown_field_messages = collect_control_unknown_field_messages(&section_value);
    let raw = deserialize_selected_section::<RawControlConfig>(path, "control", &section_value)?;
    let address = runtime_control_address.or(raw.address);
    let trust = prepare_control_trust(
        raw.trust.as_deref(),
        raw.ca_file,
        config_dir,
        &default_control_ca_path,
    );
    Ok(PreparedControlSection {
        section_present: true,
        address,
        trust,
        unknown_field_messages,
    })
}

pub(crate) fn prepare_control_section_without_config(
    runtime_control_address: Option<String>,
) -> PreparedControlSection {
    PreparedControlSection {
        section_present: false,
        address: runtime_control_address,
        trust: PreparedControlTrust::System,
        unknown_field_messages: Vec::new(),
    }
}

fn prepare_control_trust(
    trust_mode: Option<&str>,
    ca_file: Option<PathBuf>,
    config_dir: &Path,
    default_ca_path: &dyn Fn() -> Result<PathBuf, XdgPathError>,
) -> PreparedControlTrust {
    match resolve_control_trust_with_default(trust_mode, ca_file, config_dir, default_ca_path) {
        Ok(ControlTrust::System) => PreparedControlTrust::System,
        Ok(ControlTrust::CaFile(ca_file)) => {
            PreparedControlTrust::CaFile(PreparedValue::Ready(ca_file))
        }
        Err(ResolveControlTrustError::InvalidMode { value }) => {
            PreparedControlTrust::InvalidMode(value)
        }
        Err(ResolveControlTrustError::UnexpectedCaFile) => PreparedControlTrust::UnexpectedCaFile,
        Err(ResolveControlTrustError::DefaultCaPath(error)) => {
            PreparedControlTrust::CaFile(PreparedValue::Error(error.to_string()))
        }
    }
}
