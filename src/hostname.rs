use std::borrow::Borrow;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicHostnameError {
    Empty,
    TooLong,
    EmptyLabel,
    LabelTooLong,
    InvalidCharacter,
    LeadingOrTrailingHyphen,
    Wildcard,
    IpLiteral,
    RawUnicode,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicHostname(String);

impl PublicHostname {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PublicHostname {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for PublicHostname {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PublicHostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for PublicHostname {
    type Error = PublicHostnameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_public_hostname(value).map(Self)
    }
}

impl TryFrom<String> for PublicHostname {
    type Error = PublicHostnameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<PublicHostname> for String {
    fn from(value: PublicHostname) -> Self {
        value.0
    }
}

pub type ServerHostnameError = PublicHostnameError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerHostname(String);

impl ServerHostname {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ServerHostname {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ServerHostname {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ServerHostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&str> for ServerHostname {
    type Error = ServerHostnameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        validate_public_hostname(value).map(Self)
    }
}

impl TryFrom<String> for ServerHostname {
    type Error = ServerHostnameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<ServerHostname> for String {
    fn from(value: ServerHostname) -> Self {
        value.0
    }
}

pub(crate) fn normalize_public_hostname(hostname: &str) -> String {
    hostname.trim_end_matches('.').to_ascii_lowercase()
}

impl fmt::Display for PublicHostnameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("hostname must not be empty"),
            Self::TooLong => formatter.write_str("hostname must be 253 bytes or shorter"),
            Self::EmptyLabel => formatter.write_str("hostname labels must not be empty"),
            Self::LabelTooLong => {
                formatter.write_str("hostname labels must be 63 bytes or shorter")
            }
            Self::InvalidCharacter => formatter.write_str(
                "hostname must contain only lowercase ASCII letters, digits, dots, and hyphens",
            ),
            Self::LeadingOrTrailingHyphen => {
                formatter.write_str("hostname labels must not start or end with a hyphen")
            }
            Self::Wildcard => formatter.write_str("wildcard hostnames are not supported"),
            Self::IpLiteral => formatter.write_str("IP literals are not supported"),
            Self::RawUnicode => formatter.write_str("raw Unicode hostnames are not supported"),
        }
    }
}

pub(crate) fn validate_public_hostname(hostname: &str) -> Result<String, PublicHostnameError> {
    let normalized = normalize_public_hostname(hostname);
    if normalized.is_empty() {
        return Err(PublicHostnameError::Empty);
    }
    if !normalized.is_ascii() {
        return Err(PublicHostnameError::RawUnicode);
    }
    if normalized.contains('*') {
        return Err(PublicHostnameError::Wildcard);
    }
    if normalized.parse::<IpAddr>().is_ok() {
        return Err(PublicHostnameError::IpLiteral);
    }
    if normalized.len() > 253 {
        return Err(PublicHostnameError::TooLong);
    }

    for label in normalized.split('.') {
        if label.is_empty() {
            return Err(PublicHostnameError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(PublicHostnameError::LabelTooLong);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(PublicHostnameError::LeadingOrTrailingHyphen);
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(PublicHostnameError::InvalidCharacter);
        }
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        PublicHostname, PublicHostnameError, ServerHostname, normalize_public_hostname,
        validate_public_hostname,
    };

    #[test]
    fn lowercases_public_hostnames() {
        assert_eq!(
            normalize_public_hostname("App.Example.Test"),
            "app.example.test"
        );
    }

    #[test]
    fn strips_a_trailing_dot_from_public_hostnames() {
        assert_eq!(
            normalize_public_hostname("app.example.test."),
            "app.example.test"
        );
    }

    #[test]
    fn strips_all_trailing_dots_from_public_hostnames() {
        assert_eq!(
            normalize_public_hostname("app.example.test..."),
            "app.example.test"
        );
        assert_eq!(normalize_public_hostname(".."), "");
    }

    #[test]
    fn accepts_punycode_a_labels() {
        assert_eq!(
            validate_public_hostname("XN--BCHER-KVA.example").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn rejects_raw_unicode_hostnames() {
        assert_eq!(
            validate_public_hostname("bücher.example").unwrap_err(),
            PublicHostnameError::RawUnicode
        );
    }

    #[test]
    fn rejects_wildcard_hostnames() {
        assert_eq!(
            validate_public_hostname("*.example.test").unwrap_err(),
            PublicHostnameError::Wildcard
        );
    }

    #[test]
    fn rejects_ip_literals() {
        assert_eq!(
            validate_public_hostname("127.0.0.1").unwrap_err(),
            PublicHostnameError::IpLiteral
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn normalization_is_idempotent(hostname in ".*") {
            let normalized = normalize_public_hostname(&hostname);
            prop_assert_eq!(normalize_public_hostname(&normalized), normalized);
        }

        #[test]
        fn validated_hostnames_remain_in_canonical_form(hostname in ".*") {
            if let Ok(validated) = validate_public_hostname(&hostname) {
                prop_assert_eq!(normalize_public_hostname(&validated), validated.clone());
                prop_assert_eq!(validate_public_hostname(&validated), Ok(validated.clone()));
                let typed = PublicHostname::try_from(validated.as_str()).unwrap();
                prop_assert_eq!(typed.as_str(), validated);
            }
        }
    }

    #[test]
    fn server_hostnames_share_the_public_hostname_canonical_form() {
        let hostname = ServerHostname::try_from("Tunnel.Example.Test.").unwrap();

        assert_eq!(hostname.as_str(), "tunnel.example.test");
    }
}
