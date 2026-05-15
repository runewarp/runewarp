pub(crate) fn normalize_public_hostname(hostname: &str) -> String {
    hostname
        .strip_suffix('.')
        .unwrap_or(hostname)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::normalize_public_hostname;

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
}
