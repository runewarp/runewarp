pub fn emit(enabled: bool, line: &str, mut sink: impl FnMut(&str)) {
    if enabled {
        sink(line);
    }
}

pub fn emit_stderr(enabled: bool, line: &str) {
    emit(enabled, line, |line| eprintln!("{line}"));
}

pub fn server_route_line(public_hostname: &str, outcome: &str) -> String {
    format!("server route {public_hostname} -> {outcome}")
}

pub fn client_route_line(public_hostname: &str, outcome: &str) -> String {
    format!("client route {public_hostname} -> {outcome}")
}

pub fn warning_line(role: &str, message: &str) -> String {
    format!("{role} warning: {message}")
}

#[cfg(test)]
mod tests {
    use super::{client_route_line, emit, server_route_line, warning_line};

    #[test]
    fn emit_suppresses_disabled_lines() {
        let mut lines = Vec::new();

        emit(false, "server route app.example.test -> forwarded", |line| {
            lines.push(line.to_owned());
        });

        assert!(lines.is_empty());
    }

    #[test]
    fn emit_writes_enabled_lines() {
        let mut lines = Vec::new();

        emit(true, "server route app.example.test -> forwarded", |line| {
            lines.push(line.to_owned());
        });

        assert_eq!(lines, vec!["server route app.example.test -> forwarded"]);
    }

    #[test]
    fn formats_route_and_warning_lines() {
        assert_eq!(
            server_route_line("app.example.test", "forwarded"),
            "server route app.example.test -> forwarded"
        );
        assert_eq!(
            client_route_line("app.example.test", "backend caddy.local:443"),
            "client route app.example.test -> backend caddy.local:443"
        );
        assert_eq!(
            warning_line("client", "tunnel connection lost"),
            "client warning: tunnel connection lost"
        );
    }
}
