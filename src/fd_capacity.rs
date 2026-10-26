//! Startup sizing for Visitor-owned TCP sockets.

#[cfg(any(unix, test))]
pub(crate) fn client_capacity(configured: usize, nofile: u64, reserve: u64) -> usize {
    configured.min(usize::try_from(nofile.saturating_sub(reserve)).unwrap_or(usize::MAX))
}

/// Pending ClientHellos, pending opens and active proxies each retain a distinct TCP socket.
#[cfg(any(unix, test))]
pub(crate) fn server_capacity(configured: [usize; 3], nofile: u64, reserve: u64) -> [usize; 3] {
    let available = u128::from(nofile.saturating_sub(reserve));
    let total = configured.into_iter().map(|v| v as u128).sum::<u128>();
    if total <= available {
        return configured;
    }
    let mut result = configured.map(|v| ((v as u128 * available) / total) as usize);
    // Give integer-rounding leftovers to active proxies first, never above configured limits.
    let mut remaining = available - result.into_iter().map(|v| v as u128).sum::<u128>();
    for index in [2, 0, 1] {
        let extra = remaining.min((configured[index] - result[index]) as u128) as usize;
        result[index] += extra;
        remaining -= extra as u128;
    }
    result
}

/// Fixed descriptor headroom for runtime polling, QUIC, configuration/certificates, logs and ACME.
/// Client startup additionally reserves one UDP endpoint per configured address, or the Managed
/// snapshot address cap. This sizes Visitor sockets, not arbitrary files opened by library callers.
#[cfg(unix)]
const FD_RESERVE: u64 = 512;

#[cfg(any(unix, test))]
fn apply_client(
    configured: usize,
    nofile: Option<u64>,
    reserve: u64,
    mut warn: impl FnMut(String),
) -> usize {
    let Some(nofile) = nofile else {
        return configured;
    };
    let effective = client_capacity(configured, nofile, reserve);
    if effective != configured {
        warn(format!(
            "RLIMIT_NOFILE={nofile} reserve={reserve}: max-visitor-streams configured={configured} effective={effective}; raise the hard fd limit with systemd LimitNOFILE or container --ulimit nofile and restart"
        ));
    }
    effective
}

#[cfg(any(unix, test))]
fn apply_server(
    configured: [usize; 3],
    nofile: Option<u64>,
    reserve: u64,
    mut warn: impl FnMut(String),
) -> [usize; 3] {
    let Some(nofile) = nofile else {
        return configured;
    };
    let effective = server_capacity(configured, nofile, reserve);
    if effective != configured {
        warn(format!(
            "RLIMIT_NOFILE={nofile} reserve={reserve}: pending-visitors/pending-stream-opens/active-routed-streams configured={configured:?} effective={effective:?}; raise the hard fd limit with systemd LimitNOFILE or container --ulimit nofile and restart"
        ));
    }
    effective
}

#[cfg(unix)]
fn raise_nofile() -> (Option<u64>, Option<String>) {
    // The safe crate also respects macOS kern.maxfilesperproc when hard is RLIM_INFINITY.
    match rlimit::increase_nofile_limit(u64::MAX) {
        Ok(soft) => (Some(soft), None),
        Err(error) => (
            rlimit::Resource::NOFILE.get().ok().map(|(soft, _)| soft),
            Some(format!(
                "could not raise RLIMIT_NOFILE to the hard limit: {error}; check systemd LimitNOFILE or container --ulimit nofile"
            )),
        ),
    }
}

pub(crate) fn client(config: &crate::ClientConfig) -> usize {
    #[cfg(unix)]
    {
        let addresses = if config.admission == crate::ClientAdmission::Managed {
            crate::ManagedSessionLimits::default().max_server_addresses
        } else {
            config.server_addresses.len()
        };
        let reserve = FD_RESERVE.saturating_add(addresses as u64);
        let (nofile, problem) = raise_nofile();
        let mut warning = None;
        let effective = apply_client(config.max_visitor_streams, nofile, reserve, |message| {
            warning = Some(message)
        });
        if let Some(message) = warning.or(problem) {
            crate::runtime_log::warning("client", &message);
        }
        effective
    }
    #[cfg(not(unix))]
    {
        config.max_visitor_streams
    }
}

pub(crate) fn server(configured: [usize; 3]) -> [usize; 3] {
    #[cfg(unix)]
    {
        let (nofile, problem) = raise_nofile();
        let mut warning = None;
        let effective = apply_server(configured, nofile, FD_RESERVE, |message| {
            warning = Some(message)
        });
        if let Some(message) = warning.or(problem) {
            crate::runtime_log::warning("server", &message);
        }
        effective
    }
    #[cfg(not(unix))]
    {
        configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_clamps_even_below_idle_credit_and_reserve() {
        assert_eq!(client_capacity(16_384, 1_024, 512), 512);
        assert_eq!(client_capacity(256, 600, 512), 88);
        assert_eq!(client_capacity(256, 512, 512), 0);
        assert_eq!(client_capacity(256, 1, 512), 0);
        assert_eq!(client_capacity(256, u64::MAX, 512), 256);
    }

    #[test]
    fn server_clamps_all_socket_owners_without_overflow_or_raising_limits() {
        assert_eq!(server_capacity([10, 20, 30], 542, 512), [5, 10, 15]);
        assert_eq!(server_capacity([4096, 4096, 65536], 512, 512), [0, 0, 0]);
        assert_eq!(server_capacity([4096, 4096, 65536], 1, 512), [0, 0, 0]);
        for nofile in [0, 1, 513, 514, 515, 1024, u64::MAX] {
            let result = server_capacity([usize::MAX; 3], nofile, 512);
            assert!(
                result.into_iter().map(|v| v as u128).sum::<u128>()
                    <= u128::from(nofile.saturating_sub(512))
            );
        }
        assert_eq!(server_capacity([0, 0, 0], u64::MAX, 512), [0, 0, 0]);
        assert_eq!(server_capacity([10, 20, 30], u64::MAX, 512), [10, 20, 30]);
    }

    #[test]
    fn clamped_startup_warns_once_for_all_server_capacities() {
        let mut warnings = Vec::new();
        let result = apply_server([4096, 4096, 65536], Some(1024), 512, |message| {
            warnings.push(message)
        });
        assert!(result.into_iter().sum::<usize>() <= 512);
        assert_eq!(warnings.len(), 1);
        let warning = &warnings[0];
        for value in [
            "1024",
            "512",
            "4096",
            "65536",
            "hard",
            "LimitNOFILE",
            "ulimit",
        ] {
            assert!(warning.contains(value), "{warning}");
        }
        warnings.clear();
        assert_eq!(
            apply_client(512, Some(1024), 512, |message| warnings.push(message)),
            512
        );
        assert!(warnings.is_empty());
        assert_eq!(
            apply_client(256, Some(600), 512, |message| warnings.push(message)),
            88
        );
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn server_fit_counts_pending_opens_as_distinct_socket_owners() {
        assert_eq!(
            server_capacity([4096, 4096, 65536], 74240, 512),
            [4096, 4096, 65536]
        );
        assert_eq!(server_capacity([10, 20, 30], 1000, 512), [10, 20, 30]);
    }

    #[test]
    fn client_fit_keeps_a_smaller_configured_budget() {
        assert_eq!(client_capacity(256, 10_000, 512), 256);
        assert_eq!(client_capacity(16_384, 16_896, 512), 16_384);
    }
}
