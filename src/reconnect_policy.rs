use std::time::Duration;

use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;

const RETRY_WINDOWS_SECS: [u64; 10] = [1, 2, 3, 5, 8, 12, 18, 27, 41, 60];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetryDecision {
    pub(crate) window: Duration,
    pub(crate) delay: Duration,
    pub(crate) display_delay_secs: u64,
}

pub(crate) struct ReconnectPolicy<R> {
    retry_count: usize,
    rng: R,
}

impl ReconnectPolicy<StdRng> {
    pub(crate) fn new() -> Self {
        Self::new_with_rng(StdRng::from_os_rng())
    }
}

impl<R: RngCore> ReconnectPolicy<R> {
    pub(crate) fn new_with_rng(rng: R) -> Self {
        Self {
            retry_count: 0,
            rng,
        }
    }

    pub(crate) fn is_fresh(&self) -> bool {
        self.retry_count == 0
    }

    pub(crate) fn reset(&mut self) {
        self.retry_count = 0;
    }

    pub(crate) fn next_retry(&mut self) -> RetryDecision {
        let window = Duration::from_secs(RETRY_WINDOWS_SECS[self.retry_count]);
        let delay = jitter_delay(window, &mut self.rng);
        self.retry_count = usize::min(self.retry_count + 1, RETRY_WINDOWS_SECS.len() - 1);

        RetryDecision {
            window,
            delay,
            display_delay_secs: display_delay_secs(delay),
        }
    }
}

fn jitter_delay<R: RngCore>(window: Duration, rng: &mut R) -> Duration {
    let upper_bound_nanos = u64::try_from(window.as_nanos()).expect("retry windows fit in u64");
    if upper_bound_nanos == 0 {
        return Duration::ZERO;
    }

    Duration::from_nanos(rng.next_u64() % upper_bound_nanos)
}

fn display_delay_secs(delay: Duration) -> u64 {
    let rounded = delay.as_nanos().div_ceil(1_000_000_000);
    u64::try_from(rounded.max(1)).expect("display delay fits in u64")
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::{RETRY_WINDOWS_SECS, ReconnectPolicy};

    #[derive(Debug)]
    struct TestRng {
        values: Vec<u64>,
        next: usize,
    }

    impl TestRng {
        fn new(values: Vec<u64>) -> Self {
            Self { values, next: 0 }
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            let value = self.values[self.next];
            self.next += 1;
            value
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut remaining = dest;
            while !remaining.is_empty() {
                let bytes = self.next_u64().to_le_bytes();
                let count = remaining.len().min(bytes.len());
                remaining[..count].copy_from_slice(&bytes[..count]);
                remaining = &mut remaining[count..];
            }
        }
    }

    #[test]
    fn retry_windows_follow_the_documented_sequence_and_cap() {
        let mut policy = ReconnectPolicy::new_with_rng(TestRng::new(vec![0; 12]));

        let windows = (0..12)
            .map(|_| policy.next_retry().window.as_secs())
            .collect::<Vec<_>>();

        assert_eq!(
            windows,
            vec![
                RETRY_WINDOWS_SECS[0],
                RETRY_WINDOWS_SECS[1],
                RETRY_WINDOWS_SECS[2],
                RETRY_WINDOWS_SECS[3],
                RETRY_WINDOWS_SECS[4],
                RETRY_WINDOWS_SECS[5],
                RETRY_WINDOWS_SECS[6],
                RETRY_WINDOWS_SECS[7],
                RETRY_WINDOWS_SECS[8],
                RETRY_WINDOWS_SECS[9],
                RETRY_WINDOWS_SECS[9],
                RETRY_WINDOWS_SECS[9],
            ]
        );
    }

    #[test]
    fn retries_use_full_jitter_and_operator_friendly_display_rounding() {
        let mut policy =
            ReconnectPolicy::new_with_rng(TestRng::new(vec![400_000_000, 1_500_000_000]));

        let first_retry = policy.next_retry();
        let second_retry = policy.next_retry();

        assert_eq!(first_retry.window.as_secs(), 1);
        assert_eq!(first_retry.delay.as_millis(), 400);
        assert_eq!(first_retry.display_delay_secs, 1);

        assert_eq!(second_retry.window.as_secs(), 2);
        assert_eq!(second_retry.delay.as_millis(), 1_500);
        assert_eq!(second_retry.display_delay_secs, 2);
    }

    #[test]
    fn display_delay_rounds_up_so_logs_do_not_understate_the_wait() {
        let mut policy = ReconnectPolicy::new_with_rng(TestRng::new(vec![0, 1_100_000_000]));

        let _ = policy.next_retry();
        let retry = policy.next_retry();

        assert_eq!(retry.window.as_secs(), 2);
        assert_eq!(retry.delay.as_millis(), 1_100);
        assert_eq!(retry.display_delay_secs, 2);
    }

    #[test]
    fn reset_starts_a_later_outage_from_the_first_window_again() {
        let mut policy = ReconnectPolicy::new_with_rng(TestRng::new(vec![0, 0, 0]));

        let _ = policy.next_retry();
        let _ = policy.next_retry();
        policy.reset();

        assert!(policy.is_fresh());
        assert_eq!(policy.next_retry().window.as_secs(), 1);
    }
}
