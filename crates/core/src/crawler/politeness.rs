//! Owns the compile-time host limits and checked timing policy shared by every fetch.
//! Configuration may slow requests but cannot raise concurrency or lower the hard gap.
//! Cross-process coordination is a production deployment prerequisite, not implied here.

#![deny(missing_docs)]

/// Minimum time between request starts to one host, in milliseconds.
pub const HARD_MIN_HOST_GAP_MS: u64 = 500;
/// Maximum simultaneously live connections/bodies to one host.
pub const HARD_MAX_HOST_CONCURRENCY: usize = 2;
/// Minimum access-denial block, in seconds from observation.
pub const MIN_BLOCK_SECS: u64 = 24 * 60 * 60;
/// Maximum lifetime of a usable robots snapshot, in seconds.
pub const MAX_ROBOTS_CACHE_SECS: u64 = 24 * 60 * 60;
/// Default time between host request starts, in milliseconds.
pub const DEFAULT_HOST_GAP_MS: u64 = 10_000;
/// Default simultaneously live connections/bodies to one host.
pub const DEFAULT_HOST_CONCURRENCY: usize = 1;
/// Publisher delays above this many seconds cause a policy skip, never clamping.
pub const MAX_ACCEPTED_CRAWL_DELAY_SECS: u64 = 60;
/// Earliest retry of unreachable robots, in seconds; rate deadlines can enlarge it.
pub const ROBOTS_FAILURE_RETRY_SECS: u64 = 300;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ingestion::IngestionPolicy;
    use proptest::prelude::*;

    #[test]
    fn ceiling_constants() {
        const GAP: u64 = HARD_MIN_HOST_GAP_MS;
        const CONNECTIONS: usize = HARD_MAX_HOST_CONCURRENCY;
        assert_eq!(GAP, 500);
        assert_eq!(CONNECTIONS, 2);
    }

    proptest! {
        #[test]
        fn politeness_config_prop(gap in any::<u64>(), concurrency in any::<usize>()) {
            let mut policy = IngestionPolicy::default();
            policy.politeness.gap_ms = gap;
            policy.politeness.max_concurrent_per_host = concurrency;
            prop_assert_eq!(policy.validate().is_ok(), (500..=86_400_000).contains(&gap) && (1..=2).contains(&concurrency));
            for boundary in [0, 499, 500, 10_000, 86_400_000, 86_400_001, u64::MAX] {
                for count in [0, 1, 2, 3, usize::MAX] {
                    policy.politeness.gap_ms = boundary;
                    policy.politeness.max_concurrent_per_host = count;
                    prop_assert_eq!(policy.validate().is_ok(), (500..=86_400_000).contains(&boundary) && (1..=2).contains(&count));
                }
            }
        }
    }
}
