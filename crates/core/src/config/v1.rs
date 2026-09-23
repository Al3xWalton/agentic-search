//! Defines finite HTTP budgets and the local management boundary for the v1 contract.
//! Legacy API settings remain independent; these defaults also apply to old configuration files.

use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

/// Default complete JSON wire-body limit for authenticated management ingest, in bytes.
pub const MAX_INGEST_BODY_BYTES: usize = 2_097_152;

/// Configuration for each v1 HTTP listener and its shared suppression store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct V1ApiConfig {
    /// Trusted loopback management HTTP socket, distinct from API, metrics and Sonic.
    pub management_http_host: SocketAddr,
    /// Trusted local snapshot path, resolved relative to the startup working directory.
    pub suppression_store_path: PathBuf,
    /// Whole-request deadline in milliseconds; accepted range is 1..=60,000.
    pub request_timeout_ms: u64,
    /// Nonqueued requests per listener; must be Some(1..=32).
    pub max_concurrent_requests: Option<usize>,
    /// Complete ingest JSON body bytes; accepted range is 65,536..=8,388,608.
    pub ingest_max_body_bytes: usize,
}

impl Default for V1ApiConfig {
    fn default() -> Self {
        Self {
            management_http_host: SocketAddr::from(([127, 0, 0, 1], 3012)),
            suppression_store_path: "data/v1/suppression.json".into(),
            request_timeout_ms: 60_000,
            max_concurrent_requests: Some(32),
            ingest_max_body_bytes: MAX_INGEST_BODY_BYTES,
        }
    }
}

impl V1ApiConfig {
    /// Validates budgets and the loopback boundary before constructing either listener.
    /// Port zero requests independent ephemeral sockets and is allowed in local fixtures.
    /// Returns an error for empty store paths, unlimited budgets or conflicting fixed sockets.
    pub fn validate(&self, other_sockets: &[SocketAddr]) -> anyhow::Result<usize> {
        let limit = self
            .max_concurrent_requests
            .filter(|n| (1..=32).contains(n))
            .ok_or_else(|| anyhow::anyhow!("v1 concurrency must be Some(1..=32)"))?;
        anyhow::ensure!(
            (1..=60_000).contains(&self.request_timeout_ms),
            "v1 timeout must be 1..=60000 ms"
        );
        anyhow::ensure!(
            (65_536..=8_388_608).contains(&self.ingest_max_body_bytes),
            "v1 ingest body limit must be 65536..=8388608 bytes"
        );
        anyhow::ensure!(
            self.management_http_host.ip().is_loopback(),
            "v1 management must use loopback"
        );
        anyhow::ensure!(
            !self.suppression_store_path.as_os_str().is_empty(),
            "v1 store path is empty"
        );
        anyhow::ensure!(
            !other_sockets
                .iter()
                .any(|other| sockets_conflict(self.management_http_host, *other)),
            "v1 management socket conflicts with another listener"
        );
        Ok(limit)
    }
}

fn sockets_conflict(left: SocketAddr, right: SocketAddr) -> bool {
    if left.port() == 0 || left.port() != right.port() {
        return false;
    }
    let same_family = left.is_ipv4() == right.is_ipv4();
    left.ip() == right.ip()
        || (same_family && right.ip().is_unspecified())
        || (right.is_ipv6() && right.ip().is_unspecified())
        || left.ip().to_canonical() == right.ip().to_canonical()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_configuration_has_exact_limits() {
        assert_eq!(MAX_INGEST_BODY_BYTES, 2_097_152);
        let sample = include_str!("../../../../configs/api.toml");
        for source in [sample.split("[v1]").next().unwrap(), sample] {
            let config: crate::config::ApiConfig = toml::from_str(source).unwrap();
            assert_eq!(config.v1.ingest_max_body_bytes, 2_097_152);
            assert_eq!(config.v1.max_concurrent_requests, Some(32));
            assert_eq!(config.v1.request_timeout_ms, 60_000);
            assert!(config.v1.validate(&[]).is_ok());
        }
        for (bytes, valid) in [
            (0, false),
            (65_535, false),
            (65_536, true),
            (2_097_152, true),
            (8_388_608, true),
            (8_388_609, false),
        ] {
            let config = V1ApiConfig {
                ingest_max_body_bytes: bytes,
                ..Default::default()
            };
            assert_eq!(config.validate(&[]).is_ok(), valid, "body bytes {bytes}");
        }
        assert!(toml::from_str::<V1ApiConfig>("ingest_unknown = 1").is_err());
        assert_eq!(crate::live_index::TTL.as_secs(), 5_184_000);
        assert_eq!(crate::live_index::AUTO_COMMIT_INTERVAL.as_secs(), 600);
    }

    #[test]
    fn defaults_and_configuration_preserve_finite_v1_limits() {
        let sample = include_str!("../../../../configs/api.toml");
        let old = sample.split("[v1]").next().unwrap();
        for source in [old, sample] {
            let config: crate::config::ApiConfig = toml::from_str(source).unwrap();
            assert_eq!(config.v1.max_concurrent_requests, Some(32));
            assert_eq!(config.v1.request_timeout_ms, 60_000);
            assert_eq!(
                config.v1.management_http_host,
                "127.0.0.1:3012".parse().unwrap()
            );
            assert_eq!(
                config.v1.suppression_store_path,
                PathBuf::from("data/v1/suppression.json")
            );
            assert_eq!(config.max_concurrent_searches, None);
            assert_eq!(
                config
                    .v1
                    .validate(&[config.host, config.prometheus_host, config.management_host])
                    .unwrap(),
                32
            );
        }
        for timeout in [0, 60_001] {
            let config = V1ApiConfig {
                request_timeout_ms: timeout,
                ..Default::default()
            };
            assert!(config.validate(&[]).is_err());
        }
        for count in [None, Some(0), Some(33)] {
            let config = V1ApiConfig {
                max_concurrent_requests: count,
                ..Default::default()
            };
            assert!(config.validate(&[]).is_err());
        }
        for addr in ["0.0.0.0:3012", "[::]:3012", "192.0.2.1:3012"] {
            let config = V1ApiConfig {
                management_http_host: addr.parse().unwrap(),
                ..Default::default()
            };
            assert!(config.validate(&[]).is_err());
        }
        for conflict in ["127.0.0.1:3012", "0.0.0.0:3012", "[::]:3012"] {
            assert!(V1ApiConfig::default()
                .validate(&[conflict.parse().unwrap()])
                .is_err());
        }
        let lower = V1ApiConfig {
            request_timeout_ms: 1,
            max_concurrent_requests: Some(1),
            management_http_host: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        assert_eq!(
            lower.validate(&["127.0.0.1:0".parse().unwrap()]).unwrap(),
            1
        );
        assert!(toml::from_str::<V1ApiConfig>("unexpected = true").is_err());
    }
}
