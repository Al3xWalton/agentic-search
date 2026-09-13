// SPDX-License-Identifier: AGPL-3.0-only
//! Validate literal loopback authorities before a URL client can normalize or resolve them.
//! Only explicit nonzero ports on 127.0.0.1 or ::1 are accepted.
//! No DNS, proxy, redirect, alternate-address spelling or returned-URL fetch is supported.

use super::EvalError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A validated literal loopback socket and canonical HTTP base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Pinned literal address, never obtained through DNS.
    pub socket: SocketAddr,
    /// Canonical base used only after raw-authority validation.
    pub base: String,
}

impl Endpoint {
    /// Accept only http://127.0.0.1:port or http://[::1]:port, optionally with one root slash.
    pub fn parse(raw: &str) -> Result<Self, EvalError> {
        let authority = raw
            .strip_prefix("http://")
            .ok_or(EvalError::InvalidEndpoint)?;
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        let socket = Self::shard(authority)?;
        Ok(Self {
            socket,
            base: format!("http://{socket}"),
        })
    }

    /// Parse a direct shard address with the same literal and nonzero-port restrictions.
    pub fn shard(raw: &str) -> Result<SocketAddr, EvalError> {
        let (ip, port) = if let Some(port) = raw.strip_prefix("127.0.0.1:") {
            (IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        } else if let Some(port) = raw.strip_prefix("[::1]:") {
            (IpAddr::V6(Ipv6Addr::LOCALHOST), port)
        } else {
            return Err(EvalError::InvalidEndpoint);
        };
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EvalError::InvalidEndpoint);
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| EvalError::InvalidEndpoint)?;
        if port == 0 {
            return Err(EvalError::InvalidEndpoint);
        }
        Ok(SocketAddr::new(ip, port))
    }

    /// Build a fresh HTTP/1 client with all proxy and redirect paths disabled and no idle pool.
    pub fn client(&self) -> Result<reqwest::Client, EvalError> {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .pool_max_idle_per_host(0)
            .connect_timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|_| EvalError::Network)
    }
}
