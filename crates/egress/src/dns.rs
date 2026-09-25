//! Error-aware DNS seam and offline fixture resolver, with no system or network fallback.

use crate::{
    inventory::{is_label_subdomain, valid_domain},
    strict, Error, Result, VerifiedInventory, MAX_FILE_BYTES,
};
use serde::Deserialize;
use std::{collections::BTreeMap, fmt, net::IpAddr};

/// A resolver failure remains distinct from a successful empty answer.
#[derive(Clone, Copy, Debug)]
pub enum DnsLookupError {
    /// The resolver could not obtain the requested answer.
    Unavailable,
}

impl fmt::Display for DnsLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dns_unavailable")
    }
}

impl std::error::Error for DnsLookupError {}

/// Supplies untrusted reverse names and all returned forward addresses.
pub trait DnsResolver: Send + Sync {
    /// Returns reverse names, preserving their original spelling.
    fn ptr(&self, ip: IpAddr) -> std::result::Result<Vec<String>, DnsLookupError>;
    /// Resolves a previously validated name without silently converting errors to empty success.
    fn addresses(&self, fqdn: &str) -> std::result::Result<Vec<IpAddr>, DnsLookupError>;
}

/// A parsed offline fixture whose missing/null entries always fail, never fall back.
#[derive(Debug)]
pub struct FixtureResolver {
    ptr: BTreeMap<String, Option<Vec<String>>>,
    addresses: BTreeMap<String, Option<Vec<IpAddr>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureMaps {
    ptr: BTreeMap<String, Option<Vec<String>>>,
    addresses: BTreeMap<String, Option<Vec<IpAddr>>>,
}

impl FixtureResolver {
    /// Parses both required maps with recursive duplicate rejection and canonical reverse keys.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let fixture: FixtureMaps = serde_json::from_value(strict::json(bytes, MAX_FILE_BYTES)?)
            .map_err(|_| Error::DnsFixture)?;
        for key in fixture.ptr.keys() {
            let ip: IpAddr = key.parse().map_err(|_| Error::DnsFixture)?;
            if ip.to_string() != *key {
                return Err(Error::DnsFixture);
            }
        }
        Ok(Self {
            ptr: fixture.ptr,
            addresses: fixture.addresses,
        })
    }
}

impl DnsResolver for FixtureResolver {
    fn ptr(&self, ip: IpAddr) -> std::result::Result<Vec<String>, DnsLookupError> {
        self.ptr
            .get(&ip.to_string())
            .and_then(Option::as_ref)
            .cloned()
            .ok_or(DnsLookupError::Unavailable)
    }

    fn addresses(&self, fqdn: &str) -> std::result::Result<Vec<IpAddr>, DnsLookupError> {
        self.addresses
            .get(fqdn)
            .and_then(Option::as_ref)
            .cloned()
            .ok_or(DnsLookupError::Unavailable)
    }
}

/// Checks the entire ordered inventory, including every returned PTR name for each address.
pub fn verify_dns(inventory: &VerifiedInventory, resolver: &dyn DnsResolver) -> Result<()> {
    for ip in &inventory.payload().egress_ips {
        verify_ip(*ip, &inventory.payload().controlled_domain, resolver)?;
    }
    Ok(())
}

/// Separates attested-domain membership from forward confirmation of every returned name.
pub(crate) fn verify_ip(ip: IpAddr, domain: &str, resolver: &dyn DnsResolver) -> Result<()> {
    let ptrs = match resolver.ptr(ip) {
        Ok(names) => names,
        Err(_) => return Err(Error::PtrLookup),
    };
    if ptrs.is_empty() {
        return Err(Error::PtrEmpty);
    }
    for ptr in &ptrs {
        if ptr.ends_with('.') {
            return Err(Error::PtrTrailingDot);
        }
        if !valid_domain(ptr) {
            return Err(Error::PtrName);
        }
    }
    if !ptrs.iter().any(|ptr| is_label_subdomain(ptr, domain)) {
        return Err(Error::PtrDomain);
    }
    for ptr in &ptrs {
        let forward_addresses = resolver.addresses(ptr).map_err(|_| Error::ForwardLookup)?;
        if forward_addresses.is_empty() {
            return Err(Error::ForwardEmpty);
        }
        if !forward_addresses.contains(&ip) {
            return Err(Error::ForwardMismatch);
        }
    }
    Ok(())
}
