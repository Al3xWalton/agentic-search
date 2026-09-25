//! Validate explicit UTC windows, attested names and complete individual address inventories.

use crate::{Error, ObservedInventory, Payload, Result, VerifiedInventory, SCHEMA_VERSION};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use std::{collections::BTreeSet, net::IpAddr, time::SystemTime};

fn timestamp(value: &str) -> Result<DateTime<Utc>> {
    let raw = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
        .ok_or(Error::Timestamp)?;
    let bytes = raw.as_bytes();
    if bytes.len() < 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(Error::Timestamp);
    }
    if !(0..19)
        .filter(|i| ![4, 7, 10, 13, 16].contains(i))
        .all(|i| bytes[i].is_ascii_digit())
        || &bytes[17..19] > b"59"
    {
        return Err(Error::Timestamp);
    }
    if bytes.len() > 19
        && (!(21..=29).contains(&bytes.len())
            || bytes[19] != b'.'
            || !bytes[20..].iter().all(u8::is_ascii_digit))
    {
        return Err(Error::Timestamp);
    }
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| Error::Timestamp)
}

/// Requires one unambiguous lowercase ASCII operational DNS name, without normalization.
pub(crate) fn valid_domain(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || !name.contains('.') {
        return false;
    }
    name.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && !label.starts_with("xn--")
            && bytes[0].is_ascii_alphanumeric()
            && bytes[bytes.len() - 1].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    })
}

/// Checks equality or a real DNS label boundary, never a substring suffix alone.
pub(crate) fn is_label_subdomain(ptr: &str, domain: &str) -> bool {
    ptr == domain || ptr.strip_suffix(domain).is_some_and(|p| p.ends_with('.'))
}

/// Keeps membership family-aware without enumerating addresses.
pub(crate) fn cidr_contains(range: &IpNet, ip: &IpAddr) -> bool {
    range.contains(ip)
}

fn ranges(payload: &Payload) -> Result<Vec<IpNet>> {
    if payload.ranges.is_empty() {
        return Err(Error::RangesEmpty);
    }
    let mut unique = BTreeSet::new();
    let mut networks = Vec::new();
    for raw in &payload.ranges {
        let network: IpNet = raw.parse().map_err(|_| Error::RangeInvalid)?;
        if *raw != network.trunc().to_string() {
            return Err(Error::RangeNoncanonical);
        }
        if !unique.insert(raw) {
            return Err(Error::RangeDuplicate);
        }
        networks.push(network);
    }
    Ok(networks)
}

/// Checks schema, nanosecond UTC validity, domain, canonical ranges and unique nonempty inventory.
pub fn validate_payload(payload: &Payload, now: SystemTime) -> Result<()> {
    if payload.schema_version != SCHEMA_VERSION {
        return Err(Error::PayloadSchema);
    }
    let generated_at = timestamp(&payload.generated_at_utc)?;
    let valid_until = timestamp(&payload.valid_until_utc)?;
    let now: DateTime<Utc> = now.into();
    if generated_at >= valid_until {
        return Err(Error::ValidityWindow);
    }
    if now < generated_at {
        return Err(Error::NotYetValid);
    }
    if now >= valid_until {
        return Err(Error::Expired);
    }
    if !valid_domain(&payload.controlled_domain) {
        return Err(Error::ControlledDomain);
    }
    let networks = ranges(payload)?;
    if payload.egress_ips.is_empty() {
        return Err(Error::InventoryEmpty);
    }
    let mut unique = BTreeSet::new();
    for ip in &payload.egress_ips {
        if !unique.insert(ip) {
            return Err(Error::InventoryDuplicate);
        }
        if !networks.iter().any(|range| cidr_contains(range, ip)) {
            return Err(Error::IpOutsideRanges);
        }
    }
    if payload.policy_version.trim().is_empty() {
        return Err(Error::PolicyVersion);
    }
    Ok(())
}

/// Rechecks observation even when a caller constructed its DTO without parsing.
pub(crate) fn validate_observed(observed: &ObservedInventory) -> Result<()> {
    if observed.egress_ips.is_empty() {
        return Err(Error::ObservedEmpty);
    }
    let mut unique = BTreeSet::new();
    if !observed.egress_ips.iter().all(|ip| unique.insert(ip)) {
        return Err(Error::ObservedDuplicate);
    }
    Ok(())
}

/// Requires each independently observed address in both declared list and advertised ranges.
pub(crate) fn observed_subset_of_declared(observed: &ObservedInventory, payload: &Payload) -> bool {
    let Ok(networks) = ranges(payload) else {
        return false;
    };
    observed.egress_ips.iter().all(|ip| {
        payload.egress_ips.contains(ip) && networks.iter().any(|range| cidr_contains(range, ip))
    })
}

/// Verifies a nonempty unique independent observation; a proper subset is permitted.
pub fn verify_observed(inventory: &VerifiedInventory, observed: &ObservedInventory) -> Result<()> {
    validate_observed(observed)?;
    let payload = inventory.payload();
    if !observed_subset_of_declared(observed, payload) {
        return Err(Error::ObservedIpMissing);
    }
    Ok(())
}
