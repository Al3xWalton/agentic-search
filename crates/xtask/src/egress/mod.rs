//! Local signing and independent inventory/DNS verification.
//! Production keys are supplied externally.

mod atomic;
mod system;

use anyhow::Result;
use std::{path::Path, time::SystemTime};

/// Signs a local payload using external PKCS8 and atomically publishes its envelope.
pub fn egress_sign(payload: &Path, key: &Path, out: &Path) -> Result<()> {
    sign(payload, key, out).map_err(|error| command_error("egress-sign", error))
}

fn command_error(command: &str, error: anyhow::Error) -> anyhow::Error {
    let reason = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<::egress::Error>())
        .map(::egress::Error::reason)
        .unwrap_or("io_error");
    let messages: Vec<_> = error
        .chain()
        .filter(|cause| cause.downcast_ref::<::egress::Error>().is_none())
        .map(ToString::to_string)
        .collect();
    let detail = if messages.is_empty() {
        String::new()
    } else {
        format!(" ({})", messages.join(": "))
    };
    let message = format!("{command}: {reason}{detail}");
    anyhow::anyhow!(message)
}

fn sign(payload: &Path, key: &Path, out: &Path) -> Result<()> {
    let bytes = ::egress::read_bounded(payload, ::egress::MAX_PAYLOAD_BYTES)?;
    let now = SystemTime::now();
    // Invalid payloads must fail before the private-key path is opened.
    ::egress::validate_payload(&::egress::parse_payload(&bytes)?, now)?;
    let pkcs8 = ::egress::read_bounded(key, ::egress::MAX_PKCS8_BYTES)?;
    let signed = ::egress::sign_payload(&bytes, &pkcs8, now)?;
    atomic::write(out, key, &signed.bytes)?;
    println!(
        "egress-sign: wrote {}; key_id={}; public_key_base64={}",
        out.display(),
        signed.key_id,
        signed.public_key_base64
    );
    Ok(())
}

/// Checks independent trust, observed addresses and every PTR; fixtures never fall back to DNS.
pub fn egress_verify(
    file: &Path,
    trusted_keys: &Path,
    observed: &Path,
    dns_fixture: Option<&Path>,
) -> Result<()> {
    verify(file, trusted_keys, observed, dns_fixture)
        .map_err(|error| command_error("egress-verify", error))
}

fn verify(file: &Path, trusted_keys: &Path, observed: &Path, fixture: Option<&Path>) -> Result<()> {
    let bytes = ::egress::read_bounded(file, ::egress::MAX_FILE_BYTES)?;
    ::egress::parse_envelope(&bytes)?;
    let keys = ::egress::parse_trusted_keys(&::egress::read_bounded(
        trusted_keys,
        ::egress::MAX_FILE_BYTES,
    )?)?;
    let inventory = ::egress::verify_file(&bytes, &keys, SystemTime::now())?;
    let observed =
        ::egress::parse_observed(&::egress::read_bounded(observed, ::egress::MAX_FILE_BYTES)?)?;
    ::egress::verify_observed(&inventory, &observed)?;
    match fixture {
        Some(path) => {
            let resolver = ::egress::FixtureResolver::from_json(&::egress::read_bounded(
                path,
                ::egress::MAX_FILE_BYTES,
            )?)?;
            ::egress::verify_dns(&inventory, &resolver)?;
        }
        None => ::egress::verify_dns(&inventory, &system::SystemDnsResolver)?,
    }
    println!(
        "egress-verify: verified key_id={} egress_ips={} observed_ips={}",
        inventory.key_id(),
        inventory.payload().egress_ips.len(),
        observed.egress_ips.len()
    );
    Ok(())
}
