//! Reads one private bearer at startup and verifies fixed-width buffers without secret formatting.
//! Every attempt invokes the same ring verifier, including malformed, duplicate or absent headers.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey, TextClass},
    disk::{self, ComplianceHooks, ComplianceStage, OpenMode},
    model::decode_hex,
    Error, Result,
};
use std::{fs::File, io, path::Path};

/// Authentication observations contain only lengths and attempts, never compared bytes.
pub trait AuthObserver {
    /// Observes entry to the authentication boundary before body decoding or ticket lookup.
    fn authentication_attempt(&self) {}
    /// Observes the two argument lengths at the fixed-buffer verifier boundary.
    fn verifier_invoked(&self, _expected_bytes: usize, _presented_bytes: usize) {}
}

/// Startup-only shared bearer verifier. No Debug, Display or serialization exposes its contents.
pub struct Authenticator {
    configured: bool,
    expected: [u8; 32],
}
impl Authenticator {
    /// Installs a disabled verifier; it still performs a fixed-width comparison on every attempt.
    pub fn disabled() -> Self {
        Self {
            configured: false,
            expected: [0; 32],
        }
    }

    /// Loads exactly 64 lowercase hexadecimal bytes and at most one trailing LF from a private file.
    /// A configured failure must disable management and compliance writes at the caller.
    pub fn load(path: Option<&Path>, hooks: &dyn ComplianceHooks) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::disabled());
        };
        let file = open_token(path, hooks).map_err(|_| Error::Unavailable)?;
        let bytes = disk::read_bounded(file, BoundKey::TokenFile.spec().max)
            .map_err(|_| Error::Unavailable)?;
        BoundKey::TokenFile
            .validate(bytes.len() as u64)
            .map_err(|_| Error::Unavailable)?;
        hooks
            .at(ComplianceStage::BeforeDecode)
            .map_err(|_| Error::Unavailable)?;
        let raw = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        let expected = decode_hex(std::str::from_utf8(raw).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)?;
        BoundKey::TokenBytes
            .validate(expected.len() as u64)
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            configured: true,
            expected,
        })
    }

    /// Requires exactly one correctly shaped Bearer header and one successful fixed-width comparison.
    /// Missing/malformed input becomes the same dummy buffer; shape and configuration remain required.
    pub fn authorises<'a>(
        &self,
        values: impl IntoIterator<Item = &'a [u8]>,
        observer: &dyn AuthObserver,
    ) -> bool {
        observer.authentication_attempt();
        let mut values = values.into_iter();
        let first = values.next();
        let single = values.next().is_none();
        let decoded = first
            .and_then(|value| value.strip_prefix(b"Bearer "))
            .and_then(|raw| std::str::from_utf8(raw).ok())
            .and_then(|raw| decode_hex(raw).ok());
        let valid_shape = single && decoded.is_some();
        let presented = decoded.filter(|_| valid_shape).unwrap_or([0; 32]);
        let comparison = verify_fixed(&self.expected, &presented, observer);
        self.configured && valid_shape && comparison.is_ok()
    }
}

fn verify_fixed(
    expected: &[u8; 32],
    presented: &[u8; 32],
    observer: &dyn AuthObserver,
) -> std::result::Result<(), ring::error::Unspecified> {
    observer.verifier_invoked(expected.len(), presented.len());
    ring::constant_time::verify_slices_are_equal(expected, presented)
}

fn open_token(path: &Path, hooks: &dyn ComplianceHooks) -> io::Result<File> {
    disk::open_for(path, OpenMode::Read, hooks)
}

/// Validates the caller's operational alias and excludes every reserved system actor.
pub fn actor(value: &str) -> Result<()> {
    bounds::text(value, BoundKey::Actor, TextClass::Slug)?;
    if value.starts_with("system.") {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
