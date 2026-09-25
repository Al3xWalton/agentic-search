//! Raw strict wire models and opaque authenticated or independently registered values.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

/// Required integer version of both JSON layers.
pub const SCHEMA_VERSION: u32 = 1;
/// The sole, case-sensitive signature algorithm.
pub const ALGORITHM: &str = "Ed25519";
/// Domain separation ending with one LF byte.
pub const SIGNING_PREFIX: &[u8] = b"AVA-SEARCH-EGRESS-V1\n";
/// Recommended authoring lifetime, neither a maximum nor a statutory requirement.
pub const DEFAULT_LIFETIME_SECONDS: u64 = 86_400;
/// Inclusive bound for envelope and auxiliary JSON files.
pub const MAX_FILE_BYTES: usize = 1_048_576;
/// Inclusive bound for exact raw payload bytes.
pub const MAX_PAYLOAD_BYTES: usize = 262_144;
/// Inclusive bound for deployment-supplied private DER.
pub const MAX_PKCS8_BYTES: usize = 16_384;

/// Unverified envelope; deserialization alone establishes no trust.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Required integer schema version.
    pub schema_version: u32,
    /// Exact algorithm name authenticated in the signing message.
    pub algorithm: String,
    /// Independent registry identifier authenticated in the message.
    pub key_id: String,
    /// Standard padded base64 of exact JSON payload bytes.
    pub payload_base64: String,
    /// Standard padded base64 of the Ed25519 signature.
    pub signature_base64: String,
}

/// Unverified deployment attestation; use validate_payload even for constructed values.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    /// Required integer schema version.
    pub schema_version: u32,
    /// Inclusive beginning of validity, in strict UTC spelling.
    pub generated_at_utc: String,
    /// Exclusive end of validity, in strict UTC spelling.
    pub valid_until_utc: String,
    /// Domain the deployer attests it controls; not ownership proved by DNS.
    pub controlled_domain: String,
    /// Canonically spelled networks containing every declared individual address.
    pub ranges: Vec<String>,
    /// Complete individual inventory; ranges are never enumerated.
    pub egress_ips: Vec<IpAddr>,
    /// Nonempty deployment policy version.
    pub policy_version: String,
}

/// Independently supplied outbound observation, possibly a proper declared subset.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedInventory {
    /// Nonempty unique observed individual addresses.
    pub egress_ips: Vec<IpAddr>,
}

/// Independently installed public keys, constructible only through strict parsing.
#[derive(Debug)]
pub struct TrustedKeys(BTreeMap<String, [u8; 32]>);

impl TrustedKeys {
    /// Stores entries whose encodings, lengths and identities were checked by the parser.
    pub(crate) fn from_parsed(entries: BTreeMap<String, [u8; 32]>) -> Self {
        Self(entries)
    }

    /// Selects only the exact independently registered identifier, without a fallback.
    pub(crate) fn lookup(&self, key_id: &str) -> Result<&[u8; 32]> {
        self.0.get(key_id).ok_or(Error::UntrustedKey)
    }
}

/// An authenticated inventory validated at one explicit clock instant.
#[derive(Debug)]
pub struct VerifiedInventory {
    payload: Payload,
    key_id: String,
}

impl VerifiedInventory {
    /// Records the result of the shared load-verifier, without mutable public access.
    pub(crate) fn from_verified(payload: Payload, key_id: String) -> Self {
        Self { payload, key_id }
    }

    /// Borrows the authenticated and validated deployment attestation.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Returns the authenticated registered signer identifier.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Signed publication and public registration metadata, containing no private material.
#[derive(Debug)]
pub struct SignedFile {
    /// Serialized envelope authenticating the original payload bytes.
    pub bytes: Vec<u8>,
    /// Lowercase hex SHA-256 of the raw public key.
    pub key_id: String,
    /// Public registration value for independent installation.
    pub public_key_base64: String,
}
