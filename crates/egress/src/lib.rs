//! Authenticate a deployer's complete crawler egress inventory using independent trusted keys.
//!
//! The file proves nothing by itself. Trust comes from independently installed public keys,
//! Ed25519 authentication of the precise domain-separated message, and the deployer's attestation
//! that it controls `controlled_domain`. DNS confirms name/address consistency, not corporate
//! ownership. Never infer domain control or identity from an AVA-looking name. Route verification
//! happens only at load; it is neither ongoing DNS verification nor expiry monitoring.
//!
//! Keys are generated and held outside the repository and CI. Signing accepts deployment-supplied
//! Ed25519 PKCS8 v1/v2 DER and returns only an envelope and public registration metadata.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod crypto;
mod dns;
mod error;
mod inventory;
mod model;
mod strict;
mod verify;

pub use crypto::{key_id, sign_payload, signing_message};
pub use dns::{verify_dns, DnsLookupError, DnsResolver, FixtureResolver};
pub use error::{Error, Result};
pub use inventory::{validate_payload, verify_observed};
pub use model::{
    Envelope, ObservedInventory, Payload, SignedFile, TrustedKeys, VerifiedInventory, ALGORITHM,
    DEFAULT_LIFETIME_SECONDS, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES, MAX_PKCS8_BYTES, SCHEMA_VERSION,
    SIGNING_PREFIX,
};
pub use strict::{parse_envelope, parse_observed, parse_payload, parse_trusted_keys};
pub use verify::{read_bounded, verify_file};
