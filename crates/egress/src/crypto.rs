//! Exact-byte Ed25519 signing and verification with a length-prefixed domain-separated message.

use crate::{
    parse_payload, validate_payload, Envelope, Error, Result, SignedFile, ALGORITHM,
    MAX_PKCS8_BYTES, SCHEMA_VERSION, SIGNING_PREFIX,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{
    digest,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use std::time::SystemTime;

/// Lowercase hex SHA-256 of exactly 32 raw public-key bytes, not their encoded spelling.
pub fn key_id(public_key: &[u8; 32]) -> String {
    digest::digest(&digest::SHA256, public_key)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Frames schema ASCII, algorithm, key ID and exact payload with four u64 big-endian lengths.
pub fn signing_message(envelope: &Envelope, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(SIGNING_PREFIX);
    for field in [
        envelope.schema_version.to_string().as_bytes(),
        envelope.algorithm.as_bytes(),
        envelope.key_id.as_bytes(),
        payload,
    ] {
        message.extend_from_slice(&(field.len() as u64).to_be_bytes());
        message.extend_from_slice(field);
    }
    message
}

/// Authenticates the exact message with only the selected independently installed key.
pub(crate) fn verify_signature(
    envelope: &Envelope,
    payload: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<()> {
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&signing_message(envelope, payload), signature)
        .map_err(|_| Error::Signature)
}

/// Validates first, accepts Ed25519 PKCS8 v1/v2, self-checks and signs the original payload bytes.
pub fn sign_payload(bytes: &[u8], pkcs8: &[u8], now: SystemTime) -> Result<SignedFile> {
    validate_payload(&parse_payload(bytes)?, now)?;
    if pkcs8.len() > MAX_PKCS8_BYTES {
        return Err(Error::InputTooLarge);
    }
    let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8).map_err(|_| Error::PrivateKey)?;
    let public_key: [u8; 32] = key
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| Error::PrivateKey)?;
    let key_id = key_id(&public_key);
    let mut envelope = Envelope {
        schema_version: SCHEMA_VERSION,
        algorithm: ALGORITHM.into(),
        key_id: key_id.clone(),
        payload_base64: STANDARD.encode(bytes),
        signature_base64: String::new(),
    };
    let signature = key.sign(&signing_message(&envelope, bytes));
    verify_signature(&envelope, bytes, signature.as_ref(), &public_key)
        .map_err(|_| Error::SigningSelfCheck)?;
    envelope.signature_base64 = STANDARD.encode(signature.as_ref());
    Ok(SignedFile {
        bytes: serde_json::to_vec(&envelope).map_err(|_| Error::Io)?,
        key_id,
        public_key_base64: STANDARD.encode(public_key),
    })
}
