//! Walk decoded JSON keys recursively before any map can discard duplicate entries.

use crate::{
    inventory::validate_observed, key_id, Envelope, Error, ObservedInventory, Payload, Result,
    TrustedKeys, ALGORITHM, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES, SCHEMA_VERSION,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt,
};

struct Walk<'a>(&'a Cell<bool>);

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> std::result::Result<Value, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value with unique decoded object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(value.into()))
    }

    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Walk(self.0))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut keys = BTreeSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                self.0.set(true);
                return Err(A::Error::custom("duplicate_key"));
            }
            values.insert(key, map.next_value_seed(Walk(self.0))?);
        }
        Ok(Value::Object(values))
    }
}

/// Consumes an entire bounded document, retaining serde_json's recursion protection.
pub(crate) fn json(bytes: &[u8], limit: usize) -> Result<Value> {
    if bytes.len() > limit {
        return Err(Error::InputTooLarge);
    }
    let duplicate = Cell::new(false);
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = Walk(&duplicate).deserialize(&mut de).map_err(|_| {
        if duplicate.get() {
            Error::DuplicateKey
        } else {
            Error::JsonSyntax
        }
    })?;
    de.end().map_err(|_| Error::JsonSyntax)?;
    Ok(value)
}

/// Rejects noncanonical encodings, including discarded nonzero trailing bits.
pub(crate) fn base64(value: &str) -> Result<Vec<u8>> {
    let decoded = STANDARD.decode(value).map_err(|_| Error::Base64)?;
    if STANDARD.encode(&decoded) != value {
        return Err(Error::Base64);
    }
    Ok(decoded)
}

fn valid_key_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Strictly parses envelope schema, exact algorithm and registered-identifier spelling.
pub fn parse_envelope(bytes: &[u8]) -> Result<Envelope> {
    let value = json(bytes, MAX_FILE_BYTES)?;
    if value
        .as_object()
        .is_some_and(|map| !map.contains_key("key_id"))
    {
        return Err(Error::MissingKey);
    }
    if value.get("algorithm").is_none() {
        return Err(Error::EnvelopeSchema);
    }
    if !matches!(value.get("algorithm"), Some(Value::String(s)) if s == ALGORITHM) {
        return Err(Error::Algorithm);
    }
    let envelope: Envelope = serde_json::from_value(value).map_err(|_| Error::EnvelopeSchema)?;
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(Error::EnvelopeSchema);
    }
    if !valid_key_id(&envelope.key_id) {
        return Err(Error::KeyId);
    }
    Ok(envelope)
}

/// Strictly parses bounded UTF-8 payload JSON; validation is a separate explicit-clock step.
pub fn parse_payload(bytes: &[u8]) -> Result<Payload> {
    let payload: Payload = serde_json::from_value(json(bytes, MAX_PAYLOAD_BYTES)?)
        .map_err(|_| Error::PayloadSchema)?;
    if payload.schema_version != SCHEMA_VERSION {
        return Err(Error::PayloadSchema);
    }
    Ok(payload)
}

/// Parses the independent map and checks every public key's encoding, length and derived ID.
pub fn parse_trusted_keys(bytes: &[u8]) -> Result<TrustedKeys> {
    let value = json(bytes, MAX_FILE_BYTES)?;
    let map = value.as_object().ok_or(Error::TrustedKeysSchema)?;
    if map.is_empty() {
        return Err(Error::TrustedKeysEmpty);
    }
    let mut keys = BTreeMap::new();
    for (id, encoded) in map {
        let encoded = encoded.as_str().ok_or(Error::TrustedKeysSchema)?;
        let key: [u8; 32] = base64(encoded)?.try_into().map_err(|_| Error::KeyLength)?;
        if !valid_key_id(id) {
            return Err(Error::KeyId);
        }
        if key_id(&key) != *id {
            return Err(Error::KeyIdentity);
        }
        keys.insert(id.clone(), key);
    }
    Ok(TrustedKeys::from_parsed(keys))
}

/// Parses the strict nonempty, unique independently observed IP list.
pub fn parse_observed(bytes: &[u8]) -> Result<ObservedInventory> {
    let observed =
        serde_json::from_value(json(bytes, MAX_FILE_BYTES)?).map_err(|_| Error::ObservedSchema)?;
    validate_observed(&observed)?;
    Ok(observed)
}
