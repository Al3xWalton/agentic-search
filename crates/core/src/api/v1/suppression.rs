//! Defines canonical URL identities and the final serving gate.
//! Identifiers are public URL hashes, independent of content, ranking, process and shard ordinals.

use super::{error::V1Error, search::ServingContext};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use tokio::sync::RwLock;

/// Public SHA-256 identifier of the v1 canonical URL; never an authorization credential.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DocumentId(String);

impl utoipa::PartialSchema for DocumentId {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .min_length(Some(64))
            .max_length(Some(64))
            .pattern(Some("^[0-9a-f]{64}$"))
            .into()
    }
}
impl utoipa::ToSchema for DocumentId {
    fn name() -> std::borrow::Cow<'static, str> {
        "V1DocumentId".into()
    }
}

impl DocumentId {
    /// Validates borrowed raw bytes before allocating an identifier, including raw URI segments.
    /// Rejects anything except exactly 64 lowercase ASCII hexadecimal characters.
    pub fn parse(raw: &str) -> Result<Self, V1Error> {
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(V1Error::invalid_document_id());
        }
        Ok(Self(raw.to_owned()))
    }

    /// Returns the immutable lowercase hexadecimal representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DocumentId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Canonicalizes an HTTP(S) URL with locked url 2.5.4 semantics and computes its public ID.
/// Preserves query order, trailing slashes, trailing host dots and parser-serialized escapes.
/// Rejects credentials, whitespace, controls, backslashes, relative URLs and missing hosts.
pub fn canonical_identity(raw: &str) -> Result<(String, DocumentId), V1Error> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b == b'\\')
    {
        return Err(V1Error::invalid_result());
    }
    let mut parsed = url::Url::parse(raw).map_err(|_| V1Error::invalid_result())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(V1Error::invalid_result());
    }
    parsed.set_fragment(None);
    let canonical = parsed.to_string();
    let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
    let id = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    Ok((canonical, DocumentId(id)))
}

/// Serializes final response assembly against changes to the local suppression set.
pub struct SuppressionStore {
    pub(super) state: RwLock<ServingState>,
}

pub(super) struct ServingState {
    pub(super) ids: BTreeSet<DocumentId>,
    pub(super) unavailable: bool,
}

impl SuppressionStore {
    /// Creates an empty serving gate with no durable deletion operation.
    pub fn empty() -> Self {
        Self {
            state: RwLock::new(ServingState {
                ids: BTreeSet::new(),
                unavailable: false,
            }),
        }
    }
}

impl ServingState {
    pub(super) fn allows_document(&self, id: &DocumentId, _context: &ServingContext) -> bool {
        !self.ids.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_url_hash_vectors_are_fixed() {
        let fixed = "0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7";
        for raw in [
            "HTTPS://EXAMPLE.COM:443",
            "https://example.com/",
            "https://example.com/#part",
            "https://example.com/#",
        ] {
            let (url, id) = canonical_identity(raw).unwrap();
            assert_eq!(url, "https://example.com/");
            assert_eq!(id.as_str(), fixed);
        }
        let (url, id) = canonical_identity("https://example.com/a?b=2&a=1#fragment").unwrap();
        assert_eq!(url, "https://example.com/a?b=2&a=1");
        assert_eq!(
            id.as_str(),
            "9e1b7931d74ecb77efdde8e79ca52c2b63da671a086a011e1c949e9da31640be"
        );
        for (raw, canonical) in [
            ("http://EXAMPLE.COM:80", "http://example.com/"),
            ("https://example.com:444/", "https://example.com:444/"),
            ("https://example.com/a/../b", "https://example.com/b"),
            ("https://example.com/a?", "https://example.com/a?"),
            ("https://example.com./a", "https://example.com./a"),
            (
                "https://example.com/A//%2f?x=1&x=2&y=",
                "https://example.com/A//%2f?x=1&x=2&y=",
            ),
            ("https://[2001:0db8:0:0:0:0:0:1]/", "https://[2001:db8::1]/"),
            ("https://bücher.example/", "https://xn--bcher-kva.example/"),
        ] {
            assert_eq!(canonical_identity(raw).unwrap().0, canonical);
        }
        for (left, right) in [
            ("http://example.com/", "https://example.com/"),
            ("https://example.com:444/", "https://example.com/"),
            ("https://example.com/a", "https://example.com/a/"),
            (
                "https://example.com/a?b=2&a=1",
                "https://example.com/a?a=1&b=2",
            ),
            ("https://example.com/a?", "https://example.com/a"),
            ("https://example.com./a", "https://example.com/a"),
        ] {
            assert_ne!(
                canonical_identity(left).unwrap().1,
                canonical_identity(right).unwrap().1
            );
        }
        for raw in [
            "",
            " ",
            "relative",
            "file:///x",
            "https://user@example.com/",
            "https://example.com/a\\b",
            "https://example.com/\n",
            "https://example.com/a b",
            "https://",
        ] {
            assert!(canonical_identity(raw).is_err(), "accepted {raw:?}");
        }
    }
}
