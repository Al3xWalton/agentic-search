//! Defines the HTTP-only v1 types and enforces attribution at construction and deserialization.
//! These DTOs never enter the shard codec; source fields cannot be forged or mutated.

use super::{
    error::V1Error,
    suppression::{canonical_identity, DocumentId},
};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

/// The sole supported response contract version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum V1Version {
    /// Version one of the agent HTTP contract.
    #[default]
    #[serde(rename = "v1")]
    V1,
}

/// Original caller classification, retained independently of effective UK measures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[schema(as = V1Country)]
pub enum Country {
    /// Caller is classified as UK.
    #[serde(rename = "UK")]
    Uk,
    /// Caller is classified as outside the UK.
    #[serde(rename = "non-UK")]
    NonUk,
    /// Caller geography is unknown; conservative UK measures apply.
    #[default]
    #[serde(rename = "unknown")]
    Unknown,
}

/// Strict text-search input. Missing numeric/country fields default; explicit null is invalid.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1SearchRequest {
    /// Original query, at most 4096 UTF-8 bytes, validated without truncation.
    #[schema(max_length = 4096)]
    pub query: String,
    /// Zero-based page number in 0..=99; defaults to zero.
    #[serde(default)]
    #[schema(minimum = 0, maximum = 99, default = 0)]
    pub page: u64,
    /// Requested page size in 1..=100; defaults to 20.
    #[serde(default = "default_count")]
    #[schema(minimum = 1, maximum = 100, default = 20)]
    pub num_results: u64,
    /// Original country classification; absent means unknown.
    #[serde(default)]
    pub country: Country,
    /// Caller assertion only: absent/null/false receives child treatment.
    pub adult_verified: Option<bool>,
}

fn default_count() -> u64 {
    20
}

/// Text that retains the caller's bytes but cannot be blank.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct NonEmptyText(String);

impl utoipa::PartialSchema for NonEmptyText {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .min_length(Some(1))
            .pattern(Some("\\S"))
            .into()
    }
}
impl ToSchema for NonEmptyText {
    fn name() -> std::borrow::Cow<'static, str> {
        "V1NonEmptyText".into()
    }
}

impl NonEmptyText {
    fn new(text: String) -> Result<Self, V1Error> {
        if text.trim().is_empty() {
            return Err(V1Error::invalid_result());
        }
        Ok(Self(text))
    }
}
impl<'de> Deserialize<'de> for NonEmptyText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One immutable result with validated source attribution and an ID computed from its URL.
///
/// ```compile_fail
/// use stract::api::v1::dto::AttributedResult;
/// let forged = AttributedResult { url: String::new() };
/// ```
/// ```compile_fail
/// use stract::api::v1::dto::AttributedResult;
/// let mut result = AttributedResult::try_new("https://example.com/", "example.com", "Title", "").unwrap();
/// result.title = String::new();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[schema(as = V1AttributedResult)]
pub struct AttributedResult {
    id: DocumentId,
    #[schema(min_length = 1, pattern = "^https?://")]
    url: String,
    domain: NonEmptyText,
    title: NonEmptyText,
    snippet: String,
}

impl AttributedResult {
    /// Validates source text and URL, computes the ID, and retains the supplied plain snippet.
    /// Returns invalid_result for blank attribution or an unsupported URL.
    pub fn try_new(url: &str, domain: &str, title: &str, snippet: &str) -> Result<Self, V1Error> {
        let (url, id) = canonical_identity(url)?;
        Ok(Self {
            id,
            url,
            domain: NonEmptyText::new(domain.into())?,
            title: NonEmptyText::new(title.into())?,
            snippet: snippet.into(),
        })
    }
    /// Converts an upstream page without dates, markup, scores or attribution fallbacks.
    pub fn try_from_page(
        page: &crate::search_prettifier::DisplayedWebpage,
    ) -> Result<Self, V1Error> {
        Self::try_new(
            &page.url,
            &page.domain,
            &page.title,
            &page.snippet.text.unhighlighted_string(),
        )
    }
    /// Returns the stable public URL identifier.
    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    /// Returns the canonical source URL.
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Returns the validated source domain text without rewriting it.
    pub fn domain(&self) -> &str {
        &self.domain.0
    }
    /// Returns the validated source title without rewriting it.
    pub fn title(&self) -> &str {
        &self.title.0
    }
    /// Returns plain snippet text, which may be empty.
    pub fn snippet(&self) -> &str {
        &self.snippet
    }
}

impl<'de> Deserialize<'de> for AttributedResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            id: DocumentId,
            url: NonEmptyText,
            domain: NonEmptyText,
            title: NonEmptyText,
            snippet: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let result = Self::try_new(&raw.url.0, &raw.domain.0, &raw.title.0, &raw.snippet)
            .map_err(serde::de::Error::custom)?;
        if raw.id != result.id {
            return Err(serde::de::Error::custom(
                "The result identifier does not match its URL",
            ));
        }
        Ok(result)
    }
}

/// Narrow text-search response; the page-size echo and pagination hint precede suppression.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1SearchResponse {
    version: V1Version,
    results: Vec<AttributedResult>,
    page: u64,
    num_results: u64,
    has_more_results: bool,
}

impl V1SearchResponse {
    pub(super) fn new(
        results: Vec<AttributedResult>,
        page: u64,
        num_results: u64,
        has_more_results: bool,
    ) -> Self {
        Self {
            version: V1Version::default(),
            results,
            page,
            num_results,
            has_more_results,
        }
    }
}

/// Public build source metadata, versioned independently of the legacy source endpoint.
#[derive(Serialize, ToSchema)]
pub struct V1SourceResponse {
    version: V1Version,
    licence: String,
    source_url: String,
    revision: String,
    revision_source: String,
}

impl V1SourceResponse {
    /// Returns exactly the embedded source metadata and AGPL-3.0-only licence.
    pub fn embedded() -> Self {
        let metadata = crate::source_metadata::embedded();
        Self {
            version: V1Version::default(),
            licence: crate::source_metadata::LICENCE.into(),
            source_url: metadata.source_url,
            revision: metadata.revision.into(),
            revision_source: metadata.revision_source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribution_constructor_rejects_missing_source_fields() {
        for blank in ["", " ", "\t\n"] {
            assert!(AttributedResult::try_new(blank, "domain", "title", "").is_err());
            assert!(AttributedResult::try_new("https://example.com/", blank, "title", "").is_err());
            assert!(
                AttributedResult::try_new("https://example.com/", "domain", blank, "").is_err()
            );
        }
        for url in [
            "relative",
            "file:///x",
            "https://user:pass@example.com/",
            "https://example.com/\n",
        ] {
            assert!(AttributedResult::try_new(url, "domain", "title", "").is_err());
        }
        let valid = AttributedResult::try_new(
            "HTTPS://EXAMPLE.COM:443#fragment",
            " domain ",
            " title ",
            "plain <text>",
        )
        .unwrap();
        let value = serde_json::to_value(&valid).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        for field in ["id", "url", "domain", "title", "snippet"] {
            assert!(value.get(field).is_some());
        }
        assert_eq!(valid.domain(), " domain ");
        assert_eq!(valid.title(), " title ");
        assert_eq!(valid.snippet(), "plain <text>");
        assert_eq!(valid.url(), "https://example.com/");
    }

    #[test]
    fn attribution_deserialization_rejects_forged_results() {
        let result =
            AttributedResult::try_new("https://example.com/", "example.com", "Title", "").unwrap();
        let valid = serde_json::to_value(&result).unwrap();
        assert_eq!(
            serde_json::from_value::<AttributedResult>(valid.clone()).unwrap(),
            result
        );
        let mut invalid = Vec::new();
        for field in ["url", "domain", "title", "id"] {
            for bad in [
                serde_json::Value::Null,
                serde_json::json!(""),
                serde_json::json!(" "),
            ] {
                let mut value = valid.clone();
                value[field] = bad;
                invalid.push(value);
            }
            let mut value = valid.clone();
            value.as_object_mut().unwrap().remove(field);
            invalid.push(value);
        }
        for (field, bad) in [
            ("url", "file:///x"),
            ("url", "https://user@example.com/"),
            ("id", "gggg"),
            (
                "id",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("unknown", "extra"),
        ] {
            let mut value = valid.clone();
            value[field] = serde_json::json!(bad);
            invalid.push(value);
        }
        for value in invalid {
            assert!(serde_json::from_value::<AttributedResult>(value.clone()).is_err());
            let nested = serde_json::json!({"version":"v1","results":[value],"page":0,"num_results":20,"has_more_results":false});
            assert!(serde_json::from_value::<V1SearchResponse>(nested).is_err());
        }
    }
}
