//! Defines the HTTP-only v1 types and enforces attribution at construction and deserialization.
//! These DTOs never enter the shard codec; source fields cannot be forged or mutated.

use super::{
    error::V1Error,
    scholarly::*,
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
    pub query: String,
    /// Zero-based page number in 0..=99; defaults to zero.
    #[serde(default)]
    #[schema(minimum = 0, maximum = 99, default = 0)]
    pub page: u64,
    /// Requested page size in 1..=100 for web, 1..=20 for papers; defaults to 20.
    #[serde(default = "default_count")]
    #[schema(minimum = 1, maximum = 100, default = 20)]
    pub num_results: u64,
    /// Original country classification; absent means unknown.
    #[serde(default)]
    pub country: Country,
    /// Caller assertion only: absent/null/false receives child treatment.
    pub adult_verified: Option<bool>,
    /// Missing or false selects web; true selects the configured provider, without fallback.
    /// Paper queries are <=4096 UTF-8 bytes and contain 1..=64 Unicode alphanumeric runs.
    #[serde(default)]
    #[schema(default = false)]
    pub scholarly: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    scholarly: Option<ScholarlyAttribution>,
}

impl AttributedResult {
    /// Validates source text and URL, computes the ID, and retains the supplied plain snippet.
    /// Returns invalid_result for blank attribution or an unsupported URL.
    pub fn try_new(url: &str, domain: &str, title: &str, snippet: &str) -> Result<Self, V1Error> {
        // Recompute the DTO's invariant rather than trusting a caller-supplied suppression ID.
        let (url, id) = canonical_identity(url)?;
        Ok(Self {
            id,
            url,
            domain: NonEmptyText::new(domain.into())?,
            title: NonEmptyText::new(title.into())?,
            snippet: snippet.into(),
            scholarly: None,
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

    /// Returns validated metadata attribution; web results omit the scholarly key entirely.
    pub fn scholarly(&self) -> Option<&ScholarlyAttribution> {
        self.scholarly.as_ref()
    }

    /// Constructs a metadata-only paper with canonical URL/hash/domain and an empty snippet.
    /// Invalid attribution or a blank/oversize title returns fixed invalid_result.
    pub fn try_from_paper(title: &str, attribution: ScholarlyAttribution) -> Result<Self, V1Error> {
        attribution.validate()?;
        paper_title(title)?;
        let mut result = Self::try_new(&attribution.openalex_id, "openalex.org", title, "")?;
        result.scholarly = Some(attribution);
        Ok(result)
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
            #[serde(default, deserialize_with = "non_null_scholarly")]
            scholarly: Option<ScholarlyAttribution>,
        }
        let raw = Raw::deserialize(deserializer)?;
        if raw.scholarly.is_some() {
            validate_id(&raw.url.0).map_err(serde::de::Error::custom)?;
        }
        let mut result = Self::try_new(&raw.url.0, &raw.domain.0, &raw.title.0, &raw.snippet)
            .map_err(serde::de::Error::custom)?;
        if raw.id != result.id {
            return Err(serde::de::Error::custom(
                "The result identifier does not match its URL",
            ));
        }
        if let Some(scholarly) = raw.scholarly {
            scholarly.bind(&result).map_err(serde::de::Error::custom)?;
            result.scholarly = Some(scholarly);
        }
        Ok(result)
    }
}

/// Eight required metadata keys with explicit nulls for absent optional source facts.
/// Metadata carries CC0-1.0 provenance; it grants no rights to abstracts or linked content.
#[derive(Clone, PartialEq, Eq, Serialize, ToSchema)]
#[schema(as = V1ScholarlyAttribution)]
pub struct ScholarlyAttribution {
    /// Canonical https://openalex.org/W plus digits, at most 64 ASCII bytes; equals result URL.
    #[schema(max_length = 64, pattern = "^https://openalex\\.org/W[0-9]+$")]
    openalex_id: String,
    /// Canonical HTTPS DOI URL, at most 2048 UTF-8 bytes, or explicit null; key is required.
    #[schema(required = true, nullable = true)]
    doi: Option<String>,
    /// Canonical HTTP(S) DNS URL, at most 2048 UTF-8 bytes, or null; never fetched.
    #[schema(required = true, nullable = true)]
    oa_url: Option<String>,
    /// Ordered 0..=100 nonblank names, each <=256 Unicode scalars and <=1024 UTF-8 bytes.
    #[schema(max_items = 100)]
    authors: Vec<String>,
    /// Source publication year in 1..=9999; no frozen corpus slice.
    #[schema(minimum = 1, maximum = 9999)]
    publication_year: u16,
    /// Nonblank venue <=256 Unicode scalars and <=1024 UTF-8 bytes, or explicit null.
    #[schema(required = true, nullable = true)]
    venue: Option<String>,
    /// Valid ten-byte YYYY-MM-DD source snapshot date, or null for the live OpenAlex API.
    /// This is never a retrieval date; compatible HTTP services must supply a source date.
    #[schema(required = true, nullable = true)]
    snapshot_date: Option<String>,
    /// Exact SPDX metadata licence CC0-1.0, independent of paper or location rights.
    #[schema(schema_with = metadata_license_schema)]
    metadata_license: String,
}

// A single literal must be represented exactly, rather than by a permissive regex pattern.
fn metadata_license_schema() -> utoipa::openapi::Object {
    utoipa::openapi::ObjectBuilder::new()
        .schema_type(utoipa::openapi::schema::Type::String)
        .enum_values(Some(["CC0-1.0"]))
        .build()
}

impl std::fmt::Debug for ScholarlyAttribution {
    // Formatting metadata can disclose queries indirectly through matching source text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScholarlyAttribution { .. }")
    }
}

impl ScholarlyAttribution {
    // Revalidate external deserialization and internal construction against identical invariants.
    fn validate(&self) -> Result<(), V1Error> {
        validate_id(&self.openalex_id)?;
        if let Some(doi) = &self.doi {
            validate_doi(doi)?;
        }
        if let Some(oa) = &self.oa_url {
            validate_link(oa)?;
        }
        if self.authors.len() > MAX_PAPER_AUTHORS
            || !(1..=MAX_PAPER_YEAR).contains(&self.publication_year)
            || self.metadata_license != "CC0-1.0"
        {
            return Err(V1Error::invalid_result());
        }
        for name in self.authors.iter().chain(self.venue.iter()) {
            paper_name(name)?;
        }
        if let Some(date) = &self.snapshot_date {
            if date.len() != SNAPSHOT_DATE_BYTES
                || !date.is_ascii()
                || date.bytes().enumerate().any(|(i, b)| {
                    if i == 4 || i == 7 {
                        b != b'-'
                    } else {
                        !b.is_ascii_digit()
                    }
                })
                || date.starts_with("0000")
                || chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err()
            {
                return Err(V1Error::invalid_result());
            }
        }
        Ok(())
    }
    // A valid attribution alone cannot authorize a forged enclosing result.
    fn bind(&self, result: &AttributedResult) -> Result<(), V1Error> {
        if self.openalex_id != result.url
            || result.domain() != "openalex.org"
            || !result.snippet.is_empty()
        {
            return Err(V1Error::invalid_result());
        }
        paper_title(result.title())
    }
    /// Enumerates independently checked known links; callers deduplicate canonical URLs.
    pub(crate) fn known_urls(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.openalex_id.as_str())
            .chain(self.doi.as_deref())
            .chain(self.oa_url.as_deref())
    }
}

impl<'de> Deserialize<'de> for ScholarlyAttribution {
    // Required nullable decoding distinguishes a truthful null from a missing protocol key.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            openalex_id: String,
            #[serde(deserialize_with = "required_nullable_text")]
            doi: Option<String>,
            #[serde(deserialize_with = "required_nullable_text")]
            oa_url: Option<String>,
            #[serde(deserialize_with = "paper_authors")]
            authors: Vec<String>,
            publication_year: u16,
            #[serde(deserialize_with = "required_nullable_text")]
            venue: Option<String>,
            #[serde(deserialize_with = "required_nullable_text")]
            snapshot_date: Option<String>,
            metadata_license: String,
        }
        let raw = Raw::deserialize(d)?;
        let value = Self {
            openalex_id: raw.openalex_id,
            doi: raw.doi,
            oa_url: raw.oa_url,
            authors: raw.authors,
            publication_year: raw.publication_year,
            venue: raw.venue,
            snapshot_date: raw.snapshot_date,
            metadata_license: raw.metadata_license,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

// Omission is handled only by the enclosing serde default; a present null is never web.
fn non_null_scholarly<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<ScholarlyAttribution>, D::Error> {
    ScholarlyAttribution::deserialize(d).map(Some)
}

// No serde default on callers: explicit null is valid but absence is a protocol error.
fn required_nullable_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

// Separate scalar and byte guards preserve exact source text without silent truncation.
fn paper_title(value: &str) -> Result<(), V1Error> {
    if value.trim().is_empty()
        || value.len() > MAX_PAPER_TITLE_BYTES
        || value.chars().count() > MAX_PAPER_TITLE_SCALARS
    {
        return Err(V1Error::invalid_result());
    }
    Ok(())
}

// Names have different bounds from titles and cannot be blank, even in optional venues.
fn paper_name(value: &str) -> Result<(), V1Error> {
    if value.trim().is_empty()
        || value.len() > MAX_PAPER_NAME_BYTES
        || value.chars().count() > MAX_PAPER_NAME_SCALARS
    {
        return Err(V1Error::invalid_result());
    }
    Ok(())
}

/// Enforces the author allocation bound for external DTO decoding as well as transport parsing.
pub(super) fn paper_authors<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    struct Authors;
    impl<'de> serde::de::Visitor<'de> for Authors {
        type Value = Vec<String>;
        // Fixed expectation text cannot echo a malformed name.
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded author array")
        }
        // Stop on entry 101 rather than first allocating an unbounded vector.
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut names = Vec::new();
            while let Some(name) = seq.next_element::<String>()? {
                if names.len() >= MAX_PAPER_AUTHORS {
                    return Err(serde::de::Error::custom("paper author bounds"));
                }
                paper_name(&name).map_err(serde::de::Error::custom)?;
                names.push(name);
            }
            Ok(names)
        }
    }
    d.deserialize_seq(Authors)
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
    /// Assembles the versioned response from validated results and the upstream pagination hint.
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

/// A singleton true value; callers cannot construct a false acknowledgement.
#[derive(Serialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = bool)]
#[schema(as = V1Suppressed)]
pub struct Suppressed(bool);

/// Non-enumerating acknowledgement of durable local suppression.
#[derive(Serialize, ToSchema)]
pub struct V1DeleteResponse {
    version: V1Version,
    id: DocumentId,
    suppressed: Suppressed,
}
impl V1DeleteResponse {
    /// Constructs the sole successful acknowledgement shape after a completed transaction.
    pub(super) fn new(id: DocumentId) -> Self {
        Self {
            version: V1Version::default(),
            id,
            suppressed: Suppressed(true),
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
