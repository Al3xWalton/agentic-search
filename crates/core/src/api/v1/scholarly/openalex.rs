//! Adapts a fixed-origin OpenAlex page to attributed metadata without fetching content.
//! Unmappable records are dropped only for the documented record defects; identity is page-fatal.

#![deny(missing_docs)]

use super::{transport, *};
use crate::{api::v1::dto::ScholarlyAttribution, config::papers::Secret};
use serde_json::Value;

/// Inclusive maximum encoded OpenAlex request URL size, in bytes.
const MAX_OPENALEX_REQUEST_URL_BYTES: usize = 4_094;
/// Inclusive one-based page-times-count result window.
const MAX_OPENALEX_WINDOW: u32 = 10_000;

/// Fixed-origin, network-idle metadata adapter with opaque diagnostics.
pub(super) struct OpenAlex {
    client: reqwest::Client,
    authorization: reqwest::header::HeaderValue,
    origin: url::Url,
    budgets: transport::Budgets,
}

impl fmt::Debug for OpenAlex {
    // reqwest's own Debug can include destinations; expose none of its internals.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenAlex { .. }")
    }
}

impl OpenAlex {
    /// Loads an immutable sensitive header and the fixed public API destination.
    pub(super) fn new(secret: Secret) -> Result<Self, PaperProviderError> {
        let budgets = transport::Budgets::default();
        let origin = url::Url::parse("https://api.openalex.org/works")
            .map_err(|_| PaperProviderError::Configuration)?;
        #[cfg(test)]
        let origin = super::tests::openalex_origin(origin);
        Ok(Self {
            client: transport::client(budgets)?,
            authorization: secret.header()?,
            origin,
            budgets,
        })
    }

    // Check service limits before a paid operation, while preserving exact query bytes.
    fn request_url(&self, request: &PaperQuery) -> Result<url::Url, PaperProviderError> {
        let page = request
            .page
            .checked_add(1)
            .ok_or(PaperProviderError::Unavailable)?;
        if u32::from(page)
            .checked_mul(u32::from(request.num_results))
            .is_none_or(|end| end > MAX_OPENALEX_WINDOW)
        {
            return Err(PaperProviderError::Unavailable);
        }
        let mut url = self.origin.clone();
        url.query_pairs_mut()
            .append_pair("search", &request.query)
            .append_pair("per_page", &request.num_results.to_string())
            .append_pair("page", &page.to_string());
        if url.as_str().len() > MAX_OPENALEX_REQUEST_URL_BYTES {
            return Err(PaperProviderError::Unavailable);
        }
        Ok(url)
    }
}

impl PaperProvider for OpenAlex {
    // Isolation covers request construction, actual transport, JSON decoding and conversion.
    fn search(&self, request: PaperQuery) -> BoxFuture<'_, Result<PaperPage, PaperProviderError>> {
        Box::pin(async move {
            let (page, dropped) = transport::isolated(self.search_counted(request)).await?;
            tracing::trace!(provider = "openalex", dropped, "paper records processed");
            Ok(page)
        })
    }
}

impl OpenAlex {
    // Return only a finite counter across isolation; no provider metadata reaches diagnostics.
    async fn search_counted(
        &self,
        request: PaperQuery,
    ) -> Result<(PaperPage, usize), PaperProviderError> {
        let started = tokio::time::Instant::now();
        let url = self.request_url(&request)?;
        let builder = self
            .client
            .get(url)
            .header("Authorization", self.authorization.clone());
        let response = transport::exchange(builder, self.budgets, false).await?;
        if response.status != 200 {
            return Err(PaperProviderError::Unavailable);
        }
        if started.elapsed() >= self.budgets.total {
            return Err(PaperProviderError::Deadline);
        }
        let page = map_page(transport::parse(&response.body)?, &request)?;
        if started.elapsed() >= self.budgets.total {
            return Err(PaperProviderError::Deadline);
        }
        Ok(page)
    }
}

// Count before drops so bad metadata cannot hide a false count or duplicate identity.
fn map_page(value: Value, query: &PaperQuery) -> Result<(PaperPage, usize), PaperProviderError> {
    let count = value
        .get("meta")
        .and_then(|m| m.get("count"))
        .and_then(Value::as_u64)
        .ok_or(PaperProviderError::InvalidResponse)?;
    let records = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or(PaperProviderError::InvalidResponse)?;
    if records.len() > usize::from(query.num_results) || count < records.len() as u64 {
        return Err(PaperProviderError::InvalidResponse);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut results = Vec::new();
    let mut dropped = 0usize;
    for record in records {
        let id = required_text(record, "id")?;
        validate_id(id).map_err(|_| PaperProviderError::InvalidResponse)?;
        if !ids.insert(id) {
            return Err(PaperProviderError::InvalidResponse);
        }
        match map_record(record, id)? {
            Some(hit) => results.push(hit),
            None => dropped += 1,
        }
    }
    let end = u64::from(query.page)
        .checked_add(1)
        .and_then(|page| page.checked_mul(u64::from(query.num_results)))
        .ok_or(PaperProviderError::InvalidResponse)?;
    let next = if count > end && u64::from(query.page) < super::super::search::MAX_PAGE {
        query.page.checked_add(1)
    } else {
        None
    };
    Ok((PaperPage::try_new(results, next)?, dropped))
}

// A record is either wholly validated or absent; there is no partial attribution fallback.
fn map_record(record: &Value, id: &str) -> Result<Option<AttributedResult>, PaperProviderError> {
    let title = optional_text(record, "title")?;
    let Some(title) = title else {
        return Ok(None);
    };
    if title.trim().is_empty()
        || title.len() > MAX_PAPER_TITLE_BYTES
        || title.chars().count() > MAX_PAPER_TITLE_SCALARS
    {
        return Ok(None);
    }
    let year = match record.get("publication_year") {
        None | Some(Value::Null) => return Ok(None),
        Some(value) => match value.as_i64() {
            Some(year) => year,
            None if value.is_u64() => return Ok(None),
            None => return Err(PaperProviderError::InvalidResponse),
        },
    };
    if !(1..=i64::from(MAX_PAPER_YEAR)).contains(&year) {
        return Ok(None);
    }
    let authorships = record
        .get("authorships")
        .and_then(Value::as_array)
        .ok_or(PaperProviderError::InvalidResponse)?;
    if authorships.len() > MAX_PAPER_AUTHORS {
        return Ok(None);
    }
    let mut authors = Vec::new();
    for authorship in authorships {
        let Some(author) = authorship.get("author") else {
            return Ok(None);
        };
        let Some(name) = author.get("display_name").and_then(Value::as_str) else {
            return Ok(None);
        };
        if !valid_name(name) {
            return Ok(None);
        }
        authors.push(name);
    }
    let Ok(doi) = optional_text(record, "doi") else {
        return Ok(None);
    };
    if doi.is_some_and(|value| validate_doi(value).is_err()) {
        return Ok(None);
    }
    let venue = nested(record, &["primary_location", "source", "display_name"])?;
    if venue.is_some_and(|name| !valid_name(name)) {
        return Ok(None);
    }
    let Ok(candidates) = [
        nested(record, &["best_oa_location", "landing_page_url"]),
        nested(record, &["best_oa_location", "pdf_url"]),
        nested(record, &["open_access", "oa_url"]),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>() else {
        return Ok(None);
    };
    if candidates
        .iter()
        .flatten()
        .any(|value| validate_link(value).is_err())
    {
        return Ok(None);
    }
    let oa = candidates.into_iter().flatten().next();
    let attribution = serde_json::from_value::<ScholarlyAttribution>(serde_json::json!({
        "openalex_id": id, "doi": doi, "oa_url": oa, "authors": authors,
        "publication_year": year, "venue": venue, "snapshot_date": null,
        "metadata_license": "CC0-1.0"
    }))
    .map_err(|_| PaperProviderError::InvalidResponse)?;
    AttributedResult::try_from_paper(title, attribution)
        .map(Some)
        .map_err(|_| PaperProviderError::InvalidResponse)
}

// Validate before cloning a remote name into local attributed metadata.
fn valid_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= MAX_PAPER_NAME_BYTES
        && name.chars().count() <= MAX_PAPER_NAME_SCALARS
}

// Required identities cannot be converted from nulls or other JSON types.
fn required_text<'a>(value: &'a Value, field: &str) -> Result<&'a str, PaperProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(PaperProviderError::InvalidResponse)
}

// Missing optional metadata differs from malformed non-null metadata.
fn optional_text<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>, PaperProviderError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        _ => Err(PaperProviderError::InvalidResponse),
    }
}

// Reject malformed containers instead of treating wrong types as missing source facts.
fn nested<'a>(value: &'a Value, path: &[&str]) -> Result<Option<&'a str>, PaperProviderError> {
    let mut node = value;
    for key in path {
        if node.is_null() {
            return Ok(None);
        }
        let map = node
            .as_object()
            .ok_or(PaperProviderError::InvalidResponse)?;
        let Some(child) = map.get(*key) else {
            return Ok(None);
        };
        node = child;
    }
    if node.is_null() {
        Ok(None)
    } else {
        node.as_str()
            .map(Some)
            .ok_or(PaperProviderError::InvalidResponse)
    }
}
