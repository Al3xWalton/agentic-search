//! Independently implements the public scholar v1 wire contract for an explicit compatible service.
//! It accepts metadata-only attributed results and never forwards remote envelopes or headers.

#![deny(missing_docs)]

use super::{transport, *};
use crate::config::papers::Secret;
use serde::{Deserialize, Deserializer, Serialize};

/// Explicitly configured provider, with one immutable client and sensitive bearer value.
pub(super) struct HttpProvider {
    client: reqwest::Client,
    endpoint: url::Url,
    authorization: reqwest::header::HeaderValue,
    budgets: transport::Budgets,
}

impl fmt::Debug for HttpProvider {
    // Omit endpoints as well as credentials to keep private service topology out of diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HttpProvider { .. }")
    }
}

impl HttpProvider {
    /// Validates the explicit endpoint and builds an idle client without probing the service.
    pub(super) fn new(endpoint: &str, secret: Secret) -> Result<Self, PaperProviderError> {
        let endpoint = transport::endpoint(endpoint)?;
        let budgets = transport::Budgets::default();
        Ok(Self {
            client: transport::client(budgets)?,
            endpoint,
            authorization: secret.header()?,
            budgets,
        })
    }
}

#[derive(Serialize)]
struct WireRequest<'a> {
    query: &'a str,
    page: u16,
    num_results: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePage {
    results: Vec<AttributedResult>,
    #[serde(deserialize_with = "required_hint")]
    next_page: Option<u16>,
}

// Absence of a nullable hint is a protocol error, not an implicit last page.
fn required_hint<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u16>, D::Error> {
    Option::<u16>::deserialize(d)
}

impl PaperProvider for HttpProvider {
    // One isolated future owns every phase, and dropping it drops the in-flight HTTP exchange.
    fn search(&self, request: PaperQuery) -> BoxFuture<'_, Result<PaperPage, PaperProviderError>> {
        Box::pin(transport::isolated(async move {
            let started = tokio::time::Instant::now();
            let body = super::super::error::capped_bytes(
                &WireRequest {
                    query: &request.query,
                    page: request.page,
                    num_results: request.num_results,
                },
                MAX_PROVIDER_REQUEST_BYTES,
            )
            .map_err(|_| PaperProviderError::InvalidRequest)?;
            let builder = self
                .client
                .post(self.endpoint.clone())
                .header("Authorization", self.authorization.clone())
                .header("Content-Type", "application/json")
                .body(body);
            let response = transport::exchange(builder, self.budgets, true).await?;
            if started.elapsed() >= self.budgets.total {
                return Err(PaperProviderError::Deadline);
            }
            let result = map_response(response, &request);
            if started.elapsed() >= self.budgets.total {
                return Err(PaperProviderError::Deadline);
            }
            result
        }))
    }
}

// Even recognized status codes need their exact closed body; arbitrary remote prose is discarded.
fn map_response(
    response: transport::Collected,
    query: &PaperQuery,
) -> Result<PaperPage, PaperProviderError> {
    if response.status != 200 {
        if let Some(name) = transport::error_name(response.status) {
            let value = transport::parse(&response.body)?;
            if value.as_object().is_none_or(|map| map.len() != 1)
                || value.get("error").and_then(serde_json::Value::as_str) != Some(name)
            {
                return Err(PaperProviderError::InvalidResponse);
            }
            if response.status == 504 {
                return Err(PaperProviderError::Deadline);
            }
        }
        return Err(PaperProviderError::Unavailable);
    }
    let value = transport::parse(&response.body)?;
    let hits = value
        .get("results")
        .and_then(serde_json::Value::as_array)
        .ok_or(PaperProviderError::InvalidResponse)?;
    for hit in hits {
        if hit
            .get("scholarly")
            .and_then(|s| s.get("snapshot_date"))
            .is_none_or(serde_json::Value::is_null)
        {
            return Err(PaperProviderError::InvalidResponse);
        }
    }
    let wire: WirePage =
        serde_json::from_value(value).map_err(|_| PaperProviderError::InvalidResponse)?;
    let page = PaperPage::try_new(wire.results, wire.next_page)?;
    page.validate_for(query)?;
    Ok(page)
}
