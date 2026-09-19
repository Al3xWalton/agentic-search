//! Validates original requests before the unchanged search backend, then assembles attributed results.
//! Country classification is a serving-policy input, independent of ranking geography.

use super::{
    dto::{AttributedResult, Country, V1SearchRequest, V1SearchResponse},
    error::{self, V1Error, V1Failure},
    suppression::canonical_identity,
    CappedBody, V1State,
};
use crate::{
    config::ingestion::ServingPolicy,
    query::{
        parser::Term,
        planner::bounds::{self, InputError},
    },
    searcher::{SearchQuery, SearchResult},
};
use axum::{
    extract::{FromRequest, Request, State},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// Maximum zero-based public page depth; independent of inherited arithmetic bounds.
pub const MAX_PAGE: u64 = 99;

/// Immutable classification passed to the live suppression decision for every candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServingContext {
    /// Original UK/non-UK/unknown classification; unknown is never relabelled UK.
    pub country: Country,
    /// Whether the stored policy requires conservative UK measures.
    pub uk_measures: bool,
    /// Child treatment; a true adult assertion is not independent age assurance.
    pub is_child: bool,
}

fn context(request: &V1SearchRequest, policy: &ServingPolicy) -> ServingContext {
    let uk_measures = match request.country {
        Country::Uk => policy.uk_or_unknown_measures,
        Country::Unknown => policy.uk_or_unknown_measures,
        // Startup validation accepts only same-as-uk, so the stored policy requires UK measures.
        Country::NonUk => true,
    };
    let is_child = match request.adult_verified {
        None => policy.missing_adult_is_child,
        Some(adult) => !adult,
    };
    ServingContext {
        country: request.country,
        uk_measures,
        is_child,
    }
}

/// A bounded request ready for the backend; its fields are private to prevent validation bypass.
pub struct ValidatedSearchRequest {
    query: SearchQuery,
    context: ServingContext,
    page: u64,
    count: u64,
}

fn validate(
    request: V1SearchRequest,
    policy: &ServingPolicy,
) -> Result<ValidatedSearchRequest, V1Error> {
    if request.page > MAX_PAGE {
        return Err(InputError::InvalidPage.into());
    }
    let page = usize::try_from(request.page).map_err(|_| InputError::InvalidPage)?;
    let count = usize::try_from(request.num_results).map_err(|_| InputError::InvalidResultCount)?;
    let _offset = bounds::validate_numbers(page, count, true)?;
    let atoms = bounds::scan_query(&request.query)?;
    if atoms.iter().any(|atom| has_bang(&atom.term)) {
        return Err(InputError::InvalidQuerySyntax.into());
    }
    let context = context(&request, policy);
    let query = SearchQuery {
        query: request.query,
        page,
        num_results: count,
        return_ranking_signals: false,
        return_structured_data: false,
        return_body: None,
        ..Default::default()
    };
    Ok(ValidatedSearchRequest {
        query,
        context,
        page: request.page,
        count: request.num_results,
    })
}

fn has_bang(term: &Term) -> bool {
    match term {
        Term::PossibleBang { .. } => true,
        Term::Not(inner) => has_bang(inner),
        _ => false,
    }
}

#[axum::async_trait]
impl FromRequest<Arc<V1State>> for ValidatedSearchRequest {
    type Rejection = V1Error;
    async fn from_request(request: Request, state: &Arc<V1State>) -> Result<Self, Self::Rejection> {
        let media = request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !media
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
        {
            return Err(V1Error::failure(V1Failure::UnsupportedMediaType));
        }
        let body = request
            .extensions()
            .get::<CappedBody>()
            .ok_or_else(|| V1Error::failure(V1Failure::InternalError))?;
        state.observer.json_decode();
        let decoded = serde_json::from_slice(&body.0).map_err(|_| InputError::InvalidRequest)?;
        validate(decoded, &state.policy)
    }
}

/// Returns attributed text results, preserving order and the upstream pre-suppression page hint.
#[utoipa::path(post, path = "/v1/search", request_body = V1SearchRequest, responses((status = 200, description = "Attributed text results; suppression can shorten a page", body = V1SearchResponse)), tag = "v1")]
pub async fn route(State(state): State<Arc<V1State>>, request: ValidatedSearchRequest) -> Response {
    // Avoid paid backend work when the store is already unable to serve.
    if state.store.unavailable().await {
        return V1Error::failure(V1Failure::SuppressionUnavailable).into_response();
    }
    if state.compliance.rules().unavailable().await {
        return V1Error::failure(V1Failure::RulesUnavailable).into_response();
    }
    let query_tokens = crate::compliance::rules::query_tokens(&request.query.query);
    state.observer.backend_enter();
    let result = match state.backend.search(request.query).await {
        Ok(SearchResult::Websites(result)) => result,
        Ok(SearchResult::Bang(_)) => return V1Error::invalid_result().into_response(),
        Err(error) => return V1Error::from_error(error).into_response(),
    };
    state.observer.before_assembly().await;
    let gate = state.store.state.read().await;
    // This live gate check is the linearization point, after potentially concurrent retrieval.
    if gate.unavailable {
        return V1Error::failure(V1Failure::SuppressionUnavailable).into_response();
    }
    let rules = state.compliance.rules().read().await;
    if rules.unavailable() {
        return V1Error::failure(V1Failure::RulesUnavailable).into_response();
    }
    let rule_context = crate::compliance::rules::RuleContext {
        country: match request.context.country {
            Country::Uk => crate::compliance::rules::RuleCountry::Uk,
            Country::NonUk => crate::compliance::rules::RuleCountry::NonUk,
            Country::Unknown => crate::compliance::rules::RuleCountry::Unknown,
        },
        is_child: request.context.is_child,
        uk_measures: request.context.uk_measures,
    };
    let now = state.compliance.rules().serving_now();
    let mut hosts = crate::compliance::listed::HostCache::default();
    let mut results = Vec::with_capacity(result.webpages.len());
    for page in result.webpages {
        // This hash is the suppression key; the DTO independently enforces its own identity.
        let (canonical_url, id) = match canonical_identity(&page.url) {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
        state.observer.serving_context(&id, &request.context);
        if !gate.allows_document(&id, &request.context) {
            continue;
        }
        let document = match crate::compliance::model::DocumentKey::parse(id.as_str()) {
            Ok(document) => document,
            Err(_) => return V1Error::invalid_result().into_response(),
        };
        state.observer.compliance_context(&rule_context);
        if !rules.allows(
            &document,
            &canonical_url,
            &query_tokens,
            &rule_context,
            now,
            &mut hosts,
        ) {
            continue;
        }
        state.observer.attribution_construct(&id);
        match AttributedResult::try_from_page(&page) {
            Ok(page) => results.push(page),
            Err(error) => return error.into_response(),
        }
    }
    // Serialization stays inside the gate: a completed delete precedes every later assembly.
    error::success(&V1SearchResponse::new(
        results,
        request.page,
        request.count,
        result.has_more_results,
    ))
}
