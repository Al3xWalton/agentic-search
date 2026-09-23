//! Checks management headers before admission and at the route, then acknowledges audited delivery.
//! Raw HTML lives only in the bounded request and audited RPC payload, never in API persistence.

#![deny(missing_docs)]

use super::{
    compliance_adapter,
    dto::AttributedResult,
    error::{self, V1Error, V1Failure},
    ingest_dto::{
        validate_bound, IngestBound, V1AdmissionReason, V1IngestRequest, V1IngestResponse,
    },
    ingest_register::{digest, Submission},
    suppression::{canonical_identity, DocumentId},
    V1State,
};
use crate::{
    crawler::{directives, network::ResponseHeaders},
    entrypoint::indexer::{IndexableWebpage, IndexingWorker},
    query::planner::bounds::InputError,
    webpage::url_ext::UrlExt,
};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::put,
    Router,
};
use kuchiki::traits::TendrilSink;
use std::{collections::BTreeSet, sync::Arc, time::Duration};

/// A page that passed this route's admission checks; callers cannot construct it unchecked.
/// It retains the original fetched HTML for one RPC, without retaining a non-Send DOM.
pub struct AuditedIngestPage {
    page: IndexableWebpage,
}

impl AuditedIngestPage {
    /// Consumes the admission wrapper for the existing live-index message or a local test adapter.
    pub fn into_indexable_webpage(self) -> IndexableWebpage {
        self.page
    }

    /// Retains the current version's validated fetch duration when dispatching its content again.
    pub(super) fn with_fetch_time_ms(mut self, fetch_time_ms: u64) -> Self {
        self.page.fetch_time_ms = fetch_time_ms;
        self
    }
}

/// Builds PUT-only authentication; unsupported methods retain the ordinary unauthenticated 405.
pub(super) fn routes(state: Arc<V1State>) -> Router<Arc<V1State>> {
    Router::new().route(
        "/documents/:id",
        put(route).route_layer(middleware::from_fn_with_state(state, authenticate)),
    )
}

/// Verifies management headers through the shared fixed-width bearer authenticator.
fn verify(state: &V1State, headers: &HeaderMap) -> Result<(), V1Error> {
    if !state.compliance_auth.authorises(
        headers
            .get_all("authorization")
            .iter()
            .map(|value| value.as_bytes()),
        state.compliance_observer.as_ref(),
    ) {
        return Err(V1Error::failure(V1Failure::Unauthorised));
    }
    Ok(())
}

async fn authenticate(State(state): State<Arc<V1State>>, request: Request, next: Next) -> Response {
    if let Err(error) = verify(&state, request.headers()) {
        return error.into_response();
    }
    next.run(request).await
}

/// Rejects unauthorised ingest headers before listener admission or body collection.
pub(super) async fn precheck(
    State(state): State<Arc<V1State>>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() == Method::PUT && request.uri().path().starts_with("/documents/") {
        if let Err(error) = verify(&state, request.headers()) {
            return error.into_response();
        }
    }
    next.run(request).await
}

/// Admits one fetched HTML document on the authenticated management listener.
/// A 200 acknowledges WAL receipt, not immediate visibility or newest-content replacement.
#[utoipa::path(
    put, path = "/v1/documents/{id}",
    params(("id" = String, Path, description = "Lowercase SHA-256 of the canonical URL")),
    request_body = V1IngestRequest,
    responses((status = 200, description = "Admitted and acknowledged by the live index",
        body = V1IngestResponse)),
    tag = "v1"
)]
pub async fn route(State(state): State<Arc<V1State>>, request: Request) -> Response {
    match execute(&state, request).await {
        Ok(response) => error::success(&response),
        Err(error) => error.into_response(),
    }
}

async fn execute(state: &V1State, request: Request) -> Result<V1IngestResponse, V1Error> {
    state.observer.ingest_enter();
    let raw = request
        .uri()
        .path()
        .strip_prefix("/documents/")
        .unwrap_or("");
    let id = DocumentId::parse(raw)?;
    let input: V1IngestRequest = compliance_adapter::decode(&request, state)?;
    input.validate()?;
    let received_at = state.ingest_register.now()?;
    if input.retrieved_at > received_at {
        return Err(InputError::InvalidRequest.into());
    }
    let (canonical_url, canonical_id) = canonical_identity(&input.url)
        .map_err(|_| V1Error::not_admitted(V1AdmissionReason::InvalidUrl))?;
    validate_bound(IngestBound::Url, canonical_url.len() as i128)?;
    if id != canonical_id {
        return Err(V1Error::invalid_document_id());
    }
    state.observer.ingest_audit();
    let body_sha256 = digest(input.body.as_bytes());
    let V1IngestRequest {
        body,
        fetch_time_ms,
        retrieved_at,
        source,
        x_robots_tag,
        ..
    } = input;
    let page = IndexableWebpage {
        record: None,
        url: canonical_url.clone(),
        body,
        fetch_time_ms,
    };
    let attribution = audit(&page, &x_robots_tag, &canonical_url, received_at)?;
    admit_rules(state, &id, &canonical_url).await?;
    let page = AuditedIngestPage { page };
    let submission = Submission {
        id,
        canonical_url,
        body_sha256,
        received_at,
        retrieved_at,
        fetch_time_ms,
        source,
    };
    let receipt = state
        .ingest_register
        .submit(
            submission,
            page,
            state.ingest_backend.clone(),
            Duration::from_millis(state.config.request_timeout_ms),
            compliance_adapter::lease(&request)?,
        )
        .await?;
    V1IngestResponse::new(&attribution, receipt.version, receipt.received_at)
}

fn audit(
    page: &IndexableWebpage,
    x_robots_tag: &[String],
    canonical_url: &str,
    received_at: i64,
) -> Result<AttributedResult, V1Error> {
    let html = IndexingWorker::audit_page(page).map_err(|reason| {
        V1Error::not_admitted(match reason {
            "invalid-url" => V1AdmissionReason::InvalidUrl,
            "noindex" => V1AdmissionReason::Noindex,
            "empty title" => V1AdmissionReason::EmptyTitle,
            _ => V1AdmissionReason::Excluded,
        })
    })?;
    if html.url().as_str() != canonical_url {
        return Err(V1Error::not_admitted(V1AdmissionReason::InvalidUrl));
    }
    let domain = html.url().root_domain().unwrap_or_default();
    if domain.trim().is_empty() {
        return Err(V1Error::not_admitted(V1AdmissionReason::InvalidUrl));
    }
    let title = html.title().unwrap_or_default();
    if title.trim().is_empty() {
        return Err(V1Error::not_admitted(V1AdmissionReason::EmptyTitle));
    }
    let attribution = AttributedResult::try_new(canonical_url, domain, &title, "")?;
    publisher_policy(&page.body, x_robots_tag, html.url(), received_at)?;
    Ok(attribution)
}

fn publisher_policy(
    body: &str,
    x_robots_tag: &[String],
    url: &url::Url,
    received_at: i64,
) -> Result<(), V1Error> {
    let now = chrono::DateTime::from_timestamp(received_at, 0)
        .ok_or_else(|| V1Error::failure(V1Failure::IngestUnavailable))?;
    let mut headers = ResponseHeaders::default();
    for value in x_robots_tag {
        headers.observe("x-robots-tag", Some(value.as_str()));
    }
    let effective = directives::parse_headers(&headers, url).effective;
    if !effective.index_eligible(now)
        || effective.nosnippet
        || effective.max_snippet.is_some()
        || effective.unavailable_after_utc.is_some()
    {
        return Err(V1Error::not_admitted(V1AdmissionReason::HeaderDirective));
    }
    // The indexer's audit handles meta noindex and malformed directives. Only the display and
    // future-removal guarantees missing from this RPC payload need an additional conservative gate.
    let root = kuchiki::parse_html().one(body);
    let meta = directives::parse_meta(&root).effective;
    if meta
        .unavailable_after_utc
        .is_some_and(|deadline| now >= deadline)
    {
        return Err(V1Error::not_admitted(V1AdmissionReason::Noindex));
    }
    if meta.nosnippet || meta.max_snippet.is_some() || meta.unavailable_after_utc.is_some() {
        return Err(V1Error::not_admitted(V1AdmissionReason::Excluded));
    }
    Ok(())
}

async fn admit_rules(state: &V1State, id: &DocumentId, url: &str) -> Result<(), V1Error> {
    use crate::compliance::{listed::HostCache, model::DocumentKey, rules::*};
    let rules = state.compliance.rules().read().await;
    if rules.unavailable() {
        return Err(V1Error::failure(V1Failure::RulesUnavailable));
    }
    let document = DocumentKey::parse(id.as_str()).map_err(|_| V1Error::invalid_result())?;
    if !rules.allows(
        &document,
        url,
        &BTreeSet::new(),
        &RuleContext {
            country: RuleCountry::Unknown,
            is_child: true,
            uk_measures: true,
        },
        state.compliance.rules().serving_now(),
        &mut HostCache::default(),
    ) {
        return Err(V1Error::not_admitted(V1AdmissionReason::Excluded));
    }
    Ok(())
}
