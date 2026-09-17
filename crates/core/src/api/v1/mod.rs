//! Implements the bounded agent HTTP contract as an independently finished router subtree.
//! Request order is headers, envelope normalization, unwind catch, deadline, admission, body cap,
//! then route extraction and assembly. Nesting keeps its fallback separate from legacy routes.

use crate::{
    config::{
        ingestion::{IngestionPolicy, ServingPolicy},
        v1::V1ApiConfig,
        ApiConfig,
    },
    query::planner::bounds::{self, InputError},
    searcher::{SearchQuery, SearchResult},
};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Request, State},
    http::{HeaderValue, Method},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use error::{V1Error, V1Failure};
use futures::{future::BoxFuture, FutureExt};
use std::{panic::AssertUnwindSafe, sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Management-only durable document suppression.
pub mod documents;
/// Immutable attributed HTTP types and their rejecting constructors/decoders.
pub mod dto;
/// Closed errors and private safe-response marking.
pub mod error;
/// Request validation, country context and final result assembly.
pub mod search;
/// Versioned source metadata operation.
pub mod source;
/// Canonical identifiers and shared serving state.
pub mod suppression;

/// Narrow adapter for the unchanged internal search result; validation happens before this call.
pub trait SearchBackend: Send + Sync + 'static {
    /// Searches the validated internal query without accepting HTTP-specific policy fields.
    fn search(&self, query: SearchQuery) -> BoxFuture<'_, anyhow::Result<SearchResult>>;
}

impl<F, Fut> SearchBackend for F
where
    F: Fn(SearchQuery) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = anyhow::Result<SearchResult>> + Send + 'static,
{
    fn search(&self, query: SearchQuery) -> BoxFuture<'_, anyhow::Result<SearchResult>> {
        Box::pin(self(query))
    }
}

/// Optional bounded observation seam; default production behavior performs no instrumentation.
pub trait Observer: Send + Sync + 'static {
    /// Observes entry to JSON decoding, after admission and bounded body collection.
    fn json_decode(&self) {}
    /// Observes the backend boundary after request validation.
    fn backend_enter(&self) {}
    /// Observes source handler entry after bodyless validation.
    fn source_enter(&self) {}
    /// Observes a validated delete entering the serialized store gate.
    fn delete_enter(&self) {}
    /// Allows a fixture to pause after retrieval, before the assembly read gate.
    fn before_assembly(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
    /// Observes actual immutable context at the live suppression decision.
    fn serving_context(&self, _id: &suppression::DocumentId, _context: &search::ServingContext) {}
    /// Observes attributed construction only for unsuppressed candidates.
    fn attribution_construct(&self, _id: &suppression::DocumentId) {}
}
struct NoObserver;
impl Observer for NoObserver {}

/// Shared backend, immutable validated policy and suppression gate.
pub struct V1State {
    /// Validated-query adapter, shared with the legacy internal searcher.
    pub(super) backend: Arc<dyn SearchBackend>,
    /// Immutable policy copied only from the validated ingestion policy.
    pub(super) policy: ServingPolicy,
    /// One durable local owner shared by both listeners.
    pub(super) store: Arc<suppression::SuppressionStore>,
    /// Bounded lifecycle instrumentation; absent in ordinary production operation.
    pub(super) observer: Arc<dyn Observer>,
    config: V1ApiConfig,
}

/// Startup-owned policy and durable store, loaded before binding any HTTP listener.
pub struct V1Resources {
    policy: ServingPolicy,
    store: Arc<suppression::SuppressionStore>,
}

fn validated_policy(config: &ApiConfig) -> anyhow::Result<ServingPolicy> {
    config
        .v1
        .validate(&[config.host, config.prometheus_host, config.management_host])?;
    let policy = match config.crawler_policy_config_path.as_deref() {
        Some(path) => IngestionPolicy::load(path)?,
        None => crate::crawler::policy::template()?,
    };
    Ok(policy.get().exclusions.serving.clone())
}

impl V1Resources {
    /// Performs blocking startup validation and opens the lifetime store lock.
    /// Call through spawn_blocking in an async entrypoint; any failure prevents serving.
    pub fn load(config: &ApiConfig) -> anyhow::Result<Self> {
        let policy = validated_policy(config)?;
        let store = Arc::new(suppression::SuppressionStore::open(
            &config.v1.suppression_store_path,
        )?);
        Ok(Self { policy, store })
    }

    /// Uses an already opened store with the same validated startup policy and configuration.
    /// This enables filesystem instrumentation without replacing persistence or policy checks.
    pub fn with_store(
        config: &ApiConfig,
        store: Arc<suppression::SuppressionStore>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            policy: validated_policy(config)?,
            store,
        })
    }
}

impl V1State {
    /// Loads the configured conservative policy before any HTTP listener can be constructed.
    /// Rejects invalid budgets, socket conflicts and missing/invalid policy files.
    pub fn initialize(config: &ApiConfig, backend: Arc<dyn SearchBackend>) -> anyhow::Result<Self> {
        let resources = V1Resources::load(config)?;
        Ok(Self::from_resources(config, backend, &resources))
    }
    /// Shares startup resources across the API and management builders without reopening the lock.
    pub fn from_resources(
        config: &ApiConfig,
        backend: Arc<dyn SearchBackend>,
        resources: &V1Resources,
    ) -> Self {
        Self {
            backend,
            policy: resources.policy.clone(),
            store: resources.store.clone(),
            observer: Arc::new(NoObserver),
            config: config.v1.clone(),
        }
    }
    /// Attaches bounded instrumentation without changing validation or backend implementation.
    pub fn with_observer(mut self, observer: Arc<dyn Observer>) -> Self {
        self.observer = observer;
        self
    }
    /// Returns the same serving gate shared by all routers built from this state.
    pub fn store(&self) -> Arc<suppression::SuppressionStore> {
        self.store.clone()
    }
}

#[derive(Clone)]
struct ListenerLimits {
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}
/// Capped request bytes collected before any route-specific decoding.
#[derive(Clone)]
pub(super) struct CappedBody(pub(super) Bytes);
/// Shared admission lease retained by a started durable transaction across requester cancellation.
#[derive(Clone)]
pub(super) struct AdmissionLease(pub(super) Arc<OwnedSemaphorePermit>);

/// Builds a standalone, prefix-relative public router with its own finite admission budget.
pub fn api_router(state: Arc<V1State>) -> Router {
    let routes = Router::new()
        .route("/search", post(search::route))
        .route("/source", get(source::route))
        .with_state(state.clone());
    finish_v1_router(routes, &state.config)
}

/// Builds the prefix-relative management surface with its own complete middleware and semaphore.
pub fn management_router(state: Arc<V1State>) -> Router {
    let routes = Router::new()
        .route("/documents/:id", axum::routing::delete(documents::route))
        .route("/source", get(source::route))
        .with_state(state.clone());
    finish_v1_router(routes, &state.config)
}

/// Mounts only the finished management subtree on its separate HTTP listener.
pub fn compose_management(state: Arc<V1State>) -> Router {
    mount(Router::new(), management_router(state))
}

/// Mounts the finished v1 subtree without replacing any legacy route or fallback.
pub fn compose_api(legacy: Router, state: Arc<V1State>) -> Router {
    mount(legacy, api_router(state))
}

fn mount(outer: Router, finished: Router) -> Router {
    // Axum's nested root matches /v1; its wildcard excludes the empty /v1/ tail.
    // Reuse the same finished service and semaphore for that exact miss.
    outer
        .nest("/v1", finished.clone())
        .route_service("/v1/", finished.into_service())
}

/// Applies the production contract to routes and their fallback, including fixture routes.
/// The supplied config must pass startup validation; this builder owns a separate semaphore.
///
/// # Panics
/// Panics if the configuration has invalid limits, an empty store path or a non-loopback address.
pub fn finish_v1_router(routes: Router, config: &V1ApiConfig) -> Router {
    let validated_limit = config
        .validate(&[])
        .expect("validated v1 listener configuration");
    let limits = ListenerLimits {
        semaphore: Arc::new(Semaphore::new(validated_limit)),
        timeout: Duration::from_millis(config.request_timeout_ms),
    };
    // `.layer` wraps outermost-last; read this chain bottom-up for request order.
    routes
        .fallback(|| async { V1Error::failure(V1Failure::NotFound) })
        .layer(middleware::from_fn(body_cap))
        .layer(middleware::from_fn_with_state(limits.clone(), admit))
        .layer(middleware::from_fn_with_state(limits, deadline))
        .layer(middleware::from_fn(catch_panic))
        .layer(middleware::from_fn(envelope))
        .layer(middleware::from_fn(super::source_offer::header))
        .layer(middleware::from_fn(version_header))
}

async fn version_header(request: Request, next: Next) -> Response {
    let head = request.method() == Method::HEAD;
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("x-api-version", HeaderValue::from_static("v1"));
    if head {
        *response.body_mut() = Body::empty();
    }
    response
}
async fn envelope(request: Request, next: Next) -> Response {
    error::normalize(next.run(request).await)
}
async fn catch_panic(request: Request, next: Next) -> Response {
    AssertUnwindSafe(next.run(request))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| V1Error::failure(V1Failure::InternalError).into_response())
}
async fn deadline(State(limits): State<ListenerLimits>, request: Request, next: Next) -> Response {
    tokio::time::timeout(limits.timeout, next.run(request))
        .await
        .unwrap_or_else(|_| V1Error::failure(V1Failure::RequestTimeout).into_response())
}
async fn admit(State(limits): State<ListenerLimits>, mut request: Request, next: Next) -> Response {
    let Ok(permit) = limits.semaphore.try_acquire_owned() else {
        return V1Error::failure(V1Failure::Overloaded).into_response();
    };
    let lease = Arc::new(permit);
    request
        .extensions_mut()
        .insert(AdmissionLease(lease.clone()));
    // A durable transaction can retain a cloned lease beyond an HTTP timeout.
    let response = next.run(request).await;
    drop(lease);
    response
}
async fn body_cap(request: Request, next: Next) -> Response {
    match bounded_request(request).await {
        Ok(request) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}
async fn bounded_request(request: Request) -> Result<Request, V1Error> {
    if request
        .headers()
        .get_all("content-encoding")
        .iter()
        .enumerate()
        .any(|(index, value)| index != 0 || !value.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(V1Error::failure(V1Failure::UnsupportedMediaType));
    }
    if request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|size| size > bounds::MAX_BODY_BYTES as u64)
    {
        return Err(InputError::RequestTooLarge.into());
    }
    let (mut parts, body) = request.into_parts();
    // The cap is the only client-violable bound here. A broken stream cannot be decoded;
    // report it as too large without exposing transport details.
    let bytes = to_bytes(body, bounds::MAX_BODY_BYTES)
        .await
        .map_err(|_| InputError::RequestTooLarge)?;
    if parts.uri.query().is_some() {
        return Err(InputError::InvalidRequest.into());
    }
    let bodyless = (parts.method == Method::GET && parts.uri.path() == "/source")
        || (parts.method == Method::DELETE && parts.uri.path().starts_with("/documents/"));
    if bodyless && !bytes.is_empty() {
        return Err(InputError::InvalidRequest.into());
    }
    if parts.method == Method::HEAD {
        return Err(V1Error::failure(V1Failure::MethodNotAllowed));
    }
    parts.extensions.insert(CappedBody(bytes));
    Ok(Request::from_parts(parts, Body::empty()))
}

/// Returns the language-independent v1 document, without creating an HTTP documentation route.
pub fn openapi() -> utoipa::openapi::OpenApi {
    super::docs::v1_openapi()
}
