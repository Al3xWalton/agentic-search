// Stract is an open source web search engine.
// Copyright (C) 2023 Stract ApS
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! The api module contains the http api.
//! All http requests are handled using axum.

use axum::{body::Body, extract, middleware, Router};
use tokio::sync::Mutex;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::compression::CompressionLayer;

use crate::{
    autosuggest::Autosuggest,
    bangs::Bangs,
    config::ApiConfig,
    distributed::cluster::Cluster,
    generic_query::TopKeyPhrasesQuery,
    improvement::{store_improvements_loop, ImprovementEvent},
    leaky_queue::LeakyQueue,
    models::dual_encoder::DualEncoder,
    ranking::models::lambdamart::LambdaMART,
    searcher::{api::ApiSearcher, DistributedSearcher, SearchClient},
    similar_hosts::SimilarHostsFinder,
    webgraph::remote::RemoteWebgraph,
};

use crate::ranking::models::cross_encoder::CrossEncoderModel;

use anyhow::Result;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    routing::post,
};

mod autosuggest;
mod crawler_policy;
mod docs;
mod explore;
mod hosts;
pub mod improvement;
mod metrics;
pub mod search;
mod source_offer;
pub mod user_count;
pub mod webgraph;

const WARMUP_QUERIES: usize = 100;

pub struct Counters {
    pub search_counter_success: crate::metrics::Counter,
    pub search_counter_fail: crate::metrics::Counter,
    pub explore_counter: crate::metrics::Counter,
    pub daily_active_users: user_count::UserCount<user_count::Daily>,
}

pub struct State {
    pub config: ApiConfig,
    pub searcher: Arc<ApiSearcher<DistributedSearcher, Arc<RemoteWebgraph>>>,
    pub webgraph: Arc<RemoteWebgraph>,
    pub autosuggest: Autosuggest,
    pub counters: Counters,
    pub improvement_queue: Option<Arc<Mutex<LeakyQueue<ImprovementEvent>>>>,
    pub _cluster: Arc<Cluster>,
    pub similar_hosts: SimilarHostsFinder,
}

pub async fn favicon() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(
            include_bytes!("../../../../frontend/static/favicon.ico").to_vec(),
        ))
        .unwrap()
}

fn build_router(state: Arc<State>) -> Router {
    let mut search = Router::new()
        .route("/beta/api/search", post(search::search))
        .route_layer(middleware::from_fn_with_state(state.clone(), search_metric))
        .layer(cors_layer());

    if let Some(limit) = state.config.max_concurrent_searches {
        search = search.layer(ConcurrencyLimitLayer::new(limit));
    }

    let router = Router::new()
        .merge(search)
        .route("/favicon.ico", get(favicon))
        .merge(
            Router::new()
                .route("/improvement/click", post(improvement::click))
                .route("/improvement/store", post(improvement::store))
                .layer(cors_layer()),
        )
        .layer(CompressionLayer::new())
        .merge(docs::router().into().layer(cors_layer()))
        .nest(
            "/beta",
            Router::new()
                .route("/api/search/widget", post(search::widget))
                .route("/api/search/sidebar", post(search::sidebar))
                .route("/api/search/spellcheck", post(search::spellcheck))
                .route("/api/autosuggest", post(autosuggest::route))
                .route("/api/autosuggest/browser", get(autosuggest::browser))
                .route("/api/webgraph/host/similar", post(webgraph::host::similar))
                .route("/api/webgraph/host/knows", post(webgraph::host::knows))
                .route(
                    "/api/webgraph/host/ingoing",
                    post(webgraph::host::ingoing_hosts),
                )
                .route(
                    "/api/webgraph/host/outgoing",
                    post(webgraph::host::outgoing_hosts),
                )
                .route(
                    "/api/webgraph/page/ingoing",
                    post(webgraph::page::ingoing_pages),
                )
                .route(
                    "/api/webgraph/page/outgoing",
                    post(webgraph::page::outgoing_pages),
                )
                .route("/api/hosts/export", post(hosts::hosts_export_optic))
                .route("/api/explore/export", post(explore::explore_export_optic))
                .route("/api/entity_image", get(search::entity_image))
                .layer(cors_layer()),
        )
        .with_state(state);
    finish_router(router)
}

pub async fn router(
    config: &ApiConfig,
    counters: Counters,
    cluster: Arc<Cluster>,
) -> Result<Router> {
    let policy_router = crawler_policy::router(config.crawler_policy_config_path.as_deref())?;
    let lambda_model = match &config.lambda_model_path {
        Some(path) => Some(LambdaMART::open(path)?),
        None => None,
    };

    let dual_encoder_model = match &config.dual_encoder_model_path {
        Some(path) => Some(DualEncoder::open(path)?),
        None => None,
    };

    let query_store_queue = config.query_store_db.clone().map(|query_store_config| {
        let query_store_queue = Arc::new(Mutex::new(LeakyQueue::new(10_000)));
        tokio::spawn(store_improvements_loop(
            query_store_queue.clone(),
            query_store_config.host,
            query_store_config.username,
            query_store_config.password,
        ));
        query_store_queue
    });

    let bangs = match &config.bangs_path {
        Some(bangs_path) => Bangs::from_path(bangs_path),
        None => Bangs::empty(),
    };

    let webgraph = RemoteWebgraph::new(cluster.clone()).await;

    let dist_searcher = DistributedSearcher::new(Arc::clone(&cluster)).await;

    if !cluster
        .members()
        .await
        .iter()
        .any(|m| m.service.is_searcher())
    {
        log::info!("Waiting for search nodes to join the cluster");
        cluster.await_member(|m| m.service.is_searcher()).await;
        log::info!("Search nodes joined the cluster");
    }

    log::info!("Building autosuggest");
    let autosuggest = Autosuggest::from_key_phrases(
        dist_searcher
            .search_generic(TopKeyPhrasesQuery::new(config.top_phrases_for_autosuggest))
            .await
            .unwrap_or_default(),
    )?;

    let state = {
        let mut cross_encoder = None;

        if let Some(path) = config.crossencoder_model_path.as_ref() {
            cross_encoder = Some(CrossEncoderModel::open(path)?);
        }

        let mut searcher =
            ApiSearcher::new(dist_searcher, Some(cluster.clone()), bangs, config.clone()).await;

        if let Some(cross_encoder) = cross_encoder {
            searcher = searcher.with_cross_encoder(cross_encoder);
        }

        if let Some(lambda) = lambda_model {
            searcher = searcher.with_lambda_model(lambda);
        }

        if let Some(dual_encoder_model) = dual_encoder_model {
            searcher = searcher.with_dual_encoder(dual_encoder_model);
        }

        if cluster.members().await.into_iter().all(|m| {
            !matches!(m.service, crate::distributed::member::Service::Api { .. })
                && cluster.self_node().unwrap().id < m.id
        }) {
            log::info!("Warming up searchers");
            searcher
                .warmup(autosuggest.scores().keys().take(WARMUP_QUERIES).cloned())
                .await;
        }

        let webgraph = Arc::new(webgraph);

        searcher = searcher.with_webgraph(Arc::clone(&webgraph));

        let similar_hosts =
            SimilarHostsFinder::new(Arc::clone(&webgraph), config.max_similar_hosts);

        Arc::new(State {
            config: config.clone(),
            searcher: Arc::new(searcher),
            autosuggest,
            counters,
            webgraph,
            improvement_queue: query_store_queue,
            _cluster: cluster,
            similar_hosts,
        })
    };

    Ok(build_router(state).merge(policy_router))
}

/// Enables CORS for development where the API and frontend are on
/// different hosts.
fn cors_layer() -> tower_http::cors::CorsLayer {
    #[cfg(feature = "cors")]
    return tower_http::cors::CorsLayer::permissive()
        // Keep wildcard exposure while explicitly advertising the source offer.
        .expose_headers([
            axum::http::HeaderName::from_static("*"),
            axum::http::HeaderName::from_static("source-offer"),
        ]);
    #[cfg(not(feature = "cors"))]
    tower_http::cors::CorsLayer::new()
}

pub fn metrics_router(registry: crate::metrics::PrometheusRegistry) -> Router {
    let router = Router::new()
        .route("/metrics", get(metrics::route))
        .with_state(Arc::new(registry));
    finish_router(router)
}

async fn search_metric(
    extract::State(state): extract::State<Arc<State>>,
    extract::ConnectInfo(addr): extract::ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    // It is very important that the ip address is not stored. It is only used
    // for a probabilistic estimate of the number of unique users using a hyperloglog datastructure.
    let mut ip = None;

    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        let forwarded_for = forwarded_for.to_str().unwrap_or_default();
        if let Some(client_ip) = forwarded_for.split(',').next() {
            if let Ok(client_ip) = client_ip.trim().parse::<IpAddr>() {
                ip = Some(client_ip);
            }
        }
    }

    let ip = ip.unwrap_or_else(|| addr.ip());
    state.counters.daily_active_users.inc(&ip).ok();

    let response = next.run(request).await;

    if response.status().is_success() {
        state.counters.search_counter_success.inc();
    } else if response.status().is_server_error() {
        state.counters.search_counter_fail.inc();
    }

    response
}

/// Finishes both HTTP routers after their routes, fallbacks and inner middleware.
fn finish_router(router: Router) -> Router {
    router
        .merge(
            Router::new()
                .route("/.well-known/ava-search-source", get(source_offer::route))
                .layer(cors_layer()),
        )
        .layer(middleware::from_fn(source_offer::header))
}

#[cfg(test)]
mod source_offer_tests {
    use super::*;
    use axum::{body::to_bytes, http::Request, Json};
    use tower::ServiceExt;

    fn stub() -> Router {
        Router::new()
            .route(
                "/ok",
                get(|| async { ([("source-offer", "conflict")], "original") }),
            )
            .route(
                "/redirect",
                get(|| async { axum::response::Redirect::temporary("/ok") }),
            )
            .route(
                "/json",
                post(|Json(_): Json<serde_json::Value>| async { "accepted" }),
            )
            .route(
                "/error",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "error body") }),
            )
            .merge(
                Router::new()
                    .route("/early", get(|| async { "unreachable" }))
                    .route_layer(middleware::from_fn(
                        |_: extract::Request, _: middleware::Next| async {
                            (StatusCode::UNAUTHORIZED, "early body")
                        },
                    )),
            )
    }

    async fn call(
        router: Router,
        method: &str,
        path: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 8192).await.unwrap().to_vec();
        (status, headers, body)
    }

    #[tokio::test]
    async fn source_offer_header_covers_success_and_errors() {
        for (method, path, expected) in [
            ("GET", "/ok", 200),
            ("GET", "/redirect", 307),
            ("POST", "/json", 415),
            ("GET", "/absent", 404),
            ("POST", "/ok", 405),
            ("GET", "/early", 401),
            ("GET", "/error", 500),
        ] {
            let original = call(stub(), method, path).await;
            let (status, headers, body) = call(finish_router(stub()), method, path).await;
            assert_eq!(status.as_u16(), expected);
            assert_eq!(status, original.0);
            assert_eq!(body, original.2);
            assert_eq!(headers.get_all("source-offer").iter().count(), 1);
            assert_eq!(
                headers["source-offer"],
                crate::source_metadata::embedded().source_url
            );
            if path == "/redirect" {
                assert_eq!(headers["location"], "/ok");
            }
        }
    }

    #[tokio::test]
    async fn source_offer_layer_covers_fallback() {
        let (status, headers, body) = call(finish_router(Router::new()), "GET", "/absent").await;
        assert_eq!(status, 404);
        assert!(body.is_empty());
        assert_eq!(
            headers["source-offer"],
            crate::source_metadata::embedded().source_url
        );
    }

    #[tokio::test]
    async fn source_offer_route_shape() {
        let (status, headers, body) = call(
            finish_router(Router::new()),
            "GET",
            "/.well-known/ava-search-source",
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(headers["content-type"], "application/json");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let object = json.as_object().unwrap();
        assert_eq!(object.len(), 4);
        for key in ["licence", "source_url", "revision", "revision_source"] {
            assert!(object[key].is_string());
        }
        let revision = object["revision"].as_str().unwrap();
        assert!(
            revision == "unknown"
                || (revision.len() == 40
                    && revision
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        );
        assert!(["git", "environment", "unknown"]
            .contains(&object["revision_source"].as_str().unwrap()));
        if revision == "unknown" {
            assert_eq!(object["revision_source"], "unknown");
        }
        assert_eq!(
            headers["source-offer"],
            object["source_url"].as_str().unwrap()
        );
    }

    fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
        let body = source
            .split_once(signature)
            .unwrap()
            .1
            .split_once('{')
            .unwrap()
            .1;
        let mut depth = 1;
        for (i, ch) in body.char_indices() {
            if ch == '{' {
                depth += 1;
            }
            if ch == '}' {
                depth -= 1;
            }
            if depth == 0 {
                return &body[..i];
            }
        }
        panic!("unterminated function")
    }

    #[tokio::test]
    async fn source_offer_production_wiring() {
        let source = include_str!("mod.rs");
        for signature in ["fn build_router(", "pub fn metrics_router("] {
            let body = function_body(source, signature);
            assert!(
                body.trim_end().ends_with("finish_router(router)"),
                "unwired {signature}"
            );
        }
        let (status, headers, _) = call(finish_router(stub()), "GET", "/ok").await;
        assert_eq!(status, 200);
        assert!(headers.contains_key("source-offer"));
    }

    #[tokio::test]
    async fn source_offer_cors_exposes_header() {
        let router = finish_router(stub());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/.well-known/ava-search-source")
                    .header("origin", "https://example.invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        #[cfg(feature = "cors")]
        {
            assert_eq!(response.headers()["access-control-allow-origin"], "*");
            let exposed = response.headers()["access-control-expose-headers"]
                .to_str()
                .unwrap();
            assert!(exposed
                .split(',')
                .any(|h| h.trim().eq_ignore_ascii_case("source-offer")));
            assert!(exposed.split(',').any(|h| h.trim() == "*"));
        }
        #[cfg(not(feature = "cors"))]
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
}
