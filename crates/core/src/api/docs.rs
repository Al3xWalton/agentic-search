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

//! Preserves the beta document and separately describes the bounded v1 agent contract.

use super::{autosuggest, crawler_policy, explore, hosts, search, source_offer, webgraph};
use axum::Router;
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
        paths(
            source_offer::route,
            crawler_policy::route,
            search::search,
            search::widget,
            search::sidebar,
            search::spellcheck,
            webgraph::host::similar,
            webgraph::host::knows,
            webgraph::host::ingoing_hosts,
            webgraph::host::outgoing_hosts,
            webgraph::page::ingoing_pages,
            webgraph::page::outgoing_pages,
            autosuggest::route,
            hosts::hosts_export_optic,
            explore::explore_export_optic,
        ),
        components(
            schemas(
                source_offer::SourceOffer,
                crate::webpage::region::Region,
                optics::HostRankings,
                search::ApiSearchQuery,
                search::ApiSearchResult,
                search::WidgetQuery,
                search::SidebarQuery,
                search::SpellcheckQuery,
                search::ReturnBody,
                autosuggest::AutosuggestQuery,
                crate::searcher::WebsitesResult,
                crate::searcher::provenance::QueryPlanProvenance,
                crate::searcher::provenance::StageProvenance,
                crate::searcher::provenance::PlanTerm,
                crate::searcher::provenance::PlanMode,
                crate::searcher::provenance::NumHitsScope,
                crate::searcher::provenance::TermKind,
                crate::searcher::provenance::TermOccur,
                crate::query::planner::StageId,
                crate::query::planner::bounds::InputError,
                crate::searcher::wire::QueryServiceError,
                crate::searcher::provenance::SearchErrorResponse,
                crate::searcher::provenance::SearchErrorDetail,
                crate::searcher::provenance::SearchErrorCode,
                crate::searcher::provenance::BangErrorCode,
                crate::search_prettifier::HighlightedSpellCorrection,
                crate::search_prettifier::SpellCorrectionOffer,
                crate::search_prettifier::DisplayedWebpage,
                crate::search_prettifier::DisplayedEntity,
                crate::search_prettifier::DisplayedAnswer,
                crate::search_prettifier::DisplayedSidebar,
                crate::search_prettifier::Snippet,
                crate::search_prettifier::RichSnippet,
                crate::search_prettifier::StackOverflowAnswer,
                crate::search_prettifier::StackOverflowQuestion,
                crate::search_prettifier::CodeOrText,

                crate::snippet::TextSnippet,
                crate::highlighted::HighlightedFragment,
                crate::highlighted::HighlightedKind,

                crate::entity_index::entity::EntitySnippet,
                crate::entity_index::entity::EntitySnippetFragment,

                crate::bangs::UrlWrapper,

                crate::widgets::Widget,
                crate::widgets::calculator::Calculation,
                crate::widgets::thesaurus::ThesaurusWidget,
                crate::widgets::thesaurus::Lemma,
                crate::widgets::thesaurus::WordMeaning,
                crate::widgets::thesaurus::Definition,
                crate::widgets::thesaurus::Example,
                crate::widgets::thesaurus::PartOfSpeech,
                crate::widgets::thesaurus::PartOfSpeechMeaning,

                crate::ranking::SignalEnumDiscriminants,
                crate::ranking::SignalScore,

                crate::bangs::BangHit,
                crate::bangs::Bang,

                webgraph::host::SimilarHostsQuery,
                webgraph::KnowsHost,
                crate::entrypoint::webgraph_server::ScoredHost,

                autosuggest::Suggestion,

                hosts::HostsExportOpticParams,
                explore::ExploreExportOpticParams,

                crate::webgraph::Node,
                crate::webgraph::PrettyRelFlag,
                crate::webgraph::PrettyEdge,

                crate::search_prettifier::StructuredData,
                crate::search_prettifier::OneOrManyString,
                crate::search_prettifier::OneOrManyProperty,
                crate::search_prettifier::Property,

                crate::collector::approx_count::Count,
            ),
        ),
        modifiers(&ApiModifier),
        tags(
            (name = "stract"),
        )
    )]
/// Shared API schema used by the documentation route and local contract witnesses.
pub(super) struct BetaApiDoc;

/// Aggregates registrations while retaining the complete legacy document's metadata.
pub(super) struct ApiDoc;

impl OpenApi for ApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        let doc = BetaApiDoc::openapi();
        doc.merge_from(super::v1::openapi())
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Agentic Search v1", version = "v1"),
    paths(super::v1::search::route, super::v1::source::route),
    components(schemas(
        super::v1::dto::V1SearchRequest,
        super::v1::dto::V1SearchResponse,
        super::v1::dto::AttributedResult,
        super::v1::suppression::DocumentId,
        super::v1::dto::Country,
        super::v1::dto::V1Version,
        super::v1::dto::V1SourceResponse,
        super::v1::error::V1ErrorResponse,
        super::v1::error::V1ErrorDetail,
        super::v1::error::V1ErrorCode
    ))
)]
struct V1ApiDoc;

pub(super) fn v1_openapi() -> utoipa::openapi::OpenApi {
    let mut value =
        serde_json::to_value(V1ApiDoc::openapi()).expect("static OpenAPI serialization");
    value["info"]["description"] = serde_json::json!("Versioned text retrieval with required URL/domain/title attribution. HTTP(S) URLs use url 2.5.4 serialization, remove fragments, preserve query order and trailing slashes, and receive lowercase SHA-256 identifiers. Bodies are limited to 65536 bytes on every method and fallback, without trusting Content-Length; content encoding must be identity. No query component is accepted. Source and DELETE accept only empty bodies. Each listener admits at most 32 requests without queuing (configurable 1..32); the whole-request timeout is 60000 ms (configurable 1..60000). HEAD is rejected with 405 and an empty wire body, retaining both contract headers; OPTIONS is a JSON 405. Malformed pre-router HTTP and broken connections cannot be enveloped. Country defaults to unknown; UK and unknown receive stored UK measures, non-UK uses stored same-as-uk. Missing/null adult_verified means child; true is only a caller assertion. Global suppression applies to every context. No classifier or age-assurance claim. Search pages are 0..99, sizes 1..100 (default 20); query limits are 4096 UTF-8 bytes, 32 atoms, 1024 scalars per atom, 32 phrase words, 8 operators and 8 repetitions. Bangs are unsupported. has_more_results is the upstream pre-suppression hint; pages can be short or empty without refill.");
    let paths = value["paths"].as_object_mut().expect("static paths");
    for (path, item) in paths {
        for (method, operation) in item.as_object_mut().expect("static path item") {
            if ["get", "post", "delete"].contains(&method.as_str()) {
                operation["x-listener"] = serde_json::json!(if path == "/v1/source" {
                    "api-and-management"
                } else {
                    "api"
                });
                v1_responses(operation);
            }
        }
    }
    value["servers"] = serde_json::json!([{"url":"{api_base}","description":"Search/source API listener. Management operations use a separately configured trusted loopback listener.","variables":{"api_base":{"default":"http://127.0.0.1:3000","description":"Configured API base URL; no production URL is implied"}}}]);
    v1_error_schema(&mut value);
    serde_json::from_value(value).expect("valid static OpenAPI augmentation")
}

fn v1_responses(operation: &mut serde_json::Value) {
    let headers = serde_json::json!({
        "Source-Offer":{"description":"Exactly one embedded Corresponding Source URL","schema":{"type":"string"}},
        "X-Api-Version":{"description":"Explicit contract version, also present on HEAD","schema":{"type":"string","enum":["v1"]}}
    });
    let responses = operation["responses"]
        .as_object_mut()
        .expect("static responses");
    for status in [
        "400", "404", "405", "413", "415", "500", "503", "504", "default",
    ] {
        responses.insert(status.into(), serde_json::json!({"description":"Closed V1ErrorResponse with a fixed safe message; no request text or internal cause", "content":{"application/json":{"schema":{"$ref":"#/components/schemas/V1ErrorResponse"}}}}));
    }
    for response in responses.values_mut() {
        response["headers"] = headers.clone();
    }
}

fn v1_error_schema(document: &mut serde_json::Value) {
    document["components"]["schemas"]["V1ErrorCode"] = serde_json::json!({"type":"string","enum":[
        "invalid_request", "request_too_large", "empty_query", "query_too_long", "too_many_terms", "term_too_long", "phrase_too_long", "empty_phrase", "invalid_quotes", "invalid_operator", "invalid_query_syntax", "too_many_operators", "no_searchable_terms", "forbidden_character", "excessive_repetition", "invalid_result_count", "invalid_page", "plan_too_complex", "preferences_too_large",
        "no_shards", "too_many_shards", "budget_exhausted", "protocol_unavailable", "invalid_plan", "schema_mismatch", "shard_failed", "retrieval_failed", "worker_failed",
        "invalid_document_id", "not_found", "no_bang_target", "method_not_allowed", "unsupported_media_type", "internal_error", "invalid_result", "overloaded", "suppression_unavailable", "request_timeout"
    ]});
}

struct ApiModifier;

fn mark_internal(path: &mut utoipa::openapi::path::PathItem) {
    let internal_extensions = utoipa::openapi::extensions::ExtensionsBuilder::new()
        .add("x-internal", true)
        .build();

    let mut current_extensions = path.extensions.clone().unwrap_or_default();
    current_extensions.merge(internal_extensions.clone());
    path.extensions = Some(current_extensions);

    if let Some(operation) = path.post.as_mut() {
        let mut current_extensions = operation.extensions.clone().unwrap_or_default();
        current_extensions.merge(internal_extensions.clone());
        operation.extensions = Some(current_extensions);
    }

    if let Some(operation) = path.get.as_mut() {
        let mut current_extensions = operation.extensions.clone().unwrap_or_default();
        current_extensions.merge(internal_extensions.clone());
        operation.extensions = Some(current_extensions);
    }
}

impl Modify for ApiModifier {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.info.title = "Agentic Search API".to_string();
        openapi.info.description = Some(
            "Agentic Search is AVA's open-source web retrieval service for AI agents, derived from Stract. \
The [source offer](/.well-known/ava-search-source) identifies this build's AGPL-3.0-only source. \
Read the [crawler policy](/.well-known/ava-search-crawler) for identity, access rules and pending founder approvals. \
Every API response includes its source URL in the Source-Offer header.\n\n\
Remember to always give proper attributions to the sources you use from the search results.".to_string(),
        );

        mark_internal(
            openapi
                .paths
                .paths
                .get_mut("/beta/api/explore/export")
                .unwrap(),
        );
        mark_internal(
            openapi
                .paths
                .paths
                .get_mut("/beta/api/hosts/export")
                .unwrap(),
        );
        mark_internal(
            openapi
                .paths
                .paths
                .get_mut("/beta/api/webgraph/host/knows")
                .unwrap(),
        );
    }
}

/// Serves the API schema and Swagger UI with existing paths intact.
pub fn router<S: Clone + Send + Sync + 'static>() -> impl Into<Router<S>> {
    SwaggerUi::new("/beta/api/docs/swagger")
        .url("/beta/api/docs/openapi.json", BetaApiDoc::openapi())
        .config(
            utoipa_swagger_ui::Config::default()
                .use_base_layout()
                .default_models_expand_depth(0),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn beta_openapi_bytes_are_unchanged_from_base() {
        use axum::{
            body::{to_bytes, Body},
            http::Request,
        };
        use tower::ServiceExt;
        let golden = include_bytes!("../../tests/fixtures/api_v1/beta-openapi.json");
        assert_eq!(serde_json::to_vec(&BetaApiDoc::openapi()).unwrap(), golden);
        let docs: Router = router().into();
        let response = super::super::finish_router(docs)
            .oneshot(
                Request::builder()
                    .uri("/beta/api/docs/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers()["source-offer"],
            crate::source_metadata::embedded().source_url
        );
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(response.status(), 200);
        assert_eq!(
            to_bytes(response.into_body(), 4 * 1024 * 1024)
                .await
                .unwrap()
                .as_ref(),
            golden
        );
    }

    #[test]
    fn v1_openapi_matches_runtime_contract() {
        let doc = serde_json::to_value(super::super::v1::openapi()).unwrap();
        let aggregate = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(doc["info"]["version"], "v1");
        assert_eq!(doc["paths"].as_object().unwrap().len(), 2);
        for (path, method, listener) in [
            ("/v1/search", "post", "api"),
            ("/v1/source", "get", "api-and-management"),
        ] {
            assert!(aggregate["paths"][path][method].is_object());
            let operation = &doc["paths"][path][method];
            assert_eq!(operation["x-listener"], listener);
            for status in [
                "200", "400", "404", "405", "413", "415", "500", "503", "504", "default",
            ] {
                assert!(operation["responses"][status]["headers"]["Source-Offer"].is_object());
                assert_eq!(
                    operation["responses"][status]["headers"]["X-Api-Version"]["schema"]["enum"],
                    serde_json::json!(["v1"])
                );
            }
        }
        let schemas = &doc["components"]["schemas"];
        for name in [
            "V1SearchRequest",
            "V1SearchResponse",
            "V1AttributedResult",
            "V1DocumentId",
            "V1Country",
            "V1Version",
            "V1SourceResponse",
            "V1ErrorResponse",
            "V1ErrorDetail",
            "V1ErrorCode",
        ] {
            assert!(schemas[name].is_object(), "missing {name}");
        }
        assert_eq!(schemas["V1SearchRequest"]["additionalProperties"], false);
        assert_eq!(schemas["V1DocumentId"]["pattern"], "^[0-9a-f]{64}$");
        assert_eq!(schemas["V1DocumentId"]["minLength"], 64);
        assert_eq!(schemas["V1Version"]["enum"], serde_json::json!(["v1"]));
        assert_eq!(
            schemas["V1AttributedResult"]["properties"]
                .as_object()
                .unwrap()
                .len(),
            5
        );
        for field in ["id", "url", "domain", "title", "snippet"] {
            assert!(schemas["V1AttributedResult"]["required"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(field)));
        }
        assert_eq!(schemas["V1NonEmptyText"]["minLength"], 1);
        assert_eq!(
            schemas["V1SearchRequest"]["properties"]["page"]["maximum"],
            99
        );
        assert_eq!(
            schemas["V1SearchRequest"]["properties"]["num_results"]["default"],
            20
        );
        if let Some(path) = std::env::var_os("V1_OPENAPI_ARTIFACT") {
            std::fs::write(path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        }
    }

    #[test]
    fn openapi_spell_offer_contract() {
        let value = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let schemas = &value["components"]["schemas"];
        let result = &schemas["WebsitesResult"];
        assert!(result["properties"].get("spellCorrection").is_some());
        assert!(!result["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "spellCorrection"));
        let offer = &schemas["SpellCorrectionOffer"];
        assert!(!offer.is_null());
        let serialized = offer.to_string();
        assert!(
            serialized.contains("applied")
                && serialized.contains("false")
                && serialized.contains("escaped")
        );
        assert!(schemas["ApiSearchQuery"]["properties"]
            .get("spellCorrection")
            .is_none());
        assert!(schemas["ApiSearchQuery"]["properties"]
            .get("spellCheck")
            .is_none());
    }

    #[test]
    fn openapi_planner_contract() {
        let value = serde_json::to_value(ApiDoc::openapi()).unwrap();
        let schemas = &value["components"]["schemas"];
        assert!(schemas["InputError"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "preferences_too_large"));
        for name in [
            "QueryPlanProvenance",
            "StageProvenance",
            "PlanTerm",
            "PlanMode",
            "NumHitsScope",
            "TermKind",
            "TermOccur",
            "StageId",
            "InputError",
            "QueryServiceError",
            "SearchErrorResponse",
            "SourceOffer",
        ] {
            assert!(schemas.get(name).is_some(), "missing {name}");
        }
        assert!(schemas["WebsitesResult"]["properties"]
            .get("queryPlan")
            .is_some());
        assert!(schemas["DisplayedWebpage"]["properties"]
            .get("planStage")
            .is_some());
        for (schema, optional) in [
            ("WebsitesResult", "queryPlan"),
            ("DisplayedWebpage", "planStage"),
        ] {
            assert!(!schemas[schema]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == optional));
        }
        assert_eq!(
            schemas["PlanMode"]["enum"],
            serde_json::json!(["staged", "strict_only", "pagination_strict"])
        );
        let response = &value["paths"]["/beta/api/search"]["post"]["responses"];
        for status in ["200", "400", "404", "413", "503"] {
            assert!(response.get(status).is_some());
        }
        assert!(response["200"]["description"]
            .as_str()
            .unwrap()
            .contains("largest-stage estimate"));
        assert!(value["paths"]
            .get("/.well-known/ava-search-source")
            .is_some());
    }

    #[test]
    fn source_offer_docs_are_discoverable() {
        let docs = ApiDoc::openapi();
        assert_eq!(docs.info.title, "Agentic Search API");
        let description = docs.info.description.as_deref().unwrap();
        assert!(description.contains("[source offer](/.well-known/ava-search-source)"));
        assert!(description.contains("Source-Offer"));
        assert!(!description.contains("paid by consumption"));
        assert!(docs.paths.paths["/.well-known/ava-search-source"]
            .get
            .is_some());
        assert!(docs.components.unwrap().schemas.contains_key("SourceOffer"));
    }
}
