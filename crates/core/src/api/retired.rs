// SPDX-License-Identifier: AGPL-3.0-only
//! Permanently refuses the complete legacy namespaces without reading request bodies.
//! This module owns no search, queue, worker or database state.

use axum::{
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};

const RETIRED_BODY: &str = r#"{"error":{"code":"legacy_api_retired","message":"Use the v1 API"}}"#;

/// Reserves both roots and all descendants independently of configuration or state.
pub(super) fn router() -> Router {
    Router::new()
        .route("/beta", any(gone))
        .route("/beta/", any(gone))
        .route("/beta/*path", any(gone))
        .route("/improvement", any(gone))
        .route("/improvement/", any(gone))
        .route("/improvement/*path", any(gone))
}

// A parts-only extractor refuses input before any body poll or request-sized allocation.
async fn gone(method: Method) -> Response {
    let body = if method == Method::HEAD {
        ""
    } else {
        RETIRED_BODY
    };
    (
        StatusCode::GONE,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        body,
    )
        .into_response()
}
