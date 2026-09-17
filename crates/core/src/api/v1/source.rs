//! Serves only public embedded build metadata through the versioned responder.
use super::{dto::V1SourceResponse, error, V1State};
use axum::{extract::State, response::Response};
use std::sync::Arc;

/// Returns AGPL-3.0-only source metadata without backend or store access.
#[utoipa::path(get, path = "/v1/source", responses((status = 200, description = "Public embedded source metadata", body = V1SourceResponse)), tag = "v1")]
pub async fn route(State(state): State<Arc<V1State>>) -> Response {
    state.observer.source_enter();
    error::success(&V1SourceResponse::embedded())
}
