//! Provides management-only idempotent suppression without consulting index existence.
//! Raw identifiers are checked before percent decoding or owned path allocation.
use super::{
    dto::V1DeleteResponse,
    error::{self, V1Error, V1Failure},
    suppression::DocumentId,
    AdmissionLease, V1State,
};
use axum::{
    extract::{Request, State},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// Durably suppresses any syntactically valid ID and returns the same acknowledgement on repeats.
#[utoipa::path(delete, path = "/v1/documents/{id}", params(("id" = String, Path, description = "Exactly 64 lowercase hexadecimal bytes; escapes and extra segments are rejected")), responses((status = 200, description = "Durable local suppression; identical acknowledgement for known, unknown and repeated IDs", body = V1DeleteResponse)), tag = "v1")]
pub async fn route(State(state): State<Arc<V1State>>, request: Request) -> Response {
    let raw = request
        .uri()
        .path()
        .strip_prefix("/documents/")
        .unwrap_or("");
    let id = match DocumentId::parse(raw) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let Some(lease) = request.extensions().get::<AdmissionLease>() else {
        return V1Error::failure(V1Failure::InternalError).into_response();
    };
    state.observer.delete_enter();
    match state.store.suppress(id.clone(), lease.0.clone()).await {
        Ok(()) => error::success(&V1DeleteResponse::new(id)),
        Err(error) => error.into_response(),
    }
}
