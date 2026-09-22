//! Serves the startup-cached public statement without opening any record or ticket file.

use super::{
    dto::V1Version,
    error::{self, V1Error, V1Failure},
    V1State,
};
use axum::{extract::State, response::Response};
use serde::Serialize;
use std::sync::Arc;

/// Public JSON wrapper for the versioned Markdown statement.
#[derive(Serialize, utoipa::ToSchema)]
pub struct V1StatementResponse {
    /// Fixed API version.
    pub version: V1Version,
    /// Selected configured statement revision.
    pub statement_version: String,
    /// Escaped deterministic Markdown, including explicit pending approvals where applicable.
    pub markdown: String,
}

/// Returns the cached rendered publication or the fixed publication-unavailable response.
#[utoipa::path(
    get, path = "/v1/statement",
    responses((status = 200,
        description = "Public policy from the immutable startup record view",
        body = V1StatementResponse)),
    tag = "v1"
)]
pub(super) async fn route(State(state): State<Arc<V1State>>) -> Result<Response, V1Error> {
    let response = state
        .publication
        .as_ref()
        .map_err(|_| V1Error::failure(V1Failure::ComplianceUnavailable))?;
    Ok(error::success(response.as_ref()))
}
