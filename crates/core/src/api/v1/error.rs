//! Maps closed input, service and HTTP failures to fixed text, without exposing internal causes.
//! A private response marker lets the outer normalizer preserve only owned JSON responders.

use super::dto::V1Version;
use crate::{query::planner::bounds::InputError, searcher::wire::QueryServiceError};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Closed wire error codes; every message is independent of request and internal error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum V1ErrorCode {
    /// Inherited finite validation failures, serialized as a snake_case string.
    Input(InputError),
    /// Inherited finite search-service failures, serialized as a snake_case string.
    Service(QueryServiceError),
    /// Versioned transport, attribution and store failures.
    Failure(V1Failure),
}

/// Finite versioned failures not represented by the inherited query enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum V1Failure {
    /// Identifier has an invalid raw path shape.
    InvalidDocumentId,
    /// No route exists on this listener.
    NotFound,
    /// The legacy backend found no bang target.
    NoBangTarget,
    /// The known route does not accept this method.
    MethodNotAllowed,
    /// The body media type or encoding is unsupported.
    UnsupportedMediaType,
    /// An unclassified internal error or panic occurred.
    InternalError,
    /// Upstream result attribution is invalid.
    InvalidResult,
    /// All local listener admission permits are held.
    Overloaded,
    /// The durable suppression state cannot safely serve.
    SuppressionUnavailable,
    /// The complete local request deadline expired.
    RequestTimeout,
    /// The configured management bearer did not authorise the request.
    Unauthorised,
    /// The closed ticket lifecycle forbids this event.
    InvalidTransition,
    /// Closure and calendar retention have not made the payload eligible for purge.
    RetentionNotDue,
    /// The journal or required personal payloads cannot safely serve compliance operations.
    ComplianceUnavailable,
    /// A complete transaction would exceed a healthy store's finite capacity.
    ComplianceCapacity,
    /// The independent serving-rule state cannot safely serve search.
    RulesUnavailable,
}

/// Safe error details with a closed code and its fixed message.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct V1ErrorDetail {
    code: V1ErrorCode,
    message: String,
}

/// Universal v1 JSON error envelope.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct V1ErrorResponse {
    version: V1Version,
    error: V1ErrorDetail,
}

/// Typed HTTP failure; internal causes never enter the serialized representation.
#[derive(Debug, Clone)]
pub struct V1Error {
    status: StatusCode,
    code: V1ErrorCode,
    message: String,
}

#[derive(Clone)]
struct OwnedResponse;

impl V1Error {
    /// Converts a finite input error, using 413 for body overflow and 400 otherwise.
    pub fn input(error: InputError) -> Self {
        let status = if error == InputError::RequestTooLarge {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        Self {
            status,
            code: V1ErrorCode::Input(error),
            message: error.to_string(),
        }
    }

    /// Preserves the typed search-service failure identity and returns 503.
    pub fn service(error: QueryServiceError) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: V1ErrorCode::Service(error),
            message: error.to_string(),
        }
    }

    /// Constructs a fixed versioned error without accepting caller-controlled text.
    pub fn failure(failure: V1Failure) -> Self {
        use V1Failure::*;
        let (status, message) = match failure {
            InvalidDocumentId => (400, "The document identifier is invalid"),
            NotFound => (404, "The route was not found"),
            NoBangTarget => (404, "No bang target was found"),
            MethodNotAllowed => (405, "The method is not allowed"),
            UnsupportedMediaType => (415, "The request content type is unsupported"),
            InternalError => (500, "The request could not be completed"),
            InvalidResult => (500, "The search result is invalid"),
            Overloaded => (503, "The service is busy"),
            SuppressionUnavailable => (503, "The suppression store is unavailable"),
            RequestTimeout => (504, "The request timed out"),
            Unauthorised => (401, "The request is not authorised"),
            InvalidTransition => (409, "The ticket cannot make that transition"),
            RetentionNotDue => (409, "The payload is not eligible for purge"),
            ComplianceUnavailable => (503, "The compliance service is unavailable"),
            ComplianceCapacity => (503, "The compliance store is full"),
            RulesUnavailable => (503, "The serving rules are unavailable"),
        };
        Self {
            status: StatusCode::from_u16(status).expect("fixed valid status"),
            code: V1ErrorCode::Failure(failure),
            message: message.into(),
        }
    }

    /// Sanitizes unknown causes while preserving the known query-service and input types.
    pub fn from_error(error: anyhow::Error) -> Self {
        if let Some(input) = error.downcast_ref::<InputError>() {
            return Self::input(*input);
        }
        if let Some(service) = error.downcast_ref::<QueryServiceError>() {
            return Self::service(*service);
        }
        if error.is::<crate::searcher::api::staged::NoBangTarget>() {
            return Self::failure(V1Failure::NoBangTarget);
        }
        Self::failure(V1Failure::InternalError)
    }

    /// Returns the fixed invalid-attribution failure.
    pub fn invalid_result() -> Self {
        Self::failure(V1Failure::InvalidResult)
    }
    /// Returns the fixed invalid-identifier failure.
    pub fn invalid_document_id() -> Self {
        Self::failure(V1Failure::InvalidDocumentId)
    }
}

impl From<InputError> for V1Error {
    fn from(error: InputError) -> Self {
        Self::input(error)
    }
}
impl std::fmt::Display for V1Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for V1Error {}

impl IntoResponse for V1Error {
    fn into_response(self) -> Response {
        let body = V1ErrorResponse {
            version: V1Version::default(),
            error: V1ErrorDetail {
                code: self.code,
                message: self.message,
            },
        };
        let mut response = axum::Json(body).into_response();
        *response.status_mut() = self.status;
        response.extensions_mut().insert(OwnedResponse);
        response
    }
}

/// Serializes the complete owned response before releasing the serving gate.
pub(super) fn success(value: &impl serde::Serialize) -> Response {
    match serde_json::to_vec(value) {
        Ok(bytes) => {
            let mut response = ([("content-type", "application/json")], bytes).into_response();
            response.extensions_mut().insert(OwnedResponse);
            response
        }
        Err(_) => V1Error::failure(V1Failure::InternalError).into_response(),
    }
}

/// Replaces unowned responses with safe closed errors, retaining only a method Allow header.
pub(super) fn normalize(response: Response) -> Response {
    if response.extensions().get::<OwnedResponse>().is_some() {
        return response;
    }
    let error = match response.status().as_u16() {
        400 => V1Error::input(InputError::InvalidRequest),
        404 => V1Error::failure(V1Failure::NotFound),
        405 => V1Error::failure(V1Failure::MethodNotAllowed),
        413 => V1Error::input(InputError::RequestTooLarge),
        415 => V1Error::failure(V1Failure::UnsupportedMediaType),
        504 => V1Error::failure(V1Failure::RequestTimeout),
        _ => V1Error::failure(V1Failure::InternalError),
    };
    let mut replacement = error.into_response();
    if let Some(allow) = response.headers().get(axum::http::header::ALLOW) {
        replacement
            .headers_mut()
            .insert(axum::http::header::ALLOW, allow.clone());
    }
    replacement
}
