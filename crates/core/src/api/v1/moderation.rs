//! Exposes management-only typed operations behind one fixed-width bearer authentication boundary.
//! Authentication runs before id or JSON extraction; queue and read never append ticket events.

use super::{
    compliance_adapter as adapter,
    dto::V1Version,
    error::{self, V1Error, V1Failure},
    moderation_dto::*,
    V1State,
};
use crate::{
    compliance::{
        clock,
        model::TicketId,
        tickets::{AdministrationEvent, Outcome, QueueView},
        transitions,
    },
    query::planner::bounds::InputError,
};
use axum::{
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde::de::DeserializeOwned;
use std::sync::Arc;

pub(super) fn routes(state: Arc<V1State>) -> Router<Arc<V1State>> {
    Router::new()
        .route("/compliance/queue", post(queue))
        .route("/compliance/tickets/:ticket_id/read", post(read))
        .route("/compliance/tickets/:ticket_id/identity", post(identity))
        .route("/compliance/tickets/:ticket_id/extension", post(extension))
        .route("/compliance/tickets/:ticket_id/decision", post(decision))
        .route("/compliance/tickets/:ticket_id/appeal", post(appeal))
        .route("/compliance/tickets/:ticket_id/reversal", post(reversal))
        .route("/compliance/tickets/:ticket_id/uphold", post(uphold))
        .route("/compliance/tickets/:ticket_id/progress", post(progress))
        .route("/compliance/tickets/:ticket_id/close", post(close))
        .route("/compliance/tickets/:ticket_id/purge", post(purge))
        .route_layer(middleware::from_fn_with_state(state, authenticate))
}

async fn authenticate(State(state): State<Arc<V1State>>, request: Request, next: Next) -> Response {
    let authorised = state.compliance_auth.authorises(
        request
            .headers()
            .get_all("authorization")
            .iter()
            .map(|value| value.as_bytes()),
        state.compliance_observer.as_ref(),
    );
    if !authorised {
        return V1Error::failure(V1Failure::Unauthorised).into_response();
    }
    next.run(request).await
}

fn ticket_id(request: &Request) -> Result<TicketId, V1Error> {
    let raw = request
        .uri()
        .path()
        .strip_prefix("/compliance/tickets/")
        .and_then(|tail| tail.rsplit_once('/').map(|(id, _)| id))
        .unwrap_or("");
    TicketId::parse(raw).map_err(|_| InputError::InvalidRequest.into())
}

fn result(outcome: Outcome) -> Response {
    error::success(&V1AdminResult {
        version: V1Version::default(),
        ticket_id: outcome.ticket.id,
        state: outcome.ticket.state,
        recorded_at: outcome.ticket.last_at,
        notice: outcome.notice,
    })
}

trait Administration: DeserializeOwned {
    fn event(self) -> (String, AdministrationEvent);
}
impl Administration for V1IdentityEvent {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Identity {
                event: self.event,
                reasons: self.reasons,
            },
        )
    }
}
impl Administration for V1Extension {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Extension {
                necessity: self.necessity,
                reasons: self.reasons,
                notice: self.notice,
                delivery: self.delivery,
            },
        )
    }
}
impl Administration for V1DecisionRequest {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Decision {
                decision: self.decision,
            },
        )
    }
}
impl Administration for V1Appeal {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Appeal {
                reasons: self.reasons,
                related_ticket_id: self.related_ticket_id,
            },
        )
    }
}
impl Administration for V1Reversal {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Reversal {
                reasons: self.reasons,
                delivery: self.delivery,
            },
        )
    }
}
impl Administration for V1Uphold {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Uphold {
                reasons: self.reasons,
                delivery: self.delivery,
            },
        )
    }
}
impl Administration for V1Progress {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Progress {
                enquiries: self.enquiries,
                update: self.update,
                delivery: self.delivery,
            },
        )
    }
}
impl Administration for V1Close {
    fn event(self) -> (String, AdministrationEvent) {
        (
            self.actor,
            AdministrationEvent::Closure {
                reasons: self.reasons,
            },
        )
    }
}

async fn administer<T: Administration>(
    state: Arc<V1State>,
    request: Request,
) -> Result<Response, V1Error> {
    let id = ticket_id(&request)?;
    let (actor, event) = adapter::decode::<T>(&request, &state)?.event();
    Ok(result(
        state
            .compliance
            .administer(id, actor, event, adapter::lease(&request)?)
            .await?,
    ))
}

macro_rules! handler {
    ($name:ident, $path:literal, $body:ty, $description:literal) => {
        #[doc = $description]
        #[utoipa::path(post, path = $path, request_body = $body,
            params(("ticket_id" = String, Path, description = "64 lowercase hexadecimal characters")),
            responses((status = 200, description = "Durable administration result", body = V1AdminResult)), tag = "v1")]
        pub async fn $name(State(state): State<Arc<V1State>>, request: Request) -> Result<Response, V1Error> {
            administer::<$body>(state, request).await
        }
    };
}
handler!(
    identity,
    "/v1/compliance/tickets/{ticket_id}/identity",
    V1IdentityEvent,
    "Records a data-rights evidence request or matching reply."
);
handler!(
    extension,
    "/v1/compliance/tickets/{ticket_id}/extension",
    V1Extension,
    "Records a timely reasoned extension for the current relevant-time epoch."
);
handler!(
    decision,
    "/v1/compliance/tickets/{ticket_id}/decision",
    V1DecisionRequest,
    "Records a reviewed decision and completes its required rule transaction."
);
handler!(
    appeal,
    "/v1/compliance/tickets/{ticket_id}/appeal",
    V1Appeal,
    "Records an appeal of the original reviewed outcome."
);
handler!(
    reversal,
    "/v1/compliance/tickets/{ticket_id}/reversal",
    V1Reversal,
    "Atomically reverses only this ticket's rules and persists no-reapply markers."
);
handler!(
    uphold,
    "/v1/compliance/tickets/{ticket_id}/uphold",
    V1Uphold,
    "Records a reasoned appeal disposal without changing serving rules."
);
handler!(
    progress,
    "/v1/compliance/tickets/{ticket_id}/progress",
    V1Progress,
    "Records enquiries and an essential progress communication without moving clocks."
);
handler!(
    close,
    "/v1/compliance/tickets/{ticket_id}/close",
    V1Close,
    "Closes an eligible ticket without removing any serving rule."
);

/// Lists open moderation work or due purges using the shared eligibility guard and stable cursor.
#[utoipa::path(post, path = "/v1/compliance/queue", request_body = V1QueueRequest,
    responses((status = 200, description = "Bounded private work queue", body = V1QueueResponse)), tag = "v1")]
pub async fn queue(
    State(state): State<Arc<V1State>>,
    request: Request,
) -> Result<Response, V1Error> {
    let input: V1QueueRequest = adapter::decode(&request, &state)?;
    let view = match input.view {
        V1QueueView::Open => QueueView::Open,
        V1QueueView::PurgeDue => QueueView::PurgeDue,
    };
    let page = state
        .compliance
        .queue(
            &input.actor,
            input.after_ticket_id.as_ref(),
            input.limit,
            view,
        )
        .await?;
    let items = page
        .items
        .into_iter()
        .map(|ticket| {
            Ok(match view {
                QueueView::Open => {
                    let deadline_at = transitions::deadline(&ticket)?;
                    let overdue = transitions::queue_overdue(&ticket, page.observed_at)?;
                    V1QueueItem::Open(V1OpenQueueItem {
                        ticket_id: ticket.id,
                        route: ticket.route.as_str(),
                        state: ticket.state,
                        received_at: ticket.times.received_at,
                        deadline_at,
                        overdue,
                    })
                }
                QueueView::PurgeDue => {
                    let closed_at = ticket
                        .times
                        .closed_at
                        .ok_or(crate::compliance::Error::Unavailable)?;
                    V1QueueItem::PurgeDue(V1PurgeDueItem {
                        ticket_id: ticket.id,
                        closed_at,
                        eligible_at: clock::retention_due(
                            closed_at,
                            state.compliance_config.settings().retention_months,
                        )?,
                    })
                }
            })
        })
        .collect::<crate::compliance::Result<Vec<_>>>()?;
    Ok(error::success(&V1QueueResponse {
        version: V1Version::default(),
        items,
        next_ticket_id: page.next_ticket_id,
    }))
}

/// Returns verified personal revisions only on the authenticated management listener.
#[utoipa::path(post, path = "/v1/compliance/tickets/{ticket_id}/read", request_body = V1TicketRead,
    params(("ticket_id" = String, Path, description = "64 lowercase hexadecimal characters")),
    responses((status = 200, description = "Private ticket and typed personal revisions", body = V1AdminTicket)), tag = "v1")]
pub async fn read(
    State(state): State<Arc<V1State>>,
    request: Request,
) -> Result<Response, V1Error> {
    let id = ticket_id(&request)?;
    let input: V1TicketRead = adapter::decode(&request, &state)?;
    let private = state
        .compliance
        .read(id, input.actor, adapter::lease(&request)?)
        .await?;
    let ticket = private.ticket;
    Ok(error::success(&V1AdminTicket {
        version: V1Version::default(),
        ticket_id: ticket.id,
        route: ticket.route.as_str(),
        state: ticket.state,
        timestamps: ticket.times,
        payload_events: private.events,
        payload_state: if ticket.purged { "purged" } else { "present" },
    }))
}

/// Purges eligible closed-ticket personal revisions without changing history or active serving rules.
#[utoipa::path(post, path = "/v1/compliance/tickets/{ticket_id}/purge", request_body = V1Purge,
    params(("ticket_id" = String, Path, description = "64 lowercase hexadecimal characters")),
    responses((status = 200, description = "Durable purge result; completed retries append nothing", body = V1AdminResult)), tag = "v1")]
pub async fn purge(
    State(state): State<Arc<V1State>>,
    request: Request,
) -> Result<Response, V1Error> {
    let id = ticket_id(&request)?;
    let input: V1Purge = adapter::decode(&request, &state)?;
    Ok(result(
        state
            .compliance
            .purge(id, input.actor, adapter::lease(&request)?)
            .await?,
    ))
}
