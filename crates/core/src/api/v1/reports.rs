//! Exposes eight typed public intakes, one shared entry point and a minimal status capability.
//! The raw capability is validated before lookup and never grants private read or mutation access.

use super::{
    compliance_adapter as adapter,
    dto::V1Version,
    error::{self, V1Error, V1Failure},
    report_dto::*,
    V1State,
};
use crate::compliance::{
    model::{EvidencedName, Intake, IntakeKind, Route, TicketId},
    tickets::Admission,
};
use axum::{
    extract::{Request, State},
    response::Response,
    routing::{get, post},
    Router,
};
use serde::de::DeserializeOwned;
use std::sync::Arc;

/// Written policy shared by complaint descriptions, API documentation and the public statement.
pub(crate) const MANIFESTLY_UNFOUNDED_CLAUSE: &str = concat!(
    "A complaint may be treated as manifestly unfounded only when it repeats a concluded ",
    "complaint without new information. A reviewer must identify the earlier complaint ",
    "and explain why no new information changes the decision. Disagreement alone is not enough."
);

const REPORT_DESCRIPTION: &str = concat!(
    "You can report even if you do not use AVA. Required object. ",
    "Form and email availability is pending deployment."
);
static COMPLAINT_DESCRIPTION: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| format!("{REPORT_DESCRIPTION} {MANIFESTLY_UNFOUNDED_CLAUSE}"));

pub(super) fn routes() -> Router<Arc<V1State>> {
    Router::new()
        .route("/reports", get(index))
        .route("/reports/status/:ticket_id", get(status))
        .route("/reports/illegal-content", post(illegal))
        .route("/reports/harmful-to-children", post(children))
        .route("/reports/intimate-images", post(intimate))
        .route("/reports/site-complaints", post(site))
        .route("/reports/rights-removal", post(rights))
        .route("/reports/data-rights", post(data_rights))
        .route("/reports/data-protection-complaints", post(data_protection))
        .route("/reports/online-safety-complaints", post(online_safety))
}

trait IntakeRequest: DeserializeOwned {
    fn convert(self) -> Result<Intake, V1Error>;
}
impl IntakeRequest for V1IllegalContentReport {
    fn convert(self) -> Result<Intake, V1Error> {
        adapter::intake(
            self.report,
            self.urls,
            IntakeKind::IllegalContent {
                suspected_illegality: self.suspected_illegality,
            },
        )
    }
}
impl IntakeRequest for V1ChildrenReport {
    fn convert(self) -> Result<Intake, V1Error> {
        adapter::intake(
            self.report,
            self.urls,
            IntakeKind::HarmfulToChildren {
                harm_description: self.harm_description,
            },
        )
    }
}
impl IntakeRequest for V1IntimateImageReport {
    fn convert(self) -> Result<Intake, V1Error> {
        let declarations = self.declarations();
        adapter::intake(self.report, self.urls, declarations)
    }
}
impl IntakeRequest for V1SiteComplaint {
    fn convert(self) -> Result<Intake, V1Error> {
        adapter::intake(
            self.report,
            self.urls,
            IntakeKind::SiteComplaint {
                interest: self.interest,
                related_ticket_id: self.related_ticket_id,
            },
        )
    }
}
impl IntakeRequest for V1RightsRemoval {
    fn convert(self) -> Result<Intake, V1Error> {
        adapter::intake(
            self.report,
            self.urls,
            IntakeKind::RightsRemoval {
                rights_basis: self.rights_basis,
                authority: self.authority,
            },
        )
    }
}
impl IntakeRequest for V1DataRightsRequest {
    fn convert(self) -> Result<Intake, V1Error> {
        adapter::intake(
            self.report,
            self.urls,
            IntakeKind::DataRights {
                request_kind: self.request_kind,
                names: self
                    .names
                    .into_iter()
                    .map(|name| EvidencedName {
                        name: name.name,
                        kind: name.kind,
                        evidence: name.evidence,
                    })
                    .collect(),
            },
        )
    }
}
impl IntakeRequest for V1DataProtectionComplaint {
    fn convert(self) -> Result<Intake, V1Error> {
        adapter::intake(self.report, Vec::new(), IntakeKind::DataProtectionComplaint)
    }
}
impl IntakeRequest for V1OnlineSafetyComplaint {
    fn convert(self) -> Result<Intake, V1Error> {
        adapter::intake(self.report, Vec::new(), IntakeKind::OnlineSafetyComplaint)
    }
}

async fn admit<T: IntakeRequest>(
    state: Arc<V1State>,
    request: Request,
) -> Result<Response, V1Error> {
    let intake = adapter::decode::<T>(&request, &state)?.convert()?;
    let admission = state
        .compliance
        .admit(intake, adapter::lease(&request)?)
        .await?;
    Ok(error::success(&acknowledgement(admission)?))
}

macro_rules! handler {
    ($name:ident, $path:literal, $request:ty, $description:literal) => {
        #[doc = $description]
        #[utoipa::path(post, path = $path, request_body = $request,
            responses((status = 200, description = "Durable acknowledgement and minimal status capability", body = V1ReportAcknowledgement)), tag = "v1")]
        pub async fn $name(State(state): State<Arc<V1State>>, request: Request) -> Result<Response, V1Error> {
            admit::<$request>(state, request).await
        }
    };
}
handler!(
    illegal,
    "/v1/reports/illegal-content",
    V1IllegalContentReport,
    "Admits an unlawful-content report and queues it durably."
);
handler!(
    children,
    "/v1/reports/harmful-to-children",
    V1ChildrenReport,
    "Admits a child-harm report and queues it durably."
);
handler!(
    intimate,
    "/v1/reports/intimate-images",
    V1IntimateImageReport,
    "Persists every intimate-image timer before acknowledging its report."
);
handler!(
    site,
    "/v1/reports/site-complaints",
    V1SiteComplaint,
    "Admits an independent site complaint without looking up a related ticket."
);
handler!(
    rights,
    "/v1/reports/rights-removal",
    V1RightsRemoval,
    "Admits a rights-owner removal request with private evidence."
);
handler!(
    data_rights,
    "/v1/reports/data-rights",
    V1DataRightsRequest,
    "Admits delisting, erasure or objection with the receipt-based calendar clock."
);
handler!(
    data_protection,
    "/v1/reports/data-protection-complaints",
    V1DataProtectionComplaint,
    "Immediately acknowledges a data-protection complaint and queues review."
);
handler!(
    online_safety,
    "/v1/reports/online-safety-complaints",
    V1OnlineSafetyComplaint,
    "Admits an online-safety complaint without creating an asset rule."
);

fn acknowledgement(admission: Admission) -> Result<V1ReportAcknowledgement, V1Error> {
    let ticket = admission.ticket;
    let metadata = metadata(ticket.route);
    Ok(V1ReportAcknowledgement {
        version: V1Version::default(),
        status_path: format!("/v1/reports/status/{}", ticket.id.as_str()),
        ticket_id: ticket.id,
        received_at: ticket.times.received_at,
        acknowledged_at: ticket
            .times
            .acknowledged_at
            .ok_or_else(|| V1Error::failure(V1Failure::ComplianceUnavailable))?,
        indicative_timeframe: metadata.indicative_timeframe,
        possible_outcomes: metadata.possible_outcomes,
        nonessential_opt_out: admission.nonessential_opt_out,
    })
}

/// Describes every supported public reporting route for users and nonusers on either listener.
#[utoipa::path(get, path = "/v1/reports", responses((status = 200, description = "Reports and requests entry point", body = V1ReportsIndex)), tag = "v1")]
pub async fn index(State(state): State<Arc<V1State>>) -> Result<Response, V1Error> {
    state.compliance.available().await?;
    let routes = [
        Route::IllegalContent,
        Route::HarmfulToChildren,
        Route::IntimateImages,
        Route::SiteComplaint,
        Route::RightsRemoval,
        Route::DataRights,
        Route::DataProtectionComplaint,
        Route::OnlineSafetyComplaint,
    ];
    Ok(error::success(&V1ReportsIndex {
        version: V1Version::default(),
        title: "Reports and requests",
        submission_listener: "api",
        routes: routes.into_iter().map(metadata).collect(),
    }))
}

/// Returns only the state and milestone whitelist for one well-formed raw capability.
#[utoipa::path(get, path = "/v1/reports/status/{ticket_id}", params(("ticket_id" = String, Path, description = "64 lowercase hexadecimal characters; escapes are rejected")),
    responses((status = 200, description = "Minimal capability status", body = V1TicketStatus)), tag = "v1")]
pub async fn status(
    State(state): State<Arc<V1State>>,
    request: Request,
) -> Result<Response, V1Error> {
    let raw = request
        .uri()
        .path()
        .strip_prefix("/reports/status/")
        .unwrap_or("");
    let id = TicketId::parse(raw).map_err(|_| V1Error::failure(V1Failure::NotFound))?;
    let ticket = state.compliance.status(&id).await?;
    Ok(error::success(&V1TicketStatus {
        version: V1Version::default(),
        state: ticket.state,
        times: ticket.times,
    }))
}

fn metadata(route: Route) -> V1ReportRouteDescription {
    let review = "We will review this report as soon as possible";
    let (name, path, indicative_timeframe, possible_outcomes) = match route {
        Route::IllegalContent => ("Illegal content", "/v1/reports/illegal-content", review, vec!["deindexed", "no_action"]),
        Route::HarmfulToChildren => ("Harmful to children", "/v1/reports/harmful-to-children", review, vec!["deindexed", "no_action"]),
        Route::IntimateImages => ("Intimate images", "/v1/reports/intimate-images",
            "Listed URLs are scheduled to be hidden within 48 hours unless a recorded determination excludes this duty",
            vec!["deindexed", "not_intimate_image", "no_standing"]),
        Route::SiteComplaint => ("Site complaints", "/v1/reports/site-complaints", review, vec!["reversed", "upheld", "no_action"]),
        Route::RightsRemoval => ("Rights removal", "/v1/reports/rights-removal", review, vec!["deindexed", "no_action"]),
        Route::DataRights => ("Data rights", "/v1/reports/data-rights",
            "A decision is due within one calendar month of the relevant time; a reasoned extension may add two calendar months",
            vec!["name_delisted", "deindexed", "no_action"]),
        Route::DataProtectionComplaint => ("Data protection complaints", "/v1/reports/data-protection-complaints",
            "We acknowledge now, within 30 days; we will make enquiries and communicate progress and an outcome without undue delay",
            vec!["complaint_resolved", "no_action"]),
        Route::OnlineSafetyComplaint => ("Online safety complaints", "/v1/reports/online-safety-complaints", review, vec!["complaint_resolved", "no_action"]),
    };
    V1ReportRouteDescription {
        route: route.as_str(),
        name,
        path,
        method: "POST",
        fields: fields(route),
        indicative_timeframe,
        possible_outcomes,
    }
}

fn report_description(route: Route) -> &'static str {
    match route {
        Route::SiteComplaint | Route::DataProtectionComplaint | Route::OnlineSafetyComplaint => {
            &COMPLAINT_DESCRIPTION
        }
        _ => REPORT_DESCRIPTION,
    }
}

fn fields(route: Route) -> Vec<V1ReportFieldDescription> {
    let mut fields = Vec::new();
    let mut add = |name, required, description| {
        fields.push(V1ReportFieldDescription {
            name,
            required,
            description,
        })
    };
    add("report", true, report_description(route));
    add(
        "report.contact",
        true,
        "Required private reply-contact object.",
    );
    add(
        "report.contact.method",
        true,
        "Required literal email. This API records contact; it sends no email.",
    );
    add(
        "report.contact.address",
        true,
        "Nonblank text, 1..254 UTF-8 bytes; controls prohibited. No SMTP validation or fetch.",
    );
    add(
        "report.description",
        true,
        "Nonblank text, 1..4096 UTF-8 bytes; only LF and TAB controls permitted.",
    );
    add(
        "report.requester_type",
        true,
        "Claim: self, representative, affected_person, site_operator, rights_owner or other.",
    );
    add("report.nonessential_opt_out", true, "Required boolean. Opt-out excludes essential replies: acknowledgements, notices, progress and outcomes remain enabled.");
    if !matches!(
        route,
        Route::DataProtectionComplaint | Route::OnlineSafetyComplaint
    ) {
        add("urls", true, "1..16 distinct canonical HTTP(S) URLs, each 1..2048 UTF-8 bytes. No credentials, whitespace, controls or backslashes.");
    }
    match route {
        Route::IllegalContent => add(
            "suspected_illegality",
            true,
            "Nonblank evidence, 1..1024 UTF-8 bytes; only LF and TAB controls permitted.",
        ),
        Route::HarmfulToChildren => add(
            "harm_description",
            true,
            "Nonblank evidence, 1..1024 UTF-8 bytes; only LF and TAB controls permitted.",
        ),
        Route::IntimateImages => {
            add(
                "intimate_image_content",
                true,
                "Required JSON true: the reported content is intimate-image content.",
            );
            add(
                "subject_or_authorised",
                true,
                "Required JSON true: you are the subject or authorised to act for them.",
            );
            add(
                "good_faith",
                true,
                "Required JSON true: this report is made in good faith.",
            );
        }
        Route::SiteComplaint => {
            add(
                "interest",
                true,
                "Required responsible_uk_person or uk_incorporated_body claim.",
            );
            add("related_ticket_id", false, "Optional null or 64-lowercase-hex capability; no public lookup or mutation follows.");
        }
        Route::RightsRemoval => {
            add("rights_basis", true, "Nonblank rights evidence, 1..1024 UTF-8 bytes; only LF and TAB controls permitted.");
            add("authority", true, "Nonblank authority evidence, 1..1024 UTF-8 bytes; only LF and TAB controls permitted.");
        }
        Route::DataRights => {
            add("request_kind", true, "Required delisting, erasure or objection. Delisting grants apply only to evidenced-name queries.");
            add(
                "names",
                true,
                "Required array: 1..8 evidenced names for delisting, 0..8 otherwise.",
            );
            add("names[].name", true, "Nonblank name, 1..128 UTF-8 bytes, 1..16 distinct normalized tokens including an alphanumeric token.");
            add("names[].kind", true, "Required legal_name or pseudonym.");
            add(
                "names[].evidence",
                true,
                "Nonblank evidence, 1..1024 UTF-8 bytes; only LF and TAB controls permitted.",
            );
        }
        Route::DataProtectionComplaint | Route::OnlineSafetyComplaint => {}
    }
    fields
}
