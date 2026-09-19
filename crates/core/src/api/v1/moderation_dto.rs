//! Defines the closed management requests and private responses without exposing domain schemas.
//! Every request rejects extra fields and every private scalar is bounded again before persistence.

use super::{
    dto::V1Version,
    report_dto::{V1Milestones, V1TicketState},
};
use crate::compliance::{
    model,
    payload::{Notice, PersonalEvent},
    transitions::Milestones,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Queue discovery mode; absent means the unchanged open-work view.
#[derive(Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum V1QueueView {
    /// Pending moderation and unresolved operations.
    #[default]
    Open,
    /// Closed unpurged tickets at their configured retention threshold.
    PurgeDue,
}

/// Authenticated bounded work queue; no personal payload is read.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1QueueRequest {
    /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
    pub actor: String,
    /// Optional stable receipt/id cursor; an unknown capability is invalid_request.
    #[schema(value_type = Option<String>, pattern = "^[0-9a-f]{64}$")]
    pub after_ticket_id: Option<model::TicketId>,
    /// Page size 1..50, default 20.
    #[serde(default = "default_limit")]
    #[schema(minimum = 1, maximum = 50, default = 20)]
    pub limit: u16,
    /// Closed view selector, default open.
    #[serde(default)]
    pub view: V1QueueView,
}
fn default_limit() -> u16 {
    20
}

macro_rules! actor_request {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Deserialize, ToSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
            pub actor: String,
        }
    };
}
actor_request!(
    V1TicketRead,
    "Authenticated sole private narrative read request."
);
actor_request!(
    V1Purge,
    "Authenticated retention-gated purge of this ticket's personal files only."
);

/// Closed identity or clarification evidence event.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum V1IdentityKind {
    /// Requests identity evidence without changing the relevant time.
    RequestIdentity,
    /// Confirms the matching requested evidence and advances relevant time.
    IdentityConfirmed,
    /// Requests clarification without changing the relevant time.
    RequestClarification,
    /// Receives the matching requested clarification and advances relevant time.
    ClarificationReceived,
}

/// Evidence event on a data-rights ticket with bounded reasons.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1IdentityEvent {
    /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
    pub actor: String,
    /// Closed evidence request or matching reply.
    #[schema(value_type = V1IdentityKind)]
    pub event: model::IdentityEvent,
    /// Nonblank reasons, 1..2048 UTF-8 bytes; only LF and TAB controls permitted.
    pub reasons: String,
}

/// Statutory necessity for a data-rights extension.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum V1Necessity {
    /// Complexity of the request.
    Complexity,
    /// Volume of requests.
    Volume,
}

/// Manual communication channel; this API sends no message.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum V1DeliveryChannel {
    /// Operator attests to email communication.
    ManualEmail,
    /// Operator attests to form communication.
    ManualForm,
    /// Operator attests to API communication.
    ManualApi,
}

/// Operator attestation at the event's UTC time, not proof of receipt by the addressee.
#[derive(ToSchema)]
pub struct V1Delivery {
    /// Closed manually attested channel.
    pub channel: V1DeliveryChannel,
    /// Nonblank opaque reference, 1..128 UTF-8 bytes; controls prohibited.
    pub reference: String,
}

/// Once-per-epoch data-rights extension, accepted no later than the first-month deadline.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1Extension {
    /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
    pub actor: String,
    /// Required complexity or volume basis.
    #[schema(value_type = V1Necessity)]
    pub necessity: model::Necessity,
    /// Nonblank reasons, 1..2048 UTF-8 bytes.
    pub reasons: String,
    /// Nonblank essential written notice, 1..4096 UTF-8 bytes.
    pub notice: String,
    /// Required communication attestation.
    #[schema(value_type = V1Delivery)]
    pub delivery: model::Delivery,
}

macro_rules! assessment {
    ($($field:ident),+ $(,)?) => {
        /// All nineteen reasoned criteria are required, each nonblank and 1..2048 UTF-8 bytes.
        #[derive(ToSchema)]
        pub struct V1DelistingAssessment {
            $(#[doc = concat!("Required reasoned ", stringify!($field), " assessment; explicit N/A reasoning is permitted.")]
                pub $field: String,)+
        }
    };
}
assessment!(
    natural_person,
    name_search,
    role_in_public_life,
    child,
    accuracy,
    working_life,
    hate_speech_or_defamation,
    sensitive_data,
    currency,
    prejudice,
    risk,
    original_basis_of_publication,
    journalistic_context,
    legal_power_or_obligation_to_publish,
    criminal_offence,
    offence_seriousness,
    time_elapsed,
    spent_status,
    reasoned_decision
);

/// Closed reviewed disposition; extra or missing variant fields are rejected.
#[derive(Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum V1Decision {
    /// Grants the route-specific remedy; assessment is required only for name delisting.
    Granted {
        /// Nonblank reasons, 1..2048 UTF-8 bytes.
        reasons: String,
        /// Essential communication attestation.
        #[schema(value_type = V1Delivery)]
        delivery: model::Delivery,
        /// Nineteen required criteria for a delisting grant; forbidden on unrelated grants.
        #[schema(value_type = Option<V1DelistingAssessment>)]
        assessment: Option<Box<model::DelistingAssessment>>,
    },
    /// Refuses with all three fixed remedy instructions.
    Refused {
        /// Nonblank reasons, 1..2048 UTF-8 bytes.
        reasons: String,
        /// Essential communication attestation.
        #[schema(value_type = V1Delivery)]
        delivery: model::Delivery,
    },
    /// Intimate route only: recorded determination outside the content definition.
    NotIntimateImage {
        /// Nonblank reasons, 1..2048 UTF-8 bytes.
        reasons: String,
        /// Essential communication attestation.
        #[schema(value_type = V1Delivery)]
        delivery: model::Delivery,
    },
    /// Intimate route only: recorded determination that standing is absent.
    NoStanding {
        /// Nonblank reasons, 1..2048 UTF-8 bytes.
        reasons: String,
        /// Essential communication attestation.
        #[schema(value_type = V1Delivery)]
        delivery: model::Delivery,
    },
    /// Complaint-only duplicate disposition; disagreement alone is insufficient.
    ManifestlyUnfounded {
        /// Reasons explaining absence of new information, 1..2048 UTF-8 bytes.
        reasons: String,
        /// Essential communication attestation.
        #[schema(value_type = V1Delivery)]
        delivery: model::Delivery,
        /// Configured policy version, 1..64 ASCII slug bytes.
        policy_version: String,
        /// Required literal duplicate_without_new_information.
        policy_clause: String,
        /// Existing concluded complaint of the same route, 64 lowercase hexadecimal characters.
        #[schema(value_type = String, pattern = "^[0-9a-f]{64}$")]
        duplicate_of: model::TicketId,
    },
}

/// Authenticated reviewed disposition; generated name salts and notices cannot be supplied here.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1DecisionRequest {
    /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
    pub actor: String,
    /// Closed route-specific decision.
    #[schema(value_type = V1Decision)]
    pub decision: model::Decision,
}

/// Authenticated appeal of the original decision, retaining its original serving ground.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1Appeal {
    /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
    pub actor: String,
    /// Nonblank reasons, 1..2048 UTF-8 bytes.
    pub reasons: String,
    /// Optional authenticated association, 64 lowercase hexadecimal characters.
    #[schema(value_type = Option<String>, pattern = "^[0-9a-f]{64}$")]
    pub related_ticket_id: Option<model::TicketId>,
}

macro_rules! disposal {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Deserialize, ToSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
            pub actor: String,
            /// Nonblank reasons, 1..2048 UTF-8 bytes.
            pub reasons: String,
            /// Essential communication attestation.
            #[schema(value_type = V1Delivery)]
            pub delivery: model::Delivery,
        }
    };
}
disposal!(
    V1Reversal,
    "Reverses only an original rule-bearing grant, persisting same-ground markers atomically."
);
disposal!(
    V1Uphold,
    "Records a reasoned appeal disposal upholding the original outcome without changing rules."
);

/// Enquiries and essential progress communication, without resetting any statutory clock.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1Progress {
    /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
    pub actor: String,
    /// Nonblank enquiry record, 1..4096 UTF-8 bytes.
    pub enquiries: String,
    /// Nonblank progress update, 1..4096 UTF-8 bytes.
    pub update: String,
    /// Essential communication attestation.
    #[schema(value_type = V1Delivery)]
    pub delivery: model::Delivery,
}

/// Final closure with private reasons; closure never removes serving protection.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1Close {
    /// Claimed operator alias, 1..64 ASCII bytes; system. prefix is reserved.
    pub actor: String,
    /// Nonblank reasons, 1..2048 UTF-8 bytes.
    pub reasons: String,
}

/// Essential service-prepared notice with any required remedy instructions.
#[derive(ToSchema)]
pub struct V1Notice {
    /// Plain text, never interpreted as markup.
    pub text: String,
    /// Fixed remedy instructions for refusals; otherwise empty.
    pub remedies: Vec<String>,
}

/// Exact successful administration envelope.
#[derive(Serialize, ToSchema)]
pub struct V1AdminResult {
    /// Fixed API version.
    pub version: V1Version,
    /// Authenticated target capability.
    #[schema(value_type = String, pattern = "^[0-9a-f]{64}$")]
    pub ticket_id: model::TicketId,
    /// Resulting closed state.
    #[schema(value_type = V1TicketState)]
    pub state: model::TicketState,
    /// Last recorded UTC-second instant; repeated purge preserves it.
    pub recorded_at: i64,
    /// Essential communication, null for operations without a notice.
    #[schema(value_type = Option<V1Notice>, required = true)]
    pub notice: Option<Notice>,
}

/// One open-work queue item; no private report fields are included.
#[derive(Serialize, ToSchema)]
pub struct V1OpenQueueItem {
    /// Target capability for an authenticated operator.
    #[schema(value_type = String)]
    pub ticket_id: model::TicketId,
    /// Closed route category.
    pub route: &'static str,
    /// Current lifecycle state.
    #[schema(value_type = V1TicketState)]
    pub state: model::TicketState,
    /// Immutable UTC-second receipt.
    pub received_at: i64,
    /// Applicable statutory deadline, null when no fixed deadline is prescribed here.
    #[schema(required = true)]
    pub deadline_at: Option<i64>,
    /// True when observation time is outside the route's allowed window; equality is on time.
    /// Intimate-image and complaint clocks earlier than receipt also read overdue; data rights
    /// does not. Null-deadline routes are false. This measures queue age, not retrospective
    /// acknowledgement compliance.
    pub overdue: bool,
}

/// Minimal due-purge discovery item; exactly these three fields are disclosed.
#[derive(Serialize, ToSchema)]
pub struct V1PurgeDueItem {
    /// Target capability for a single-ticket purge request.
    #[schema(value_type = String)]
    pub ticket_id: model::TicketId,
    /// Final UTC-second closure.
    pub closed_at: i64,
    /// Inclusive configured calendar-retention threshold.
    pub eligible_at: i64,
}

/// Queue view's exact item type, without an extra discriminator in its wire shape.
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum V1QueueItem {
    /// Default pending moderation item.
    Open(V1OpenQueueItem),
    /// Due-purge whitelist item.
    PurgeDue(V1PurgeDueItem),
}

/// Bounded authenticated queue page with a stable receipt/id cursor.
#[derive(Serialize, ToSchema)]
pub struct V1QueueResponse {
    /// Fixed API version.
    pub version: V1Version,
    /// At most the validated requested limit of selected items.
    pub items: Vec<V1QueueItem>,
    /// Cursor for the next selected page, null if exhausted.
    #[schema(value_type = Option<String>, required = true)]
    pub next_ticket_id: Option<model::TicketId>,
}

/// Sole private narrative response; purged payloads are empty and never reconstructed from history.
#[derive(Serialize, ToSchema)]
pub struct V1AdminTicket {
    /// Fixed API version.
    pub version: V1Version,
    /// Authenticated target capability.
    #[schema(value_type = String)]
    pub ticket_id: model::TicketId,
    /// Fixed intake category.
    pub route: &'static str,
    /// Current lifecycle.
    #[schema(value_type = V1TicketState)]
    pub state: model::TicketState,
    /// Exact milestone whitelist, without another version or state.
    #[schema(value_type = V1Milestones)]
    pub timestamps: Milestones,
    /// Typed private revision history within the per-ticket count and byte caps.
    #[schema(value_type = Vec<V1PersonalEvent>)]
    pub payload_events: Vec<PersonalEvent>,
    /// Literal present or purged.
    pub payload_state: &'static str,
}

/// Private event schema, assembled from the same strict management and reporting schemas.
pub struct V1PersonalEvent;
impl utoipa::PartialSchema for V1PersonalEvent {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        use serde_json::json;
        let reason = json!({"type":"string","description":"Nonblank reason, 1..2048 UTF-8 bytes"});
        let narrative =
            json!({"type":"string","description":"Nonblank narrative, 1..4096 UTF-8 bytes"});
        let delivery = json!({"$ref":"#/components/schemas/V1Delivery"});
        let notice = json!({"$ref":"#/components/schemas/V1Notice"});
        let variants = vec![
            private_variant("intake", json!({"intake": private_intake_schema()})),
            private_variant(
                "identity",
                json!({"event":{"$ref":"#/components/schemas/V1IdentityKind"},"reasons":reason}),
            ),
            private_variant(
                "extension",
                json!({"necessity":{"$ref":"#/components/schemas/V1Necessity"},"reasons":reason,"notice":narrative,"delivery":delivery}),
            ),
            private_variant(
                "decision",
                json!({"decision":{"$ref":"#/components/schemas/V1Decision"},"name_rule_salts":{"type":"array","maxItems":8,"items":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"notice":notice}),
            ),
            private_variant(
                "appeal",
                json!({"reasons":reason,"related_ticket_id":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"}}),
            ),
            private_variant(
                "reversal",
                json!({"reasons":reason,"delivery":delivery,"notice":notice}),
            ),
            private_variant(
                "uphold",
                json!({"reasons":reason,"delivery":delivery,"notice":notice}),
            ),
            private_variant(
                "progress",
                json!({"enquiries":narrative,"update":narrative,"delivery":delivery}),
            ),
            private_variant("closure", json!({"reasons":reason})),
        ];
        serde_json::from_value(json!({"oneOf":variants})).expect("static personal-event schema")
    }
}
impl ToSchema for V1PersonalEvent {}

fn private_variant(kind: &str, mut properties: serde_json::Value) -> serde_json::Value {
    properties["kind"] = serde_json::json!({"type":"string","enum":[kind]});
    let required = properties
        .as_object()
        .expect("static properties")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
}

fn private_intake_schema() -> serde_json::Value {
    use serde_json::json;
    let evidence = json!({"type":"string","description":"Nonblank evidence, 1..1024 UTF-8 bytes"});
    let variants = vec![
        private_variant("illegal_content", json!({"suspected_illegality":evidence})),
        private_variant("harmful_to_children", json!({"harm_description":evidence})),
        private_variant(
            "intimate_images",
            json!({"intimate_image_content":{"type":"boolean","enum":[true]},
            "subject_or_authorised":{"type":"boolean","enum":[true]},"good_faith":{"type":"boolean","enum":[true]}}),
        ),
        private_variant(
            "site_complaint",
            json!({"interest":{"$ref":"#/components/schemas/V1Interest"},
            "related_ticket_id":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"}}),
        ),
        private_variant(
            "rights_removal",
            json!({"rights_basis":evidence,"authority":evidence}),
        ),
        private_variant(
            "data_rights",
            json!({"request_kind":{"$ref":"#/components/schemas/V1RequestKind"},
            "names":{"type":"array","maxItems":8,"items":{"$ref":"#/components/schemas/V1EvidencedName"}}}),
        ),
        private_variant("data_protection_complaint", json!({})),
        private_variant("online_safety_complaint", json!({})),
    ];
    json!({"type":"object","additionalProperties":false,"required":["report","assets","category"],"properties":{
        "report":{"$ref":"#/components/schemas/V1ReportFields"},
        "assets":{"type":"array","maxItems":16,"items":{"type":"object","additionalProperties":false,
            "required":["url","document_id"],"properties":{"url":{"type":"string","description":"Canonical HTTP(S) URL, 1..2048 UTF-8 bytes"},
                "document_id":{"type":"string","pattern":"^[0-9a-f]{64}$"}}}},
        "category":{"oneOf":variants}}})
}
