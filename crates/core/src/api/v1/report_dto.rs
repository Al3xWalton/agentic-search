//! Defines strict reporting inputs and the minimal public acknowledgement and capability responses.
//! Schema adapters remain in v1; private domain models carry no HTTP or OpenAPI dependencies.

use super::dto::V1Version;
use crate::compliance::{model, transitions::Milestones};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

macro_rules! vocabulary {
    ($name:ident, $description:literal, $($variant:ident => $wire:literal),+ $(,)?) => {
        #[doc = $description]
        #[derive(Serialize, ToSchema)]
        pub enum $name { $(#[doc = $wire] #[serde(rename = $wire)] $variant,)+ }
    };
}
vocabulary!(V1RequesterType, "Claimed relationship to the report, not authenticated identity.",
    SelfRequester => "self", Representative => "representative", AffectedPerson => "affected_person",
    SiteOperator => "site_operator", RightsOwner => "rights_owner", Other => "other");
vocabulary!(V1ContactMethod, "Essential reply channel; no delivery is performed by this API.", Email => "email");
vocabulary!(V1Interest, "Claimed qualifying interest in an interested-person complaint.",
    ResponsibleUkPerson => "responsible_uk_person", UkIncorporatedBody => "uk_incorporated_body");
vocabulary!(V1RequestKind, "Requested data-subject remedy.", Delisting => "delisting", Erasure => "erasure", Objection => "objection");
vocabulary!(V1NameKind, "Name evidence category.", LegalName => "legal_name", Pseudonym => "pseudonym");
vocabulary!(V1TicketState, "Closed lifecycle; missing milestones remain null.", Received => "received",
    Acknowledged => "acknowledged", IdentityPending => "identity_pending", Queued => "queued", Decided => "decided",
    Actioned => "actioned", Appealed => "appealed", Reversed => "reversed", Upheld => "upheld", Closed => "closed");

/// Reply contact retained solely in the private payload; no email is sent here.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1Contact {
    /// Required literal email channel.
    #[schema(value_type = V1ContactMethod)]
    pub method: model::ContactMethod,
    /// Nonblank address, 1..254 UTF-8 bytes; no SMTP validation or fetch.
    pub address: String,
}

/// Required common fields. Nonessential opt-out never disables essential acknowledgements or notices.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1ReportFields {
    /// Required private reply contact.
    pub contact: V1Contact,
    /// Nonblank narrative, 1..4096 UTF-8 bytes; LF and TAB are the only permitted controls.
    pub description: String,
    /// Required reporter relationship claim; nonusers may report.
    #[schema(value_type = V1RequesterType)]
    pub requester_type: model::RequesterType,
    /// Required boolean; essential replies remain enabled when true.
    pub nonessential_opt_out: bool,
}
impl From<V1ReportFields> for model::ReportFields {
    fn from(value: V1ReportFields) -> Self {
        Self {
            contact: model::Contact {
                method: value.contact.method,
                address: value.contact.address,
            },
            description: value.description,
            requester_type: value.requester_type,
            nonessential_opt_out: value.nonessential_opt_out,
        }
    }
}

/// An evidenced name, retained outside the journal and hashed serving snapshot.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1EvidencedName {
    /// Nonblank name, 1..128 UTF-8 bytes and 1..16 distinct normalized tokens.
    pub name: String,
    /// Legal name or evidenced pseudonym.
    #[schema(value_type = V1NameKind)]
    pub kind: model::NameKind,
    /// Nonblank supporting evidence, 1..1024 UTF-8 bytes.
    pub evidence: String,
}

/// Report of potentially unlawful content; every unknown or repeated field is rejected.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1IllegalContentReport {
    /// Required common reporting fields.
    pub report: V1ReportFields,
    /// 1..16 distinct canonical HTTP(S) URLs, each 1..2048 UTF-8 bytes.
    #[schema(min_items = 1, max_items = 16)]
    pub urls: Vec<String>,
    /// Nonblank explanation, 1..1024 UTF-8 bytes.
    pub suspected_illegality: String,
}

/// Report of content potentially harmful to children.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1ChildrenReport {
    /// Required common reporting fields.
    pub report: V1ReportFields,
    /// 1..16 distinct canonical HTTP(S) URLs, each 1..2048 UTF-8 bytes.
    #[schema(min_items = 1, max_items = 16)]
    pub urls: Vec<String>,
    /// Nonblank harm explanation, 1..1024 UTF-8 bytes.
    pub harm_description: String,
}

/// True-only statutory declaration; no false, string, number or null is accepted.
pub struct V1TrueDeclaration;
impl utoipa::PartialSchema for V1TrueDeclaration {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::Boolean)
            .enum_values(Some([true]))
            .into()
    }
}
impl ToSchema for V1TrueDeclaration {}
impl V1TrueDeclaration {
    fn value(&self) -> bool {
        true
    }
}

/// Intimate-image report with three independent required true declarations.
#[derive(ToSchema)]
pub struct V1IntimateImageReport {
    /// Required common reporting fields.
    pub report: V1ReportFields,
    /// 1..16 distinct canonical HTTP(S) URLs, each 1..2048 UTF-8 bytes.
    #[schema(min_items = 1, max_items = 16)]
    pub urls: Vec<String>,
    /// Required declaration that the material is intimate-image content.
    intimate_image_content: V1TrueDeclaration,
    /// Required declaration that the reporter is the subject or authorised.
    subject_or_authorised: V1TrueDeclaration,
    /// Required declaration of good faith.
    good_faith: V1TrueDeclaration,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIntimateReport {
    report: V1ReportFields,
    urls: Vec<String>,
    intimate_image_content: bool,
    subject_or_authorised: bool,
    good_faith: bool,
}
impl<'de> Deserialize<'de> for V1IntimateImageReport {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let raw = RawIntimateReport::deserialize(decoder)?;
        if !raw.intimate_image_content {
            return Err(serde::de::Error::custom("declaration required"));
        }
        if !raw.subject_or_authorised {
            return Err(serde::de::Error::custom("declaration required"));
        }
        if !raw.good_faith {
            return Err(serde::de::Error::custom("declaration required"));
        }
        Ok(Self {
            report: raw.report,
            urls: raw.urls,
            intimate_image_content: V1TrueDeclaration,
            subject_or_authorised: V1TrueDeclaration,
            good_faith: V1TrueDeclaration,
        })
    }
}
impl V1IntimateImageReport {
    pub(super) fn declarations(&self) -> model::IntakeKind {
        model::IntakeKind::IntimateImages {
            intimate_image_content: self.intimate_image_content.value(),
            subject_or_authorised: self.subject_or_authorised.value(),
            good_faith: self.good_faith.value(),
        }
    }
}

/// Independent site complaint; public intake never looks up the optional related capability.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1SiteComplaint {
    /// Required common reporting fields.
    pub report: V1ReportFields,
    /// 1..16 distinct canonical HTTP(S) URLs, each 1..2048 UTF-8 bytes.
    #[schema(min_items = 1, max_items = 16)]
    pub urls: Vec<String>,
    /// Required qualifying-interest claim.
    #[schema(value_type = V1Interest)]
    pub interest: model::Interest,
    /// Optional 64-lowercase-hex capability; unknown valid values are accepted without lookup.
    #[schema(value_type = Option<String>, pattern = "^[0-9a-f]{64}$")]
    pub related_ticket_id: Option<model::TicketId>,
}

/// Rights-owner request with required rights and authority evidence.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1RightsRemoval {
    /// Required common reporting fields.
    pub report: V1ReportFields,
    /// 1..16 distinct canonical HTTP(S) URLs, each 1..2048 UTF-8 bytes.
    #[schema(min_items = 1, max_items = 16)]
    pub urls: Vec<String>,
    /// Nonblank rights explanation, 1..1024 UTF-8 bytes.
    pub rights_basis: String,
    /// Nonblank authority evidence, 1..1024 UTF-8 bytes.
    pub authority: String,
}

/// Delisting, erasure or objection with a required evidenced-name array.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1DataRightsRequest {
    /// Required common reporting fields.
    pub report: V1ReportFields,
    /// 1..16 distinct canonical HTTP(S) URLs, each 1..2048 UTF-8 bytes.
    #[schema(min_items = 1, max_items = 16)]
    pub urls: Vec<String>,
    /// Requested remedy; a delisting grant is always name scoped.
    #[schema(value_type = V1RequestKind)]
    pub request_kind: model::RequestKind,
    /// 1..8 names for delisting, 0..8 for other remedies; the array itself is required.
    #[schema(max_items = 8)]
    pub names: Vec<V1EvidencedName>,
}

/// Complaint about AVA's processing of personal data, with no reported assets.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1DataProtectionComplaint {
    /// Required common reporting fields.
    pub report: V1ReportFields,
}

/// Complaint about AVA's online-safety duties, with no reported assets.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct V1OnlineSafetyComplaint {
    /// Required common reporting fields.
    pub report: V1ReportFields,
}

/// Durable admission acknowledgement; the capability only permits minimal status reads.
#[derive(Serialize, ToSchema)]
pub struct V1ReportAcknowledgement {
    /// Fixed API version.
    pub version: V1Version,
    /// Full-entropy 64-lowercase-hex capability.
    #[schema(value_type = String, pattern = "^[0-9a-f]{64}$")]
    pub ticket_id: model::TicketId,
    /// Immutable UTC-second receipt after complete validation, before the writer wait.
    pub received_at: i64,
    /// UTC-second durable preparation of acknowledgement.
    pub acknowledged_at: i64,
    /// Category-specific timing explanation, shared with the index.
    pub indicative_timeframe: &'static str,
    /// Closed category-specific possible outcomes.
    pub possible_outcomes: Vec<&'static str>,
    /// Original preference; essential notices remain enabled.
    pub nonessential_opt_out: bool,
    /// Relative path for the minimal capability status.
    pub status_path: String,
}

/// Public capability response with exactly a version, state and ten milestone fields.
#[derive(Serialize, ToSchema)]
pub struct V1TicketStatus {
    /// Fixed API version.
    pub version: V1Version,
    /// Current lifecycle only; no decision, category or personal content is disclosed.
    #[schema(value_type = V1TicketState)]
    pub state: model::TicketState,
    /// UTC-second milestones; absent milestones are null.
    #[serde(flatten)]
    #[schema(value_type = V1Milestones)]
    pub times: Milestones,
}

/// Exact UTC-second fields used by both minimal status and authenticated private read.
#[derive(ToSchema)]
pub struct V1Milestones {
    /// Immutable receipt.
    pub received_at: i64,
    /// Durable acknowledgement preparation.
    #[schema(required = true)]
    pub acknowledged_at: Option<i64>,
    /// Latest evidence request.
    #[schema(required = true)]
    pub identity_pending_at: Option<i64>,
    /// Latest queue entry.
    #[schema(required = true)]
    pub queued_at: Option<i64>,
    /// Reviewed decision.
    #[schema(required = true)]
    pub decided_at: Option<i64>,
    /// Completed rule-bearing grant.
    #[schema(required = true)]
    pub actioned_at: Option<i64>,
    /// Appeal recorded.
    #[schema(required = true)]
    pub appealed_at: Option<i64>,
    /// Reversal completed.
    #[schema(required = true)]
    pub reversed_at: Option<i64>,
    /// Appeal upheld.
    #[schema(required = true)]
    pub upheld_at: Option<i64>,
    /// Final closure.
    #[schema(required = true)]
    pub closed_at: Option<i64>,
}

/// Public entry-point field explanation, with byte bounds in prose rather than character limits.
#[derive(Serialize, ToSchema)]
pub struct V1ReportFieldDescription {
    /// Dotted nested field name.
    pub name: &'static str,
    /// Whether the field must be present.
    pub required: bool,
    /// Plain description and exact byte/cardinality constraints.
    pub description: &'static str,
}

/// One closed intake route description shared with acknowledgement metadata.
#[derive(Serialize, ToSchema)]
pub struct V1ReportRouteDescription {
    /// Fixed category name.
    pub route: &'static str,
    /// Plain title and reporting eligibility.
    pub name: &'static str,
    /// Relative API-listener path.
    pub path: &'static str,
    /// Literal POST.
    pub method: &'static str,
    /// Every common and category-specific request field.
    pub fields: Vec<V1ReportFieldDescription>,
    /// Implemented timing, without a fabricated statutory deadline.
    pub indicative_timeframe: &'static str,
    /// Closed route-specific potential outcomes.
    pub possible_outcomes: Vec<&'static str>,
}

/// Reports and requests entry point on both listeners; submission routes are API-only.
#[derive(Serialize, ToSchema)]
pub struct V1ReportsIndex {
    /// Fixed API version.
    pub version: V1Version,
    /// Literal Reports and requests.
    pub title: &'static str,
    /// Literal api; forms and email availability are pending deployment.
    pub submission_listener: &'static str,
    /// Exactly eight route descriptions in their public contract order.
    pub routes: Vec<V1ReportRouteDescription>,
}
