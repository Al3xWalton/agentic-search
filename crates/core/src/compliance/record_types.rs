//! Defines strict, bounded assessment records independently of storage and publication.
//! Each body has one semantic validator, shared by admission and verified historical reads.
//! References select immutable versions; dates use the supplied UTC observation only.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey, TextClass},
    clock,
    measures::MeasuresRecord,
    Error, Result,
};
use crate::config::compliance::ValidatedComplianceConfig;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

macro_rules! vocabulary {
    ($(#[$doc:meta])* $name:ident { $($(#[$item:meta])* $variant:ident => $wire:literal,)* }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum $name { $($(#[$item])* #[serde(rename = $wire)] $variant,)* }
        impl $name {
            /// Returns the closed serialized spelling.
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire,)* }
            }
        }
    };
}

vocabulary! {
    /// Closed immutable record categories.
    RecordKind {
        /// Illegal-content risk assessment.
        Icra => "icra",
        /// Children's access assessment.
        Caa => "caa",
        /// Children's risk assessment.
        Cra => "cra",
        /// Measures and reasoned alternatives.
        Measures => "measures",
        /// Approval and publication selection.
        Manifest => "manifest",
        /// Integer monthly aggregates.
        Metrics => "metrics",
        /// Review work and its completion history.
        Review => "review",
    }
}
vocabulary! {
    /// Operator-stated approval, not an authenticated signature.
    ApprovalStatus {
        /// Incomplete or unapproved working record.
        Draft => "draft",
        /// Operator assertion subject to completeness validation.
        Approved => "approved",
    }
}
vocabulary! {
    /// Explicit attestation with no implicit default.
    Attestation {
        /// The activity is asserted to have occurred.
        Yes => "yes",
        /// The activity has not been asserted.
        No => "no",
    }
}
vocabulary! {
    /// Ordered qualitative risk levels, without numerical interpolation.
    RiskLevel {
        /// High assessed risk.
        High => "high",
        /// Medium assessed risk.
        Medium => "medium",
        /// Low assessed risk.
        Low => "low",
        /// Negligible assessed risk.
        Negligible => "negligible",
    }
}
vocabulary! {
    /// Fixed catalog slots; legal labels come only from operator configuration.
    PriorityKind {
        /// Catalog slot 01.
        P01 => "P01",
        /// Catalog slot 02.
        P02 => "P02",
        /// Catalog slot 03.
        P03 => "P03",
        /// Catalog slot 04.
        P04 => "P04",
        /// Catalog slot 05.
        P05 => "P05",
        /// Catalog slot 06.
        P06 => "P06",
        /// Catalog slot 07.
        P07 => "P07",
        /// Catalog slot 08.
        P08 => "P08",
        /// Catalog slot 09.
        P09 => "P09",
        /// Catalog slot 10.
        P10 => "P10",
        /// Catalog slot 11.
        P11 => "P11",
        /// Catalog slot 12.
        P12 => "P12",
        /// Catalog slot 13.
        P13 => "P13",
        /// Catalog slot 14.
        P14 => "P14",
        /// Catalog slot 15.
        P15 => "P15",
        /// Catalog slot 16.
        P16 => "P16",
        /// Catalog slot 17.
        P17 => "P17",
    }
}
vocabulary! {
    /// Causes of review, including the derived annual cause.
    TriggerKind {
        /// Elapsed review period.
        Annual => "annual",
        /// New risk-profile information.
        RiskProfileChanged => "risk_profile_changed",
        /// Planned or observed significant service change.
        SignificantChange => "significant_change",
        /// New evidence that children use the service.
        EvidenceOfChildUse => "evidence_of_child_use",
    }
}
vocabulary! {
    /// Assessment conclusion about likely child access.
    AccessConclusion {
        /// Children are likely to access the service.
        Likely => "likely",
        /// Children are not likely to access the service.
        NotLikely => "not_likely",
    }
}
vocabulary! {
    /// The three required children's risk classes.
    ChildClass {
        /// Primary priority content.
        PrimaryPriority => "primary_priority",
        /// Priority content.
        Priority => "priority",
        /// Other non-designated content.
        NonDesignated => "non_designated",
    }
}
vocabulary! {
    /// Target of a review; the referenced record fixes its service and version.
    ReviewScope {
        /// Review of compliance measures.
        Compliance => "compliance",
        /// Review of illegal-content or children's risk.
        Risk => "risk",
        /// Repeat children's access assessment.
        ChildAccess => "child_access",
    }
}
vocabulary! {
    /// Persisted review work state.
    ReviewStatus {
        /// Work remains outstanding.
        Open => "open",
        /// Completion is recorded without changing assessment freshness.
        Completed => "completed",
    }
}

/// Immutable scalar reference, encoded as an identifier and canonical decimal version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordRef {
    /// Validated record identifier.
    pub id: String,
    /// Positive immutable version.
    pub version: u32,
}
impl RecordRef {
    /// Rejects malformed, noncanonical or reserved references before lookup.
    pub fn parse(text: &str) -> Result<Self> {
        let (id, version) = text.split_once(':').ok_or(Error::InvalidInput)?;
        let number = version.parse::<u32>().map_err(|_| Error::InvalidInput)?;
        require(number.to_string() == version)?;
        let reference = Self {
            id: id.into(),
            version: number,
        };
        reference.validate()?;
        Ok(reference)
    }
    /// Applies identifier and positive-version bounds to programmatically supplied references.
    pub fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        bounds::validate_range(u64::from(self.version), 1, u64::from(u32::MAX))
    }
}
impl std::fmt::Display for RecordRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.version)
    }
}
impl Serialize for RecordRef {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for RecordRef {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

macro_rules! record_struct {
    ($(#[$doc:meta])* $name:ident { $($(#[$field_doc:meta])* $field:ident: $ty:ty,)* }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $($(#[$field_doc])* pub $field: $ty,)* }
    };
}

record_struct! {
    /// One questionnaire answer with its stable local identifier.
    QuestionAnswer {
        /// Unique questionnaire entry.
        id: String,
        /// Reasoned response.
        answer: String,
    }
}
record_struct! {
    /// Existing control and an assessment of its effect.
    ControlEffect {
        /// Bounded control description.
        description: String,
        /// Bounded effectiveness explanation.
        effect: String,
    }
}
record_struct! {
    /// One explicitly evaluated priority catalog slot.
    PriorityRisk {
        /// Fixed catalog slot.
        kind: PriorityKind,
        /// Qualitative assessed level.
        level: RiskLevel,
        /// Reasoned assessment.
        explanation: String,
        /// Distinct references to local evidence.
        evidence_ids: Vec<String>,
    }
}
record_struct! {
    /// Additional illegal-content risk beyond the fixed catalog.
    OtherRisk {
        /// Unique bounded risk label.
        name: String,
        /// Qualitative assessed level.
        level: RiskLevel,
        /// Reasoned assessment.
        explanation: String,
        /// Distinct references to local evidence.
        evidence_ids: Vec<String>,
    }
}
record_struct! {
    /// Inert evidence metadata, never fetched or interpreted as a link.
    Evidence {
        /// Unique local identifier.
        id: String,
        /// What the evidence establishes.
        description: String,
        /// Bounded source or reference text.
        source: String,
    }
}
record_struct! {
    /// An attested cause and instant of review.
    ReviewTrigger {
        /// Closed cause.
        kind: TriggerKind,
        /// Nonfuture UTC seconds.
        at: i64,
        /// Opaque bounded attestation reference.
        reference: String,
    }
}
record_struct! {
    /// Children's access conclusion and the steps supporting it.
    AccessAssessment {
        /// Likelihood conclusion.
        conclusion: AccessConclusion,
        /// UTC conclusion no later than completion.
        concluded_at: i64,
        /// Reasoned assessment steps.
        steps: String,
        /// Distinct local evidence identifiers.
        evidence_ids: Vec<String>,
    }
}
record_struct! {
    /// One mandatory children's risk class.
    ChildRisk {
        /// Closed class identifier.
        class: ChildClass,
        /// Qualitative level.
        level: RiskLevel,
        /// Reasoned assessment.
        explanation: String,
        /// Distinct local evidence identifiers.
        evidence_ids: Vec<String>,
    }
}
record_struct! {
    /// Exactly one assessment of each children's risk class.
    ChildrenAssessment {
        /// Three distinct mandatory classes.
        classes: Vec<ChildRisk>,
    }
}
record_struct! {
    /// Complete common schema shared by all three assessment categories.
    Assessment {
        /// Service being assessed.
        service: String,
        /// Initial completion UTC second.
        date_completed: i64,
        /// Increasing completion and review history.
        review_update_dates: Vec<i64>,
        /// Named assessment author.
        author: String,
        /// Named responsible individual.
        responsible_person: String,
        /// Named approving individual or explicit draft placeholder.
        approver: String,
        /// Operator-stated approval.
        approval_status: ApprovalStatus,
        /// Approval UTC second when approved.
        #[serde(deserialize_with = "required_option")]
        approved_at: Option<i64>,
        /// Explicit risk-profile consultation attestation.
        risk_profiles_consulted: Attestation,
        /// Distinct questionnaire answers.
        questionnaire_outcomes: Vec<QuestionAnswer>,
        /// Distinct assessed risk factors.
        risk_factors: Vec<String>,
        /// Optional distinct additional characteristics.
        additional_characteristics: Vec<String>,
        /// Existing controls and their assessed effects.
        existing_controls: Vec<ControlEffect>,
        /// Exactly seventeen priority slots.
        priority_risks: Vec<PriorityRisk>,
        /// Optional additional illegal-content risks.
        other_illegal_risks: Vec<OtherRisk>,
        /// Reasoning including an explicit absence of additional risks.
        other_illegal_reasoning: String,
        /// Distinct inert evidence entries.
        evidence: Vec<Evidence>,
        /// Overall assessment reasoning.
        reasoning: String,
        /// Governance reporting attestation.
        governance_reporting: Attestation,
        /// Opaque governance reporting reference.
        governance_reference: String,
        /// How this assessment is kept current.
        keep_up_to_date_policy: String,
        /// Latest assessment review UTC second.
        last_reviewed_at: i64,
        /// Bounded distinct review triggers.
        review_triggers: Vec<ReviewTrigger>,
        /// Operator-supplied catalog version or pending for local drafts.
        priority_catalog_version: String,
        /// Required only for a children's access assessment.
        #[serde(deserialize_with = "required_option")]
        access: Option<AccessAssessment>,
        /// Required only for a children's risk assessment.
        #[serde(deserialize_with = "required_option")]
        children: Option<ChildrenAssessment>,
    }
}
record_struct! {
    /// Immutable selection of assessment versions and public accountability.
    ComplianceManifest {
        /// Service shared by every selected record.
        service: String,
        /// Named individual matching the assessments' responsible person.
        accountable_person: String,
        /// Named governance body.
        governance_body: String,
        /// Selected illegal-content assessment.
        icra: RecordRef,
        /// Selected children's access assessment.
        caa: RecordRef,
        /// Selected children's risk assessment when present.
        #[serde(deserialize_with = "required_option")]
        cra: Option<RecordRef>,
        /// Selected measures version.
        measures: RecordRef,
        /// Matching public policy revision.
        statement_version: String,
        /// Operator-stated approval.
        approval_status: ApprovalStatus,
        /// Named approving individual or draft placeholder.
        approver: String,
        /// Nonfuture approval when approved.
        #[serde(deserialize_with = "required_option")]
        approved_at: Option<i64>,
    }
}
record_struct! {
    /// Review work retained independently of assessment freshness.
    ReviewRecord {
        /// Kind of assessment or measures work.
        scope: ReviewScope,
        /// Trigger fixing the idempotency identity.
        trigger: ReviewTrigger,
        /// Immutable source assessment or measures version.
        assessment: RecordRef,
        /// Work opening UTC second.
        opened_at: i64,
        /// Representable due UTC second, possibly still in the future.
        due_at: i64,
        /// Open or completed work.
        status: ReviewStatus,
        /// Completion UTC second when completed.
        #[serde(deserialize_with = "required_option")]
        completed_at: Option<i64>,
        /// Reasoned work record.
        reasons: String,
    }
}
record_struct! {
    /// One receipt-cohort route count.
    RouteCount {
        /// Closed route spelling.
        route: super::model::Route,
        /// Number of receipts in the month.
        count: u64,
    }
}
record_struct! {
    /// Integer nearest-rank durations, absent when there are no completed milestones.
    Durations {
        /// Number of observed milestones.
        n: u64,
        /// Lower nearest-rank median seconds.
        #[serde(deserialize_with = "required_option")]
        median: Option<u64>,
        /// Nearest-rank ninety-fifth percentile seconds.
        #[serde(deserialize_with = "required_option")]
        p95: Option<u64>,
    }
}
vocabulary! {
    /// Closed effective original protection types.
    ActionKind {
        /// Global result exclusion.
        GlobalDeindex => "global_deindex",
        /// Name-scoped result exclusion.
        NameDelisting => "name_delisting",
    }
}
record_struct! {
    /// Number of completed original protections of one type.
    ActionCount {
        /// Protection type.
        kind: ActionKind,
        /// Number of protections.
        count: u64,
    }
}
record_struct! {
    /// Disjoint intimate-image deadline outcomes.
    IntimateCounts {
        /// Non-exempt tickets whose outer deadline has arrived.
        due: u64,
        /// Due tickets protected in time.
        met: u64,
        /// Due tickets not protected in time.
        missed: u64,
        /// Non-exempt tickets before the outer deadline.
        pending: u64,
        /// Timely completed exemption determinations.
        exempt: u64,
    }
}
record_struct! {
    /// Aggregate use of a versioned manifestly-unfounded policy clause.
    ClauseCount {
        /// Policy revision.
        policy_version: String,
        /// Closed journal reason code.
        policy_clause: String,
        /// First decisions using that clause.
        count: u64,
    }
}
record_struct! {
    /// Integer monthly aggregates over a frozen committed ticket prefix.
    MonthlyMetrics {
        /// Strict UTC month spelling.
        month: String,
        /// Captured committed ticket sequence.
        as_of_sequence: u64,
        /// Snapshot observation UTC second.
        generated_at: i64,
        /// All routes in the prescribed order.
        counts_by_route: Vec<RouteCount>,
        /// Receipt-to-first-acknowledgement latencies.
        ack_seconds: Durations,
        /// Receipt-to-first-decision latencies.
        decision_seconds: Durations,
        /// Receipt-to-effective-completed-action latencies.
        action_seconds: Durations,
        /// Both original action types in order.
        actions_by_type: Vec<ActionCount>,
        /// Cohort reversal events through the cutoff.
        reversals: u64,
        /// Disjoint deadline outcomes.
        intimate: IntimateCounts,
        /// Unique sorted policy/clause counts.
        unfounded_by_clause: Vec<ClauseCount>,
    }
}

/// Body selection is encoded only by the envelope's kind, with no nested discriminator.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum RecordBody {
    /// Illegal-content assessment.
    Icra(Assessment),
    /// Children's access assessment.
    Caa(Assessment),
    /// Children's risk assessment.
    Cra(Assessment),
    /// Measures and alternatives.
    Measures(MeasuresRecord),
    /// Approval and public accountability selection.
    Manifest(ComplianceManifest),
    /// Frozen monthly aggregates.
    Metrics(MonthlyMetrics),
    /// Review work.
    Review(ReviewRecord),
}

/// Strict imported envelope before salt and commitment are added by the owner.
#[derive(Debug, Clone, Serialize)]
pub struct RecordEnvelope {
    /// Fixed schema version one.
    pub format_version: u64,
    /// Bounded identifier excluding private runtime names.
    pub id: String,
    /// Positive immutable version.
    pub version: u32,
    /// Body category.
    pub kind: RecordKind,
    /// Body's completion, effect, generation or opening UTC second.
    pub completed_at: i64,
    /// Immediate predecessor for later versions; null for the first.
    pub supersedes: Option<RecordRef>,
    /// Typed body corresponding exactly to kind.
    pub body: RecordBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    format_version: u64,
    id: String,
    version: u32,
    kind: RecordKind,
    completed_at: i64,
    #[serde(deserialize_with = "required_option")]
    supersedes: Option<RecordRef>,
    body: serde_json::Value,
}
impl<'de> Deserialize<'de> for RecordEnvelope {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        let raw = RawEnvelope::deserialize(decoder)?;
        let body = match raw.kind {
            RecordKind::Icra => serde_json::from_value(raw.body).map(RecordBody::Icra),
            RecordKind::Caa => serde_json::from_value(raw.body).map(RecordBody::Caa),
            RecordKind::Cra => serde_json::from_value(raw.body).map(RecordBody::Cra),
            RecordKind::Measures => serde_json::from_value(raw.body).map(RecordBody::Measures),
            RecordKind::Manifest => serde_json::from_value(raw.body).map(RecordBody::Manifest),
            RecordKind::Metrics => serde_json::from_value(raw.body).map(RecordBody::Metrics),
            RecordKind::Review => serde_json::from_value(raw.body).map(RecordBody::Review),
        }
        .map_err(serde::de::Error::custom)?;
        Ok(Self {
            format_version: raw.format_version,
            id: raw.id,
            version: raw.version,
            kind: raw.kind,
            completed_at: raw.completed_at,
            supersedes: raw.supersedes,
            body,
        })
    }
}

/// Requires the field to exist even when its explicitly supplied value is null.
pub(crate) fn required_option<'de, D, T>(decoder: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(decoder)
}

/// Requires a semantic invariant with no personal information in the error.
pub(crate) fn require(valid: bool) -> Result<()> {
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Applies the one shared text guard with the named record text class.
pub(crate) fn text(value: &str, key: BoundKey) -> Result<()> {
    let class = match key {
        BoundKey::Slug => TextClass::Slug,
        BoundKey::Narrative => TextClass::Narrative,
        _ => TextClass::Label,
    };
    bounds::text(value, key, class)
}

/// Validates finite nonfuture UTC seconds without reading a clock.
pub(crate) fn date(at: i64, now: i64) -> Result<()> {
    clock::instant(at)?;
    require(at <= now)
}

/// Rejects identifiers that could alias record-store runtime files or staging families.
pub fn validate_id(id: &str) -> Result<()> {
    text(id, BoundKey::Slug)?;
    require(
        !matches!(id, "index" | "index.jsonl" | "head" | "head.json")
            && !id.starts_with("record-")
            && !id.starts_with("quarantine-"),
    )
}

/// Checks a bounded collection's identifiers for exact uniqueness.
pub(crate) fn unique<T: Ord>(values: impl IntoIterator<Item = T>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require(seen.insert(value))?;
    }
    Ok(())
}

/// Validates distinct text items using the common bounds and character policy.
pub(crate) fn texts(values: &[String], count: BoundKey, key: BoundKey) -> Result<()> {
    count.validate(values.len() as u64)?;
    unique(values)?;
    for value in values {
        text(value, key)?;
    }
    Ok(())
}

impl RecordEnvelope {
    /// Returns this immutable version's scalar reference.
    pub fn reference(&self) -> RecordRef {
        RecordRef {
            id: self.id.clone(),
            version: self.version,
        }
    }
    /// Validates the body without disk access; the store checks cross-record references.
    pub fn validate(&self, now: i64) -> Result<()> {
        require(self.format_version == 1)?;
        self.reference().validate()?;
        date(self.completed_at, now)?;
        if let Some(previous) = &self.supersedes {
            previous.validate()?;
        }
        let completed = match (&self.kind, &self.body) {
            (RecordKind::Icra, RecordBody::Icra(body))
            | (RecordKind::Caa, RecordBody::Caa(body))
            | (RecordKind::Cra, RecordBody::Cra(body)) => {
                body.validate(self.kind, now)?;
                body.date_completed
            }
            (RecordKind::Measures, RecordBody::Measures(body)) => {
                super::measures::validate(body, now)?;
                body.date_effective
            }
            (RecordKind::Manifest, RecordBody::Manifest(body)) => {
                body.validate(self.completed_at, now)?;
                match body.approval_status {
                    ApprovalStatus::Approved => body.approved_at.ok_or(Error::InvalidInput)?,
                    ApprovalStatus::Draft => self.completed_at,
                }
            }
            (RecordKind::Metrics, RecordBody::Metrics(body)) => {
                body.validate(now)?;
                body.generated_at
            }
            (RecordKind::Review, RecordBody::Review(body)) => {
                body.validate(now)?;
                body.opened_at
            }
            _ => return Err(Error::InvalidInput),
        };
        require(self.completed_at == completed)
    }
    /// Returns the assessed service when the body contains it directly.
    pub fn service(&self) -> Option<&str> {
        match &self.body {
            RecordBody::Icra(body) | RecordBody::Caa(body) | RecordBody::Cra(body) => {
                Some(&body.service)
            }
            RecordBody::Measures(body) => Some(&body.service),
            RecordBody::Manifest(body) => Some(&body.service),
            _ => None,
        }
    }
    /// Returns an assessment body without changing its kind.
    pub fn assessment(&self) -> Option<&Assessment> {
        match &self.body {
            RecordBody::Icra(body) | RecordBody::Caa(body) | RecordBody::Cra(body) => Some(body),
            _ => None,
        }
    }
}

impl ReviewTrigger {
    /// Checks the attested reference and nonfuture trigger date.
    pub fn validate(&self, now: i64) -> Result<()> {
        date(self.at, now)?;
        text(&self.reference, BoundKey::DeliveryRef)
    }
}

impl Assessment {
    /// Validates every common and kind-specific assessment field using one semantic path.
    pub fn validate(&self, kind: RecordKind, now: i64) -> Result<()> {
        for label in [
            &self.service,
            &self.author,
            &self.responsible_person,
            &self.approver,
        ] {
            text(label, BoundKey::Label)?;
        }
        for narrative in [
            &self.other_illegal_reasoning,
            &self.reasoning,
            &self.keep_up_to_date_policy,
        ] {
            text(narrative, BoundKey::Narrative)?;
        }
        text(&self.governance_reference, BoundKey::DeliveryRef)?;
        text(&self.priority_catalog_version, BoundKey::Slug)?;
        self.validate_dates(now)?;
        self.validate_questions()?;
        texts(&self.risk_factors, BoundKey::RecordItems, BoundKey::Reason)?;
        texts(
            &self.additional_characteristics,
            BoundKey::OptionalRecordItems,
            BoundKey::Reason,
        )?;
        let evidence = self.validate_evidence()?;
        self.validate_risks(&evidence)?;
        self.validate_children(kind, &evidence, now)?;
        if self.approval_status == ApprovalStatus::Approved {
            validate_approved(self, now)?;
        }
        Ok(())
    }
    fn validate_dates(&self, now: i64) -> Result<()> {
        date(self.date_completed, now)?;
        date(self.last_reviewed_at, now)?;
        require(self.last_reviewed_at >= self.date_completed)?;
        BoundKey::RecordHistory.validate(self.review_update_dates.len() as u64)?;
        let mut previous = None;
        for &at in &self.review_update_dates {
            date(at, self.last_reviewed_at)?;
            require(at >= self.date_completed && previous.is_none_or(|last| at > last))?;
            previous = Some(at);
        }
        require(
            self.review_update_dates.first() == Some(&self.date_completed)
                && self.review_update_dates.last() == Some(&self.last_reviewed_at),
        )?;
        if let Some(at) = self.approved_at {
            date(at, now)?;
            require(at >= self.date_completed)?;
        }
        BoundKey::OptionalHistory.validate(self.review_triggers.len() as u64)?;
        unique(
            self.review_triggers
                .iter()
                .map(|trigger| (trigger.kind, trigger.at, &trigger.reference)),
        )?;
        for trigger in &self.review_triggers {
            trigger.validate(now)?;
        }
        Ok(())
    }
    fn validate_questions(&self) -> Result<()> {
        BoundKey::RecordItems.validate(self.questionnaire_outcomes.len() as u64)?;
        unique(self.questionnaire_outcomes.iter().map(|answer| &answer.id))?;
        for answer in &self.questionnaire_outcomes {
            text(&answer.id, BoundKey::Slug)?;
            text(&answer.answer, BoundKey::Reason)?;
        }
        BoundKey::RecordItems.validate(self.existing_controls.len() as u64)?;
        unique(
            self.existing_controls
                .iter()
                .map(|control| &control.description),
        )?;
        for control in &self.existing_controls {
            text(&control.description, BoundKey::Reason)?;
            text(&control.effect, BoundKey::Reason)?;
        }
        Ok(())
    }
    fn validate_evidence(&self) -> Result<BTreeSet<&str>> {
        BoundKey::RecordItems.validate(self.evidence.len() as u64)?;
        unique(self.evidence.iter().map(|evidence| &evidence.id))?;
        for evidence in &self.evidence {
            text(&evidence.id, BoundKey::Slug)?;
            text(&evidence.description, BoundKey::Reason)?;
            text(&evidence.source, BoundKey::Url)?;
        }
        Ok(self
            .evidence
            .iter()
            .map(|evidence| evidence.id.as_str())
            .collect())
    }
    fn validate_risks(&self, evidence: &BTreeSet<&str>) -> Result<()> {
        BoundKey::PriorityKinds.validate(self.priority_risks.len() as u64)?;
        unique(self.priority_risks.iter().map(|risk| risk.kind))?;
        for risk in &self.priority_risks {
            text(&risk.explanation, BoundKey::Reason)?;
            evidence_refs(&risk.evidence_ids, evidence)?;
        }
        BoundKey::OptionalRecordItems.validate(self.other_illegal_risks.len() as u64)?;
        unique(self.other_illegal_risks.iter().map(|risk| &risk.name))?;
        for risk in &self.other_illegal_risks {
            text(&risk.name, BoundKey::Label)?;
            text(&risk.explanation, BoundKey::Reason)?;
            evidence_refs(&risk.evidence_ids, evidence)?;
        }
        Ok(())
    }
    fn validate_children(
        &self,
        kind: RecordKind,
        evidence: &BTreeSet<&str>,
        now: i64,
    ) -> Result<()> {
        match (kind, &self.access, &self.children) {
            (RecordKind::Icra, None, None) => Ok(()),
            (RecordKind::Caa, Some(access), None) => {
                date(access.concluded_at, now)?;
                require(access.concluded_at <= self.date_completed)?;
                text(&access.steps, BoundKey::Narrative)?;
                evidence_refs(&access.evidence_ids, evidence)
            }
            (RecordKind::Cra, None, Some(children)) => {
                BoundKey::ChildrenClasses.validate(children.classes.len() as u64)?;
                unique(children.classes.iter().map(|risk| risk.class))?;
                for risk in &children.classes {
                    text(&risk.explanation, BoundKey::Reason)?;
                    evidence_refs(&risk.evidence_ids, evidence)?;
                }
                Ok(())
            }
            _ => Err(Error::InvalidInput),
        }
    }
}

fn evidence_refs(refs: &[String], evidence: &BTreeSet<&str>) -> Result<()> {
    texts(refs, BoundKey::RecordItems, BoundKey::Slug)?;
    require(
        refs.iter()
            .all(|reference| evidence.contains(reference.as_str())),
    )
}

/// Tests for explicit founder placeholders without treating ordinary punctuation as unsafe.
pub(crate) fn has_placeholder(value: &impl Serialize) -> Result<bool> {
    Ok(serde_json::to_string(value)
        .map_err(|_| Error::InvalidInput)?
        .contains("[FOUNDER REQUIRED:"))
}

/// Checks a complete operator catalog without supplying or inferring legal labels.
pub fn catalog_complete(catalog: &ValidatedComplianceConfig) -> bool {
    let settings = catalog.settings();
    settings.priority_catalog_version.is_some()
        && settings.priority_catalog_source.is_some()
        && settings.priority_kind_labels.iter().all(Option::is_some)
}

fn approved_complete(assessment: &Assessment, now: i64) -> bool {
    assessment
        .approved_at
        .is_some_and(|at| at >= assessment.date_completed && at <= now)
        && assessment.risk_profiles_consulted == Attestation::Yes
        && assessment.governance_reporting == Attestation::Yes
        && has_placeholder(assessment).is_ok_and(|present| !present)
}

fn validate_approved(assessment: &Assessment, now: i64) -> Result<()> {
    require(approved_complete(assessment, now))
}

impl ComplianceManifest {
    /// Checks shape and approval chronology; the store resolves immutable references.
    pub fn validate(&self, completed: i64, now: i64) -> Result<()> {
        for label in [
            &self.service,
            &self.accountable_person,
            &self.governance_body,
            &self.approver,
        ] {
            text(label, BoundKey::Label)?;
        }
        text(&self.statement_version, BoundKey::Slug)?;
        for reference in [&self.icra, &self.caa, &self.measures]
            .into_iter()
            .chain(self.cra.iter())
        {
            reference.validate()?;
        }
        if let Some(at) = self.approved_at {
            date(at, now)?;
            require(self.approval_status == ApprovalStatus::Draft || at == completed)?;
        }
        if self.approval_status == ApprovalStatus::Approved {
            require(self.approved_at.is_some() && !has_placeholder(self)?)?;
        }
        Ok(())
    }
}

impl ReviewRecord {
    /// Validates work state while permitting a not-yet-due annual item.
    pub fn validate(&self, now: i64) -> Result<()> {
        self.assessment.validate()?;
        self.trigger.validate(now)?;
        date(self.opened_at, now)?;
        clock::instant(self.due_at)?;
        text(&self.reasons, BoundKey::Reason)?;
        match (self.status, self.completed_at) {
            (ReviewStatus::Open, None) => Ok(()),
            (ReviewStatus::Completed, Some(at)) => {
                date(at, now)?;
                require(at >= self.opened_at)
            }
            _ => Err(Error::InvalidInput),
        }
    }
}

impl MonthlyMetrics {
    /// Validates integer shape and consistency of an imported or generated aggregate.
    pub fn validate(&self, now: i64) -> Result<()> {
        super::metrics::month_start(&self.month)?;
        date(self.generated_at, now)?;
        let expected = [
            "illegal_content",
            "harmful_to_children",
            "intimate_images",
            "site_complaint",
            "rights_removal",
            "data_rights",
            "data_protection_complaint",
            "online_safety_complaint",
        ];
        require(
            self.counts_by_route
                .iter()
                .map(|row| row.route.as_str())
                .eq(expected),
        )?;
        require(
            self.actions_by_type
                .iter()
                .map(|row| row.kind)
                .eq([ActionKind::GlobalDeindex, ActionKind::NameDelisting]),
        )?;
        for durations in [
            &self.ack_seconds,
            &self.decision_seconds,
            &self.action_seconds,
        ] {
            require(match (durations.n, durations.median, durations.p95) {
                (0, None, None) => true,
                (n, Some(median), Some(p95)) if n > 0 => median <= p95,
                _ => false,
            })?;
        }
        require(self.intimate.met.checked_add(self.intimate.missed) == Some(self.intimate.due))?;
        BoundKey::OptionalRecordItems.validate(self.unfounded_by_clause.len() as u64)?;
        let mut previous = None;
        for clause in &self.unfounded_by_clause {
            text(&clause.policy_version, BoundKey::Slug)?;
            text(&clause.policy_clause, BoundKey::Slug)?;
            require(clause.policy_clause == "duplicate_without_new_information")?;
            let key = (&clause.policy_version, &clause.policy_clause);
            require(previous.is_none_or(|last| last < key))?;
            previous = Some(key);
        }
        Ok(())
    }
}
