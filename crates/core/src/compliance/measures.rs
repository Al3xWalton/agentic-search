//! Validates the exact supplied measures set and reasoned alternatives without inventing approvals.
//! Adoption status records the pending counsel decision explicitly for the seven affected measures.

#![deny(missing_docs)]

use super::{
    bounds::BoundKey,
    record_types::{date, require, text, unique, ApprovalStatus},
    Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Exact closed vocabulary supplied for this search-service implementation.
pub const MEASURE_IDS: [&str; 28] = [
    "ICS A2", "ICS C1.2", "ICS C1.4", "ICS C3", "ICS C7.6", "ICS D1", "ICS D2", "ICS D3", "ICS D4",
    "ICS D5", "ICS D8", "ICS D9", "ICS D12", "ICS G1", "ICS G3", "PCS A2", "PCS C1", "PCS D1",
    "PCS D2", "PCS D4", "PCS D5", "PCS D6", "PCS D7", "PCS D9", "PCS D10", "PCS D14", "PCS G1",
    "PCS G3",
];

/// Validated measure code; private representation prevents unknown programmatic codes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct MeasureId(String);
impl MeasureId {
    /// Accepts only one supplied code, with exact punctuation and spaces.
    pub fn parse(value: &str) -> Result<Self> {
        require(MEASURE_IDS.contains(&value))?;
        Ok(Self(value.into()))
    }
    /// Returns the exact code for statements and comparisons.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for MeasureId {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

/// Whether the supplied measure was taken or a reasoned alternative selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Supplied measure is taken.
    Taken,
    /// A documented alternative is selected.
    Alternative,
}
/// Stated basis for adopting a measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Adoption {
    /// Required within this supplied scope.
    Required,
    /// Voluntarily adopted pending counsel's determination.
    VoluntaryPendingLegalReview,
}

/// The complete reasoning for not taking one or more supplied measures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alternative {
    /// Distinct omitted codes, including the containing row's code.
    pub not_taken: Vec<MeasureId>,
    /// Alternative measure adopted.
    pub measure: String,
    /// Why the alternative satisfies the duty.
    pub compliance_reasoning: String,
    /// Assessment of freedom of expression and privacy.
    pub freedom_of_expression_and_privacy: String,
}
/// One supplied measure and its actual or alternative disposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasureRow {
    /// Exact supplied code.
    pub code: MeasureId,
    /// Bounded measure description.
    pub description: String,
    /// Effective UTC second no later than the complete record.
    pub date_effective: i64,
    /// Taken or alternative.
    pub disposition: Disposition,
    /// Required reasoning for an alternative, absent for a taken measure.
    #[serde(deserialize_with = "super::record_types::required_option")]
    pub alternative: Option<Alternative>,
    /// Required or explicitly voluntary pending counsel.
    pub adoption: Adoption,
}
/// Complete measures statement for one service and one immutable version.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuresRecord {
    /// Service covered.
    pub service: String,
    /// Complete record's effective UTC second.
    pub date_effective: i64,
    /// Operator-stated approval.
    pub approval_status: ApprovalStatus,
    /// Named approver or an explicit draft placeholder.
    pub approver: String,
    /// Exactly the twenty-eight supplied codes.
    pub rows: Vec<MeasureRow>,
    /// Latest review UTC second.
    pub last_reviewed_at: i64,
}

/// Validates the exact set, row semantics and date ordering once for writes and reads.
pub fn validate(record: &MeasuresRecord, now: i64) -> Result<()> {
    text(&record.service, BoundKey::Label)?;
    text(&record.approver, BoundKey::Label)?;
    date(record.date_effective, now)?;
    date(record.last_reviewed_at, now)?;
    require(record.last_reviewed_at >= record.date_effective)?;
    let rows = &record.rows;
    BoundKey::MeasureRows.validate(rows.len() as u64)?;
    let actual = rows
        .iter()
        .map(|row| row.code.as_str())
        .collect::<BTreeSet<_>>();
    let expected = MEASURE_IDS.into_iter().collect::<BTreeSet<_>>();
    require(actual == expected)?;
    for row in rows {
        text(&row.description, BoundKey::Reason)?;
        date(row.date_effective, record.date_effective)?;
        let voluntary = matches!(
            row.code.as_str(),
            "ICS D3" | "ICS D4" | "ICS D5" | "ICS C3" | "PCS D4" | "PCS D5" | "PCS D6"
        );
        require((row.adoption == Adoption::VoluntaryPendingLegalReview) == voluntary)?;
        validate_alternative(row)?;
    }
    if record.approval_status == ApprovalStatus::Approved {
        require(!super::record_types::has_placeholder(record)?)?;
    }
    Ok(())
}

fn validate_alternative(row: &MeasureRow) -> Result<()> {
    match (&row.disposition, &row.alternative) {
        (Disposition::Taken, None) => Ok(()),
        (Disposition::Alternative, Some(alternative)) => {
            BoundKey::RecordItems.validate(alternative.not_taken.len() as u64)?;
            unique(&alternative.not_taken)?;
            require(alternative.not_taken.contains(&row.code))?;
            for reason in [
                &alternative.measure,
                &alternative.compliance_reasoning,
                &alternative.freedom_of_expression_and_privacy,
            ] {
                text(reason, BoundKey::Reason)?;
            }
            Ok(())
        }
        _ => require(false),
    }
}
