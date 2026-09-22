//! Validates prospective significant changes against immutable, approved assessment updates.
//! Operators wire the pure validation outcome into their deployment gate.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey},
    clock,
    record_types::{
        require, text, unique, AccessConclusion, ApprovalStatus, RecordKind, RecordRef, TriggerKind,
    },
    records::RecordView,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Closed set of changes requiring reassessment before release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignificantChange {
    /// Ranking model or ranking behaviour.
    RankingModel,
    /// Classes of content indexed.
    IndexContentClasses,
    /// Geographical scope of indexing.
    IndexGeographies,
    /// Image indexing.
    IndexImages,
    /// Query completion suggestions.
    Autocomplete,
    /// Advertising surfaces.
    Advertising,
    /// Cached copies of third-party material.
    CachedCopies,
    /// Synthesized answers.
    AiAnswerSynthesis,
    /// Age-related protections.
    AgeControls,
    /// Access restrictions.
    AccessControls,
}

/// Bounded prospective release attestation, with no embedded approval or deployment authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    /// Fixed schema version one.
    pub format_version: u64,
    /// Bounded identifier matched by assessment review triggers.
    pub release_id: String,
    /// Service being changed.
    pub service: String,
    /// Prospective UTC release instant; future dates are permitted.
    pub planned_at: i64,
    /// Zero to ten distinct significant changes.
    pub changes: Vec<SignificantChange>,
    /// Zero to sixty-four distinct immutable assessment references.
    pub assessment_updates: Vec<RecordRef>,
}

/// Validates shape and all supplied updates even when no significant change is declared.
pub fn validate_release(manifest: &ReleaseManifest, records: &RecordView) -> Result<()> {
    require(manifest.format_version == 1)?;
    text(&manifest.release_id, BoundKey::Slug)?;
    text(&manifest.service, BoundKey::Label)?;
    clock::instant(manifest.planned_at)?;
    bounds::validate_range(manifest.changes.len() as u64, 0, 10)?;
    bounds::validate_range(manifest.assessment_updates.len() as u64, 0, 64)?;
    unique(&manifest.changes)?;
    unique(&manifest.assessment_updates)?;
    let mut identities = BTreeSet::new();
    for reference in &manifest.assessment_updates {
        reference.validate()?;
        require(identities.insert(&reference.id))?;
        validate_update(manifest, records, reference)?;
    }
    validate_required_updates(manifest, records)?;
    Ok(())
}

fn validate_update(
    manifest: &ReleaseManifest,
    records: &RecordView,
    reference: &RecordRef,
) -> Result<()> {
    let record = records.get(reference).ok_or(Error::InvalidInput)?;
    require(
        records
            .latest(&reference.id)
            .is_some_and(|latest| latest.reference() == *reference),
    )?;
    let assessment = record.assessment().ok_or(Error::InvalidInput)?;
    require(assessment.service == manifest.service)?;
    require(assessment.approval_status == ApprovalStatus::Approved)?;
    require(record.completed_at <= manifest.planned_at)?;
    require(
        assessment
            .approved_at
            .is_some_and(|at| at <= manifest.planned_at),
    )?;
    require(assessment.review_triggers.iter().any(|trigger| {
        trigger.kind == TriggerKind::SignificantChange
            && trigger.reference == manifest.release_id
            && trigger.at <= manifest.planned_at
    }))
}

fn validate_required_updates(manifest: &ReleaseManifest, records: &RecordView) -> Result<()> {
    if manifest.changes.is_empty() {
        return Ok(());
    }
    let updates = manifest
        .assessment_updates
        .iter()
        .filter_map(|reference| records.get(reference));
    let kinds = updates
        .clone()
        .map(|record| record.kind)
        .collect::<BTreeSet<_>>();
    require(kinds.contains(&RecordKind::Icra) && kinds.contains(&RecordKind::Caa))?;
    let likely = updates
        .filter_map(|record| record.assessment())
        .any(|assessment| {
            assessment
                .access
                .as_ref()
                .is_some_and(|access| access.conclusion == AccessConclusion::Likely)
        });
    require(!likely || kinds.contains(&RecordKind::Cra))
}
