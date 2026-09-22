//! Derives review work from immutable selections and a caller-supplied UTC instant.
//! Completed work never advances assessment freshness; a new assessment version does that.
//! Explicit attestations retain their identity across retries at a later clock reading.

#![deny(missing_docs)]

use super::{
    bounds::BoundKey,
    clock,
    model::sha256,
    record_types::{
        require, text, AccessConclusion, ApprovalStatus, RecordBody, RecordEnvelope, RecordKind,
        RecordRef, ReviewRecord, ReviewScope, ReviewStatus, ReviewTrigger, TriggerKind,
    },
    records::{resolve, RecordStore, RecordView},
    Error, Result,
};
use serde::Serialize;

/// One pending review deadline, including work that is not yet overdue.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewDue {
    /// Kind of work.
    pub scope: ReviewScope,
    /// Immutable assessment or measures version.
    pub assessment: RecordRef,
    /// Attestation or derived annual cause.
    pub trigger: ReviewTrigger,
    /// Checked UTC due second.
    pub due_at: i64,
    /// Whether the threshold has passed; explicit work is immediately due.
    pub overdue: bool,
}

/// A completed child-risk assessment whose lateness must remain visible.
#[derive(Debug, Clone, Serialize)]
pub struct LateCompletion {
    /// Access conclusion establishing the original deadline.
    pub access: RecordRef,
    /// Completed and approved risk assessment.
    pub assessment: RecordRef,
    /// Original UTC deadline.
    pub due_at: i64,
    /// Assessment completion UTC second.
    pub completed_at: i64,
}

/// Pure assessment of pending reviews and retained late completions.
#[derive(Debug, Clone, Serialize)]
pub struct Freshness {
    /// Deterministically sorted pending review work.
    pub items: Vec<ReviewDue>,
    /// Completed work does not erase evidence of a missed assessment deadline.
    pub late_completions: Vec<LateCompletion>,
}

/// Safe counts and references returned by review writers, never private assessment text.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewWrites {
    /// Newly created work records.
    pub created: u64,
    /// Work identities already present, including completed work.
    pub existing: u64,
    /// References in deterministic work order.
    pub record_refs: Vec<RecordRef>,
}

/// Uses manifest selections when present, otherwise the current local assessment versions.
pub fn selected(view: &RecordView) -> Result<Vec<&RecordEnvelope>> {
    let Some(manifest) = view.manifest()? else {
        return Ok(view.current().collect());
    };
    let RecordBody::Manifest(manifest) = &manifest.body else {
        return Err(Error::InvalidInput);
    };
    [
        (&manifest.icra, RecordKind::Icra),
        (&manifest.caa, RecordKind::Caa),
        (&manifest.measures, RecordKind::Measures),
    ]
    .into_iter()
    .chain(
        manifest
            .cra
            .iter()
            .map(|reference| (reference, RecordKind::Cra)),
    )
    .map(|(reference, kind)| resolve(view, reference, kind))
    .collect()
}

fn scope(record: &RecordEnvelope) -> Option<ReviewScope> {
    match record.kind {
        RecordKind::Measures => Some(ReviewScope::Compliance),
        RecordKind::Icra | RecordKind::Cra => Some(ReviewScope::Risk),
        RecordKind::Caa => Some(ReviewScope::ChildAccess),
        _ => None,
    }
}

fn sort(items: &mut [ReviewDue]) {
    items.sort_by(|a, b| {
        (
            a.scope,
            &a.assessment,
            a.trigger.kind,
            &a.trigger.reference,
            a.due_at,
        )
            .cmp(&(
                b.scope,
                &b.assessment,
                b.trigger.kind,
                &b.trigger.reference,
                b.due_at,
            ))
    });
}

/// Computes annual freshness and the original-instant child-risk deadline without any I/O.
pub fn freshness(view: &RecordView, now: i64) -> Result<Freshness> {
    clock::instant(now)?;
    let records = selected(view)?;
    let mut result = Freshness {
        items: Vec::new(),
        late_completions: Vec::new(),
    };
    for record in &records {
        let Some(scope) = scope(record) else { continue };
        if let Some(assessment) = record.assessment() {
            if let Some(access) = &assessment.access {
                if access.conclusion == AccessConclusion::Likely {
                    child_risk(record, access.concluded_at, &records, now, &mut result)?;
                    continue;
                }
            }
        }
        let reviewed_at = match &record.body {
            RecordBody::Icra(assessment)
            | RecordBody::Caa(assessment)
            | RecordBody::Cra(assessment) => assessment.last_reviewed_at,
            RecordBody::Measures(measures) => measures.last_reviewed_at,
            _ => continue,
        };
        result.items.push(ReviewDue {
            scope,
            assessment: record.reference(),
            trigger: ReviewTrigger {
                kind: TriggerKind::Annual,
                at: reviewed_at,
                reference: "annual-review".into(),
            },
            due_at: clock::add_seconds(reviewed_at, clock::REVIEW_FRESHNESS_SECONDS)?,
            overdue: !clock::review_fresh(reviewed_at, now)?,
        });
    }
    sort(&mut result.items);
    result
        .late_completions
        .sort_by(|a, b| a.access.cmp(&b.access));
    Ok(result)
}

fn child_risk(
    access: &RecordEnvelope,
    concluded_at: i64,
    records: &[&RecordEnvelope],
    now: i64,
    result: &mut Freshness,
) -> Result<()> {
    let due_at = clock::child_risk_due(concluded_at)?;
    let overdue = clock::child_risk_overdue(concluded_at, now)?;
    let approved = records.iter().find(|record| {
        record.kind == RecordKind::Cra
            && record.service() == access.service()
            && record
                .assessment()
                .is_some_and(|body| body.approval_status == ApprovalStatus::Approved)
    });
    if let Some(completed) = approved {
        if completed.completed_at > due_at {
            result.late_completions.push(LateCompletion {
                access: access.reference(),
                assessment: completed.reference(),
                due_at,
                completed_at: completed.completed_at,
            });
        }
    } else {
        result.items.push(ReviewDue {
            scope: ReviewScope::ChildAccess,
            assessment: access.reference(),
            trigger: ReviewTrigger {
                kind: TriggerKind::Annual,
                at: concluded_at,
                reference: "child-risk-assessment".into(),
            },
            due_at,
            overdue,
        });
    }
    Ok(())
}

/// Applies the closed trigger-to-scope table to current immutable selections.
pub fn triggered(
    view: &RecordView,
    kind: TriggerKind,
    reference: &str,
    now: i64,
) -> Result<Vec<ReviewDue>> {
    require(kind != TriggerKind::Annual)?;
    text(reference, BoundKey::Slug)?;
    clock::instant(now)?;
    let mut items = Vec::new();
    for record in selected(view)? {
        let Some(scope) = scope(record) else { continue };
        let included = match kind {
            TriggerKind::RiskProfileChanged => match scope {
                ReviewScope::Compliance => true,
                ReviewScope::Risk => true,
                ReviewScope::ChildAccess => false,
            },
            TriggerKind::SignificantChange => true,
            TriggerKind::EvidenceOfChildUse => scope == ReviewScope::ChildAccess,
            TriggerKind::Annual => false,
        };
        if included {
            items.push(ReviewDue {
                scope,
                assessment: record.reference(),
                trigger: ReviewTrigger {
                    kind,
                    at: now,
                    reference: reference.into(),
                },
                due_at: now,
                overdue: true,
            });
        }
    }
    sort(&mut items);
    Ok(items)
}

fn key(scope: ReviewScope, assessment: &RecordRef, trigger: &ReviewTrigger, due: i64) -> String {
    let due = (trigger.kind == TriggerKind::Annual).then_some(due);
    // This tuple contains only validated scalar fields with infallible JSON serialization.
    let bytes = serde_json::to_vec(&(scope, assessment, trigger.kind, &trigger.reference, due))
        .expect("review key scalars serialize");
    format!("review.{}", &sha256(&[b"AVA619-REVIEW-v1\0", &bytes])[..48])
}

impl RecordView {
    /// Finds the current work version for a stable cause, regardless of completion status.
    pub fn review_by_key(&self, identity: &str) -> Option<RecordRef> {
        self.current().find_map(|record| match &record.body {
            RecordBody::Review(review)
                if key(
                    review.scope,
                    &review.assessment,
                    &review.trigger,
                    review.due_at,
                ) == identity =>
            {
                Some(record.reference())
            }
            _ => None,
        })
    }
}

/// Writes only requested due work; duplicate causes do not consume entropy or append rows.
pub fn open_work(
    store: &mut RecordStore,
    items: &[ReviewDue],
    now: i64,
    actor: &str,
) -> Result<ReviewWrites> {
    let mut result = ReviewWrites {
        created: 0,
        existing: 0,
        record_refs: Vec::new(),
    };
    let mut items = items.to_vec();
    sort(&mut items);
    for item in items.iter().filter(|item| item.overdue) {
        let key = key(item.scope, &item.assessment, &item.trigger, item.due_at);
        if let Some(existing) = store.view().review_by_key(&key) {
            result.existing += 1;
            result.record_refs.push(existing);
            continue;
        }
        let review = ReviewRecord {
            scope: item.scope,
            trigger: item.trigger.clone(),
            assessment: item.assessment.clone(),
            opened_at: now,
            due_at: item.due_at,
            status: ReviewStatus::Open,
            completed_at: None,
            reasons: "Review required by the recorded cause and assessment deadline.".into(),
        };
        let record = RecordEnvelope {
            format_version: 1,
            id: key,
            version: 1,
            kind: RecordKind::Review,
            completed_at: now,
            supersedes: None,
            body: RecordBody::Review(review),
        };
        let (reference, _) = store.add(record, actor)?;
        result.created += 1;
        result.record_refs.push(reference);
    }
    Ok(result)
}
