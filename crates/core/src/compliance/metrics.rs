//! Computes integer monthly aggregates from one verified committed ticket prefix.
//! Receipt fixes cohort membership; only completed operations contribute effective protections.
//! Payloads and serving snapshots are never opened, so purge cannot erase aggregate source facts.

#![deny(missing_docs)]

use super::{
    clock,
    journal::{view::CommittedJournal, EventName, JournalRow},
    model::{Route, TicketId},
    record_types::{
        require, ActionCount, ActionKind, ClauseCount, Durations, IntimateCounts, MonthlyMetrics,
        RecordBody, RecordEnvelope, RecordKind, RecordRef, RouteCount,
    },
    records::RecordStore,
    transitions, Error, Result,
};
use crate::config::compliance::ValidatedComplianceConfig;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Parses a strict four-digit UTC month and verifies that its successor is representable.
pub fn month_start(month: &str) -> Result<i64> {
    require(
        month.len() == 7
            && month.as_bytes()[4] == b'-'
            && month
                .bytes()
                .enumerate()
                .all(|(at, byte)| at == 4 || byte.is_ascii_digit()),
    )?;
    let year = month[..4].parse::<i32>().map_err(|_| Error::InvalidInput)?;
    let number = month[5..].parse::<u32>().map_err(|_| Error::InvalidInput)?;
    let start = chrono::NaiveDate::from_ymd_opt(year, number, 1)
        .and_then(|day| day.and_hms_opt(0, 0, 0))
        .ok_or(Error::InvalidInput)?
        .and_utc()
        .timestamp();
    clock::instant(start)?;
    clock::add_months(start, 1)?;
    Ok(start)
}

fn in_month(received_at: i64, start: i64, end: i64) -> bool {
    received_at >= start && received_at < end
}

/// Computes nearest-rank median and p95 using checked integer arithmetic, with null empty ranks.
pub fn durations(mut seconds: Vec<u64>) -> Result<Durations> {
    seconds.sort_unstable();
    let n = u64::try_from(seconds.len()).map_err(|_| Error::Capacity)?;
    Ok(Durations {
        n,
        median: rank(&seconds, 50)?,
        p95: rank(&seconds, 95)?,
    })
}

fn rank(seconds: &[u64], percent: u64) -> Result<Option<u64>> {
    if seconds.is_empty() {
        return Ok(None);
    }
    let n = u64::try_from(seconds.len()).map_err(|_| Error::Capacity)?;
    let product = percent.checked_mul(n).ok_or(Error::Capacity)?;
    let one_based = product.div_ceil(100);
    let index = usize::try_from(one_based.checked_sub(1).ok_or(Error::InvalidInput)?)
        .map_err(|_| Error::Capacity)?;
    seconds
        .get(index)
        .copied()
        .map(Some)
        .ok_or(Error::InvalidInput)
}

struct TicketProjection {
    received_at: i64,
    route: Route,
    first_acknowledged_at: Option<i64>,
    first_decided_at: Option<i64>,
    actions: Vec<(i64, ActionKind)>,
    determination_at: Option<i64>,
    reversals: u64,
    unfounded: Option<(String, String)>,
}

fn project(snapshot: &CommittedJournal) -> Result<BTreeMap<String, TicketProjection>> {
    let mut tickets = snapshot
        .tickets()
        .iter()
        .map(|(id, ticket)| {
            (
                id.as_str().to_owned(),
                TicketProjection {
                    received_at: ticket.times.received_at,
                    route: ticket.route,
                    first_acknowledged_at: None,
                    first_decided_at: None,
                    actions: Vec::new(),
                    determination_at: None,
                    reversals: 0,
                    unfounded: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut intents = BTreeMap::new();
    for row in &snapshot.rows {
        let Some(ticket) = tickets.get_mut(&row.ticket_id) else {
            continue;
        };
        match row.event {
            EventName::Acknowledged => {
                ticket.first_acknowledged_at.get_or_insert(row.at);
            }
            EventName::Decided => {
                ticket.first_decided_at.get_or_insert(row.at);
                if row.decision == "manifestly_unfounded" && ticket.unfounded.is_none() {
                    ticket.unfounded = Some((row.policy_version.clone(), row.reason_code.clone()));
                }
            }
            EventName::ActionIntent => {
                intents.insert(row.sequence, row);
            }
            EventName::RulesCommitted | EventName::Actioned => {
                let intent = intents
                    .get(&row.intent_sequence)
                    .ok_or(Error::Unavailable)?;
                completed(ticket, intent, row, snapshot.observed_at)?;
            }
            EventName::Reversed => increment(&mut ticket.reversals)?,
            _ => {}
        }
    }
    Ok(tickets)
}

fn completed(
    ticket: &mut TicketProjection,
    intent: &JournalRow,
    row: &JournalRow,
    observed_at: i64,
) -> Result<()> {
    if matches!(
        intent.decision.as_str(),
        "not_intimate_image" | "no_standing"
    ) {
        ticket.determination_at.get_or_insert(row.at);
    } else if intent.decision.is_empty() || intent.decision == "granted" {
        let effective_at = intent.effective_at;
        if effective_at <= observed_at {
            let kind = if intent.reason_code == "data_delisting" {
                ActionKind::NameDelisting
            } else {
                ActionKind::GlobalDeindex
            };
            ticket.actions.push((effective_at, kind));
        }
    }
    Ok(())
}

fn increment(value: &mut u64) -> Result<()> {
    *value = value.checked_add(1).ok_or(Error::Capacity)?;
    Ok(())
}

fn latency(target: &mut Vec<u64>, receipt: i64, at: Option<i64>) -> Result<()> {
    if let Some(at) = at {
        let elapsed = at.checked_sub(receipt).ok_or(Error::Unavailable)?;
        target.push(u64::try_from(elapsed).map_err(|_| Error::Unavailable)?);
    }
    Ok(())
}

fn intimate(ticket: &TicketProjection, at: i64, counts: &mut IntimateCounts) -> Result<()> {
    let deadline = clock::intimate_due(ticket.received_at)?;
    if let Some(determination_at) = ticket.determination_at {
        if determination_at <= deadline {
            increment(&mut counts.exempt)?;
            return Ok(());
        }
    }
    if deadline <= at {
        increment(&mut counts.due)?;
        let timely = ticket
            .actions
            .first()
            .map(|(at, _)| clock::intimate_on_time(ticket.received_at, *at))
            .transpose()?
            .unwrap_or(false);
        increment(if timely {
            &mut counts.met
        } else {
            &mut counts.missed
        })?;
    } else {
        increment(&mut counts.pending)?;
    }
    Ok(())
}

/// Produces a complete ordered aggregate from the captured observation time and committed head.
pub fn monthly(snapshot: &CommittedJournal, month: &str) -> Result<MonthlyMetrics> {
    let start = month_start(month)?;
    let end = clock::add_months(start, 1)?;
    let mut result = empty(month, snapshot);
    let (mut acks, mut decisions, mut actions) = (Vec::new(), Vec::new(), Vec::new());
    let mut clauses = BTreeMap::new();
    let mut counted_original: BTreeSet<String> = BTreeSet::new();
    for (ticket_id, mut ticket) in project(snapshot)? {
        if !in_month(ticket.received_at, start, end) {
            continue;
        }
        let route = result
            .counts_by_route
            .iter_mut()
            .find(|row| row.route == ticket.route)
            .ok_or(Error::Unavailable)?;
        increment(&mut route.count)?;
        latency(&mut acks, ticket.received_at, ticket.first_acknowledged_at)?;
        latency(&mut decisions, ticket.received_at, ticket.first_decided_at)?;
        ticket.actions.sort_by_key(|(at, kind)| (*at, *kind));
        for (at, kind) in &ticket.actions {
            if counted_original.insert(ticket_id.clone()) {
                latency(&mut actions, ticket.received_at, Some(*at))?;
                let action = result
                    .actions_by_type
                    .iter_mut()
                    .find(|row| row.kind == *kind)
                    .ok_or(Error::Unavailable)?;
                increment(&mut action.count)?;
            }
        }
        result.reversals = result
            .reversals
            .checked_add(ticket.reversals)
            .ok_or(Error::Capacity)?;
        if ticket.route == Route::IntimateImages {
            intimate(&ticket, snapshot.observed_at, &mut result.intimate)?;
        }
        if let Some(clause) = ticket.unfounded {
            increment(clauses.entry(clause).or_default())?;
        }
    }
    result.ack_seconds = durations(acks)?;
    result.decision_seconds = durations(decisions)?;
    result.action_seconds = durations(actions)?;
    result.unfounded_by_clause = clauses
        .into_iter()
        .map(|((policy_version, policy_clause), count)| ClauseCount {
            policy_version,
            policy_clause,
            count,
        })
        .collect();
    result.validate(snapshot.observed_at)?;
    Ok(result)
}

fn empty(month: &str, snapshot: &CommittedJournal) -> MonthlyMetrics {
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
    let absent = || Durations {
        n: 0,
        median: None,
        p95: None,
    };
    MonthlyMetrics {
        month: month.into(),
        as_of_sequence: snapshot.sequence,
        generated_at: snapshot.observed_at,
        counts_by_route: routes
            .into_iter()
            .map(|route| RouteCount { route, count: 0 })
            .collect(),
        ack_seconds: absent(),
        decision_seconds: absent(),
        action_seconds: absent(),
        actions_by_type: [ActionKind::GlobalDeindex, ActionKind::NameDelisting]
            .into_iter()
            .map(|kind| ActionCount { kind, count: 0 })
            .collect(),
        reversals: 0,
        intimate: IntimateCounts {
            due: 0,
            met: 0,
            missed: 0,
            pending: 0,
            exempt: 0,
        },
        unfounded_by_clause: Vec::new(),
    }
}

/// Retains each requested cutoff as the next immutable version for its month.
pub fn persist(
    store: &mut RecordStore,
    snapshot: &CommittedJournal,
    month: &str,
    actor: &str,
) -> Result<RecordRef> {
    let metrics = monthly(snapshot, month)?;
    let id = format!("metrics.{month}");
    let previous = store.view().latest(&id).map(RecordEnvelope::reference);
    let version = previous
        .as_ref()
        .map_or(Some(1), |reference| reference.version.checked_add(1))
        .ok_or(Error::Capacity)?;
    let (reference, _) = store.add(
        RecordEnvelope {
            format_version: 1,
            id,
            version,
            kind: RecordKind::Metrics,
            completed_at: metrics.generated_at,
            supersedes: previous,
            body: RecordBody::Metrics(metrics),
        },
        actor,
    )?;
    Ok(reference)
}

/// One eligible payload deletion, without private payload or audit hash contents.
#[derive(Clone, Serialize)]
pub struct RetentionItem {
    /// Capability usable only by the separate authenticated purge surface.
    pub ticket_id: TicketId,
    /// Immutable closure UTC second.
    pub closed_at: i64,
    /// Inclusive configured calendar threshold.
    pub eligible_at: i64,
}

/// Read-only, sorted equivalent of the management purge-due queue over a captured prefix.
pub fn retention_due(
    snapshot: &CommittedJournal,
    config: &ValidatedComplianceConfig,
) -> Result<Vec<RetentionItem>> {
    let mut items = Vec::new();
    for (id, ticket) in snapshot.tickets() {
        if transitions::purge_due(ticket, snapshot.observed_at, config)? {
            let closed_at = ticket.times.closed_at.ok_or(Error::Unavailable)?;
            items.push(RetentionItem {
                ticket_id: id.clone(),
                closed_at,
                eligible_at: clock::retention_due(closed_at, config.settings().retention_months)?,
            });
        }
    }
    Ok(items)
}
