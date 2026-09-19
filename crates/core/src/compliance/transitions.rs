//! Defines the closed ticket lifecycle and pure statutory eligibility guards.
//! Both admission and replay use this reducer; no caller can assign an arbitrary state.

#![deny(missing_docs)]

use super::{
    clock,
    journal::{EventName, JournalRow},
    model::{
        Decision, DecisionKind, Ground, IdentityEvent, RequesterType, Route, TicketId, TicketState,
    },
    Error, Result,
};
use crate::config::compliance::ValidatedComplianceConfig;
use serde::Serialize;
use std::collections::BTreeMap;

/// Publicly disclosable lifecycle instants; absent milestones remain null.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct Milestones {
    /// Immutable receipt of the validated complete intake.
    pub received_at: i64,
    /// Durable preparation of acknowledgement, not proof of receipt by its addressee.
    pub acknowledged_at: Option<i64>,
    /// Most recent evidence request.
    pub identity_pending_at: Option<i64>,
    /// Most recent entry into the review queue.
    pub queued_at: Option<i64>,
    /// Reviewed outcome recorded.
    pub decided_at: Option<i64>,
    /// Durable completion of the original serving-rule grant.
    pub actioned_at: Option<i64>,
    /// Original decision appealed.
    pub appealed_at: Option<i64>,
    /// Durable reversal and marker completion.
    pub reversed_at: Option<i64>,
    /// Reasoned appeal disposal upholding the outcome.
    pub upheld_at: Option<i64>,
    /// Final closure from which payload retention runs.
    pub closed_at: Option<i64>,
}

/// Nonpersonal projection rebuilt exclusively from the verified journal.
#[derive(Clone)]
pub struct Ticket {
    /// Capability used internally and on authenticated surfaces.
    pub id: TicketId,
    /// Category fixed by the intake endpoint.
    pub route: Route,
    /// Reporter role claim, fixed at receipt.
    pub requester: RequesterType,
    /// Current closed lifecycle state.
    pub state: TicketState,
    /// Only milestone data is disclosed through the public capability.
    pub times: Milestones,
    /// Current data-rights deadline origin, independent of immutable receipt.
    pub relevant_at: i64,
    /// Evidence request that a matching reply must satisfy.
    pub pending_evidence: Option<IdentityEvent>,
    /// Relevant-time epoch extended by a timely notice, if any.
    pub extended_epoch: Option<i64>,
    /// Durable reviewed disposition, retained through appeal and closure.
    pub decision: Option<DecisionKind>,
    /// Ground of the original reviewed action, if any.
    pub ground: Option<Ground>,
    /// Unfinished durable operation, reconciled before any projection is exposed.
    pub pending: Option<JournalRow>,
    /// Whether this intake's provisional intimate rule transaction completed before acknowledgement.
    pub provisional_committed: bool,
    /// All personal revisions and their journal commitments.
    pub references: BTreeMap<u64, String>,
    /// Whether a completed purge authorizes permanently absent personal files.
    pub purged: bool,
    /// Lifetime event count, including purge and recovery rows.
    pub events: u64,
    /// Last durable event instant for this ticket.
    pub last_at: i64,
}

/// Returns the sole allowed successor for a state/event pair, before contextual guards.
pub fn successor(state: TicketState, event: EventName) -> Result<TicketState> {
    use EventName as E;
    use TicketState as S;
    let next = match (state, event) {
        (S::Received, E::Acknowledged) => Some(S::Acknowledged),
        (S::Acknowledged, E::Queued) => Some(S::Queued),
        (S::Queued, E::IdentityRequested | E::ClarificationRequested) => Some(S::IdentityPending),
        (S::IdentityPending, E::IdentityConfirmed | E::ClarificationReceived) => Some(S::Queued),
        (S::Queued, E::Decided) => Some(S::Decided),
        (S::Decided, E::Actioned) => Some(S::Actioned),
        (S::Actioned | S::Decided, E::Appealed) => Some(S::Appealed),
        (S::Appealed, E::Reversed) => Some(S::Reversed),
        (S::Appealed, E::Upheld) => Some(S::Upheld),
        (S::Decided | S::Actioned | S::Reversed | S::Upheld, E::Closed) => Some(S::Closed),
        (S::Queued | S::IdentityPending, E::ExtensionNotified) => Some(state),
        (
            S::Queued | S::IdentityPending | S::Decided | S::Actioned | S::Appealed,
            E::ProgressCommunicated,
        ) => Some(state),
        (S::Closed, E::PurgeIntent | E::Purged) => Some(state),
        (S::Received | S::Decided, E::ActionIntent | E::RulesCommitted) => Some(state),
        (S::Appealed, E::ReversalIntent) => Some(state),
        _ => None,
    };
    next.ok_or(Error::InvalidTransition)
}

/// Checks the original-month notice window; equality is timely.
pub fn extension_window(relevant_at: i64, now: i64) -> Result<bool> {
    Ok(now >= relevant_at && now <= clock::data_rights_due(relevant_at, false)?)
}

/// Requires the closed lifecycle, no pending work, and the inclusive calendar retention threshold.
pub fn purge_due(ticket: &Ticket, now: i64, config: &ValidatedComplianceConfig) -> Result<bool> {
    if successor(ticket.state, EventName::PurgeIntent).is_err()
        || ticket.pending.is_some()
        || ticket.purged
    {
        return Ok(false);
    }
    clock::retention_elapsed(
        ticket.times.closed_at.ok_or(Error::Unavailable)?,
        config.settings().retention_months,
        now,
    )
}

/// Computes the applicable deadline without changing the relevant-time epoch.
pub fn deadline(ticket: &Ticket) -> Result<Option<i64>> {
    match ticket.route {
        Route::IntimateImages => clock::intimate_due(ticket.times.received_at).map(Some),
        Route::DataRights => clock::data_rights_due(
            ticket.relevant_at,
            ticket.extended_epoch == Some(ticket.relevant_at),
        )
        .map(Some),
        Route::DataProtectionComplaint => {
            clock::complaint_ack_due(ticket.times.received_at).map(Some)
        }
        _ => Ok(None),
    }
}

/// Reports queue age against the applicable deadline using one captured observation time.
/// This does not retrospectively judge an already acknowledged complaint's timeliness.
pub fn queue_overdue(ticket: &Ticket, now: i64) -> Result<bool> {
    match ticket.route {
        Route::IntimateImages => Ok(!clock::intimate_on_time(ticket.times.received_at, now)?),
        Route::DataRights => clock::data_rights_overdue(
            ticket.relevant_at,
            ticket.extended_epoch == Some(ticket.relevant_at),
            now,
        ),
        Route::DataProtectionComplaint => Ok(!clock::complaint_ack_on_time(
            ticket.times.received_at,
            now,
        )?),
        _ => Ok(false),
    }
}

/// Validates reviewed route semantics, including assessment and concluded-complaint eligibility.
pub fn decision_allowed(
    ticket: &Ticket,
    decision: &Decision,
    ground: Option<Ground>,
    tickets: &BTreeMap<TicketId, Ticket>,
    config: &ValidatedComplianceConfig,
) -> Result<()> {
    successor(ticket.state, EventName::Decided)?;
    decision.validate()?;
    let eligible = match decision {
        Decision::NotIntimateImage { .. } | Decision::NoStanding { .. } => {
            ticket.route == Route::IntimateImages
        }
        Decision::ManifestlyUnfounded { .. } => matches!(
            ticket.route,
            Route::SiteComplaint | Route::DataProtectionComplaint | Route::OnlineSafetyComplaint
        ),
        _ => true,
    };
    if !eligible {
        return Err(Error::InvalidInput);
    }
    if let Decision::Granted { assessment, .. } = decision {
        if assessment.is_some() != (ground == Some(Ground::DataDelisting)) {
            return Err(Error::InvalidInput);
        }
    }
    if let Decision::ManifestlyUnfounded {
        policy_version,
        policy_clause,
        duplicate_of,
        ..
    } = decision
    {
        if policy_version != &config.settings().unfounded_policy_version
            || policy_clause != "duplicate_without_new_information"
        {
            return Err(Error::InvalidInput);
        }
        if !tickets
            .get(duplicate_of)
            .is_some_and(|prior| prior.state == TicketState::Closed && prior.route == ticket.route)
        {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

impl Ticket {
    /// Starts replay from an already verified receipt row; subsequent rows use the same reducer.
    pub fn received(row: &JournalRow) -> Result<Self> {
        if row.event != EventName::Received || row.state != "received" || row.payload_sequence != 1
        {
            return Err(Error::Unavailable);
        }
        Ok(Self {
            id: TicketId::parse(&row.ticket_id)?,
            route: Route::parse(&row.route)?,
            requester: RequesterType::parse(&row.requester_type)?,
            state: TicketState::Received,
            times: Milestones {
                received_at: row.received_at,
                ..Milestones::default()
            },
            relevant_at: row.received_at,
            pending_evidence: None,
            extended_epoch: None,
            decision: None,
            ground: None,
            pending: None,
            provisional_committed: false,
            references: BTreeMap::from([(1, row.commitment.clone())]),
            purged: false,
            events: 1,
            last_at: row.at,
        })
    }

    /// Reduces one already verified row with the same guards used during live admission.
    pub fn apply(&mut self, row: &JournalRow, config: &ValidatedComplianceConfig) -> Result<()> {
        let next = successor(self.state, row.event)?;
        if row.ticket_id != self.id.as_str()
            || row.route != self.route.as_str()
            || row.requester_type != self.requester.as_str()
            || row.received_at != self.times.received_at
            || row.state != next.as_str()
            || row.at < self.last_at
            || self.purged
        {
            return Err(Error::InvalidTransition);
        }
        self.guard(row, config)?;
        self.evidence(row)?;
        self.operation(row)?;
        if row.event == EventName::Decided {
            self.decision = Some(DecisionKind::parse(&row.decision)?);
            self.ground = Ground::parse(&row.reason_code).ok();
        }
        if row.event == EventName::ExtensionNotified {
            self.extended_epoch = Some(self.relevant_at);
        }
        self.record_reference(row)?;
        self.milestone(row);
        self.state = next;
        self.events = self.events.checked_add(1).ok_or(Error::Capacity)?;
        self.last_at = row.at;
        Ok(())
    }

    fn guard(&self, row: &JournalRow, config: &ValidatedComplianceConfig) -> Result<()> {
        use EventName as E;
        let completion = matches!(
            row.event,
            E::RulesCommitted | E::Actioned | E::Reversed | E::Purged
        );
        if self.pending.is_some() && !completion {
            return Err(Error::InvalidTransition);
        }
        if row.event == E::Acknowledged
            && self.route == Route::IntimateImages
            && !self.provisional_committed
        {
            return Err(Error::InvalidTransition);
        }
        if row.event == E::ActionIntent {
            let intake = self.state == TicketState::Received
                && self.route == Route::IntimateImages
                && row.decision.is_empty();
            let reviewed = self.state == TicketState::Decided
                && self.decision.is_some_and(|decision| {
                    row.decision == decision.as_str()
                        && matches!(
                            decision,
                            DecisionKind::Granted
                                | DecisionKind::NotIntimateImage
                                | DecisionKind::NoStanding
                        )
                });
            if (!intake && !reviewed)
                || Ground::parse(&row.reason_code).is_err()
                || row.asset_ids.is_empty()
                || row.effective_at < self.times.received_at
            {
                return Err(Error::InvalidTransition);
            }
        }
        if row.event == E::ExtensionNotified
            && (self.route != Route::DataRights
                || self.extended_epoch == Some(self.relevant_at)
                || !extension_window(self.relevant_at, row.at)?)
        {
            return Err(Error::InvalidTransition);
        }
        if row.event == E::PurgeIntent && !purge_due(self, row.at, config)? {
            return Err(Error::RetentionNotDue);
        }
        if row.event == E::Closed
            && self.state == TicketState::Decided
            && self.decision == Some(DecisionKind::Granted)
            && self.ground.is_some()
        {
            return Err(Error::InvalidTransition);
        }
        if matches!(row.event, E::ReversalIntent | E::Reversed | E::Actioned)
            && (self.decision != Some(DecisionKind::Granted) || self.ground.is_none())
        {
            return Err(Error::InvalidTransition);
        }
        Ok(())
    }

    fn evidence(&mut self, row: &JournalRow) -> Result<()> {
        use EventName as E;
        use IdentityEvent as I;
        let request = match row.event {
            E::IdentityRequested => Some(I::RequestIdentity),
            E::ClarificationRequested => Some(I::RequestClarification),
            _ => None,
        };
        let reply = match row.event {
            E::IdentityConfirmed => Some(I::RequestIdentity),
            E::ClarificationReceived => Some(I::RequestClarification),
            _ => None,
        };
        if (request.is_some() || reply.is_some()) && self.route != Route::DataRights {
            return Err(Error::InvalidTransition);
        }
        if let Some(request) = request {
            self.pending_evidence = Some(request);
        }
        if let Some(expected) = reply {
            if self.pending_evidence != Some(expected) {
                return Err(Error::InvalidTransition);
            }
            self.relevant_at = self.relevant_at.max(row.at);
            self.pending_evidence = None;
        }
        Ok(())
    }

    fn operation(&mut self, row: &JournalRow) -> Result<()> {
        use EventName as E;
        if matches!(
            row.event,
            E::ActionIntent | E::ReversalIntent | E::PurgeIntent
        ) {
            if self.pending.is_some() || row.intent_sequence != row.sequence {
                return Err(Error::InvalidTransition);
            }
            self.pending = Some(row.clone());
        } else if matches!(
            row.event,
            E::RulesCommitted | E::Actioned | E::Reversed | E::Purged
        ) {
            let intent = self.pending.as_ref().ok_or(Error::InvalidTransition)?;
            let expected = match intent.event {
                E::ReversalIntent => E::Reversed,
                E::PurgeIntent => E::Purged,
                E::ActionIntent if intent.decision == "granted" => E::Actioned,
                E::ActionIntent => E::RulesCommitted,
                _ => return Err(Error::InvalidTransition),
            };
            if row.event != expected
                || row.intent_sequence != intent.sequence
                || row.reason_code != intent.reason_code
                || row.asset_ids != intent.asset_ids
                || row.effective_at != intent.effective_at
                || row.decision != intent.decision
            {
                return Err(Error::InvalidTransition);
            }
            self.pending = None;
            self.purged = row.event == E::Purged;
            if row.event == E::RulesCommitted && row.decision.is_empty() {
                self.provisional_committed = true;
            }
        }
        Ok(())
    }

    fn record_reference(&mut self, row: &JournalRow) -> Result<()> {
        if row.payload_sequence == 0 {
            return Ok(());
        }
        if let Some(expected) = self.references.get(&row.payload_sequence) {
            if expected != &row.commitment || row.event != EventName::ActionIntent {
                return Err(Error::Unavailable);
            }
        } else {
            if row.payload_sequence != self.references.len() as u64 + 1 {
                return Err(Error::Unavailable);
            }
            self.references
                .insert(row.payload_sequence, row.commitment.clone());
        }
        Ok(())
    }

    fn milestone(&mut self, row: &JournalRow) {
        use EventName as E;
        let slot = match row.event {
            E::Acknowledged => &mut self.times.acknowledged_at,
            E::IdentityRequested | E::ClarificationRequested => &mut self.times.identity_pending_at,
            E::Queued | E::IdentityConfirmed | E::ClarificationReceived => {
                &mut self.times.queued_at
            }
            E::Decided => &mut self.times.decided_at,
            E::Actioned => &mut self.times.actioned_at,
            E::Appealed => &mut self.times.appealed_at,
            E::Reversed => &mut self.times.reversed_at,
            E::Upheld => &mut self.times.upheld_at,
            E::Closed => &mut self.times.closed_at,
            _ => return,
        };
        *slot = Some(row.at);
    }
}
