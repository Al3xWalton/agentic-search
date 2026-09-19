//! Rebuilds ticket projections from verified history and finishes idempotent durable operations.
//! Startup completes reconciliation before binding listeners; it never invents a human decision.

#![deny(missing_docs)]

use super::{
    clock,
    disk::ComplianceStage,
    journal::{EventName, JournalRow},
    model::{DecisionKind, Ground, Hex64, Intake, Route, TicketId, TicketState},
    payload::PersonalEvent,
    rules::RulesSnapshot,
    tickets::{self, Case, Plan},
    transitions::Ticket,
    Error, Result,
};
use std::collections::{BTreeMap, BTreeSet};

struct VerifiedPayloads {
    intakes: BTreeMap<TicketId, Intake>,
    lengths: BTreeMap<(TicketId, u64), u64>,
}
impl VerifiedPayloads {
    fn intake(&self, id: &TicketId) -> Result<&Intake> {
        self.intakes.get(id).ok_or(Error::Unavailable)
    }

    fn personal(
        &self,
        case: &Case,
        id: &TicketId,
        sequence: u64,
        expected: &str,
    ) -> Result<PersonalEvent> {
        if sequence != 1 {
            return case.payloads.read(id, sequence, expected);
        }
        let ticket = case.tickets.get(id).ok_or(Error::Unavailable)?;
        if ticket.references.get(&1).map(String::as_str) != Some(expected) {
            return Err(Error::Unavailable);
        }
        Ok(PersonalEvent::Intake {
            intake: self.intake(id)?.clone(),
        })
    }
}

pub(crate) fn reconcile(case: &mut Case) -> Result<()> {
    rebuild(case)?;
    let verified = verify_payloads(case)?;
    let rules_at_open = case.rules.snapshot()?;
    let referenced = case
        .tickets
        .values()
        .flat_map(|ticket| {
            ticket
                .references
                .keys()
                .map(|sequence| (ticket.id.clone(), *sequence))
        })
        .collect::<BTreeSet<_>>();
    case.usage = case
        .payloads
        .inventory(&referenced, &verified.lengths, true)?;
    let mut total = 0u64;
    for bytes in case.usage.values() {
        super::bounds::BoundKey::TicketPayload.validate(*bytes)?;
        total = total.checked_add(*bytes).ok_or(Error::Unavailable)?;
    }
    super::bounds::reserve(0, total, case.config.settings().max_payload_bytes, 0)?;
    let tickets = case.tickets.values().cloned().collect::<Vec<_>>();
    for ticket in tickets {
        if ticket.pending.is_some() {
            finish_pending(case, &ticket, &verified, &rules_at_open)?;
        } else {
            verify_completed(case, &ticket, &verified, &rules_at_open)?;
        }
        let current = case
            .tickets
            .get(&ticket.id)
            .cloned()
            .ok_or(Error::Unavailable)?;
        if matches!(
            current.state,
            TicketState::Received | TicketState::Acknowledged
        ) {
            finish_intake(case, &current, &verified)?;
        } else if current.state == TicketState::Decided {
            finish_decision(case, &current, &verified)?;
        }
    }
    case.journal.finish_recovery()
}

fn rebuild(case: &mut Case) -> Result<()> {
    for row in case.journal.rows() {
        if row.ticket_id.is_empty() {
            continue;
        }
        let id = TicketId::parse(&row.ticket_id)?;
        if row.event == EventName::Received {
            if case.tickets.insert(id, Ticket::received(row)?).is_some() {
                return Err(Error::Unavailable);
            }
        } else {
            case.tickets
                .get_mut(&id)
                .ok_or(Error::Unavailable)?
                .apply(row, &case.config)?;
        }
    }
    super::bounds::reserve(
        0,
        case.tickets.len() as u64,
        case.config.settings().max_tickets,
        0,
    )?;
    for ticket in case.tickets.values() {
        super::bounds::reserve(
            0,
            ticket.events,
            case.config.settings().max_ticket_events,
            0,
        )?;
    }
    Ok(())
}

fn verify_payloads(case: &Case) -> Result<VerifiedPayloads> {
    let mut verified = VerifiedPayloads {
        intakes: BTreeMap::new(),
        lengths: BTreeMap::new(),
    };
    for ticket in case.tickets.values() {
        let authorized = ticket.purged
            || ticket
                .pending
                .as_ref()
                .is_some_and(|row| row.event == EventName::PurgeIntent);
        for (sequence, expected) in &ticket.references {
            if let Some((content, length)) = case
                .payloads
                .read_authorized_measured(&ticket.id, *sequence, expected, authorized)?
            {
                verified
                    .lengths
                    .insert((ticket.id.clone(), *sequence), length);
                if *sequence == 1 {
                    let PersonalEvent::Intake { intake } = content else {
                        return Err(Error::Unavailable);
                    };
                    verified.intakes.insert(ticket.id.clone(), intake);
                }
            }
        }
        if !authorized {
            let intake = verified.intake(&ticket.id)?;
            if intake.route() != ticket.route || intake.report.requester_type != ticket.requester {
                return Err(Error::Unavailable);
            }
        }
    }
    let mut history = std::collections::BTreeMap::new();
    for row in case
        .journal
        .rows()
        .iter()
        .filter(|row| !row.ticket_id.is_empty())
    {
        let id = TicketId::parse(&row.ticket_id)?;
        let final_ticket = case.tickets.get(&id).ok_or(Error::Unavailable)?;
        let authorized = final_ticket.purged
            || final_ticket
                .pending
                .as_ref()
                .is_some_and(|row| row.event == EventName::PurgeIntent);
        if !authorized {
            verify_personal_row(
                case,
                row,
                verified.intake(&final_ticket.id)?,
                &history,
                &verified,
            )?;
        }
        if row.event == EventName::Received {
            history.insert(id, Ticket::received(row)?);
        } else {
            history
                .get_mut(&id)
                .ok_or(Error::Unavailable)?
                .apply(row, &case.config)?;
        }
    }
    Ok(verified)
}

fn verify_personal_row(
    case: &Case,
    row: &JournalRow,
    intake: &Intake,
    history: &std::collections::BTreeMap<TicketId, Ticket>,
    verified: &VerifiedPayloads,
) -> Result<()> {
    use EventName as E;
    if row.payload_sequence == 0 {
        if matches!(
            row.event,
            E::Received
                | E::Decided
                | E::IdentityRequested
                | E::IdentityConfirmed
                | E::ClarificationRequested
                | E::ClarificationReceived
                | E::ExtensionNotified
                | E::Appealed
                | E::ReversalIntent
                | E::Upheld
                | E::ProgressCommunicated
                | E::Closed
        ) {
            return Err(Error::Unavailable);
        }
        return Ok(());
    }
    let content = verified.personal(
        case,
        &TicketId::parse(&row.ticket_id)?,
        row.payload_sequence,
        &row.commitment,
    )?;
    let expected = match &content {
        PersonalEvent::Intake { .. } => E::Received,
        PersonalEvent::Identity { event, .. } => match event {
            super::model::IdentityEvent::RequestIdentity => E::IdentityRequested,
            super::model::IdentityEvent::IdentityConfirmed => E::IdentityConfirmed,
            super::model::IdentityEvent::RequestClarification => E::ClarificationRequested,
            super::model::IdentityEvent::ClarificationReceived => E::ClarificationReceived,
        },
        PersonalEvent::Extension { .. } => E::ExtensionNotified,
        PersonalEvent::Decision {
            decision,
            name_rule_salts,
            notice,
        } => {
            if row.decision != decision.kind().as_str() {
                return Err(Error::Unavailable);
            }
            if row.event == E::Decided {
                let before = history
                    .get(&TicketId::parse(&row.ticket_id)?)
                    .ok_or(Error::Unavailable)?;
                super::transitions::decision_allowed(
                    before,
                    decision,
                    intake.ground(),
                    history,
                    &case.config,
                )?;
            }
            tickets::verify_decision_notice(decision, notice)?;
            let names_required = decision.kind() == DecisionKind::Granted
                && intake.ground() == Some(Ground::DataDelisting);
            if name_rule_salts.len()
                != if names_required {
                    intake.names().len()
                } else {
                    0
                }
            {
                return Err(Error::Unavailable);
            }
            E::Decided
        }
        PersonalEvent::Appeal { .. } => E::Appealed,
        PersonalEvent::Reversal { .. } => E::ReversalIntent,
        PersonalEvent::Uphold { .. } => E::Upheld,
        PersonalEvent::Progress { .. } => E::ProgressCommunicated,
        PersonalEvent::Closure { .. } => E::Closed,
    };
    if row.event != expected
        && !(row.event == E::ActionIntent && matches!(expected, E::Received | E::Decided))
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn operation(
    case: &Case,
    ticket: &Ticket,
    intent: &JournalRow,
    verified: &VerifiedPayloads,
) -> Result<super::rules::RuleDelta> {
    let intake = verified.intake(&ticket.id)?;
    let salts: Vec<Hex64> = match verified.personal(
        case,
        &ticket.id,
        intent.payload_sequence,
        &intent.commitment,
    )? {
        PersonalEvent::Decision {
            name_rule_salts, ..
        } => name_rule_salts,
        PersonalEvent::Intake { .. } | PersonalEvent::Reversal { .. } => Vec::new(),
        _ => return Err(Error::Unavailable),
    };
    tickets::delta(intent, intake, &salts)
}

fn finish_pending(
    case: &mut Case,
    ticket: &Ticket,
    verified: &VerifiedPayloads,
    rules_at_open: &RulesSnapshot,
) -> Result<()> {
    let intent = ticket.pending.as_ref().ok_or(Error::Unavailable)?;
    if intent.event == EventName::PurgeIntent {
        case.payloads.purge(&ticket.id, &ticket.references)?;
        case.usage.insert(ticket.id.clone(), 0);
    } else {
        let delta = operation(case, ticket, intent, verified)?;
        if !rules_at_open.verifies(&delta) {
            let prepared = case.rules.prepare_delta(&delta)?;
            case.rules.commit(prepared)?;
        }
        case.hooks
            .at(ComplianceStage::AfterRulesSync)
            .map_err(|_| Error::Unavailable)?;
    }
    let done = tickets::completion(
        ticket,
        intent,
        case.clock.utc().timestamp(),
        "system.recovery",
    )?;
    case.execute_plan(Plan {
        rows: vec![done],
        payload: None,
        rules: None,
        purge: false,
        reserved: true,
    })
}

fn finish_decision(case: &mut Case, ticket: &Ticket, verified: &VerifiedPayloads) -> Result<()> {
    let Some(decided) = case
        .journal
        .rows()
        .iter()
        .rev()
        .find(|row| row.ticket_id == ticket.id.as_str() && row.event == EventName::Decided)
        .cloned()
    else {
        return Err(Error::Unavailable);
    };
    if decided.reason_code.is_empty()
        || !matches!(
            decided.decision.as_str(),
            "granted" | "not_intimate_image" | "no_standing"
        )
        || case.journal.rows().iter().any(|row| {
            row.ticket_id == ticket.id.as_str()
                && row.event == EventName::ActionIntent
                && row.sequence > decided.sequence
        })
    {
        return Ok(());
    }
    let intake = verified.intake(&ticket.id)?;
    let mut intent = decided.clone();
    intent.event = EventName::ActionIntent;
    intent.actor = "system.recovery".into();
    intent.at = case.clock.utc().timestamp();
    intent.intent_sequence = case
        .journal
        .sequence()
        .checked_add(1)
        .ok_or(Error::Capacity)?;
    intent.asset_ids = tickets::documents(intake);
    intent.effective_at = decided.at;
    let prepared = case
        .rules
        .prepare_delta(&operation(case, ticket, &intent, verified)?)?;
    let done = tickets::completion(ticket, &intent, intent.at, "system.recovery")?;
    case.execute_plan(Plan {
        rows: vec![intent, done],
        payload: None,
        rules: Some(prepared),
        purge: false,
        reserved: true,
    })
}

fn verify_completed(
    case: &Case,
    ticket: &Ticket,
    verified: &VerifiedPayloads,
    rules_at_open: &RulesSnapshot,
) -> Result<()> {
    let Some(intent) = case.journal.rows().iter().rev().find(|row| {
        row.ticket_id == ticket.id.as_str()
            && matches!(
                row.event,
                EventName::ActionIntent | EventName::ReversalIntent
            )
    }) else {
        return Ok(());
    };
    let valid = if ticket.purged {
        if intent.event == EventName::ReversalIntent {
            rules_at_open.verifies(&super::rules::RuleDelta::Reverse {
                ticket: ticket.id.clone(),
                documents: intent.documents()?,
                ground: Ground::parse(&intent.reason_code)?,
                at: intent.at,
                sequence: intent.intent_sequence,
            })
        } else if matches!(
            intent.decision.as_str(),
            "not_intimate_image" | "no_standing"
        ) {
            rules_at_open.verifies(&super::rules::RuleDelta::Remove {
                ticket: ticket.id.clone(),
            })
        } else {
            rules_at_open.has_intent(
                &ticket.id,
                &intent.documents()?,
                Ground::parse(&intent.reason_code)?,
                intent.intent_sequence,
            )
        }
    } else {
        let delta = operation(case, ticket, intent, verified)?;
        rules_at_open.verifies(&delta)
    };
    if !valid {
        return Err(Error::RulesUnavailable);
    }
    Ok(())
}

fn finish_intake(case: &mut Case, ticket: &Ticket, verified: &VerifiedPayloads) -> Result<()> {
    let now = case.clock.utc().timestamp();
    let mut rows = Vec::new();
    let mut rules = None;
    if ticket.state == TicketState::Received {
        let installed = case.journal.rows().iter().any(|row| {
            row.ticket_id == ticket.id.as_str() && row.event == EventName::RulesCommitted
        });
        if ticket.route == Route::IntimateImages && !installed {
            let intake = verified.intake(&ticket.id)?;
            let mut intent =
                tickets::event_row(ticket, EventName::ActionIntent, now, "system.recovery")?;
            intent.reason_code = "intimate_images".into();
            intent.asset_ids = tickets::documents(intake);
            intent.payload_sequence = 1;
            intent.commitment = ticket.references.get(&1).ok_or(Error::Unavailable)?.clone();
            intent.intent_sequence = case
                .journal
                .sequence()
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            intent.effective_at = clock::intimate_effective(
                ticket.times.received_at,
                case.config.settings().intimate_margin_seconds,
            )?;
            rules = Some(
                case.rules
                    .prepare_delta(&tickets::delta(&intent, intake, &[])?)?,
            );
            rows.push(intent.clone());
            rows.push(tickets::completion(
                ticket,
                &intent,
                now,
                "system.recovery",
            )?);
        }
        rows.push(tickets::event_row(
            ticket,
            EventName::Acknowledged,
            now,
            "system.recovery",
        )?);
    }
    let mut acknowledged = ticket.clone();
    acknowledged.state = TicketState::Acknowledged;
    rows.push(tickets::event_row(
        &acknowledged,
        EventName::Queued,
        now,
        "system.recovery",
    )?);
    case.execute_plan(Plan {
        rows,
        payload: None,
        rules,
        purge: false,
        reserved: true,
    })
}
