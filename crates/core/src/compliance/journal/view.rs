//! Reads a verified journal prefix without acquiring writer authority or reading payloads.
//! Checkpoint advances allow one freshness retry, then return the captured valid prefix.
//! Missing files, committed corruption and regressed checkpoints fail without filesystem changes.

#![deny(missing_docs)]

use super::{checkpoint_agrees, verify_link, verify_time, Head, JournalRow};
use crate::{
    compliance::{
        bounds::{self, BoundKey},
        disk::{self, ComplianceHooks, ComplianceStage, OpenMode},
        journal::EventName,
        model::{Hex64, TicketId},
        transitions::Ticket,
        Error, Result,
    },
    config::compliance::ValidatedComplianceConfig,
    crawler::politeness::Clock,
};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

/// A verified point-in-time prefix; it contains metadata only, never personal revision contents.
pub struct CommittedJournal {
    /// Complete verified rows at or below the captured checkpoint, in their original order.
    pub rows: Vec<JournalRow>,
    /// Captured checkpoint sequence, zero for an initialized empty journal.
    pub sequence: u64,
    /// Captured checkpoint hash; callers must not include it in public metrics or errors.
    pub hash: String,
    /// Exact committed byte length, excluding every suffix regardless of its validity.
    pub byte_length: u64,
    /// Injected UTC seconds captured after reading this prefix, before time validation.
    pub observed_at: i64,
    tickets: BTreeMap<TicketId, Ticket>,
}

impl CommittedJournal {
    /// Returns the lifecycle projection, including unfinished operations without completing them.
    pub fn tickets(&self) -> &BTreeMap<TicketId, Ticket> {
        &self.tickets
    }
}

/// Reads only a captured committed prefix while the service retains its independent writer lock.
/// A first advance retries for freshness; a second advance returns the verified second prefix.
/// Regressed, foreign, malformed or missing checkpoints return fixed `Unavailable` without writes.
pub fn read_committed(
    config: &ValidatedComplianceConfig,
    clock: &dyn Clock,
    hooks: &dyn ComplianceHooks,
) -> Result<CommittedJournal> {
    let mut retried = false;
    loop {
        let (head, before) = read_head(config, hooks)?;
        let bytes = read_prefix(config, &head, hooks)?;
        let observed_at = clock.utc().timestamp();
        let rows = verify_prefix(&bytes, &head, observed_at, hooks)?;
        let tickets = replay(&rows, config)?;
        let (_, after) = read_head(config, hooks)?;
        if !disk::checkpoint_stable(&before, &after) {
            return Err(Error::Unavailable);
        }
        if before == after || retried {
            return Ok(CommittedJournal {
                rows,
                sequence: head.sequence,
                hash: head.hash,
                byte_length: head.byte_length,
                observed_at,
                tickets,
            });
        }
        retried = true;
    }
}

fn open_view(path: &Path, hooks: &dyn ComplianceHooks) -> std::io::Result<File> {
    disk::open_for(path, OpenMode::Read, hooks)
}

fn read_head(
    config: &ValidatedComplianceConfig,
    hooks: &dyn ComplianceHooks,
) -> Result<(Head, Vec<u8>)> {
    let file = open_view(&config.journal_dir().join("head.json"), hooks)
        .map_err(|_| Error::Unavailable)?;
    let bytes = disk::read_bounded(file, BoundKey::JournalRow.spec().max)
        .map_err(|_| Error::Unavailable)?;
    hooks
        .at(ComplianceStage::BeforeDecode)
        .map_err(|_| Error::Unavailable)?;
    let head: Head = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
    Hex64::parse(&head.hash).map_err(|_| Error::Unavailable)?;
    bounds::validate_range(head.byte_length, 0, config.settings().max_journal_bytes)
        .map_err(|_| Error::Unavailable)?;
    let mut canonical = serde_json::to_vec(&head).map_err(|_| Error::Unavailable)?;
    canonical.push(b'\n');
    if head.format_version != 1 || canonical != bytes {
        return Err(Error::Unavailable);
    }
    Ok((head, bytes))
}

fn read_prefix(
    config: &ValidatedComplianceConfig,
    head: &Head,
    hooks: &dyn ComplianceHooks,
) -> Result<Vec<u8>> {
    let file = open_view(&config.journal_dir().join("events.jsonl"), hooks)
        .map_err(|_| Error::Unavailable)?;
    let mut bytes = Vec::new();
    file.take(head.byte_length)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() as u64 != head.byte_length {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}

fn verify_prefix(
    bytes: &[u8],
    head: &Head,
    now: i64,
    hooks: &dyn ComplianceHooks,
) -> Result<Vec<JournalRow>> {
    let mut rows = Vec::new();
    let mut sequence = 0u64;
    let mut previous = "0".repeat(64);
    let mut last_at = None;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line.last() != Some(&b'\n') {
            return Err(Error::Unavailable);
        }
        BoundKey::JournalRow
            .validate(line.len() as u64)
            .map_err(|_| Error::Unavailable)?;
        hooks
            .at(ComplianceStage::BeforeDecode)
            .map_err(|_| Error::Unavailable)?;
        let row: JournalRow = serde_json::from_slice(line).map_err(|_| Error::Unavailable)?;
        sequence = sequence.checked_add(1).ok_or(Error::Unavailable)?;
        verify_link(&row, sequence, &previous)?;
        verify_time(&row, last_at, now)?;
        row.validate_metadata().map_err(|_| Error::Unavailable)?;
        if row.bytes().map_err(|_| Error::Unavailable)? != line {
            return Err(Error::Unavailable);
        }
        last_at = Some(row.at);
        previous = row.hash.clone();
        rows.push(row);
    }
    if !checkpoint_agrees(sequence, &previous, bytes.len() as u64, head) {
        return Err(Error::Unavailable);
    }
    Ok(rows)
}

fn replay(
    rows: &[JournalRow],
    config: &ValidatedComplianceConfig,
) -> Result<BTreeMap<TicketId, Ticket>> {
    let mut tickets = BTreeMap::new();
    for row in rows {
        if row.ticket_id.is_empty() {
            continue;
        }
        let id = TicketId::parse(&row.ticket_id).map_err(|_| Error::Unavailable)?;
        if row.event == EventName::Received {
            let ticket = Ticket::received(row).map_err(|_| Error::Unavailable)?;
            if tickets.insert(id, ticket).is_some() {
                return Err(Error::Unavailable);
            }
        } else {
            tickets
                .get_mut(&id)
                .ok_or(Error::Unavailable)?
                .apply(row, config)
                .map_err(|_| Error::Unavailable)?;
        }
    }
    bounds::reserve(0, tickets.len() as u64, config.settings().max_tickets, 0)
        .map_err(|_| Error::Unavailable)?;
    Ok(tickets)
}
