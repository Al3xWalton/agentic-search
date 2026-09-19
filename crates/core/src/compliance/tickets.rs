//! Serializes ticket admission and administration over the journal and immutable personal revisions.
//! Started work owns its admission lease; cancellation while waiting never starts a transaction.

#![deny(missing_docs)]

use super::{
    auth,
    bounds::{self, BoundKey, TextClass},
    clock,
    disk::{ComplianceHooks, ComplianceStage, WriteProgress},
    journal::{EventName, Journal, JournalRow},
    listed::ListedMatcher,
    model::{
        Decision, Delivery, Entropy, Ground, Hex64, IdentityEvent, Intake, IntakeKind, Necessity,
        RequestKind, Route, TicketId, TicketState,
    },
    payload::{Notice, PayloadStore, PersonalEvent, PreparedPayload},
    rules::{NameSet, PreparedRules, RuleDelta, RulesHooks, RulesStore},
    transitions::{self, Ticket},
    Error, Result,
};
use crate::{config::compliance::ValidatedComplianceConfig, crawler::politeness::Clock};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tokio::{sync::Mutex, task::JoinSet};

/// Finite observations at actual lookup and append seams, with no personal arguments.
pub trait TicketObserver: Send + Sync + 'static {
    /// Called immediately before one validated-id projection lookup.
    fn lookup(&self) {}
    /// Called immediately before one actual journal append.
    fn journal_write(&self) {}
}

/// Default observer for production deployments without additional instrumentation.
pub struct NoObserver;
impl TicketObserver for NoObserver {}

/// Validates the complete private intake, also used when replaying a committed personal file.
pub fn validate_intake(intake: &Intake) -> Result<()> {
    intake.report.validate()?;
    if matches!(
        intake.route(),
        Route::DataProtectionComplaint | Route::OnlineSafetyComplaint
    ) {
        if !intake.assets.is_empty() {
            return Err(Error::InvalidInput);
        }
    } else {
        BoundKey::Urls.validate(intake.assets.len() as u64)?;
    }
    let assets = intake
        .assets
        .iter()
        .map(|asset| asset.document_id())
        .collect::<BTreeSet<_>>();
    if assets.len() != intake.assets.len() {
        return Err(Error::InvalidInput);
    }
    let evidence = |text: &str| bounds::text(text, BoundKey::Evidence, TextClass::Narrative);
    match &intake.category {
        IntakeKind::IllegalContent {
            suspected_illegality,
        } => evidence(suspected_illegality)?,
        IntakeKind::HarmfulToChildren { harm_description } => evidence(harm_description)?,
        IntakeKind::RightsRemoval {
            rights_basis,
            authority,
        } => {
            evidence(rights_basis)?;
            evidence(authority)?;
        }
        IntakeKind::IntimateImages {
            intimate_image_content,
            subject_or_authorised,
            good_faith,
        } => {
            if !intimate_image_content || !subject_or_authorised || !good_faith {
                return Err(Error::InvalidInput);
            }
        }
        IntakeKind::DataRights {
            request_kind,
            names,
        } => {
            let bound = if *request_kind == RequestKind::Delisting {
                BoundKey::RequiredNames
            } else {
                BoundKey::OptionalNames
            };
            bound.validate(names.len() as u64)?;
            for name in names {
                super::rules::name_tokens(&name.name)?;
                evidence(&name.evidence)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Unstored caller command; service-owned notices and salts are created only by the case owner.
#[derive(Clone)]
pub enum AdministrationEvent {
    /// Identity or clarification request/reply.
    Identity {
        /// Closed evidence event.
        event: IdentityEvent,
        /// Bounded reasons.
        reasons: String,
    },
    /// Reasoned data-rights extension and delivered caller notice.
    Extension {
        /// Statutory complexity or volume basis.
        necessity: Necessity,
        /// Bounded reasons.
        reasons: String,
        /// Written extension notice.
        notice: String,
        /// Operator delivery attestation.
        delivery: Delivery,
    },
    /// Reviewed disposition without service-owned notice or salts.
    Decision {
        /// Route-appropriate reviewed decision.
        decision: Decision,
    },
    /// Appeal of an original decision.
    Appeal {
        /// Bounded reasons.
        reasons: String,
        /// Optional authenticated association.
        related_ticket_id: Option<TicketId>,
    },
    /// Reversal of an appealed action.
    Reversal {
        /// Bounded reasons.
        reasons: String,
        /// Operator communication attestation.
        delivery: Delivery,
    },
    /// Decision to uphold an appealed outcome.
    Uphold {
        /// Bounded reasons.
        reasons: String,
        /// Operator communication attestation.
        delivery: Delivery,
    },
    /// Enquiries and communicated progress.
    Progress {
        /// Bounded enquiry record.
        enquiries: String,
        /// Bounded progress update.
        update: String,
        /// Operator communication attestation.
        delivery: Delivery,
    },
    /// Final closure.
    Closure {
        /// Bounded closure reasons.
        reasons: String,
    },
}

impl AdministrationEvent {
    fn validate(&self) -> Result<()> {
        let reason = |text: &str| bounds::text(text, BoundKey::Reason, TextClass::Narrative);
        let narrative = |text: &str| bounds::text(text, BoundKey::Narrative, TextClass::Narrative);
        match self {
            Self::Identity { reasons, .. }
            | Self::Appeal { reasons, .. }
            | Self::Closure { reasons } => reason(reasons),
            Self::Extension {
                reasons,
                notice,
                delivery,
                ..
            } => {
                reason(reasons)?;
                narrative(notice)?;
                delivery.validate()
            }
            Self::Decision { decision } => decision.validate(),
            Self::Reversal { reasons, delivery } | Self::Uphold { reasons, delivery } => {
                reason(reasons)?;
                delivery.validate()
            }
            Self::Progress {
                enquiries,
                update,
                delivery,
            } => {
                narrative(enquiries)?;
                narrative(update)?;
                delivery.validate()
            }
        }
    }

    fn personal(self, config: &ValidatedComplianceConfig) -> PersonalEvent {
        match self {
            Self::Identity { event, reasons } => PersonalEvent::Identity { event, reasons },
            Self::Extension {
                necessity,
                reasons,
                notice,
                delivery,
            } => PersonalEvent::Extension {
                necessity,
                reasons,
                notice,
                delivery,
            },
            Self::Decision { decision } => {
                let notice = decision_notice(&decision, config);
                PersonalEvent::Decision {
                    decision,
                    name_rule_salts: Vec::new(),
                    notice,
                }
            }
            Self::Appeal {
                reasons,
                related_ticket_id,
            } => PersonalEvent::Appeal {
                reasons,
                related_ticket_id,
            },
            Self::Reversal { reasons, delivery } => PersonalEvent::Reversal {
                reasons,
                delivery,
                notice: Notice {
                    text:
                        "The original action is reversed. Independent protection may still apply."
                            .into(),
                    remedies: Vec::new(),
                },
            },
            Self::Uphold { reasons, delivery } => PersonalEvent::Uphold {
                reasons,
                delivery,
                notice: Notice {
                    text: "The reviewed outcome is upheld.".into(),
                    remedies: Vec::new(),
                },
            },
            Self::Progress {
                enquiries,
                update,
                delivery,
            } => PersonalEvent::Progress {
                enquiries,
                update,
                delivery,
            },
            Self::Closure { reasons } => PersonalEvent::Closure { reasons },
        }
    }
}

/// Validated queue selection; purge discovery does not read personal payloads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum QueueView {
    /// Pending moderation and unresolved operations.
    Open,
    /// Closed, unpurged tickets at their calendar retention threshold.
    PurgeDue,
}

/// A bounded page with a stable receipt/id cursor and no personal content.
pub struct QueuePage {
    /// Injected UTC captured once for selection and observation-time deadline projection.
    pub observed_at: i64,
    /// Selected projections; the HTTP adapter discloses only the selected view's whitelist.
    pub items: Vec<Ticket>,
    /// Last returned id only when another selected item follows it.
    pub next_ticket_id: Option<TicketId>,
}

/// Successful private admission data used to assemble an exact acknowledgement.
pub struct Admission {
    /// Completed received/acknowledged/queued projection.
    pub ticket: Ticket,
    /// Retained preference, which never suppresses essential replies.
    pub nonessential_opt_out: bool,
}

/// Successful administration result and any essential notice prepared by the service.
pub struct Outcome {
    /// Current nonpersonal projection after durable completion.
    pub ticket: Ticket,
    /// Essential communication for decisions, progress and appeal disposal.
    pub notice: Option<Notice>,
}

/// The sole private read result, including verified typed personal revisions unless purged.
pub struct PrivateTicket {
    /// Journal-derived nonpersonal projection.
    pub ticket: Ticket,
    /// Verified personal events in immutable revision order; empty after purge.
    pub events: Vec<PersonalEvent>,
}

/// Shared durable owners and tracked case work, independent of search's rules-only read gate.
pub struct ComplianceStore {
    state: Arc<Mutex<CaseState>>,
    tasks: Mutex<JoinSet<()>>,
    rules: Arc<RulesStore>,
    clock: Arc<dyn Clock>,
    observer: Arc<dyn TicketObserver>,
}
struct CaseState {
    case: Option<Case>,
    unavailable: bool,
}

pub(crate) struct Case {
    pub(crate) journal: Journal,
    pub(crate) payloads: PayloadStore,
    pub(crate) tickets: BTreeMap<TicketId, Ticket>,
    pub(crate) usage: BTreeMap<TicketId, u64>,
    pub(crate) config: ValidatedComplianceConfig,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) entropy: Arc<dyn Entropy>,
    pub(crate) hooks: Arc<dyn ComplianceHooks>,
    pub(crate) observer: Arc<dyn TicketObserver>,
    pub(crate) rules: Arc<RulesStore>,
    writes_disabled: bool,
    write_progress: WriteProgress,
}

impl ComplianceStore {
    /// Opens both owners in blocking startup. Bad rules/list are fatal; bad cases disable only compliance.
    /// Constructor and startup recovery take blocking locks: run in a blocking context,
    /// outside an async task, as the production spawn_blocking caller does.
    pub fn open(
        config: &ValidatedComplianceConfig,
        clock: Arc<dyn Clock>,
        entropy: Arc<dyn Entropy>,
        hooks: Arc<dyn ComplianceHooks>,
        rule_hooks: Arc<dyn RulesHooks>,
        observer: Arc<dyn TicketObserver>,
        writes_disabled: bool,
    ) -> Result<Self> {
        let listed = ListedMatcher::load(config, hooks.as_ref())?;
        let metadata = listed.metadata();
        let rules = Arc::new(RulesStore::open(
            config,
            clock.clone(),
            listed,
            hooks.clone(),
            rule_hooks,
        )?);
        let opened = (|| {
            let journal = Journal::open_unpublished(config, clock.clone(), hooks.clone())?;
            let mut case = Case {
                journal,
                payloads: PayloadStore::new(config, hooks.clone()),
                tickets: BTreeMap::new(),
                usage: BTreeMap::new(),
                config: config.clone(),
                clock: clock.clone(),
                entropy,
                hooks,
                observer: observer.clone(),
                rules: rules.clone(),
                writes_disabled,
                write_progress: WriteProgress::default(),
            };
            super::recovery::reconcile(&mut case)?;
            if config.settings().listed_hashes_file.is_some() {
                case.journal.record_list_access(&metadata)?;
            }
            Ok(case)
        })();
        let state = match opened {
            Ok(case) => CaseState {
                case: Some(case),
                unavailable: false,
            },
            Err(Error::RulesUnavailable) => return Err(Error::RulesUnavailable),
            Err(_) => CaseState {
                case: None,
                unavailable: true,
            },
        };
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            tasks: Mutex::new(JoinSet::new()),
            rules,
            clock,
            observer,
        })
    }

    /// Returns the independent serving owner; no journal access is needed to gate search.
    pub fn rules(&self) -> &Arc<RulesStore> {
        &self.rules
    }

    /// Checks case availability for index and capability responses.
    pub async fn available(&self) -> Result<()> {
        if self.state.lock().await.unavailable {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }

    /// Loads one minimal projection after raw capability validation by the adapter.
    pub async fn status(&self, id: &TicketId) -> Result<Ticket> {
        let state = self.state.lock().await;
        if state.unavailable {
            return Err(Error::Unavailable);
        }
        self.observer.lookup();
        state
            .case
            .as_ref()
            .ok_or(Error::Unavailable)?
            .tickets
            .get(id)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// Selects pending work or due purges, using the same pure eligibility guard as deletion.
    pub async fn queue(
        &self,
        actor: &str,
        after: Option<&TicketId>,
        limit: u16,
        view: QueueView,
    ) -> Result<QueuePage> {
        auth::actor(actor)?;
        BoundKey::QueueLimit.validate(u64::from(limit))?;
        let state = self.state.lock().await;
        if state.unavailable {
            return Err(Error::Unavailable);
        }
        let case = state.case.as_ref().ok_or(Error::Unavailable)?;
        let cursor = after
            .map(|id| {
                case.tickets
                    .get(id)
                    .map(|ticket| (ticket.times.received_at, ticket.id.clone()))
                    .ok_or(Error::InvalidInput)
            })
            .transpose()?;
        let now = self.clock.utc().timestamp();
        let mut items = Vec::new();
        for ticket in case.tickets.values() {
            let selected = match view {
                QueueView::Open => {
                    ticket.pending.is_some()
                        || matches!(
                            ticket.state,
                            TicketState::Received
                                | TicketState::Acknowledged
                                | TicketState::IdentityPending
                                | TicketState::Queued
                                | TicketState::Decided
                                | TicketState::Appealed
                        )
                }
                QueueView::PurgeDue => transitions::purge_due(ticket, now, &case.config)?,
            };
            let key = (ticket.times.received_at, ticket.id.clone());
            if selected && cursor.as_ref().is_none_or(|cursor| key > *cursor) {
                items.push(ticket.clone());
            }
        }
        items.sort_by(|a, b| (a.times.received_at, &a.id).cmp(&(b.times.received_at, &b.id)));
        let more = items.len() > usize::from(limit);
        items.truncate(usize::from(limit));
        let next_ticket_id = if more {
            items.last().map(|ticket| ticket.id.clone())
        } else {
            None
        };
        Ok(QueuePage {
            observed_at: now,
            items,
            next_ticket_id,
        })
    }

    /// Captures immutable receipt after complete validation and before waiting for the writer.
    pub async fn admit(&self, intake: Intake, lease: Arc<dyn Send + Sync>) -> Result<Admission> {
        validate_intake(&intake)?;
        let received_at = self.clock.utc().timestamp();
        clock::instant(received_at)?;
        self.execute(lease, move |case| case.admit(intake, received_at))
            .await
    }

    /// Validates private event content before serialization and performs its closed state transition.
    pub async fn administer(
        &self,
        id: TicketId,
        actor: String,
        event: AdministrationEvent,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<Outcome> {
        auth::actor(&actor)?;
        event.validate()?;
        self.execute(lease, move |case| case.administer(&id, &actor, event))
            .await
    }

    /// Deletes only verified revisions of an eligible closed ticket; completed retries write nothing.
    pub async fn purge(
        &self,
        id: TicketId,
        actor: String,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<Outcome> {
        auth::actor(&actor)?;
        self.execute(lease, move |case| case.purge(&id, &actor))
            .await
    }

    /// Reads all bounded, verified revisions solely for the authenticated private read surface.
    pub async fn read(
        &self,
        id: TicketId,
        actor: String,
        lease: Arc<dyn Send + Sync>,
    ) -> Result<PrivateTicket> {
        auth::actor(&actor)?;
        self.execute(lease, move |case| {
            let ticket = case.ticket(&id)?;
            let events = if ticket.purged {
                Vec::new()
            } else {
                ticket
                    .references
                    .iter()
                    .map(|(sequence, expected)| case.payloads.read(&id, *sequence, expected))
                    .collect::<Result<Vec<_>>>()?
            };
            Ok(PrivateTicket { ticket, events })
        })
        .await
    }

    /// Joins every started transaction; shutdown never abandons a durable operation or its lease.
    pub async fn shutdown(&self) {
        let mut tasks = self.tasks.lock().await;
        while tasks.join_next().await.is_some() {}
    }

    async fn execute<T: Send + 'static>(
        &self,
        lease: Arc<dyn Send + Sync>,
        operation: impl FnOnce(&mut Case) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let mut tasks = self.tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        let mut state = self.state.clone().lock_owned().await;
        if state.unavailable {
            return Err(Error::Unavailable);
        }
        let live = self.state.clone();
        state
            .case
            .as_mut()
            .ok_or(Error::Unavailable)?
            .write_progress
            .reset();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                let _lease = lease;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    operation(state.case.as_mut().ok_or(Error::Unavailable)?)
                }));
                let result = result.unwrap_or(Err(Error::Unavailable));
                let write_started = state
                    .case
                    .as_ref()
                    .is_some_and(|case| case.write_progress.started());
                if result.is_err() && write_started {
                    state.unavailable = true;
                }
                result
            })
            .await;
            let result = match outcome {
                Ok(result) => result,
                Err(_) => {
                    let mut state = live.lock().await;
                    if state
                        .case
                        .as_ref()
                        .is_none_or(|case| case.write_progress.started())
                    {
                        state.unavailable = true;
                    }
                    Err(Error::Unavailable)
                }
            };
            let _ = sender.send(result);
        });
        drop(tasks);
        receiver.await.unwrap_or(Err(Error::Unavailable))
    }
}

pub(crate) struct Plan {
    pub(crate) rows: Vec<JournalRow>,
    pub(crate) payload: Option<PreparedPayload>,
    pub(crate) rules: Option<PreparedRules>,
    pub(crate) purge: bool,
    pub(crate) reserved: bool,
}

// Sizing-only rows and personal content cannot be submitted to execute_plan.
struct DraftPlan {
    rows: Vec<JournalRow>,
    content: PersonalEvent,
    intake: Intake,
    payload_sequence: u64,
    payload_bytes: u64,
    new_ticket: bool,
}

struct PlanMaterial {
    id: TicketId,
    payload_salt: Hex64,
    name_salts: Vec<Hex64>,
}

struct Footprint {
    new_tickets: u64,
    events: u64,
    journal_bytes: u64,
    existing_payload: u64,
    added_payload: u64,
    total_payload: u64,
    reserved: bool,
}

impl Case {
    pub(crate) fn ticket(&self, id: &TicketId) -> Result<Ticket> {
        self.observer.lookup();
        self.tickets.get(id).cloned().ok_or(Error::NotFound)
    }

    fn materialize_plan(&self, draft: DraftPlan) -> Result<Plan> {
        self.reserve_draft(&draft)?;
        let material = self.draw_material(&draft)?;
        let plan = self.finish_plan(draft, material)?;
        Ok(plan)
    }

    fn reserve_draft(&self, draft: &DraftPlan) -> Result<()> {
        let rows = self.journal.prepare_rows(draft.rows.clone())?;
        self.reserve(&rows, draft.payload_bytes, false)?;
        let mut rule_rows = draft.rows.clone();
        if draft.new_ticket {
            // A sizing id must not merge with a real rule if the all-zero capability exists.
            // This deterministic, width-equivalent identity is confined to rule measurement.
            let id = (0..=self.tickets.len())
                .find_map(|index| {
                    let id = TicketId::parse(&format!("{index:064x}")).ok()?;
                    (!self.tickets.contains_key(&id)).then_some(id)
                })
                .ok_or(Error::Capacity)?;
            for row in &mut rule_rows {
                row.ticket_id = id.as_str().into();
            }
        }
        self.plan_rules(&rule_rows, &draft.intake, &draft.content)?;
        Ok(())
    }

    fn draw_material(&self, draft: &DraftPlan) -> Result<PlanMaterial> {
        let id = if draft.new_ticket {
            let id = TicketId::generate(self.entropy.as_ref())?;
            if self.tickets.contains_key(&id) {
                return Err(Error::Unavailable);
            }
            id
        } else {
            TicketId::parse(&draft.rows.first().ok_or(Error::Unavailable)?.ticket_id)?
        };
        let payload_salt = Hex64::random(self.entropy.as_ref())?;
        let count = match &draft.content {
            PersonalEvent::Decision {
                name_rule_salts, ..
            } => name_rule_salts.len(),
            _ => 0,
        };
        let name_salts = (0..count)
            .map(|_| Hex64::random(self.entropy.as_ref()))
            .collect::<Result<_>>()?;
        Ok(PlanMaterial {
            id,
            payload_salt,
            name_salts,
        })
    }

    fn finish_plan(&self, mut draft: DraftPlan, material: PlanMaterial) -> Result<Plan> {
        if let PersonalEvent::Decision {
            name_rule_salts, ..
        } = &mut draft.content
        {
            *name_rule_salts = material.name_salts;
        }
        let payload = self.payloads.prepare_with_salt(
            &material.id,
            draft.payload_sequence,
            draft.content,
            material.payload_salt,
        )?;
        for row in &mut draft.rows {
            row.ticket_id = material.id.as_str().into();
            if row.payload_sequence != 0 {
                reference(row, &payload);
            }
        }
        let rules = self.plan_rules(&draft.rows, &draft.intake, payload.content())?;
        Ok(Plan {
            rows: draft.rows,
            payload: Some(payload),
            rules,
            purge: false,
            reserved: false,
        })
    }

    fn plan_rules(
        &self,
        rows: &[JournalRow],
        intake: &Intake,
        content: &PersonalEvent,
    ) -> Result<Option<PreparedRules>> {
        let Some(intent) = rows.iter().find(|row| {
            matches!(
                row.event,
                EventName::ActionIntent | EventName::ReversalIntent
            )
        }) else {
            return Ok(None);
        };
        let salts = match content {
            PersonalEvent::Decision {
                name_rule_salts, ..
            } => name_rule_salts.as_slice(),
            _ => &[],
        };
        self.rules
            .prepare_delta(&delta(intent, intake, salts)?)
            .map(Some)
    }

    fn admit(&mut self, intake: Intake, received_at: i64) -> Result<Admission> {
        if self.writes_disabled {
            return Err(Error::Unavailable);
        }
        let id = TicketId::parse(&"0".repeat(64))?;
        let now = self.clock.utc().timestamp();
        let payload = self.payloads.prepare_with_salt(
            &id,
            1,
            PersonalEvent::Intake {
                intake: intake.clone(),
            },
            Hex64::parse(&"0".repeat(64))?,
        )?;
        let mut received = JournalRow::empty(EventName::Received, now);
        received.actor = "system.intake".into();
        received.ticket_id = id.as_str().into();
        received.route = intake.route().as_str().into();
        received.requester_type = intake.report.requester_type.as_str().into();
        received.state = "received".into();
        received.received_at = received_at;
        reference(&mut received, &payload);
        let ticket = Ticket::received(&received)?;
        let mut rows = vec![received];
        if intake.route() == Route::IntimateImages {
            let sequence = self
                .journal
                .sequence()
                .checked_add(2)
                .ok_or(Error::Capacity)?;
            let mut intent = event_row(&ticket, EventName::ActionIntent, now, "system.intake")?;
            intent.intent_sequence = sequence;
            intent.reason_code = "intimate_images".into();
            intent.asset_ids = documents(&intake);
            intent.effective_at = clock::intimate_effective(
                received_at,
                self.config.settings().intimate_margin_seconds,
            )?;
            reference(&mut intent, &payload);
            rows.push(intent.clone());
            rows.push(completion(&ticket, &intent, now, "system.intake")?);
        }
        rows.push(event_row(
            &ticket,
            EventName::Acknowledged,
            now,
            "system.intake",
        )?);
        let mut queued = rows.last().ok_or(Error::Unavailable)?.clone();
        queued.event = EventName::Queued;
        queued.state = "queued".into();
        rows.push(queued);
        let plan = self.materialize_plan(DraftPlan {
            rows,
            content: payload.content().clone(),
            intake: intake.clone(),
            payload_sequence: 1,
            payload_bytes: payload.byte_length(),
            new_ticket: true,
        })?;
        let id = TicketId::parse(&plan.rows.first().ok_or(Error::Unavailable)?.ticket_id)?;
        self.execute_plan(plan)?;
        Ok(Admission {
            ticket: self.ticket(&id)?,
            nonessential_opt_out: intake.report.nonessential_opt_out,
        })
    }

    fn administer(
        &mut self,
        id: &TicketId,
        actor: &str,
        command: AdministrationEvent,
    ) -> Result<Outcome> {
        if self.writes_disabled {
            return Err(Error::Unavailable);
        }
        let ticket = self.ticket(id)?;
        if ticket.purged {
            return Err(Error::InvalidTransition);
        }
        let intake = self.intake(&ticket)?;
        let now = self.clock.utc().timestamp();
        let event = personal_event_name(&command);
        let mut row = event_row(&ticket, event, now, actor)?;
        if let AdministrationEvent::Decision { decision } = &command {
            transitions::decision_allowed(
                &ticket,
                decision,
                intake.ground(),
                &self.tickets,
                &self.config,
            )?;
        }
        let mut content = command.personal(&self.config);
        let notice = self.prepare_personal(&ticket, &intake, &mut content, &mut row)?;
        let sequence = ticket.references.len() as u64 + 1;
        let payload = self.payloads.prepare_with_salt(
            id,
            sequence,
            content,
            Hex64::parse(&"0".repeat(64))?,
        )?;
        reference(&mut row, &payload);
        let mut rows = vec![row];
        self.prepare_action(&ticket, &intake, &payload, &mut rows)?;
        let plan = self.materialize_plan(DraftPlan {
            rows,
            content: payload.content().clone(),
            intake,
            payload_sequence: sequence,
            payload_bytes: payload.byte_length(),
            new_ticket: false,
        })?;
        self.execute_plan(plan)?;
        Ok(Outcome {
            ticket: self.ticket(id)?,
            notice,
        })
    }

    fn prepare_personal(
        &self,
        ticket: &Ticket,
        intake: &Intake,
        content: &mut PersonalEvent,
        row: &mut JournalRow,
    ) -> Result<Option<Notice>> {
        let notice = match content {
            PersonalEvent::Decision {
                decision,
                name_rule_salts,
                notice,
            } => {
                if matches!(decision, Decision::Granted { .. })
                    && intake.ground() == Some(Ground::DataDelisting)
                {
                    *name_rule_salts = intake
                        .names()
                        .iter()
                        .map(|_| Hex64::parse(&"0".repeat(64)))
                        .collect::<Result<Vec<_>>>()?;
                }
                row.decision = decision.kind().as_str().into();
                if matches!(
                    decision,
                    Decision::Granted { .. }
                        | Decision::NotIntimateImage { .. }
                        | Decision::NoStanding { .. }
                ) {
                    row.reason_code = intake
                        .ground()
                        .map_or_else(String::new, |ground| ground.as_str().into());
                }
                if let Decision::ManifestlyUnfounded {
                    policy_version,
                    policy_clause,
                    duplicate_of,
                    ..
                } = decision
                {
                    row.policy_version = policy_version.clone();
                    row.reason_code = policy_clause.clone();
                    row.related_ticket_id = duplicate_of.as_str().into();
                }
                Some(notice.clone())
            }
            PersonalEvent::Reversal { notice, .. } => {
                reversal_fields(ticket, row)?;
                row.asset_ids = documents(intake);
                row.effective_at = row.at;
                row.intent_sequence = self
                    .journal
                    .sequence()
                    .checked_add(1)
                    .ok_or(Error::Capacity)?;
                Some(notice.clone())
            }
            PersonalEvent::Uphold { notice, .. } => Some(notice.clone()),
            PersonalEvent::Extension { notice, .. } => Some(Notice {
                text: notice.clone(),
                remedies: Vec::new(),
            }),
            PersonalEvent::Progress { update, .. } => Some(Notice {
                text: update.clone(),
                remedies: Vec::new(),
            }),
            PersonalEvent::Appeal {
                related_ticket_id, ..
            } => {
                if let Some(id) = related_ticket_id {
                    self.ticket(id)?;
                    row.related_ticket_id = id.as_str().into();
                }
                None
            }
            _ => None,
        };
        Ok(notice)
    }

    fn prepare_action(
        &self,
        ticket: &Ticket,
        intake: &Intake,
        payload: &PreparedPayload,
        rows: &mut Vec<JournalRow>,
    ) -> Result<()> {
        let row = rows.first().cloned().ok_or(Error::Unavailable)?;
        let action = matches!(
            payload.content(),
            PersonalEvent::Decision {
                decision: Decision::Granted { .. },
                ..
            }
        ) && intake.ground().is_some();
        let determination = matches!(
            payload.content(),
            PersonalEvent::Decision {
                decision: Decision::NotIntimateImage { .. } | Decision::NoStanding { .. },
                ..
            }
        );
        let reversal = row.event == EventName::ReversalIntent;
        if !action && !determination && !reversal {
            return Ok(());
        }
        let mut projected = ticket.clone();
        let mut intent = row.clone();
        if !reversal {
            projected.apply(&row, &self.config)?;
            intent.event = EventName::ActionIntent;
            intent.intent_sequence = self
                .journal
                .sequence()
                .checked_add(2)
                .ok_or(Error::Capacity)?;
            intent.asset_ids = documents(intake);
            intent.effective_at = row.at;
        }
        if !reversal {
            rows.push(intent.clone());
        }
        rows.push(completion(&projected, &intent, row.at, &row.actor)?);
        Ok(())
    }

    fn purge(&mut self, id: &TicketId, actor: &str) -> Result<Outcome> {
        if self.writes_disabled {
            return Err(Error::Unavailable);
        }
        let ticket = self.ticket(id)?;
        if ticket.purged {
            return Ok(Outcome {
                ticket,
                notice: None,
            });
        }
        let now = self.clock.utc().timestamp();
        transitions::successor(ticket.state, EventName::PurgeIntent)?;
        if !transitions::purge_due(&ticket, now, &self.config)? {
            return Err(Error::RetentionNotDue);
        }
        let mut intent = event_row(&ticket, EventName::PurgeIntent, now, actor)?;
        intent.intent_sequence = self
            .journal
            .sequence()
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let done = completion(&ticket, &intent, now, actor)?;
        self.execute_plan(Plan {
            rows: vec![intent, done],
            payload: None,
            rules: None,
            purge: true,
            reserved: true,
        })?;
        Ok(Outcome {
            ticket: self.ticket(id)?,
            notice: None,
        })
    }

    pub(crate) fn intake(&self, ticket: &Ticket) -> Result<Intake> {
        let expected = ticket.references.get(&1).ok_or(Error::Unavailable)?;
        match self.payloads.read(&ticket.id, 1, expected)? {
            PersonalEvent::Intake { intake } => Ok(intake),
            _ => Err(Error::Unavailable),
        }
    }

    pub(crate) fn execute_plan(&mut self, mut plan: Plan) -> Result<()> {
        plan.rows = self.journal.prepare_rows(plan.rows)?;
        let projected = self.reserve(
            &plan.rows,
            plan.payload
                .as_ref()
                .map_or(0, PreparedPayload::byte_length),
            plan.reserved,
        )?;
        if let Some(payload) = &plan.payload {
            self.payloads
                .write_tracked(payload, &mut self.write_progress)?;
        }
        for row in &plan.rows {
            if matches!(
                row.event,
                EventName::Actioned
                    | EventName::RulesCommitted
                    | EventName::Reversed
                    | EventName::Purged
            ) {
                self.hooks
                    .at(ComplianceStage::BeforeCompletionRow)
                    .map_err(|_| Error::Unavailable)?;
            }
            self.observer.journal_write();
            self.journal
                .append_tracked(row.clone(), &mut self.write_progress)?;
            if matches!(
                row.event,
                EventName::ActionIntent | EventName::ReversalIntent | EventName::PurgeIntent
            ) {
                self.hooks
                    .at(ComplianceStage::AfterIntentSync)
                    .map_err(|_| Error::Unavailable)?;
                if let Some(prepared) = plan.rules.take() {
                    self.rules.commit(prepared)?;
                }
                if plan.purge {
                    self.payloads.purge(&projected.id, &projected.references)?;
                }
                self.hooks
                    .at(ComplianceStage::AfterRulesSync)
                    .map_err(|_| Error::Unavailable)?;
            }
        }
        let id = projected.id.clone();
        self.tickets.insert(id.clone(), projected);
        if plan.purge {
            self.usage.insert(id, 0);
        } else if let Some(payload) = plan.payload {
            *self.usage.entry(id).or_default() += payload.byte_length();
        }
        Ok(())
    }

    fn reserve(&self, rows: &[JournalRow], payload_bytes: u64, reserved: bool) -> Result<Ticket> {
        let (candidate, footprint) = self.project_and_measure(rows, payload_bytes, reserved)?;
        self.reserve_footprint(&footprint)?;
        Ok(candidate)
    }

    fn project_and_measure(
        &self,
        rows: &[JournalRow],
        payload_bytes: u64,
        reserved: bool,
    ) -> Result<(Ticket, Footprint)> {
        let first = rows.first().ok_or(Error::Unavailable)?;
        let id = TicketId::parse(&first.ticket_id)?;
        let mut candidate = if first.event == EventName::Received {
            Ticket::received(first)?
        } else {
            self.tickets.get(&id).cloned().ok_or(Error::NotFound)?
        };
        let skip = usize::from(first.event == EventName::Received);
        for row in rows.iter().skip(skip) {
            candidate.apply(row, &self.config)?;
        }
        let journal_bytes = rows.iter().try_fold(0u64, |sum, row| {
            sum.checked_add(row.bytes()?.len() as u64)
                .ok_or(Error::Capacity)
        })?;
        let total_payload = self.usage.values().try_fold(0u64, |sum, size| {
            sum.checked_add(*size).ok_or(Error::Capacity)
        })?;
        let footprint = Footprint {
            new_tickets: skip as u64,
            events: candidate.events,
            journal_bytes,
            existing_payload: if skip == 1 {
                0
            } else {
                self.usage.get(&id).copied().unwrap_or(0)
            },
            added_payload: payload_bytes,
            total_payload,
            reserved,
        };
        Ok((candidate, footprint))
    }

    fn reserve_footprint(&self, footprint: &Footprint) -> Result<()> {
        bounds::reserve(
            self.tickets.len() as u64,
            footprint.new_tickets,
            self.config.settings().max_tickets,
            0,
        )?;
        let spare_events = if footprint.reserved {
            0
        } else {
            BoundKey::ReservedEvents.spec().min
        };
        bounds::reserve(
            0,
            footprint.events,
            self.config.settings().max_ticket_events,
            spare_events,
        )?;
        let spare_bytes = if footprint.reserved {
            0
        } else {
            BoundKey::ReservedJournalBytes.spec().min
        };
        bounds::reserve(
            self.journal.byte_length(),
            footprint.journal_bytes,
            self.config.settings().max_journal_bytes,
            spare_bytes,
        )?;
        bounds::reserve(
            footprint.existing_payload,
            footprint.added_payload,
            BoundKey::TicketPayload.spec().max,
            0,
        )?;
        bounds::reserve(
            footprint.total_payload,
            footprint.added_payload,
            self.config.settings().max_payload_bytes,
            0,
        )?;
        Ok(())
    }
}

pub(crate) fn event_row(
    ticket: &Ticket,
    event: EventName,
    at: i64,
    actor: &str,
) -> Result<JournalRow> {
    let mut row = JournalRow::empty(event, at);
    row.actor = actor.into();
    row.ticket_id = ticket.id.as_str().into();
    row.route = ticket.route.as_str().into();
    row.requester_type = ticket.requester.as_str().into();
    row.received_at = ticket.times.received_at;
    row.state = transitions::successor(ticket.state, event)?.as_str().into();
    Ok(row)
}

pub(crate) fn completion(
    ticket: &Ticket,
    intent: &JournalRow,
    at: i64,
    actor: &str,
) -> Result<JournalRow> {
    let event = match intent.event {
        EventName::ReversalIntent => EventName::Reversed,
        EventName::PurgeIntent => EventName::Purged,
        EventName::ActionIntent if intent.decision == "granted" => EventName::Actioned,
        EventName::ActionIntent => EventName::RulesCommitted,
        _ => return Err(Error::Unavailable),
    };
    let mut row = event_row(ticket, event, at, actor)?;
    row.intent_sequence = intent.intent_sequence;
    row.asset_ids = intent.asset_ids.clone();
    row.reason_code = intent.reason_code.clone();
    row.decision = intent.decision.clone();
    row.effective_at = intent.effective_at;
    Ok(row)
}

pub(crate) fn delta(intent: &JournalRow, intake: &Intake, salts: &[Hex64]) -> Result<RuleDelta> {
    let ticket = TicketId::parse(&intent.ticket_id)?;
    let ground = Ground::parse(&intent.reason_code)?;
    if intent.event == EventName::ReversalIntent {
        return Ok(RuleDelta::Reverse {
            ticket,
            documents: intent.documents()?,
            ground,
            at: intent.at,
            sequence: intent.intent_sequence,
        });
    }
    if matches!(
        intent.decision.as_str(),
        "not_intimate_image" | "no_standing"
    ) {
        return Ok(RuleDelta::Remove { ticket });
    }
    let names = if ground == Ground::DataDelisting {
        if salts.len() != intake.names().len() {
            return Err(Error::Unavailable);
        }
        intake
            .names()
            .iter()
            .zip(salts)
            .map(|(name, salt)| NameSet::new(&name.name, salt.clone()))
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    Ok(RuleDelta::Install {
        ticket,
        documents: intent.documents()?,
        ground,
        effective_at: intent.effective_at,
        sequence: intent.intent_sequence,
        names,
    })
}

fn reference(row: &mut JournalRow, payload: &PreparedPayload) {
    row.payload_sequence = payload.sequence();
    row.commitment = payload.commitment().into();
}

fn reversal_fields(ticket: &Ticket, row: &mut JournalRow) -> Result<()> {
    row.decision = ticket
        .decision
        .ok_or(Error::InvalidTransition)?
        .as_str()
        .into();
    row.reason_code = ticket
        .ground
        .ok_or(Error::InvalidTransition)?
        .as_str()
        .into();
    Ok(())
}

pub(crate) fn documents(intake: &Intake) -> String {
    intake
        .assets
        .iter()
        .map(|asset| asset.document_id().as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",")
}

fn personal_event_name(event: &AdministrationEvent) -> EventName {
    match event {
        AdministrationEvent::Identity { event, .. } => match event {
            IdentityEvent::RequestIdentity => EventName::IdentityRequested,
            IdentityEvent::IdentityConfirmed => EventName::IdentityConfirmed,
            IdentityEvent::RequestClarification => EventName::ClarificationRequested,
            IdentityEvent::ClarificationReceived => EventName::ClarificationReceived,
        },
        AdministrationEvent::Extension { .. } => EventName::ExtensionNotified,
        AdministrationEvent::Decision { .. } => EventName::Decided,
        AdministrationEvent::Appeal { .. } => EventName::Appealed,
        AdministrationEvent::Reversal { .. } => EventName::ReversalIntent,
        AdministrationEvent::Uphold { .. } => EventName::Upheld,
        AdministrationEvent::Progress { .. } => EventName::ProgressCommunicated,
        AdministrationEvent::Closure { .. } => EventName::Closed,
    }
}

pub(crate) fn decision_notice(decision: &Decision, config: &ValidatedComplianceConfig) -> Notice {
    let remedies = decision_remedies(decision);
    let mut text = decision.communication().0.to_owned();
    if matches!(decision, Decision::Refused { .. }) {
        let contact = config
            .settings()
            .public_contact
            .as_deref()
            .unwrap_or("[AVA contact pending deployment]");
        let ico = config
            .settings()
            .ico_complaints_url
            .as_deref()
            .unwrap_or("[ICO complaints link pending configuration]");
        text.push_str(&format!("\nAVA contact: {contact}\nICO complaints: {ico}"));
    }
    Notice { text, remedies }
}

fn decision_remedies(decision: &Decision) -> Vec<String> {
    if matches!(decision, Decision::Refused { .. }) {
        vec![
            "You may complain to AVA through Reports and requests".into(),
            "You may complain to the Information Commissioner's Office".into(),
            "You may seek a judicial remedy".into(),
        ]
    } else {
        Vec::new()
    }
}

pub(crate) fn verify_decision_notice(decision: &Decision, notice: &Notice) -> Result<()> {
    if notice.remedies != decision_remedies(decision) {
        return Err(Error::Unavailable);
    }
    let suffix = notice
        .text
        .strip_prefix(decision.communication().0)
        .ok_or(Error::Unavailable)?;
    if !matches!(decision, Decision::Refused { .. }) {
        return if suffix.is_empty() {
            Ok(())
        } else {
            Err(Error::Unavailable)
        };
    }
    // Contacts describe the configuration at the decision, not the current startup configuration.
    let contacts = suffix
        .strip_prefix("\nAVA contact: ")
        .ok_or(Error::Unavailable)?;
    let (contact, ico) = contacts
        .split_once("\nICO complaints: ")
        .ok_or(Error::Unavailable)?;
    bounds::text(contact, BoundKey::Contact, TextClass::Label)?;
    bounds::text(ico, BoundKey::Url, TextClass::Label)?;
    Ok(())
}
