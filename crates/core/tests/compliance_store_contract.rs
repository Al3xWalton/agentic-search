//! Probes actual private journal owners, crash recovery and durable serving-rule boundaries.
//! Every fixture is synthetic; corruption cases preserve and compare the original committed bytes.
//! This harness owns persistence, crash and hardening probes; the surfaces harness owns
//! HTTP/clock/contracts and support/compliance.rs supplies shared synthetic fixtures.
//! Assert counters/store state, exact-once headers, body/content/code, then numeric status.

#![deny(missing_docs)]

#[path = "support/compliance.rs"]
/// Shared synthetic fixtures exported for both integration harnesses.
pub mod support;

mod contracts {
    use super::support::*;
    use serde_json::json;
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::PermissionsExt,
        sync::Arc,
    };
    use stract::compliance::{
        disk::NoHooks,
        journal::{EventName, Journal},
    };

    #[test]
    fn purge_removes_personal_files_but_preserves_the_chain() {
        interrupted_purge_finishes_once();
        use stract::compliance::{model::TicketState, Error};
        let fixture = DomainFixture::new();
        fixture.clock.set_utc(utc("2024-02-29T12:00:00Z")).unwrap();
        let store = fixture.store();
        let runtime = runtime();
        let ticket = runtime.block_on(closed_retention_ticket(&store));
        let second = runtime.block_on(closed_retention_ticket(&store));
        let prefix = fs::read(fixture.path("events.jsonl")).unwrap();
        fixture.clock.set_utc(utc("2027-02-28T11:59:59Z")).unwrap();
        assert!(matches!(
            runtime.block_on(store.purge(ticket.clone(), "reviewer".into(), Arc::new(()))),
            Err(Error::RetentionNotDue)
        ));
        assert_eq!(fs::read(fixture.path("events.jsonl")).unwrap(), prefix);
        let directory = fixture.path("payloads").join(ticket.as_str());
        let sentinel = directory.join("unmanaged.txt");
        fs::write(&sentinel, "keep").unwrap();
        fixture.clock.set_utc(utc("2027-02-28T12:00:00Z")).unwrap();
        let outcome = runtime
            .block_on(store.purge(ticket.clone(), "reviewer".into(), Arc::new(())))
            .unwrap();
        assert_eq!(outcome.ticket.state.as_str(), TicketState::Closed.as_str());
        assert!(outcome.ticket.purged);
        assert!(fs::read(fixture.path("events.jsonl"))
            .unwrap()
            .starts_with(&prefix));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "keep");
        fixture.clock.set_utc(utc("2027-02-28T12:00:01Z")).unwrap();
        let second_directory = fixture.path("payloads").join(second.as_str());
        assert_eq!(fs::read_dir(&second_directory).unwrap().count(), 3);
        let prior = fs::read(fixture.path("events.jsonl")).unwrap();
        let purged = runtime
            .block_on(store.purge(second.clone(), "reviewer".into(), Arc::new(())))
            .unwrap();
        assert_eq!(fs::read_dir(&second_directory).unwrap().count(), 0);
        let after = fs::read(fixture.path("events.jsonl")).unwrap();
        assert!(after.starts_with(&prior));
        let suffix = std::str::from_utf8(&after[prior.len()..])
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
            .collect::<Vec<_>>();
        assert_eq!(suffix, vec![json!("purge_intent"), json!("purged")]);
        assert!(purged.ticket.purged);
        runtime
            .block_on(store.purge(ticket.clone(), "reviewer".into(), Arc::new(())))
            .unwrap();
        assert_eq!(fs::read(fixture.path("events.jsonl")).unwrap(), after);
        runtime.block_on(store.shutdown());
        drop(store);
        let reopened = fixture.store();
        let private = runtime
            .block_on(reopened.read(ticket, "reader".into(), Arc::new(())))
            .unwrap();
        assert!(private.ticket.purged && private.events.is_empty());
        assert!(runtime.block_on(reopened.status(&second)).unwrap().purged);
        runtime.block_on(reopened.shutdown());
    }

    async fn closed_retention_ticket(
        store: &stract::compliance::tickets::ComplianceStore,
    ) -> stract::compliance::model::TicketId {
        use stract::compliance::{
            model::{Decision, IntakeKind},
            tickets::AdministrationEvent,
            Error,
        };
        let admitted = store
            .admit(
                intake(IntakeKind::IllegalContent {
                    suspected_illegality: "Synthetic evidence".into(),
                }),
                Arc::new(()),
            )
            .await
            .unwrap();
        let id = admitted.ticket.id;
        assert!(matches!(
            store
                .purge(id.clone(), "reviewer".into(), Arc::new(()))
                .await,
            Err(Error::InvalidTransition)
        ));
        store
            .administer(
                id.clone(),
                "reviewer".into(),
                AdministrationEvent::Decision {
                    decision: Decision::Refused {
                        reasons: "Synthetic refusal".into(),
                        delivery: delivery(),
                    },
                },
                Arc::new(()),
            )
            .await
            .unwrap();
        store
            .administer(
                id.clone(),
                "reviewer".into(),
                AdministrationEvent::Closure {
                    reasons: "Synthetic closure".into(),
                },
                Arc::new(()),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .read(id.clone(), "reader".into(), Arc::new(()))
                .await
                .unwrap()
                .events
                .len(),
            3
        );
        id
    }

    fn interrupted_purge_finishes_once() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use stract::compliance::{
            disk::ComplianceStage,
            model::{Decision, IntakeKind},
            tickets::AdministrationEvent,
        };
        let fixture = DomainFixture::new();
        let hooks = Arc::new(FailOnce {
            stage: ComplianceStage::AfterPurgeDelete,
            remaining: AtomicUsize::new(0),
        });
        let store = fixture.store_with_hooks(hooks.clone());
        let runtime = runtime();
        let id = runtime.block_on(async {
            let id = store
                .admit(intake(IntakeKind::OnlineSafetyComplaint), Arc::new(()))
                .await
                .unwrap()
                .ticket
                .id;
            store
                .administer(
                    id.clone(),
                    "reviewer".into(),
                    AdministrationEvent::Decision {
                        decision: Decision::Refused {
                            reasons: "Synthetic refusal".into(),
                            delivery: delivery(),
                        },
                    },
                    Arc::new(()),
                )
                .await
                .unwrap();
            store
                .administer(
                    id.clone(),
                    "reviewer".into(),
                    AdministrationEvent::Closure {
                        reasons: "Synthetic closure".into(),
                    },
                    Arc::new(()),
                )
                .await
                .unwrap();
            fixture.clock.set_utc(utc("2029-09-18T12:00:00Z")).unwrap();
            hooks.remaining.store(1, SeqCst);
            assert!(store
                .purge(id.clone(), "reviewer".into(), Arc::new(()))
                .await
                .is_err());
            store.shutdown().await;
            id
        });
        drop(store);
        let prefix = fs::read(fixture.path("events.jsonl")).unwrap();
        let reopened = fixture.store();
        runtime.block_on(async {
            let private = reopened
                .read(id.clone(), "reader".into(), Arc::new(()))
                .await;
            assert!(private.is_ok(), "recovered purge read unavailable");
            let private = private.unwrap();
            assert!(private.ticket.purged && private.events.is_empty());
            reopened.shutdown().await;
        });
        drop(reopened);
        let once = fs::read(fixture.path("events.jsonl")).unwrap();
        assert!(once.starts_with(&prefix));
        assert_eq!(
            fs::read_dir(fixture.path("payloads").join(id.as_str()))
                .unwrap()
                .count(),
            0
        );
        let reopened = fixture.store();
        runtime.block_on(reopened.shutdown());
        drop(reopened);
        assert_eq!(fs::read(fixture.path("events.jsonl")).unwrap(), once);
    }

    #[test]
    fn payload_commitments_bind_random_salt_ticket_and_content() {
        use stract::compliance::{
            model::{Hex64, IntakeKind, TicketId},
            payload::{commitment, PayloadStore, PersonalEvent},
        };
        let id = TicketId::parse(
            &(0..32)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        let salt = Hex64::parse(
            &(32..64)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        let content = PersonalEvent::Closure {
            reasons: "synthetic".into(),
        };
        let canonical = format!(
            "{{\"content\":{{\"kind\":\"closure\",\"reasons\":\"synthetic\"}},\"format_version\":1,\"sequence\":7,\"ticket_id\":\"{}\"}}",
            id.as_str());
        let mut independent = b"AVA619-PAYLOAD-v1\0".to_vec();
        independent.extend(32u8..64);
        independent.extend((canonical.len() as u64).to_be_bytes());
        independent.extend(canonical.as_bytes());
        const FIXED: &str = "ab9248b3e2328808e64b9a25ad98729b1c4ccfc3887523b2df66d4d1f080f11d";
        assert_eq!(digest(&independent), FIXED);
        assert_eq!(
            commitment(&id, 7, &salt, &content).unwrap(),
            digest(&independent)
        );
        let other_salt = Hex64::parse(
            &(64..96)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        assert_ne!(
            commitment(&id, 7, &salt, &content).unwrap(),
            commitment(&id, 7, &other_salt, &content).unwrap()
        );
        let fixture = DomainFixture::new();
        let store = fixture.store();
        let runtime = runtime();
        let admitted = runtime
            .block_on(store.admit(
                intake(IntakeKind::IllegalContent {
                    suspected_illegality: "Synthetic evidence".into(),
                }),
                Arc::new(()),
            ))
            .unwrap();
        let ticket = admitted.ticket;
        let expected = ticket.references.get(&1).unwrap();
        let payloads = PayloadStore::new(&fixture.config, Arc::new(NoHooks));
        let path = fixture
            .path("payloads")
            .join(ticket.id.as_str())
            .join(format!("{:020}.json", 1));
        let original = fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        for field in ["salt", "ticket_id", "sequence", "content"] {
            let (before, after) = match field {
                "salt" => (
                    value[field].to_string(),
                    json!(other_salt.as_str()).to_string(),
                ),
                "ticket_id" => (value[field].to_string(), json!(id.as_str()).to_string()),
                "sequence" => ("\"sequence\":1".into(), "\"sequence\":2".into()),
                _ => (
                    "Synthetic private narrative".into(),
                    "Altered synthetic narrative".into(),
                ),
            };
            // Keep the canonical field order so only the commitment/identity guard can reject.
            let text = std::str::from_utf8(&original).unwrap();
            assert_eq!(text.matches(&before).count(), 1);
            fs::write(&path, text.replacen(&before, &after, 1)).unwrap();
            assert!(payloads.read(&ticket.id, 1, expected).is_err());
            fs::write(&path, &original).unwrap();
        }
        let saved = path.with_extension("saved");
        fs::rename(&path, &saved).unwrap();
        assert!(payloads
            .read_authorized(&ticket.id, 1, expected, false)
            .is_err());
        assert!(payloads
            .read_authorized(&ticket.id, 1, expected, true)
            .unwrap()
            .is_none());
        fs::rename(saved, &path).unwrap();
        assert!(matches!(
            payloads.read(&ticket.id, 1, expected).unwrap(),
            PersonalEvent::Intake { .. }
        ));
        let chain = fs::read_to_string(fixture.path("events.jsonl")).unwrap();
        assert!(
            !chain.contains(value["salt"].as_str().unwrap())
                && !chain.contains("Synthetic private narrative")
        );
        runtime.block_on(store.shutdown());
    }

    fn interrupted_intake(stage: stract::compliance::disk::ComplianceStage, occurrence: usize) {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use stract::compliance::{
            model::{IntakeKind, TicketId},
            tickets::QueueView,
        };
        let fixture = DomainFixture::new();
        let hooks = Arc::new(FailOnce {
            stage,
            remaining: AtomicUsize::new(0),
        });
        let store = fixture.store_with_hooks(hooks.clone());
        let runtime = runtime();
        hooks.remaining.store(occurrence, SeqCst);
        let result = runtime.block_on(store.admit(
            intake(IntakeKind::IntimateImages {
                intimate_image_content: true,
                subject_or_authorised: true,
                good_faith: true,
            }),
            Arc::new(()),
        ));
        assert!(result.is_err());
        runtime.block_on(store.shutdown());
        drop(store);
        let persisted_rules = read_json(&fixture.config.rules_dir().join("snapshot.json"));
        if stage == stract::compliance::disk::ComplianceStage::AfterIntentSync {
            assert!(persisted_rules["rules"].as_array().unwrap().is_empty());
        }
        let first: serde_json::Value = serde_json::from_str(
            fs::read_to_string(fixture.path("events.jsonl"))
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let id = TicketId::parse(first["ticket_id"].as_str().unwrap()).unwrap();
        let opened = fixture.try_store();
        assert!(opened.is_ok(), "recovered intake reopen refused");
        let reopened = opened.unwrap();
        runtime.block_on(async {
            let status = reopened.status(&id).await;
            assert!(status.is_ok(), "recovered intake status unavailable");
            recovered_intake_rule_records(&fixture, &id);
            let status = status.unwrap();
            assert_eq!(status.state.as_str(), "queued");
            assert_eq!(
                status.times.received_at,
                utc("2026-09-18T12:00:00Z").timestamp()
            );
            assert_eq!(
                reopened
                    .queue("reader", None, 20, QueueView::Open)
                    .await
                    .unwrap()
                    .items
                    .len(),
                1
            );
            reopened.shutdown().await;
        });
        drop(reopened);
        let once = fs::read(fixture.path("events.jsonl")).unwrap();
        let rules_once = fs::read(fixture.config.rules_dir().join("snapshot.json")).unwrap();
        let opened = fixture.try_store();
        assert!(opened.is_ok(), "recovered intake reopen refused");
        let reopened = opened.unwrap();
        runtime.block_on(reopened.shutdown());
        drop(reopened);
        assert_eq!(fs::read(fixture.path("events.jsonl")).unwrap(), once);
        assert_eq!(
            fs::read(fixture.config.rules_dir().join("snapshot.json")).unwrap(),
            rules_once
        );
    }

    #[test]
    fn intent_rule_completion_crashes_recover_idempotently() {
        use stract::compliance::disk::ComplianceStage as S;
        for (stage, occurrence) in [
            (S::AfterIntentSync, 1),
            (S::AfterRulesSync, 1),
            (S::BeforeCompletionRow, 1),
            (S::AfterHeadRename, 1),
            (S::AfterHeadSync, 1),
            (S::AfterJournalSync, 1),
            (S::AfterJournalSync, 4),
        ] {
            interrupted_intake(stage, occurrence);
        }
        for operation in ["granted", "not_intimate_image", "no_standing", "reversal"] {
            for stage in [
                S::AfterJournalSync,
                S::AfterIntentSync,
                S::AfterRulesSync,
                S::BeforeCompletionRow,
            ] {
                interrupted_action(operation, stage);
            }
        }
        completed_rule_is_required();
    }

    fn decision_event(kind: &str) -> stract::compliance::tickets::AdministrationEvent {
        use stract::compliance::{model::Decision, tickets::AdministrationEvent};
        let reasons = "Synthetic disposition".into();
        let decision = match kind {
            "not_intimate_image" => Decision::NotIntimateImage {
                reasons,
                delivery: delivery(),
            },
            "no_standing" => Decision::NoStanding {
                reasons,
                delivery: delivery(),
            },
            _ => Decision::Granted {
                reasons,
                delivery: delivery(),
                assessment: None,
            },
        };
        AdministrationEvent::Decision { decision }
    }

    fn interrupted_action(operation: &str, stage: stract::compliance::disk::ComplianceStage) {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use stract::compliance::{model::IntakeKind, tickets::AdministrationEvent};
        let fixture = DomainFixture::new();
        let hooks = Arc::new(FailOnce {
            stage,
            remaining: AtomicUsize::new(0),
        });
        let store = fixture.store_with_hooks(hooks.clone());
        let runtime = runtime();
        let id = runtime.block_on(async {
            seed_recovery_sentinels(&store).await;
            let category = if matches!(operation, "not_intimate_image" | "no_standing") {
                IntakeKind::IntimateImages {
                    intimate_image_content: true,
                    subject_or_authorised: true,
                    good_faith: true,
                }
            } else {
                IntakeKind::IllegalContent {
                    suspected_illegality: "Synthetic evidence".into(),
                }
            };
            let id = store
                .admit(intake(category), Arc::new(()))
                .await
                .unwrap()
                .ticket
                .id;
            if operation == "reversal" {
                store
                    .administer(
                        id.clone(),
                        "reviewer".into(),
                        decision_event("granted"),
                        Arc::new(()),
                    )
                    .await
                    .unwrap();
                store
                    .administer(
                        id.clone(),
                        "reviewer".into(),
                        AdministrationEvent::Appeal {
                            reasons: "Synthetic appeal".into(),
                            related_ticket_id: None,
                        },
                        Arc::new(()),
                    )
                    .await
                    .unwrap();
            }
            hooks.remaining.store(1, SeqCst);
            let event = if operation == "reversal" {
                AdministrationEvent::Reversal {
                    reasons: "Synthetic reversal".into(),
                    delivery: delivery(),
                }
            } else {
                decision_event(operation)
            };
            assert!(store
                .administer(id.clone(), "reviewer".into(), event, Arc::new(()))
                .await
                .is_err());
            store.shutdown().await;
            id
        });
        drop(store);
        let sentinels = recovery_sentinels(&fixture);
        check_interrupted_rules(&fixture, operation, stage);
        let events = fs::read_to_string(fixture.path("events.jsonl")).unwrap();
        let last: serde_json::Value = serde_json::from_str(events.lines().last().unwrap()).unwrap();
        assert_eq!(
            last["event"],
            if operation == "reversal" {
                "reversal_intent"
            } else if stage == stract::compliance::disk::ComplianceStage::AfterJournalSync {
                "decided"
            } else {
                "action_intent"
            }
        );
        let reopened = fixture.store();
        recovered_rule_records(&fixture, &id, operation, &sentinels);
        runtime.block_on(async {
            let ticket = reopened.status(&id).await.unwrap();
            assert!(ticket.pending.is_none());
            assert_eq!(
                ticket.state.as_str(),
                match operation {
                    "granted" => "actioned",
                    "reversal" => "reversed",
                    _ => "decided",
                }
            );
            reopened.shutdown().await;
        });
        drop(reopened);
        let once = tree(fixture.config.store_dir());
        let reopened = fixture.store();
        runtime.block_on(reopened.shutdown());
        drop(reopened);
        assert_eq!(tree(fixture.config.store_dir()), once);
    }

    async fn seed_recovery_sentinels(store: &stract::compliance::tickets::ComplianceStore) {
        use stract::compliance::{
            model::{Asset, DocumentKey, IntakeKind},
            tickets::AdministrationEvent,
        };
        for (host, reverse) in [("rule-sentinel", false), ("marker-sentinel", true)] {
            let mut content = intake(IntakeKind::IllegalContent {
                suspected_illegality: "Synthetic evidence".into(),
            });
            let url = format!("https://{host}.example.test/item");
            content.assets = vec![Asset::new(
                url.clone(),
                DocumentKey::parse(&digest(url.as_bytes())).unwrap(),
            )
            .unwrap()];
            let id = store.admit(content, Arc::new(())).await.unwrap().ticket.id;
            store
                .administer(
                    id.clone(),
                    "reviewer".into(),
                    decision_event("granted"),
                    Arc::new(()),
                )
                .await
                .unwrap();
            if reverse {
                store
                    .administer(
                        id.clone(),
                        "reviewer".into(),
                        AdministrationEvent::Appeal {
                            reasons: "Synthetic appeal".into(),
                            related_ticket_id: None,
                        },
                        Arc::new(()),
                    )
                    .await
                    .unwrap();
                store
                    .administer(
                        id,
                        "reviewer".into(),
                        AdministrationEvent::Reversal {
                            reasons: "Synthetic reversal".into(),
                            delivery: delivery(),
                        },
                        Arc::new(()),
                    )
                    .await
                    .unwrap();
            }
        }
    }

    fn recovery_sentinels(fixture: &DomainFixture) -> serde_json::Value {
        let snapshot = read_json(&fixture.config.rules_dir().join("snapshot.json"));
        let rule = digest(b"https://rule-sentinel.example.test/item");
        let marker = digest(b"https://marker-sentinel.example.test/item");
        let rules = snapshot["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["document_id"] == rule)
            .collect::<Vec<_>>();
        let markers = snapshot["do_not_reapply"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["document_id"] == marker)
            .collect::<Vec<_>>();
        let records = json!({"rules":rules, "markers":markers});
        assert_eq!(records["rules"].as_array().unwrap().len(), 1);
        assert_eq!(records["markers"].as_array().unwrap().len(), 1);
        records
    }

    fn recovered_intake_rule_records(
        fixture: &DomainFixture,
        id: &stract::compliance::model::TicketId,
    ) {
        let snapshot = read_json(&fixture.config.rules_dir().join("snapshot.json"));
        let rules = snapshot["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "recovered intake rule count");
        assert!(snapshot["do_not_reapply"].as_array().unwrap().is_empty());
        assert_eq!(
            rules[0]["document_id"],
            digest(b"https://synthetic.example.test/item")
        );
        assert_eq!(rules[0]["ticket_id"], id.as_str());
        assert_eq!(rules[0]["ground"], "intimate_images");
        let rows = fs::read_to_string(fixture.path("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let intent = rows
            .iter()
            .find(|row| row["ticket_id"] == id.as_str() && row["event"] == "action_intent")
            .unwrap();
        assert_eq!(rules[0]["intent_sequence"], intent["sequence"]);
    }

    fn recovered_rule_records(
        fixture: &DomainFixture,
        id: &stract::compliance::model::TicketId,
        operation: &str,
        sentinels: &serde_json::Value,
    ) {
        assert_eq!(&recovery_sentinels(fixture), sentinels);
        let snapshot = read_json(&fixture.config.rules_dir().join("snapshot.json"));
        let document = digest(b"https://synthetic.example.test/item");
        let rules = snapshot["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["document_id"] == document)
            .collect::<Vec<_>>();
        let markers = snapshot["do_not_reapply"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["document_id"] == document)
            .collect::<Vec<_>>();
        assert_eq!(rules.len(), usize::from(operation == "granted"));
        assert_eq!(markers.len(), usize::from(operation == "reversal"));
        let rows = fs::read_to_string(fixture.path("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let expected = if operation == "reversal" {
            "reversal_intent"
        } else {
            "action_intent"
        };
        let intent = rows
            .iter()
            .rev()
            .find(|row| row["ticket_id"] == id.as_str() && row["event"] == expected)
            .unwrap();
        for record in rules.iter().chain(markers.iter()) {
            assert_eq!(record["ground"], "illegal_content");
            assert_eq!(record["intent_sequence"], intent["sequence"]);
        }
        if let Some(rule) = rules.first() {
            assert_eq!(rule["ticket_id"], id.as_str());
        }
    }

    fn completed_rule_is_required() {
        use stract::compliance::{
            model::{IntakeKind, SystemEntropy},
            rules::NoRulesHooks,
            tickets::{ComplianceStore, NoObserver},
            Error,
        };
        let fixture = DomainFixture::new();
        let store = fixture.store();
        let runtime = runtime();
        let original = fs::read(fixture.config.rules_dir().join("snapshot.json")).unwrap();
        runtime.block_on(async {
            let id = store
                .admit(
                    intake(IntakeKind::IllegalContent {
                        suspected_illegality: "Synthetic evidence".into(),
                    }),
                    Arc::new(()),
                )
                .await
                .unwrap()
                .ticket
                .id;
            store
                .administer(
                    id,
                    "reviewer".into(),
                    decision_event("granted"),
                    Arc::new(()),
                )
                .await
                .unwrap();
            store.shutdown().await;
        });
        drop(store);
        fs::write(fixture.config.rules_dir().join("snapshot.json"), original).unwrap();
        assert!(matches!(
            ComplianceStore::open(
                &fixture.config,
                fixture.clock.clone(),
                Arc::new(SystemEntropy),
                Arc::new(NoHooks),
                Arc::new(NoRulesHooks),
                Arc::new(NoObserver),
                false
            ),
            Err(Error::RulesUnavailable)
        ));
    }

    #[test]
    fn private_stores_refuse_unsafe_paths_and_second_owners() {
        unsafe_kind_boundaries();
        use std::os::unix::fs::{symlink, MetadataExt};
        use stract::compliance::{
            disk,
            listed::ListedMatcher,
            model::IntakeKind,
            payload::PayloadStore,
            rules::{NoRulesHooks, RulesStore},
        };
        let fixture = DomainFixture::new();
        let journal = fixture.journal();
        check_owner_in_child(&fixture);
        drop(journal);
        let metadata = fs::metadata(fixture.path("head.json")).unwrap();
        let uid = metadata.uid();
        assert!(disk::validate_file_facts(true, 1, uid, 0o600, uid).is_ok());
        assert!(disk::validate_file_facts(true, 1, uid.wrapping_add(1), 0o600, uid).is_err());
        assert!(disk::validate_parent_facts(uid.wrapping_add(1), 0o700, uid).is_err());
        for fault in 0..4 {
            let path = fixture.path("head.json");
            let saved = fixture.path("head.saved");
            fs::rename(&path, &saved).unwrap();
            match fault {
                0 => symlink(&saved, &path).unwrap(),
                1 => fs::hard_link(&saved, &path).unwrap(),
                2 => fs::create_dir(&path).unwrap(),
                _ => {
                    fs::copy(&saved, &path).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            assert!(
                Journal::open(&fixture.config, fixture.clock.clone(), Arc::new(NoHooks)).is_err()
            );
            if fault == 2 {
                fs::remove_dir(&path).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
            fs::rename(saved, path).unwrap();
        }
        assert!(Journal::open(&fixture.config, fixture.clock.clone(), Arc::new(NoHooks)).is_ok());
        let fixture = DomainFixture::new();
        let store = fixture.store();
        let runtime = runtime();
        let admitted = runtime
            .block_on(store.admit(
                intake(IntakeKind::IllegalContent {
                    suspected_illegality: "Synthetic evidence".into(),
                }),
                Arc::new(()),
            ))
            .unwrap();
        let ticket = admitted.ticket;
        let path = fixture
            .path("payloads")
            .join(ticket.id.as_str())
            .join(format!("{:020}.json", 1));
        let payload = PayloadStore::new(&fixture.config, Arc::new(NoHooks));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(payload
            .read(&ticket.id, 1, ticket.references.get(&1).unwrap())
            .is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(payload
            .read(&ticket.id, 1, ticket.references.get(&1).unwrap())
            .is_ok());
        runtime.block_on(store.shutdown());
        drop(store);
        let path = fixture.config.rules_dir().join("snapshot.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(RulesStore::open(
            &fixture.config,
            fixture.clock.clone(),
            ListedMatcher::empty(),
            Arc::new(NoHooks),
            Arc::new(NoRulesHooks)
        )
        .is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let rules = RulesStore::open(
            &fixture.config,
            fixture.clock.clone(),
            ListedMatcher::empty(),
            Arc::new(NoHooks),
            Arc::new(NoRulesHooks),
        )
        .unwrap();
        assert!(RulesStore::open(
            &fixture.config,
            fixture.clock.clone(),
            ListedMatcher::empty(),
            Arc::new(NoHooks),
            Arc::new(NoRulesHooks)
        )
        .is_err());
        drop(rules);
    }

    fn unsafe_kind_boundaries() {
        for kind in ["journal", "payload", "rules"] {
            healthy_kind_control(kind);
            for fault in [4, 0, 1, 2, 3, 5, 6, 7] {
                unsafe_kind_case(kind, fault);
            }
        }
    }

    fn check_owner_in_child(fixture: &DomainFixture) {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "contracts::compliance_owner_child",
                "--nocapture",
            ])
            .env("AVA619_OWNER_ROOT", fixture.config.store_dir())
            .output()
            .unwrap();
        assert!(child.status.success());
        println!("owned child reaped=true status={}", child.status);
    }

    fn healthy_kind_control(kind: &str) {
        use std::sync::atomic::Ordering::SeqCst;
        use stract::compliance::{
            model::{IntakeKind, SystemEntropy},
            tickets::{ComplianceStore, NoObserver},
        };
        let fixture = DomainFixture::new();
        let counts = Arc::new(FileCounts::default());
        let store = ComplianceStore::open(
            &fixture.config,
            fixture.clock.clone(),
            Arc::new(SystemEntropy),
            counts.clone(),
            counts.clone(),
            Arc::new(NoObserver),
            false,
        )
        .unwrap();
        runtime().block_on(async {
            let admitted = store
                .admit(
                    intake(IntakeKind::IntimateImages {
                        intimate_image_content: true,
                        subject_or_authorised: true,
                        good_faith: true,
                    }),
                    Arc::new(()),
                )
                .await
                .unwrap();
            let read = store
                .read(admitted.ticket.id, "reader".into(), Arc::new(()))
                .await
                .unwrap();
            assert_eq!(read.events.len(), 1);
            assert!(counts.opens.load(SeqCst) > 0);
            assert!(counts.decodes.load(SeqCst) > 0);
            assert!(counts.writes.load(SeqCst) > 0);
            assert!(counts.rules[1..].iter().all(|count| count.load(SeqCst) > 0));
            store.shutdown().await;
        });
        drop(store);
        let reopened = stract::compliance::rules::RulesStore::open(
            &fixture.config,
            fixture.clock.clone(),
            stract::compliance::listed::ListedMatcher::empty(),
            counts.clone(),
            counts.clone(),
        )
        .unwrap();
        assert!(counts.rules[0].load(SeqCst) > 0);
        drop(reopened);
        println!("healthy adapter control completed: {kind}");
    }

    fn unsafe_kind_case(kind: &str, fault: usize) {
        use std::{os::unix::fs::symlink, sync::atomic::Ordering::SeqCst};
        use stract::compliance::{
            listed::ListedMatcher, model::IntakeKind, payload::PayloadStore, rules::RulesStore,
        };
        let fixture = DomainFixture::new();
        let store = fixture.store();
        let ticket = runtime().block_on(async {
            let result = store
                .admit(intake(IntakeKind::OnlineSafetyComplaint), Arc::new(()))
                .await
                .unwrap();
            store.shutdown().await;
            result.ticket
        });
        drop(store);
        let leaf = match kind {
            "journal" => fixture.path("owner.lock"),
            "rules" => fixture.config.rules_dir().join("owner.lock"),
            _ => fixture
                .path("payloads")
                .join(ticket.id.as_str())
                .join(format!("{:020}.json", 1)),
        };
        let path = match fault {
            5 | 6 => leaf.parent().unwrap().to_owned(),
            7 => fixture.config.store_dir().to_owned(),
            _ => leaf,
        };
        let saved = path.with_file_name(format!(
            "{}.saved",
            path.file_name().unwrap().to_str().unwrap()
        ));
        let original_mode = fs::metadata(&path).unwrap().permissions().mode();
        if matches!(fault, 4 | 5) {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        } else {
            fs::rename(&path, &saved).unwrap();
            match fault {
                0 | 6 | 7 => symlink(&saved, &path).unwrap(),
                1 => symlink(path.with_file_name("absent-target"), &path).unwrap(),
                2 => fs::hard_link(&saved, &path).unwrap(),
                3 => fs::create_dir(&path).unwrap(),
                _ => unreachable!(),
            }
        }
        let counts = Arc::new(FileCounts::default());
        let refused = match kind {
            "journal" => {
                Journal::open(&fixture.config, fixture.clock.clone(), counts.clone()).is_err()
            }
            "rules" => RulesStore::open(
                &fixture.config,
                fixture.clock.clone(),
                ListedMatcher::empty(),
                counts.clone(),
                counts.clone(),
            )
            .is_err(),
            _ => PayloadStore::new(&fixture.config, counts.clone())
                .read(&ticket.id, 1, ticket.references.get(&1).unwrap())
                .is_err(),
        };
        if matches!(fault, 4 | 5) {
            fs::set_permissions(&path, fs::Permissions::from_mode(original_mode)).unwrap();
        } else {
            if fault == 3 {
                fs::remove_dir(&path).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
            fs::rename(saved, path).unwrap();
        }
        assert_eq!(counts.opens.load(SeqCst), 0, "{kind}/{fault}");
        assert_eq!(counts.decodes.load(SeqCst), 0, "{kind}/{fault}");
        assert_eq!(counts.writes.load(SeqCst), 0, "{kind}/{fault}");
        assert!(counts.rules.iter().all(|count| count.load(SeqCst) == 0));
        assert!(refused, "{kind}/{fault}");
    }

    #[test]
    #[ignore = "Invoked in an owned child process by the compliance owner-lock witness"]
    fn compliance_owner_child() {
        let root = std::path::PathBuf::from(
            std::env::var_os("AVA619_OWNER_ROOT").expect("parent supplies owned root"),
        );
        let settings = stract::config::compliance::ComplianceConfig {
            store_dir: Some(root.clone()),
            ..Default::default()
        };
        let config = settings
            .validate(&root.parent().unwrap().join("suppression.json"))
            .unwrap();
        let clock = Arc::new(stract::crawler::politeness::ManualClock::new(utc(
            "2026-09-18T12:00:00Z",
        )));
        assert!(Journal::open(&config, clock, Arc::new(NoHooks)).is_err());
        println!("owner-lock child pid={} rejected=true", std::process::id());
    }

    #[test]
    fn token_file_hardening_and_absence_fail_closed() {
        let trace = TraceCapture::new();
        tracing::info!("synthetic token capture control");
        token_http_controls();
        use std::os::unix::fs::symlink;
        use stract::compliance::{
            auth::{AuthObserver, Authenticator},
            model::{Entropy, SystemEntropy},
        };
        struct Seen;
        impl AuthObserver for Seen {}
        let fixture = DomainFixture::new();
        let parent = fixture.config.store_dir().parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.join("synthetic.token");
        let mut raw = [0u8; 32];
        SystemEntropy.fill(&mut raw).unwrap();
        raw[0] = 0xab;
        let token = raw
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!Authenticator::load(None, &NoHooks)
            .unwrap()
            .authorises([format!("Bearer {token}").as_bytes()], &Seen));
        assert!(Authenticator::load(Some(&path), &NoHooks).is_err());
        let valid = format!("Bearer {token}");
        for (bytes, okay) in [
            (token.as_bytes().to_vec(), true),
            (format!("{token}\n").into_bytes(), true),
            (token.as_bytes()[..63].to_vec(), false),
            (format!("{token}x").into_bytes(), false),
            (format!("{token}\n\n").into_bytes(), false),
            ("G".repeat(64).into_bytes(), false),
            (token.to_ascii_uppercase().into_bytes(), false),
        ] {
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let loaded = Authenticator::load(Some(&path), &NoHooks);
            assert_eq!(loaded.is_ok(), okay);
            if let Ok(auth) = loaded {
                assert!(auth.authorises([valid.as_bytes()], &Seen));
            }
        }
        fs::write(&path, &token).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Authenticator::load(Some(&path), &NoHooks).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let saved = path.with_extension("saved");
        fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        assert!(Authenticator::load(Some(&path), &NoHooks).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&saved, &path).unwrap();
        assert!(Authenticator::load(Some(&path), &NoHooks).is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(saved, &path).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Authenticator::load(Some(&path), &NoHooks).is_err());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Authenticator::load(Some(&path), &NoHooks).is_ok());
        let text = trace.text();
        assert!(text.contains("synthetic token capture control"));
        assert!(!text.contains(&token));
        assert!(!text.contains(&valid));
        let encoded = token
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!text.contains(&encoded));
    }

    fn token_http_controls() {
        let trace = TraceCapture::new();
        let fixture = HttpFixture::new();
        let runtime = runtime();
        let id = runtime.block_on(async {
            let admitted = fixture
                .state
                .compliance()
                .admit(
                    intake(stract::compliance::model::IntakeKind::OnlineSafetyComplaint),
                    Arc::new(()),
                )
                .await
                .unwrap();
            token_management(&fixture, admitted.ticket.id.as_str(), true).await;
            fixture.state.compliance().shutdown().await;
            admitted.ticket.id.as_str().to_owned()
        });
        let path = fixture
            .domain
            .config
            .settings()
            .admin_token_file
            .clone()
            .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let fixture = fixture.reopen();
        runtime.block_on(async {
            token_management(&fixture, &id, false).await;
            let before = tree(fixture.domain.config.store_dir());
            let writes = fixture
                .probe
                .writes
                .load(std::sync::atomic::Ordering::SeqCst);
            let rejected = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/online-safety-complaints",
                    json!({"report":report()}),
                    false,
                )
                .await;
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(
                fixture
                    .probe
                    .writes
                    .load(std::sync::atomic::Ordering::SeqCst),
                writes
            );
            contract_headers(&rejected);
            assert_eq!(rejected.value["error"]["code"], "compliance_unavailable");
            assert_eq!(rejected.status, 503);
            for path in ["/v1/reports".into(), format!("/v1/reports/status/{id}")] {
                let response = fixture
                    .send(false, "GET", &path, serde_json::Value::Null, false)
                    .await;
                assert_eq!(tree(fixture.domain.config.store_dir()), before);
                contract_headers(&response);
                assert_eq!(response.value["version"], "v1");
                assert_eq!(response.status, 200);
            }
            fixture.state.compliance().shutdown().await;
        });
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let fixture = fixture.reopen();
        runtime.block_on(async {
            token_management(&fixture, &id, true).await;
            let admitted = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/online-safety-complaints",
                    json!({"report":report()}),
                    false,
                )
                .await;
            contract_headers(&admitted);
            assert!(admitted.value["ticket_id"].is_string());
            assert_eq!(admitted.status, 200);
        });
        let text = trace.text();
        assert!(!text.contains(&fixture.token));
        assert!(!text.contains(&format!("Bearer {}", fixture.token)));
        let encoded = fixture
            .token
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!text.contains(&encoded));
    }

    async fn token_management(fixture: &HttpFixture, id: &str, valid: bool) {
        use axum::{body::Body, http::Request};
        use std::sync::atomic::Ordering::SeqCst;
        let before = tree(fixture.domain.config.store_dir());
        let counts = (
            fixture.probe.decodes.load(SeqCst),
            fixture.probe.lookups.load(SeqCst),
            fixture.probe.writes.load(SeqCst),
        );
        for path in [
            "/v1/compliance/queue".into(),
            format!("/v1/compliance/tickets/{id}/read"),
        ] {
            for credential in [
                Some(format!("Bearer {}", fixture.token)),
                Some("Bearer synthetic-invalid".into()),
                None,
            ] {
                let accepted = valid && credential == Some(format!("Bearer {}", fixture.token));
                let mut request = Request::builder()
                    .method("POST")
                    .uri(&path)
                    .header("content-type", "application/json");
                if let Some(credential) = credential {
                    request = request.header("authorization", credential);
                }
                let denied_counts = (
                    fixture.probe.decodes.load(SeqCst),
                    fixture.probe.lookups.load(SeqCst),
                );
                let response = fixture
                    .raw(
                        true,
                        request.body(Body::from("{\"actor\":\"reader\"}")).unwrap(),
                    )
                    .await;
                assert_eq!(tree(fixture.domain.config.store_dir()), before);
                assert_eq!(fixture.probe.writes.load(SeqCst), counts.2);
                if !accepted {
                    assert_eq!(
                        (
                            fixture.probe.decodes.load(SeqCst),
                            fixture.probe.lookups.load(SeqCst)
                        ),
                        denied_counts
                    );
                }
                contract_headers(&response);
                assert_eq!(response.value["version"], "v1");
                if accepted {
                    assert!(response.value.get("error").is_none());
                    assert_eq!(response.status, 200);
                } else {
                    assert_eq!(response.value["error"]["code"], "unauthorised");
                    assert_eq!(response.status, 401);
                }
            }
        }
        if !valid {
            assert_eq!(
                (
                    fixture.probe.decodes.load(SeqCst),
                    fixture.probe.lookups.load(SeqCst)
                ),
                (counts.0, counts.1)
            );
        }
        let search = fixture
            .send(false, "POST", "/v1/search", json!({"query":"cedar"}), false)
            .await;
        assert_eq!(tree(fixture.domain.config.store_dir()), before);
        contract_headers(&search);
        assert!(search.value["results"].is_array());
        assert_eq!(search.status, 200);
    }

    #[test]
    fn store_caps_reject_before_decode_or_partial_transactions() {
        full_store_draws_no_entropy();
        delisting_entropy_reservations();
        journal_transaction_boundaries();
        reserved_purge_headroom();
        journal_file_cap_precedes_decode();
        payload_transaction_boundaries();
        payload_file_boundaries();
        journal_row_boundaries();
        listed_owner_boundaries();
        rule_owner_boundaries();
        event_capacity_precedes_personal_write();
        bounded_metadata_and_growing_stream();
        use stract::compliance::{bounds, model::IntakeKind, Error};
        assert!(bounds::reserve(u64::MAX, 1, u64::MAX, 0).is_err());
        assert!(bounds::reserve(0, 1, 0, 1).is_err());
        let fixture = HttpFixture::configured(|config| {
            config.compliance.max_tickets = 1;
            config.compliance.max_rules = 1;
        });
        let runtime = runtime();
        runtime.block_on(async {
            let before = tree(fixture.domain.config.store_dir());
            let too_many = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/intimate-images",
                    serde_json::json!({"report":report(),
                "urls":["https://first.example.test/item","https://second.example.test/item"],
                "intimate_image_content":true,"subject_or_authorised":true,"good_faith":true}),
                    false,
                )
                .await;
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(
                fixture
                    .probe
                    .writes
                    .load(std::sync::atomic::Ordering::SeqCst),
                0
            );
            contract_headers(&too_many);
            assert_eq!(too_many.value["error"]["code"], "compliance_capacity");
            assert_eq!(too_many.status, 503);
            let first = fixture
                .state
                .compliance()
                .admit(
                    intake(IntakeKind::IllegalContent {
                        suspected_illegality: "Synthetic evidence".into(),
                    }),
                    Arc::new(()),
                )
                .await
                .unwrap();
            let before = tree(fixture.domain.config.store_dir());
            assert!(matches!(
                fixture
                    .state
                    .compliance()
                    .admit(intake(IntakeKind::OnlineSafetyComplaint), Arc::new(()))
                    .await,
                Err(Error::Capacity)
            ));
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert!(fixture
                .state
                .compliance()
                .status(&first.ticket.id)
                .await
                .is_ok());
            super::support::successful_response(
                fixture
                    .send(false, "GET", "/v1/reports", serde_json::Value::Null, false)
                    .await,
            );
            super::support::successful_response(
                fixture
                    .send(false, "POST", "/v1/search", json!({"query":"cedar"}), false)
                    .await,
            );
        });
    }

    fn change_caps(
        fixture: &mut HttpFixture,
        change: impl FnOnce(&mut stract::config::compliance::ComplianceConfig),
    ) {
        let mut settings = fixture.domain.config.settings().clone();
        change(&mut settings);
        let suppression = fixture
            .domain
            .config
            .store_dir()
            .parent()
            .unwrap()
            .join("suppression.json");
        fixture.domain.config = settings.validate(&suppression).unwrap();
    }

    fn progress_body(enquiries: String, update: String) -> serde_json::Value {
        json!({"actor":"reviewer",
            "enquiries":enquiries,
            "update":update,
            "delivery":{"channel":"manual_api",
            "reference":"synthetic-ref"}})
    }

    async fn capacity_progress(
        fixture: &HttpFixture,
        entropy: &CountingEntropy,
        id: &str,
        body: serde_json::Value,
        accepted: bool,
    ) {
        use std::sync::atomic::Ordering::SeqCst;
        let before = tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let draws = entropy.widths.lock().unwrap().len();
        let response = fixture
            .send(
                true,
                "POST",
                &format!("/v1/compliance/tickets/{id}/progress"),
                body,
                true,
            )
            .await;
        if accepted {
            assert_ne!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.writes.load(SeqCst), writes + 1);
            assert_eq!(&entropy.widths.lock().unwrap()[draws..], [32]);
        } else {
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(entropy.widths.lock().unwrap().len(), draws);
        }
        contract_headers(&response);
        if accepted {
            assert_eq!(response.value["state"], "queued");
        } else {
            assert_eq!(response.value["error"]["code"], "compliance_capacity");
        }
        assert_eq!(response.status, if accepted { 200 } else { 503 });
        for path in ["/v1/reports".into(), format!("/v1/reports/status/{id}")] {
            let read = fixture
                .send(false, "GET", &path, serde_json::Value::Null, false)
                .await;
            contract_headers(&read);
            assert_eq!(read.value["version"], "v1");
            assert_eq!(read.status, 200);
        }
        let search = fixture
            .send(false, "POST", "/v1/search", json!({"query":"cedar"}), false)
            .await;
        contract_headers(&search);
        assert!(search.value["results"].is_array());
        assert_eq!(search.status, 200);
    }

    fn journal_transaction_boundaries() {
        for spare in [-1i64, 0, 1] {
            let fixture = HttpFixture::new();
            let runtime = runtime();
            let id = runtime.block_on(async {
                let store = fixture.state.compliance();
                let id = store
                    .admit(
                        intake(stract::compliance::model::IntakeKind::OnlineSafetyComplaint),
                        Arc::new(()),
                    )
                    .await
                    .unwrap()
                    .ticket
                    .id;
                store
                    .administer(
                        id.clone(),
                        "reviewer".into(),
                        stract::compliance::tickets::AdministrationEvent::Progress {
                            enquiries: "enquiry".into(),
                            update: "update".into(),
                            delivery: delivery(),
                        },
                        Arc::new(()),
                    )
                    .await
                    .unwrap();
                store.shutdown().await;
                id
            });
            let entropy = Arc::new(CountingEntropy::default());
            let fixture = fixture.reopen_after(
                |domain| journal_cap_fixture(domain, spare),
                |seams| seams.entropy = entropy.clone(),
            );
            runtime.block_on(capacity_progress(
                &fixture,
                &entropy,
                id.as_str(),
                progress_body("enquiry".into(), "update".into()),
                spare >= 0,
            ));
        }
    }

    fn journal_cap_fixture(domain: &mut DomainFixture, spare: i64) {
        grow_valid_journal(domain);
        let path = domain.path("events.jsonl");
        let bytes = fs::read_to_string(&path).unwrap();
        let rows = bytes
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let mut candidate = rows[3].clone();
        let last = rows.last().unwrap();
        candidate["sequence"] = json!(last["sequence"].as_u64().unwrap() + 1);
        candidate["previous_hash"] = last["hash"].clone();
        candidate["payload_sequence"] = json!(3);
        candidate["commitment"] = json!("0".repeat(64));
        rehash(&mut candidate);
        let required = bytes.len() as u64 + encoded_row(&candidate, true).len() as u64 + 65536;
        assert!(required > 1048577);
        let mut settings = domain.config.settings().clone();
        settings.max_journal_bytes = required.checked_add_signed(spare).unwrap();
        domain.config = settings
            .validate(
                &domain
                    .config
                    .store_dir()
                    .parent()
                    .unwrap()
                    .join("suppression.json"),
            )
            .unwrap();
    }

    fn grow_valid_journal(fixture: &DomainFixture) {
        let seed = DomainFixture::new();
        let mut journal = seed.journal();
        seed.list_row(&mut journal);
        let mut row = read_json_line(&seed.path("events.jsonl"));
        let path = fixture.path("events.jsonl");
        let mut bytes = fs::read(&path).unwrap();
        let last = serde_json::from_slice::<serde_json::Value>(
            bytes
                .split(|byte| *byte == b'\n')
                .rfind(|line| !line.is_empty())
                .unwrap(),
        )
        .unwrap();
        let mut sequence = last["sequence"].as_u64().unwrap();
        let mut previous = last["hash"].clone();
        while bytes.len() < 1048576 {
            sequence += 1;
            row["sequence"] = json!(sequence);
            row["previous_hash"] = previous;
            rehash(&mut row);
            previous = row["hash"].clone();
            bytes.extend(encoded_row(&row, true));
        }
        fs::write(path, &bytes).unwrap();
        fs::write(fixture.path("head.json"), checkpoint(&row, bytes.len())).unwrap();
        let verified = fixture.journal();
        assert_eq!(verified.byte_length(), bytes.len() as u64);
    }

    fn read_json_line(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_str(fs::read_to_string(path).unwrap().lines().next().unwrap()).unwrap()
    }

    fn revision_bytes(id: &str, sequence: u64, enquiries: &str, update: &str) -> usize {
        serde_json::to_vec(&json!({"format_version":1,
            "ticket_id":id,
            "sequence":sequence,
            "salt":"0".repeat(64),
            "content":{"kind":"progress",
                "enquiries":enquiries,
                "update":update,
                "delivery":{"channel":"manual_api",
                "reference":"synthetic-ref"}}}))
        .unwrap()
        .len()
            + 1
    }

    fn payload_bytes(fixture: &HttpFixture, id: &str) -> u64 {
        fs::read_dir(fixture.domain.path("payloads").join(id))
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum()
    }

    async fn fill_personal_history(
        fixture: &HttpFixture,
        id: &stract::compliance::model::TicketId,
        target: u64,
    ) -> u64 {
        use stract::compliance::tickets::AdministrationEvent;
        let mut revision = 2;
        while payload_bytes(fixture, id.as_str()) + 17000 < target {
            let event = AdministrationEvent::Progress {
                enquiries: "\"".repeat(4096),
                update: "\"".repeat(4096),
                delivery: delivery(),
            };
            let outcome = fixture
                .state
                .compliance()
                .administer(id.clone(), "reviewer".into(), event, Arc::new(()))
                .await
                .unwrap();
            assert_eq!(outcome.ticket.events, revision + 2);
            revision += 1;
        }
        revision
    }

    fn tuned_progress(id: &str, sequence: u64, length: usize) -> (String, String) {
        let overhead = revision_bytes(id, sequence, "", "");
        let mut extra = length.checked_sub(overhead).unwrap();
        let mut fields = Vec::new();
        for remaining_fields in [1, 0] {
            let encoded = (extra - remaining_fields).min(8192);
            let quotes = encoded.saturating_sub(4096);
            let plain = encoded - 2 * quotes;
            fields.push(format!("{}{}", "\"".repeat(quotes), "x".repeat(plain)));
            extra -= encoded;
        }
        assert_eq!(extra, 0);
        assert!(fields
            .iter()
            .all(|field| !field.is_empty() && field.len() <= 4096));
        (fields.remove(0), fields.remove(0))
    }

    fn payload_transaction_boundaries() {
        for aggregate in [false, true] {
            for delta in [-1i64, 0, 1] {
                payload_transaction_case(aggregate, delta);
            }
        }
    }

    fn payload_transaction_case(aggregate: bool, delta: i64) {
        let mut fixture = HttpFixture::new();
        let runtime = runtime();
        let (id, sequence, prior) = runtime.block_on(async {
            let store = fixture.state.compliance();
            let mut prior = 0;
            if aggregate {
                let first = store
                    .admit(
                        intake(stract::compliance::model::IntakeKind::OnlineSafetyComplaint),
                        Arc::new(()),
                    )
                    .await
                    .unwrap()
                    .ticket
                    .id;
                fill_personal_history(&fixture, &first, 600000).await;
                prior = payload_bytes(&fixture, first.as_str());
            }
            let id = store
                .admit(
                    intake(stract::compliance::model::IntakeKind::OnlineSafetyComplaint),
                    Arc::new(()),
                )
                .await
                .unwrap()
                .ticket
                .id;
            let sequence = fill_personal_history(&fixture, &id, 1048576 - prior).await;
            store.shutdown().await;
            (id, sequence, prior)
        });
        let current = payload_bytes(&fixture, id.as_str()) + prior;
        let prospective = 1048576u64.checked_add_signed(delta).unwrap();
        let (enquiries, update) =
            tuned_progress(id.as_str(), sequence, (prospective - current) as usize);
        assert_eq!(
            current + revision_bytes(id.as_str(), sequence, &enquiries, &update) as u64,
            prospective
        );
        if aggregate {
            change_caps(&mut fixture, |settings| {
                settings.max_payload_bytes = 1048576
            });
        }
        let entropy = Arc::new(CountingEntropy::default());
        let fixture = fixture.reopen_instrumented(|seams| seams.entropy = entropy.clone());
        runtime.block_on(capacity_progress(
            &fixture,
            &entropy,
            id.as_str(),
            progress_body(enquiries, update),
            delta <= 0,
        ));
    }

    fn payload_file_boundaries() {
        use std::sync::atomic::Ordering::SeqCst;
        use stract::compliance::{
            model::{SystemEntropy, TicketId},
            payload::{Notice, PayloadStore, PersonalEvent},
            Error,
        };
        for length in [65535, 65536, 65537] {
            let fixture = DomainFixture::new();
            let _owner = fixture.journal();
            let counts = Arc::new(FileCounts::default());
            let store = PayloadStore::new(&fixture.config, counts.clone());
            let id = TicketId::parse(&"b".repeat(64)).unwrap();
            let content = |text| PersonalEvent::Uphold {
                reasons: "Synthetic reason".into(),
                delivery: delivery(),
                notice: Notice {
                    text,
                    remedies: vec![],
                },
            };
            let empty = content("x".into());
            let overhead = serde_json::to_vec(&json!({"format_version":1,
                "ticket_id":id.as_str(),
                "sequence":1,
                "salt":"0".repeat(64),
                "content":empty}))
            .unwrap()
            .len();
            let text = "x".repeat(length - overhead);
            let before = tree(fixture.config.store_dir());
            let prepared = store.prepare(&id, 1, content(text.clone()), &SystemEntropy);
            assert_eq!(tree(fixture.config.store_dir()), before);
            if length <= 65536 {
                let prepared = prepared.unwrap();
                assert_eq!(prepared.byte_length(), length as u64);
                store.write(&prepared).unwrap();
                let loaded = store.read(&id, 1, prepared.commitment()).unwrap();
                assert_eq!(
                    serde_json::to_value(loaded).unwrap()["notice"]["text"],
                    text
                );
                let path = fixture
                    .path("payloads")
                    .join(id.as_str())
                    .join("00000000000000000001.json");
                fs::write(&path, vec![b' '; 65537]).unwrap();
                let decodes = counts.decodes.load(SeqCst);
                let rejected = store.read(&id, 1, prepared.commitment());
                assert_eq!(counts.decodes.load(SeqCst), decodes);
                assert!(matches!(rejected, Err(Error::Unavailable)));
            } else {
                assert!(matches!(prepared, Err(Error::Capacity)));
            }
        }
    }

    fn journal_row_boundaries() {
        use std::sync::atomic::Ordering::SeqCst;
        for length in [8191, 8192, 8193] {
            let fixture = DomainFixture::new();
            let mut journal = fixture.journal();
            fixture.list_row(&mut journal);
            drop(journal);
            let canonical = fs::read(fixture.path("events.jsonl")).unwrap();
            let counts = Arc::new(FileCounts::default());
            let valid =
                Journal::open(&fixture.config, fixture.clock.clone(), counts.clone()).unwrap();
            drop(valid);
            let mut padded = canonical[..canonical.len() - 1].to_vec();
            padded.resize(length - 1, b' ');
            padded.push(b'\n');
            let row = read_json_line(&fixture.path("events.jsonl"));
            fs::write(fixture.path("events.jsonl"), padded).unwrap();
            fs::write(fixture.path("head.json"), checkpoint(&row, length)).unwrap();
            let before = tree(fixture.config.store_dir());
            counts.decodes.store(0, SeqCst);
            let refused = Journal::open(&fixture.config, fixture.clock.clone(), counts.clone());
            assert_eq!(tree(fixture.config.store_dir()), before);
            assert_eq!(
                counts.decodes.load(SeqCst),
                if length <= 8192 { 2 } else { 1 }
            );
            assert!(refused.is_err());
        }
    }

    fn journal_file_cap_precedes_decode() {
        use std::sync::atomic::Ordering::SeqCst;
        let fixture = DomainFixture::new();
        drop(fixture.journal());
        let mut settings = fixture.config.settings().clone();
        settings.max_journal_bytes = 1048576;
        let config = settings
            .validate(
                &fixture
                    .config
                    .store_dir()
                    .parent()
                    .unwrap()
                    .join("suppression.json"),
            )
            .unwrap();
        let file = OpenOptions::new()
            .write(true)
            .open(fixture.path("events.jsonl"))
            .unwrap();
        file.set_len(1048577).unwrap();
        file.sync_all().unwrap();
        let counts = Arc::new(FileCounts::default());
        let before = tree(fixture.config.store_dir());
        let refused = Journal::open(&config, fixture.clock.clone(), counts.clone());
        assert_eq!(tree(fixture.config.store_dir()), before);
        assert_eq!(counts.decodes.load(SeqCst), 1);
        assert!(refused.is_err());
    }

    fn reserved_purge_headroom() {
        use stract::compliance::{
            model::{Decision, IntakeKind},
            tickets::AdministrationEvent,
        };
        let fixture = HttpFixture::configured(|config| config.compliance.max_ticket_events = 16);
        let runtime = runtime();
        let id = runtime.block_on(async {
            let store = fixture.state.compliance();
            let id = store
                .admit(intake(IntakeKind::OnlineSafetyComplaint), Arc::new(()))
                .await
                .unwrap()
                .ticket
                .id;
            for _ in 0..7 {
                store
                    .administer(
                        id.clone(),
                        "reviewer".into(),
                        AdministrationEvent::Progress {
                            enquiries: "enquiry".into(),
                            update: "update".into(),
                            delivery: delivery(),
                        },
                        Arc::new(()),
                    )
                    .await
                    .unwrap();
            }
            store
                .administer(
                    id.clone(),
                    "reviewer".into(),
                    AdministrationEvent::Decision {
                        decision: Decision::Granted {
                            reasons: "Synthetic grant".into(),
                            delivery: delivery(),
                            assessment: None,
                        },
                    },
                    Arc::new(()),
                )
                .await
                .unwrap();
            let closed = store
                .administer(
                    id.clone(),
                    "reviewer".into(),
                    AdministrationEvent::Closure {
                        reasons: "Synthetic closure".into(),
                    },
                    Arc::new(()),
                )
                .await
                .unwrap();
            assert_eq!(closed.ticket.events, 12);
            store.shutdown().await;
            id
        });
        let entropy = Arc::new(CountingEntropy::default());
        let fixture = fixture.reopen_after(
            |domain| {
                grow_valid_journal(domain);
                let mut settings = domain.config.settings().clone();
                settings.max_journal_bytes =
                    fs::metadata(domain.path("events.jsonl")).unwrap().len() + 5000;
                domain.config = settings
                    .validate(
                        &domain
                            .config
                            .store_dir()
                            .parent()
                            .unwrap()
                            .join("suppression.json"),
                    )
                    .unwrap();
            },
            |seams| seams.entropy = entropy.clone(),
        );
        fixture
            .domain
            .clock
            .set_utc(utc("2030-09-18T12:00:00Z"))
            .unwrap();
        let prefix = fs::read(fixture.domain.path("events.jsonl")).unwrap();
        assert!(payload_bytes(&fixture, id.as_str()) > 0);
        let purged = runtime
            .block_on(
                fixture
                    .state
                    .compliance()
                    .purge(id.clone(), "reviewer".into(), Arc::new(())),
            )
            .unwrap();
        assert_eq!(payload_bytes(&fixture, id.as_str()), 0);
        assert!(fs::read(fixture.domain.path("events.jsonl"))
            .unwrap()
            .starts_with(&prefix));
        assert!(entropy.widths.lock().unwrap().is_empty());
        assert_eq!(purged.ticket.events, 14);
        assert!(purged.ticket.purged);
    }

    fn listed_owner_boundaries() {
        for count in [99999, 100000, 100001] {
            listed_count_case(count, 100000);
        }
        for count in [1, 2, 3] {
            listed_count_case(count, 2);
        }
        for cap in [4096, 16777216] {
            for delta in [-1i64, 0, 1] {
                listed_byte_case(cap, delta);
            }
        }
    }

    fn listed_fixture(
        fixture: &DomainFixture,
        max_rules: u64,
        max_bytes: u64,
    ) -> (
        stract::config::compliance::ValidatedComplianceConfig,
        std::path::PathBuf,
    ) {
        let _journal = fixture.journal();
        let path = fixture
            .config
            .store_dir()
            .parent()
            .unwrap()
            .join("synthetic-listed.json");
        let mut settings = fixture.config.settings().clone();
        settings.listed_hashes_file = Some(path.clone());
        settings.max_rules = max_rules;
        settings.max_rules_bytes = max_bytes;
        let suppression = fixture
            .config
            .store_dir()
            .parent()
            .unwrap()
            .join("suppression.json");
        (settings.validate(&suppression).unwrap(), path)
    }

    fn listed_count_case(count: usize, cap: u64) {
        use stract::compliance::listed::ListedMatcher;
        let fixture = DomainFixture::new();
        let (config, path) = listed_fixture(&fixture, cap, 16777216);
        let mut hashes = (0..count)
            .map(|index| digest(format!("https://synthetic.example.test/{index}").as_bytes()))
            .collect::<Vec<_>>();
        hashes.sort();
        write_json(
            &path,
            &json!({"format_version":1,
                "version":"synthetic.1",
                "url_hashes":hashes,
                "host_hashes":[]}),
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = ListedMatcher::load(&config, &NoHooks);
        if count as u64 > cap {
            assert!(matches!(
                loaded,
                Err(stract::compliance::Error::RulesUnavailable)
            ));
        } else {
            assert!(loaded.is_ok());
            let loaded = loaded.unwrap();
            assert_eq!(loaded.metadata().url_count, count as u64);
        }
    }

    fn listed_byte_case(cap: u64, delta: i64) {
        use std::sync::atomic::Ordering::SeqCst;
        use stract::compliance::listed::ListedMatcher;
        let fixture = DomainFixture::new();
        let (config, path) = listed_fixture(&fixture, 2, cap);
        let mut bytes = serde_json::to_vec(
            &json!({"format_version":1,"version":"synthetic.1","url_hashes":[],"host_hashes":[]}),
        )
        .unwrap();
        bytes.resize(cap.checked_add_signed(delta).unwrap() as usize, b' ');
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let counts = FileCounts::default();
        let loaded = ListedMatcher::load(&config, &counts);
        assert_eq!(counts.decodes.load(SeqCst), usize::from(delta <= 0));
        if delta > 0 {
            assert!(matches!(
                loaded,
                Err(stract::compliance::Error::RulesUnavailable)
            ));
        } else {
            assert!(loaded.is_ok());
        }
    }

    fn rule_owner_boundaries() {
        rules_combined_count();
        for spare in [-1i64, 0, 1] {
            rules_replacement_bytes(spare);
        }
    }

    fn intimate_input(urls: Vec<String>) -> serde_json::Value {
        json!({"report":report(),
            "urls":urls,
            "intimate_image_content":true,
            "subject_or_authorised":true,
            "good_faith":true})
    }

    async fn capacity_intake(
        fixture: &HttpFixture,
        entropy: &CountingEntropy,
        input: serde_json::Value,
        accepted: bool,
    ) -> serde_json::Value {
        use std::sync::atomic::Ordering::SeqCst;
        let before = tree(fixture.domain.config.store_dir());
        let writes = fixture.probe.writes.load(SeqCst);
        let draws = entropy.widths.lock().unwrap().len();
        let response = fixture
            .send(false, "POST", "/v1/reports/intimate-images", input, false)
            .await;
        if accepted {
            assert_ne!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.writes.load(SeqCst), writes + 5);
            assert_eq!(&entropy.widths.lock().unwrap()[draws..], [32, 32]);
        } else {
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(entropy.widths.lock().unwrap().len(), draws);
        }
        contract_headers(&response);
        if accepted {
            assert!(response.value["ticket_id"].is_string());
        } else {
            assert_eq!(response.value["error"]["code"], "compliance_capacity");
        }
        assert_eq!(response.status, if accepted { 200 } else { 503 });
        response.value
    }

    fn rules_combined_count() {
        use stract::compliance::{model::TicketId, tickets::AdministrationEvent};
        let entropy = Arc::new(CountingEntropy::default());
        let fixture = HttpFixture::instrumented(
            |config| {
                config.compliance.max_rules = 2;
                let path = config
                    .v1
                    .suppression_store_path
                    .parent()
                    .unwrap()
                    .join("listed.json");
                write_json(
                    &path,
                    &json!({"format_version":1,
                        "version":"synthetic.1",
                        "url_hashes":[digest(b"https://listed-count.example.test/item")],
                        "host_hashes":[]}),
                );
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                config.compliance.listed_hashes_file = Some(path);
            },
            |seams| seams.entropy = entropy.clone(),
        );
        runtime().block_on(async {
            let first = capacity_intake(
                &fixture,
                &entropy,
                intimate_input(vec!["https://first.example.test/item".into()]),
                true,
            )
            .await;
            let id = TicketId::parse(first["ticket_id"].as_str().unwrap()).unwrap();
            let store = fixture.state.compliance();
            store
                .administer(
                    id.clone(),
                    "reviewer".into(),
                    decision_event("granted"),
                    Arc::new(()),
                )
                .await
                .unwrap();
            store
                .administer(
                    id.clone(),
                    "reviewer".into(),
                    AdministrationEvent::Appeal {
                        reasons: "Synthetic appeal".into(),
                        related_ticket_id: None,
                    },
                    Arc::new(()),
                )
                .await
                .unwrap();
            store
                .administer(
                    id,
                    "reviewer".into(),
                    AdministrationEvent::Reversal {
                        reasons: "Synthetic reversal".into(),
                        delivery: delivery(),
                    },
                    Arc::new(()),
                )
                .await
                .unwrap();
            let snapshot = read_json(&fixture.domain.config.rules_dir().join("snapshot.json"));
            assert_eq!(snapshot["rules"], json!([]));
            assert_eq!(snapshot["do_not_reapply"].as_array().unwrap().len(), 1);
            assert_eq!(
                snapshot["listed"]["url_hashes"].as_array().unwrap().len(),
                1
            );
            capacity_intake(
                &fixture,
                &entropy,
                intimate_input(vec!["https://second.example.test/item".into()]),
                false,
            )
            .await;
        });
    }

    fn rules_replacement_bytes(spare: i64) {
        use std::sync::atomic::Ordering::SeqCst;
        use stract::compliance::{listed::ListedMatcher, rules::RulesStore};
        let mut fixture = HttpFixture::new();
        let runtime = runtime();
        runtime.block_on(async {
            let response = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/intimate-images",
                    intimate_input(
                        (0..14)
                            .map(|index| format!("https://rules-{index}.example.test/item"))
                            .collect(),
                    ),
                    false,
                )
                .await;
            contract_headers(&response);
            assert!(response.value["ticket_id"].is_string());
            assert_eq!(response.status, 200);
            fixture.state.compliance().shutdown().await;
        });
        let path = fixture.domain.config.rules_dir().join("snapshot.json");
        let mut candidate = read_json(&path);
        let mut rule = candidate["rules"][0].clone();
        rule["ticket_id"] = json!("0".repeat(64));
        rule["document_id"] = json!(digest(b"https://next.example.test/item"));
        rule["rule_id"] = json!(format!(
            "{}:{}:intimate_images",
            "0".repeat(64),
            digest(b"https://next.example.test/item")
        ));
        rule["intent_sequence"] = json!(7);
        candidate["rules"].as_array_mut().unwrap().push(rule);
        candidate["rules"]
            .as_array_mut()
            .unwrap()
            .sort_by(|a, b| a["rule_id"].as_str().cmp(&b["rule_id"].as_str()));
        candidate["generation"] = json!(2);
        let required = serde_json::to_vec(&candidate).unwrap().len() as u64 + 1;
        assert!(required > 4097);
        change_caps(&mut fixture, |settings| {
            settings.max_rules_bytes = required.checked_add_signed(spare).unwrap()
        });
        let entropy = Arc::new(CountingEntropy::default());
        let fixture = fixture.reopen_instrumented(|seams| seams.entropy = entropy.clone());
        runtime.block_on(capacity_intake(
            &fixture,
            &entropy,
            intimate_input(vec!["https://next.example.test/item".into()]),
            spare >= 0,
        ));
        runtime.block_on(fixture.state.compliance().shutdown());
        let HttpFixture { domain, state, .. } = fixture;
        drop(state);
        let size = fs::metadata(&path).unwrap().len();
        for extra in [-1i64, 0, 1] {
            let mut settings = domain.config.settings().clone();
            settings.max_rules_bytes = size.checked_add_signed(extra).unwrap();
            let config = settings
                .validate(
                    &domain
                        .config
                        .store_dir()
                        .parent()
                        .unwrap()
                        .join("suppression.json"),
                )
                .unwrap();
            let counts = Arc::new(FileCounts::default());
            let before = tree(domain.config.store_dir());
            let opened = RulesStore::open(
                &config,
                domain.clock.clone(),
                ListedMatcher::empty(),
                counts.clone(),
                counts.clone(),
            );
            assert_eq!(tree(domain.config.store_dir()), before);
            assert_eq!(counts.rules[0].load(SeqCst), usize::from(extra >= 0));
            assert_eq!(opened.is_ok(), extra >= 0);
        }
    }

    fn bounded_metadata_and_growing_stream() {
        use std::{cell::Cell, io::Read};
        use stract::compliance::disk::read_capped;
        struct Counted<'a> {
            reads: &'a Cell<usize>,
            cursor: std::io::Cursor<Vec<u8>>,
        }
        impl Read for Counted<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                self.reads.set(self.reads.get() + 1);
                self.cursor.read(bytes)
            }
        }
        for cap in [8192, 65536, 1048576] {
            let reads = Cell::new(0);
            let reader = Counted {
                reads: &reads,
                cursor: std::io::Cursor::new(vec![b'x'; cap + 1]),
            };
            assert!(read_capped(reader, cap as u64 + 1, cap as u64).is_err());
            assert_eq!(reads.get(), 0);
            assert_eq!(
                read_capped(
                    std::io::Cursor::new(vec![b'x'; cap]),
                    cap as u64,
                    cap as u64
                )
                .unwrap()
                .len(),
                cap
            );
            let reader = Counted {
                reads: &reads,
                cursor: std::io::Cursor::new(vec![b'x'; cap + 1]),
            };
            assert!(read_capped(reader, 0, cap as u64).is_err());
            assert!(reads.get() > 0);
        }
        let fixture = DomainFixture::new();
        let journal = fixture.journal();
        drop(journal);
        let path = fixture.path("growing-fixture.bin");
        fs::write(&path, b"x").unwrap();
        let file = fs::File::open(&path).unwrap();
        let before = file.metadata().unwrap().len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[b'x'; 64])
            .unwrap();
        assert!(read_capped(file, before, 64).is_err());
        assert!(read_capped(std::io::empty(), 0, u64::MAX).is_err());
    }

    fn event_capacity_precedes_personal_write() {
        use std::sync::atomic::Ordering::SeqCst;
        use stract::compliance::{model::IntakeKind, tickets::AdministrationEvent, Error};
        let entropy = Arc::new(CountingEntropy::default());
        let fixture = HttpFixture::instrumented(
            |config| config.compliance.max_ticket_events = 16,
            |seams| seams.entropy = entropy.clone(),
        );
        runtime().block_on(async {
            let store = fixture.state.compliance();
            let id = store
                .admit(intake(IntakeKind::OnlineSafetyComplaint), Arc::new(()))
                .await
                .unwrap()
                .ticket
                .id;
            let progress = || AdministrationEvent::Progress {
                enquiries: "Synthetic enquiry".into(),
                update: "Synthetic update".into(),
                delivery: delivery(),
            };
            for _ in 0..9 {
                let draws = entropy.widths.lock().unwrap().len();
                store
                    .administer(id.clone(), "reviewer".into(), progress(), Arc::new(()))
                    .await
                    .unwrap();
                assert_eq!(&entropy.widths.lock().unwrap()[draws..], [32]);
            }
            let before = tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            let draws = entropy.widths.lock().unwrap().len();
            let rejected = store
                .administer(id.clone(), "reviewer".into(), progress(), Arc::new(()))
                .await;
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(entropy.widths.lock().unwrap().len(), draws);
            assert!(matches!(rejected, Err(Error::Capacity)));
            assert_eq!(store.status(&id).await.unwrap().events, 12);
            assert!(store.available().await.is_ok());
            store.shutdown().await;
        });
    }

    #[test]
    fn durable_compliance_work_survives_timeout_and_disconnect() {
        prewrite_failure_does_not_poison_case();
        panicking_transaction_closes_case();
        for disconnect in [false, true] {
            held_transaction(disconnect);
        }
    }

    fn panicking_transaction_closes_case() {
        use stract::compliance::{
            disk::{ComplianceHooks, ComplianceStage},
            model::IntakeKind,
            Error,
        };
        struct Panics;
        impl ComplianceHooks for Panics {
            fn at(&self, stage: ComplianceStage) -> std::io::Result<()> {
                if stage == ComplianceStage::AfterIntentSync {
                    panic!("synthetic durable writer panic");
                }
                Ok(())
            }
        }
        let fixture = DomainFixture::new();
        let store = fixture.store_with_hooks(Arc::new(Panics));
        runtime().block_on(async {
            let lease = Arc::new(());
            let weak = Arc::downgrade(&lease);
            let result = store
                .admit(
                    intake(IntakeKind::IntimateImages {
                        intimate_image_content: true,
                        subject_or_authorised: true,
                        good_faith: true,
                    }),
                    lease,
                )
                .await;
            assert!(matches!(result, Err(Error::Unavailable)));
            store.shutdown().await;
            assert!(weak.upgrade().is_none());
            assert!(matches!(store.available().await, Err(Error::Unavailable)));
            assert!(!store.rules().unavailable().await);
            let before = tree(fixture.config.store_dir());
            assert!(matches!(
                store
                    .admit(intake(IntakeKind::OnlineSafetyComplaint), Arc::new(()))
                    .await,
                Err(Error::Unavailable)
            ));
            assert_eq!(tree(fixture.config.store_dir()), before);
        });
        drop(store);
        let reopened = fixture.store();
        runtime().block_on(async {
            assert!(reopened.available().await.is_ok());
            reopened.shutdown().await;
        });
    }

    fn held_transaction(disconnect: bool) {
        use std::sync::{Condvar, Mutex};
        use std::time::Duration;
        use stract::compliance::disk::{ComplianceHooks, ComplianceStage};
        struct Held {
            reached: tokio::sync::Notify,
            release: Mutex<bool>,
            resumed: Condvar,
        }
        impl ComplianceHooks for Held {
            fn at(&self, stage: ComplianceStage) -> std::io::Result<()> {
                if stage == ComplianceStage::AfterIntentSync {
                    self.reached.notify_one();
                    let released = self.release.lock().unwrap();
                    let (released, _) = self
                        .resumed
                        .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                        .unwrap();
                    if !*released {
                        return Err(std::io::Error::other("synthetic bounded hold expired"));
                    }
                }
                Ok(())
            }
        }
        let held = Arc::new(Held {
            reached: tokio::sync::Notify::new(),
            release: Mutex::new(false),
            resumed: Condvar::new(),
        });
        let fixture = HttpFixture::instrumented(
            |config| {
                config.v1.max_concurrent_requests = Some(1);
                config.v1.request_timeout_ms = if disconnect { 10_000 } else { 100 };
            },
            |seams| seams.hooks = held.clone(),
        );
        runtime().block_on(async {
            use tower::ServiceExt;
            let router = stract::api::v1::compose_api(axum::Router::new(), fixture.state.clone());
            let request = intimate_request();
            let task = tokio::spawn(router.clone().oneshot(request));
            tokio::time::timeout(Duration::from_secs(2), held.reached.notified())
                .await
                .unwrap();
            let before = tree(fixture.domain.config.store_dir());
            let compliance = fixture.state.compliance();
            let mut waiting = Box::pin(compliance.admit(
                intake(stract::compliance::model::IntakeKind::OnlineSafetyComplaint),
                Arc::new(()),
            ));
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            drop(waiting);
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            if disconnect {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                let response = task.await.unwrap().unwrap();
                assert_eq!(tree(fixture.domain.config.store_dir()), before);
                rejected_response(contract_response(response).await, "request_timeout", 504);
            }
            let response = router.clone().oneshot(source_request()).await.unwrap();
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            rejected_response(contract_response(response).await, "overloaded", 503);
            *held.release.lock().unwrap() = true;
            held.resumed.notify_all();
            fixture.state.compliance().shutdown().await;
            let response = router.oneshot(source_request()).await.unwrap();
            let queue = fixture
                .state
                .compliance()
                .queue(
                    "reader",
                    None,
                    20,
                    stract::compliance::tickets::QueueView::Open,
                )
                .await
                .unwrap();
            assert_eq!(queue.items.len(), 1);
            assert_eq!(queue.items[0].state.as_str(), "queued");
            let rows = fs::read_to_string(fixture.domain.path("events.jsonl")).unwrap();
            assert_eq!(rows.lines().count(), 5);
            successful_response(contract_response(response).await);
        });
    }

    fn refuses_without_repair(fixture: &DomainFixture) {
        let events = fs::read(fixture.path("events.jsonl")).unwrap();
        let head = fs::read(fixture.path("head.json")).unwrap();
        let result = Journal::open(&fixture.config, fixture.clock.clone(), Arc::new(NoHooks));
        assert_eq!(fs::read(fixture.path("events.jsonl")).unwrap(), events);
        assert_eq!(fs::read(fixture.path("head.json")).unwrap(), head);
        assert!(result.is_err());
    }

    fn source_request() -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri("/v1/source")
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn isolated_chain_fault(kind: usize) {
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        fixture.list_row(&mut journal);
        drop(journal);
        let mut row = read_json(&fixture.path("events.jsonl"));
        match kind {
            0 => row["sequence"] = json!(2),
            1 => row["previous_hash"] = json!("a".repeat(64)),
            _ => {}
        }
        rehash(&mut row);
        if kind == 2 {
            row["hash"] = json!("b".repeat(64));
        }
        let mut bytes = encoded_row(&row, true);
        if kind == 3 {
            bytes.insert(1, b' ');
        }
        fs::write(fixture.path("events.jsonl"), &bytes).unwrap();
        fs::write(fixture.path("head.json"), checkpoint(&row, bytes.len())).unwrap();
        refuses_without_repair(&fixture);
    }

    fn checkpoint_fault(kind: usize) {
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        fixture.list_row(&mut journal);
        drop(journal);
        let row = read_json(&fixture.path("events.jsonl"));
        let mut head = read_json(&fixture.path("head.json"));
        match kind {
            0 => head["sequence"] = json!(2),
            1 => head["hash"] = json!("c".repeat(64)),
            _ => {
                head["byte_length"] =
                    json!(fs::metadata(fixture.path("events.jsonl")).unwrap().len() + 1)
            }
        }
        let bytes = format!(
            "{{\"format_version\":1,\"sequence\":{},\"hash\":{},\"byte_length\":{}}}\n",
            head["sequence"], head["hash"], head["byte_length"]
        );
        fs::write(fixture.path("head.json"), bytes).unwrap();
        assert_eq!(row["sequence"], 1);
        refuses_without_repair(&fixture);
    }

    fn damaged_history(kind: usize) {
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        for _ in 0..3 {
            fixture.list_row(&mut journal);
        }
        drop(journal);
        let bytes = fs::read(fixture.path("events.jsonl")).unwrap();
        let mut rows = bytes
            .split_inclusive(|byte| *byte == b'\n')
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        match kind {
            0 => rows[0][5] ^= 1,
            1 => {
                rows.remove(1);
            }
            2 => rows.swap(0, 1),
            3 => {
                let length = rows[2].len() / 2;
                rows[2].truncate(length);
            }
            _ => {
                rows.pop();
            }
        }
        fs::write(fixture.path("events.jsonl"), rows.concat()).unwrap();
        refuses_without_repair(&fixture);
    }

    fn complete_suffix_control() {
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        fixture.list_row(&mut journal);
        let old_head = fs::read(fixture.path("head.json")).unwrap();
        fixture.list_row(&mut journal);
        let events = fs::read(fixture.path("events.jsonl")).unwrap();
        drop(journal);
        fs::write(fixture.path("head.json"), old_head).unwrap();
        let reopened = fixture.journal();
        assert_eq!(fs::read(fixture.path("events.jsonl")).unwrap(), events);
        assert_eq!(reopened.rows().len(), 2);
        assert_eq!(reopened.sequence(), 2);
    }

    #[test]
    fn journal_detects_byte_row_order_and_tail_tampering() {
        for fault in 0..4 {
            isolated_chain_fault(fault);
        }
        for fault in 0..3 {
            checkpoint_fault(fault);
        }
        for fault in 0..5 {
            damaged_history(fault);
        }
        complete_suffix_control();
        torn_suffix_control();
    }

    fn torn_suffix_control() {
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        fixture.list_row(&mut journal);
        let prefix = fs::read(fixture.path("events.jsonl")).unwrap();
        drop(journal);
        let partial = b"{\"format_version\":1,\"sequence\":";
        let mut file = OpenOptions::new()
            .append(true)
            .open(fixture.path("events.jsonl"))
            .unwrap();
        file.write_all(partial).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let reopened = fixture.journal();
        let final_bytes = fs::read(fixture.path("events.jsonl")).unwrap();
        assert_eq!(&final_bytes[..prefix.len()], prefix);
        let quarantine = fs::read_dir(fixture.config.journal_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("quarantine-")
            })
            .collect::<Vec<_>>();
        assert_eq!(quarantine.len(), 1);
        assert_eq!(fs::read(&quarantine[0]).unwrap(), partial);
        assert_eq!(
            fs::metadata(&quarantine[0]).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert_eq!(reopened.rows().len(), 2);
        assert_eq!(reopened.rows()[1].event, EventName::TailRecovered);
        assert_eq!(reopened.rows()[1].quarantined_bytes, partial.len() as u64);
        assert_eq!(reopened.rows()[1].quarantine_hash, digest(partial));
        drop(reopened);
        assert_eq!(fixture.journal().rows().len(), 2);
    }

    #[test]
    fn journal_recovers_a_torn_tail_beyond_the_checkpoint_only() {
        interrupted_quarantine_control(true);
        interrupted_quarantine_control(false);
        owned_temp_cases("head");
        owned_temp_cases("recovery");
        torn_suffix_control();
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        fixture.list_row(&mut journal);
        drop(journal);
        let mut bytes = fs::read(fixture.path("events.jsonl")).unwrap();
        bytes.truncate(bytes.len() - 1);
        fs::write(fixture.path("events.jsonl"), bytes).unwrap();
        refuses_without_repair(&fixture);
        assert!(!fs::read_dir(fixture.config.journal_dir())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("quarantine-")));
    }
    #[test]
    fn rules_temps_are_swept_under_owner_lock() {
        let fixture = HttpFixture::new();
        let runtime = runtime();
        runtime.block_on(fixture.state.compliance().shutdown());
        let root = fixture.domain.config.rules_dir().to_path_buf();
        let snapshot = fs::read(root.join("snapshot.json")).unwrap();
        let generation = read_json(&root.join("snapshot.json"))["generation"]
            .as_u64()
            .unwrap();
        let stale_rules = root.join(format!("snapshot.{}.0.tmp", std::process::id()));
        let other_pid = root.join("snapshot.4294967295.7.tmp");
        let sentinels = [
            "keep.tmp",
            "snapshot.0.0.tmp",
            "snapshot.01.0.tmp",
            "snapshot.1.00.tmp",
            "snapshot.+1.0.tmp",
            "snapshot.1.18446744073709551616.tmp",
            "snapshot.1.0.tmp.extra",
        ];
        let fixture = fixture.reopen_after(
            |_| {
                for path in [&stale_rules, &other_pid] {
                    private_temp(path, b"partial staging bytes");
                }
                for name in sentinels {
                    private_temp(&root.join(name), name.as_bytes());
                }
            },
            |_| {},
        );
        assert!(!stale_rules.exists(), "owned rules temp survived open");
        assert!(!other_pid.exists());
        for name in sentinels {
            assert_eq!(fs::read(root.join(name)).unwrap(), name.as_bytes());
        }
        assert_eq!(fs::read(root.join("snapshot.json")).unwrap(), snapshot);
        runtime.block_on(admit_after_rules_sweep(&fixture, generation));
        let fixture = fixture.reopen();
        assert!(!stale_rules.exists());
        assert!(!other_pid.exists());
        runtime.block_on(assert_swept_rule_serves(&fixture));
        runtime.block_on(fixture.state.compliance().shutdown());
        owned_temp_cases("snapshot");
    }

    fn full_store_draws_no_entropy() {
        use std::sync::atomic::Ordering::SeqCst;
        let entropy = Arc::new(CountingEntropy::default());
        let fixture = HttpFixture::instrumented(
            |config| config.compliance.max_tickets = 2,
            |seams| seams.entropy = entropy.clone(),
        );
        runtime().block_on(async {
            let input = json!({"report":report(),"urls":["https://synthetic.example.test/item"],
                "suspected_illegality":"Synthetic evidence"});
            let admitted = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/illegal-content",
                    input.clone(),
                    false,
                )
                .await;
            assert_eq!(*entropy.widths.lock().unwrap(), [32, 32]);
            contract_headers(&admitted);
            assert!(admitted.value["ticket_id"].is_string());
            assert_eq!(admitted.status, 200);
            let second = fixture
                .send(
                    false,
                    "POST",
                    "/v1/reports/illegal-content",
                    input.clone(),
                    false,
                )
                .await;
            assert_eq!(*entropy.widths.lock().unwrap(), [32, 32, 32, 32]);
            contract_headers(&second);
            assert!(second.value["ticket_id"].is_string());
            assert_eq!(second.status, 200);
            let before = tree(fixture.domain.config.store_dir());
            let writes = fixture.probe.writes.load(SeqCst);
            let draws_before = entropy.widths.lock().unwrap().len();
            let rejected = fixture
                .send(false, "POST", "/v1/reports/illegal-content", input, false)
                .await;
            let draws_after = entropy.widths.lock().unwrap().len();
            assert_eq!(tree(fixture.domain.config.store_dir()), before);
            assert_eq!(fixture.probe.writes.load(SeqCst), writes);
            assert_eq!(draws_after, draws_before);
            contract_headers(&rejected);
            assert_eq!(rejected.value["error"]["code"], "compliance_capacity");
            assert_eq!(rejected.status, 503);
            lifetime_capacity_survives_purge(
                &fixture,
                &entropy,
                admitted.value["ticket_id"].as_str().unwrap(),
            )
            .await;
            fixture.state.compliance().shutdown().await;
        });
    }

    async fn lifetime_capacity_survives_purge(
        fixture: &HttpFixture,
        entropy: &CountingEntropy,
        id: &str,
    ) {
        use stract::compliance::{model::TicketId, tickets::AdministrationEvent, Error};
        let id = TicketId::parse(id).unwrap();
        let store = fixture.state.compliance();
        store
            .administer(
                id.clone(),
                "reviewer".into(),
                decision_event("granted"),
                Arc::new(()),
            )
            .await
            .unwrap();
        store
            .administer(
                id.clone(),
                "reviewer".into(),
                AdministrationEvent::Closure {
                    reasons: "Synthetic closure".into(),
                },
                Arc::new(()),
            )
            .await
            .unwrap();
        let extant = payload_bytes(fixture, id.as_str());
        assert!(extant > 0);
        fixture
            .domain
            .clock
            .set_utc(utc("2030-09-18T12:00:00Z"))
            .unwrap();
        let journal_before = fs::metadata(fixture.domain.path("events.jsonl"))
            .unwrap()
            .len();
        store
            .purge(id.clone(), "reviewer".into(), Arc::new(()))
            .await
            .unwrap();
        assert_eq!(payload_bytes(fixture, id.as_str()), 0);
        assert!(
            fs::metadata(fixture.domain.path("events.jsonl"))
                .unwrap()
                .len()
                > journal_before
        );
        let before = tree(fixture.domain.config.store_dir());
        let draws = entropy.widths.lock().unwrap().len();
        let result = store
            .admit(
                intake(stract::compliance::model::IntakeKind::OnlineSafetyComplaint),
                Arc::new(()),
            )
            .await;
        assert_eq!(tree(fixture.domain.config.store_dir()), before);
        assert_eq!(entropy.widths.lock().unwrap().len(), draws);
        assert!(matches!(result, Err(Error::Capacity)));
    }

    fn delisting_entropy_reservations() {
        for full in [false, true] {
            let entropy = Arc::new(CountingEntropy::default());
            let fixture = HttpFixture::instrumented(
                |config| config.compliance.max_ticket_events = 16,
                |seams| seams.entropy = entropy.clone(),
            );
            runtime().block_on(async {
                let request = json!({"report":report(),
                    "urls":["https://synthetic.example.test/item"],
                    "request_kind":"delisting",
                    "names":[{"name":"Elise Dupont",
                        "kind":"legal_name",
                        "evidence":"Synthetic evidence"},
                        {"name":"River Stone",
                        "kind":"pseudonym",
                        "evidence":"Synthetic evidence"}]});
                let admitted = fixture
                    .send(false, "POST", "/v1/reports/data-rights", request, false)
                    .await;
                assert_eq!(*entropy.widths.lock().unwrap(), [32, 32]);
                contract_headers(&admitted);
                let id = admitted.value["ticket_id"].as_str().unwrap();
                assert_eq!(admitted.status, 200);
                if full {
                    for _ in 0..9 {
                        capacity_progress(
                            &fixture,
                            &entropy,
                            id,
                            progress_body("enquiry".into(), "update".into()),
                            true,
                        )
                        .await;
                    }
                }
                let before = tree(fixture.domain.config.store_dir());
                let writes = fixture
                    .probe
                    .writes
                    .load(std::sync::atomic::Ordering::SeqCst);
                let draws = entropy.widths.lock().unwrap().len();
                let decision = json!({"actor":"reviewer",
                    "decision":{"kind":"granted",
                    "reasons":"Synthetic grant",
                    "delivery":delivery(),
                    "assessment":delisting_assessment()}});
                let response = fixture
                    .send(
                        true,
                        "POST",
                        &format!("/v1/compliance/tickets/{id}/decision"),
                        decision,
                        true,
                    )
                    .await;
                if full {
                    assert_eq!(tree(fixture.domain.config.store_dir()), before);
                    assert_eq!(
                        fixture
                            .probe
                            .writes
                            .load(std::sync::atomic::Ordering::SeqCst),
                        writes
                    );
                    assert_eq!(entropy.widths.lock().unwrap().len(), draws);
                } else {
                    assert_eq!(&entropy.widths.lock().unwrap()[draws..], [32, 32, 32]);
                }
                contract_headers(&response);
                if full {
                    assert_eq!(response.value["error"]["code"], "compliance_capacity");
                } else {
                    assert_eq!(response.value["state"], "actioned");
                }
                assert_eq!(response.status, if full { 503 } else { 200 });
            });
        }
    }

    fn delisting_assessment() -> serde_json::Value {
        let mut value = json!({});
        for key in [
            "natural_person",
            "name_search",
            "role_in_public_life",
            "child",
            "accuracy",
            "working_life",
            "hate_speech_or_defamation",
            "sensitive_data",
            "currency",
            "prejudice",
            "risk",
            "original_basis_of_publication",
            "journalistic_context",
            "legal_power_or_obligation_to_publish",
            "criminal_offence",
            "offence_seriousness",
            "time_elapsed",
            "spent_status",
            "reasoned_decision",
        ] {
            value[key] = json!("Synthetic reasoned assessment");
        }
        value
    }

    fn prewrite_failure_does_not_poison_case() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use stract::compliance::{
            disk::ComplianceStage, model::IntakeKind, tickets::AdministrationEvent, Error,
        };
        let hooks = Arc::new(FailOnce {
            stage: ComplianceStage::BeforePayloadWrite,
            remaining: AtomicUsize::new(0),
        });
        let fixture = HttpFixture::instrumented(|_| {}, |seams| seams.hooks = hooks.clone());
        let store = fixture.state.compliance();
        runtime().block_on(async {
            let input = || intake(IntakeKind::OnlineSafetyComplaint);
            let original = store.admit(input(), Arc::new(())).await.unwrap().ticket;
            for administrative in [false, true] {
                hooks.remaining.store(1, SeqCst);
                let before = tree(fixture.domain.config.store_dir());
                let writes = fixture.probe.writes.load(SeqCst);
                let result = if administrative {
                    store
                        .administer(
                            original.id.clone(),
                            "reviewer".into(),
                            AdministrationEvent::Progress {
                                enquiries: "Synthetic enquiry".into(),
                                update: "Synthetic update".into(),
                                delivery: delivery(),
                            },
                            Arc::new(()),
                        )
                        .await
                        .map(|_| ())
                } else {
                    store.admit(input(), Arc::new(())).await.map(|_| ())
                };
                assert_eq!(tree(fixture.domain.config.store_dir()), before);
                assert_eq!(fixture.probe.writes.load(SeqCst), writes);
                assert!(matches!(result, Err(Error::Unavailable)));
                assert!(store.available().await.is_ok());
                assert_eq!(
                    store.status(&original.id).await.unwrap().events,
                    original.events
                );
                let index = fixture
                    .send(false, "GET", "/v1/reports", serde_json::Value::Null, false)
                    .await;
                contract_headers(&index);
                assert!(index.value["routes"].is_array());
                assert_eq!(index.status, 200);
                let status = fixture
                    .send(
                        false,
                        "GET",
                        &format!("/v1/reports/status/{}", original.id.as_str()),
                        serde_json::Value::Null,
                        false,
                    )
                    .await;
                contract_headers(&status);
                assert_eq!(status.value["state"], "queued");
                assert_eq!(status.status, 200);
                let admitted = fixture
                    .send(
                        false,
                        "POST",
                        "/v1/reports/online-safety-complaints",
                        json!({"report":report()}),
                        false,
                    )
                    .await;
                contract_headers(&admitted);
                assert!(admitted.value["ticket_id"].is_string());
                assert_eq!(admitted.status, 200);
            }
            store.shutdown().await;
        });
    }

    fn owned_temp_cases(family: &str) {
        for fault in ["symlink", "mode", "hardlink"] {
            unsafe_owned_temp_is_refused(family, fault);
        }
        owned_temp_lock_control(family);
    }

    fn temp_root<'a>(fixture: &'a DomainFixture, family: &str) -> &'a std::path::Path {
        if family == "snapshot" {
            fixture.config.rules_dir()
        } else {
            fixture.config.journal_dir()
        }
    }

    fn open_temp_owner(fixture: &DomainFixture, family: &str) -> stract::compliance::Result<()> {
        use stract::compliance::{
            listed::ListedMatcher,
            rules::{NoRulesHooks, RulesStore},
        };
        if family == "snapshot" {
            RulesStore::open(
                &fixture.config,
                fixture.clock.clone(),
                ListedMatcher::load(&fixture.config, &NoHooks)?,
                Arc::new(NoHooks),
                Arc::new(NoRulesHooks),
            )
            .map(|_| ())
        } else {
            Journal::open(&fixture.config, fixture.clock.clone(), Arc::new(NoHooks)).map(|_| ())
        }
    }

    type TempFacts = std::collections::BTreeMap<
        std::path::PathBuf,
        (u64, u64, u32, Option<std::path::PathBuf>, Vec<u8>),
    >;

    fn temp_facts(root: &std::path::Path) -> TempFacts {
        use std::os::unix::fs::MetadataExt;
        let mut facts = TempFacts::new();
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let link = metadata
                .file_type()
                .is_symlink()
                .then(|| fs::read_link(&path).unwrap());
            let bytes = if metadata.is_file() {
                fs::read(&path).unwrap()
            } else {
                Vec::new()
            };
            facts.insert(
                path.clone(),
                (
                    metadata.ino(),
                    metadata.nlink(),
                    metadata.mode(),
                    link,
                    bytes,
                ),
            );
            if metadata.is_dir() {
                facts.extend(temp_facts(&path));
            }
        }
        facts
    }

    fn assert_temp_refusal(result: stract::compliance::Result<()>, family: &str) {
        use stract::compliance::Error;
        if family == "snapshot" {
            assert!(matches!(result, Err(Error::RulesUnavailable)));
        } else {
            assert!(matches!(result, Err(Error::Unavailable)));
        }
    }

    fn unsafe_owned_temp_is_refused(family: &str, fault: &str) {
        let fixture = DomainFixture::new();
        let store = fixture.store();
        runtime().block_on(store.shutdown());
        drop(store);
        let root = temp_root(&fixture, family);
        let candidate = root.join(format!("{family}.4294967295.7.tmp"));
        let sentinel = root.join("private-sentinel");
        private_temp(&sentinel, b"unrelated private sentinel");
        match fault {
            "symlink" => std::os::unix::fs::symlink(&sentinel, &candidate).unwrap(),
            "mode" => {
                private_temp(&candidate, b"unsafe mode staging");
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "hardlink" => {
                private_temp(&candidate, b"hardlinked staging");
                fs::hard_link(&candidate, root.join("second-link")).unwrap();
            }
            _ => panic!("unknown synthetic fault"),
        }
        // This inventory uses lstat/read_link, never the symlink-rejecting tree helper.
        // It pins entries, inode/link/mode, sentinel contents and every canonical file.
        let before = temp_facts(fixture.config.store_dir());
        let result = open_temp_owner(&fixture, family);
        assert_eq!(temp_facts(fixture.config.store_dir()), before);
        assert_temp_refusal(result, family);
    }

    fn owned_temp_lock_control(family: &str) {
        let fixture = DomainFixture::new();
        let store = fixture.store();
        let candidate = temp_root(&fixture, family).join(format!("{family}.4294967295.7.tmp"));
        private_temp(&candidate, b"healthy singly-linked staging");
        let before = temp_facts(fixture.config.store_dir());
        let result = open_temp_owner(&fixture, family);
        assert_eq!(temp_facts(fixture.config.store_dir()), before);
        assert_temp_refusal(result, family);
        runtime().block_on(store.shutdown());
        drop(store);
        let mut expected = before;
        expected.remove(&candidate);
        let result = open_temp_owner(&fixture, family);
        assert!(!candidate.exists());
        let actual = temp_facts(fixture.config.store_dir());
        assert_eq!(
            actual.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
        for (path, (_, _, mode, link, bytes)) in expected {
            let current = &actual[&path];
            assert_eq!((&current.2, &current.3, &current.4), (&mode, &link, &bytes));
        }
        assert!(result.is_ok(), "healthy temp owner refused");
    }

    fn private_temp(path: &std::path::Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    async fn admit_after_rules_sweep(fixture: &HttpFixture, generation: u64) {
        let response = fixture.raw(false, intimate_request()).await;
        let snapshot = read_json(&fixture.domain.config.rules_dir().join("snapshot.json"));
        assert_eq!(snapshot["generation"], generation + 1);
        assert_eq!(snapshot["rules"].as_array().unwrap().len(), 1);
        contract_headers(&response);
        assert!(response.value["ticket_id"].is_string());
        assert_eq!(response.status, 200);
        assert_swept_rule_serves(fixture).await;
        fixture.state.compliance().shutdown().await;
    }

    async fn assert_swept_rule_serves(fixture: &HttpFixture) {
        let before = tree(fixture.domain.config.store_dir());
        let response = fixture
            .send(
                false,
                "POST",
                "/v1/search",
                json!({"query":"synthetic"}),
                false,
            )
            .await;
        assert_eq!(tree(fixture.domain.config.store_dir()), before);
        contract_headers(&response);
        assert!(response.value["results"].is_array());
        let results = response.value["results"].as_array().unwrap();
        assert!(results
            .iter()
            .any(|row| row["url"] == "https://unrelated.example.test/item"));
        assert!(!results
            .iter()
            .any(|row| row["url"] == "https://synthetic.example.test/item"));
        assert_eq!(response.status, 200);
    }

    fn interrupted_quarantine_control(partial_final: bool) {
        let fixture = DomainFixture::new();
        let mut journal = fixture.journal();
        fixture.list_row(&mut journal);
        let prefix = fs::read(fixture.path("events.jsonl")).unwrap();
        let sequence = journal.sequence();
        drop(journal);
        let tail = b"{\"format_version\":1,\"sequence\":";
        let mut file = OpenOptions::new()
            .append(true)
            .open(fixture.path("events.jsonl"))
            .unwrap();
        file.write_all(tail).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let final_path = fixture.path(&format!("quarantine-{sequence:020}-{}.bin", digest(tail)));
        if partial_final {
            fs::write(&final_path, &tail[..5]).unwrap();
            fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let stale_head = fixture.path(&format!("head.{}.0.tmp", std::process::id()));
        let stale_recovery = fixture.path(&format!("recovery.{}.0.tmp", std::process::id()));
        for path in [&stale_head, &stale_recovery] {
            fs::write(path, b"partial staging bytes").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let sentinel = fixture.path("keep.tmp");
        fs::write(&sentinel, b"keep").unwrap();
        let opened = Journal::open(&fixture.config, fixture.clock.clone(), Arc::new(NoHooks));
        assert!(opened.is_ok(), "partial quarantine recovery refused");
        let mut reopened = opened.unwrap();
        assert!(!stale_head.exists());
        assert!(!stale_recovery.exists());
        assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
        assert_eq!(fs::read(&final_path).unwrap(), tail);
        assert_eq!(
            fs::metadata(&final_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(fs::read(fixture.path("events.jsonl"))
            .unwrap()
            .starts_with(&prefix));
        assert_eq!(
            reopened
                .rows()
                .iter()
                .filter(|row| row.event == EventName::TailRecovered)
                .count(),
            1
        );
        assert_eq!(reopened.rows()[1].quarantine_hash, digest(tail));
        assert_eq!(reopened.rows()[1].quarantined_bytes, tail.len() as u64);
        fixture.list_row(&mut reopened);
        drop(reopened);
        let before = tree(fixture.config.store_dir());
        let reopened = fixture.journal();
        assert_eq!(tree(fixture.config.store_dir()), before);
        assert_eq!(reopened.rows().len(), 3);
    }

    fn check_interrupted_rules(
        fixture: &DomainFixture,
        operation: &str,
        stage: stract::compliance::disk::ComplianceStage,
    ) {
        let rules = read_json(&fixture.config.rules_dir().join("snapshot.json"));
        let applied = !matches!(
            stage,
            stract::compliance::disk::ComplianceStage::AfterIntentSync
                | stract::compliance::disk::ComplianceStage::AfterJournalSync
        );
        assert_eq!(
            rules["rules"].as_array().unwrap().len(),
            1 + usize::from((operation == "granted") == applied)
        );
        assert_eq!(
            rules["do_not_reapply"].as_array().unwrap().len(),
            1 + usize::from(operation == "reversal" && applied)
        );
    }

    fn intimate_request() -> axum::http::Request<axum::body::Body> {
        use axum::{body::Body, http::Request};
        Request::builder()
            .method("POST")
            .uri("/v1/reports/intimate-images")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &json!({"report":report(),"urls":["https://synthetic.example.test/item"],
                "intimate_image_content":true,"subject_or_authorised":true,"good_faith":true}),
                )
                .unwrap(),
            ))
            .unwrap()
    }
}
