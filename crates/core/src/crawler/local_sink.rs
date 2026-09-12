//! Acknowledges immutable per-target local WARC writes only after body and manifest durability.
//! Rights/no-store/empty bodies never reach a raw file. Pending manifests precede staging bytes so
//! interrupted raw writes remain individually managed. Metadata/ledger retention is independent.

#![deny(missing_docs)]

use super::{
    host_state::HostRegistry,
    politeness::Clock,
    record::{validate_success_fields, BodyRetentionReason},
    retention::{self, ObjectManifest, ObjectState},
    CrawlDatum, DatumSink, Error, Result,
};
use crate::{config::ingestion::ValidatedPolicy, warc};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    sync::{Arc, Mutex},
};

/// Managed local body sink sharing the store's exclusive owner with host state and ledger.
pub struct LocalSink {
    registry: Arc<HostRegistry>,
    policy: ValidatedPolicy,
    clock: Arc<dyn Clock>,
    io: Mutex<()>,
}
impl LocalSink {
    /// Validates owned directories and runs raw retention before accepting a new capture.
    pub fn open(
        registry: Arc<HostRegistry>,
        policy: ValidatedPolicy,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>> {
        retention::managed_directory(registry.root(), "objects")?;
        retention::managed_directory(registry.root(), "manifests")?;
        retention::run(&registry, &policy, clock.utc(), false)?.ensure_success()?;
        Ok(Arc::new(Self {
            registry,
            policy,
            clock,
            io: Mutex::new(()),
        }))
    }
    /// Returns the exclusively owned registry used to validate manifests and ledger object references.
    pub fn registry(&self) -> &Arc<HostRegistry> {
        &self.registry
    }
    /// Applies immediate body deletion before metadata-only/gone target completion.
    pub fn enforce_record(&self, record: &super::record::DocumentRecord) -> Result<()> {
        let Some(key) = record.url_key.value() else {
            return Ok(());
        };
        if record.body_retention == BodyRetentionReason::NoStore {
            self.purge(key, BodyRetentionReason::NoStore)?;
        }
        if record.index_only
            || matches!(
                record.body_retention,
                BodyRetentionReason::RightsReserved
                    | BodyRetentionReason::Policy
                    | BodyRetentionReason::Gone
            )
        {
            self.purge(key, record.body_retention)?;
        }
        Ok(())
    }
    /// Deletes every managed body for an exact operational key, including prior target generations.
    /// No-store/reserved/gone decisions call this before terminal completion; no host deletion inferred.
    pub fn purge(&self, key: &str, reason: BodyRetentionReason) -> Result<()> {
        let _io = self.io.lock().map_err(|_| Error::SinkWrite)?;
        for mut manifest in retention::manifests(&self.registry)?
            .into_iter()
            .filter(|m| m.url_key == key)
        {
            manifest.body_retention = reason;
            retention::persist_manifest(&self.registry, &manifest)?;
            retention::delete_manifest_objects(&self.registry, &mut manifest, self.clock.utc())?;
        }
        Ok(())
    }
    /// Runs the raw-only TTL job under this sink's write lock and returns measured scan metrics.
    pub fn retention(&self, dry_run: bool) -> Result<retention::RetentionReport> {
        let _io = self.io.lock().map_err(|_| Error::SinkWrite)?;
        let result = retention::run(&self.registry, &self.policy, self.clock.utc(), dry_run)?;
        if !dry_run {
            result.ensure_success()?;
        }
        Ok(result)
    }
    fn write_durable(&self, datum: CrawlDatum) -> Result<()> {
        let _io = self.io.lock().map_err(|_| Error::SinkWrite)?;
        let record = &datum.record;
        record.validate()?;
        validate_success_fields(record)?;
        if record.index_only {
            return Err(Error::SinkWrite);
        }
        if record.body_retention == BodyRetentionReason::NoStore {
            return Err(Error::SinkWrite);
        }
        if datum.body.is_empty()
            || record.body_retention != BodyRetentionReason::Retained
            || record.rights.index_only()
            || record.directives.limit_exceeded
        {
            return Err(Error::SinkWrite);
        }
        let parsed_at = *record.parsed_at_utc.value().ok_or(Error::RecordInvalid)?;
        let expiry = record.raw_expires_at_utc.ok_or(Error::RecordInvalid)?;
        let shortened = parsed_at
            + chrono::TimeDelta::days(i64::from(self.policy.get().retention.raw_body_max_age_days));
        if self.clock.utc() >= expiry.min(shortened) {
            return Err(Error::SinkWrite);
        }
        let object = retention::object_name(&record.target_id)?;
        let manifest_path = retention::manifest_path(&self.registry, &record.target_id)?;
        if fs::symlink_metadata(&manifest_path).is_ok() {
            return Err(Error::SinkWrite);
        }
        let mut manifest = ObjectManifest {
            schema_version: 1,
            store_id: self.registry.identity().store_id.clone(),
            target_id: record.target_id.clone(),
            url_key: record.url_key.value().ok_or(Error::RecordInvalid)?.clone(),
            body_object: object,
            parsed_at_utc: parsed_at,
            raw_expires_at_utc: expiry,
            body_bytes: datum.body.len() as u64,
            object_bytes: 0,
            state: ObjectState::Pending,
            body_retention: BodyRetentionReason::Retained,
            deleted_at_utc: None,
        };
        if retention::validate_owned_store_and_object(&self.registry, &manifest, false)?.is_some()
            || retention::validate_owned_store_and_object(&self.registry, &manifest, true)?
                .is_some()
        {
            return Err(Error::SinkWrite);
        }
        retention::persist_manifest(&self.registry, &manifest)?;
        let record = warc::WarcRecord {
            request: warc::Request {
                url: datum.url.into(),
                date: Some(datum.date),
            },
            response: warc::Response {
                body: datum.body,
                payload_type: Some(datum.payload_type),
            },
            metadata: warc::Metadata {
                fetch_time_ms: datum.fetch_time_ms,
                document: Some(datum.record),
            },
        };
        let mut writer = warc::WarcWriter::new();
        writer.write(&record).map_err(|_| Error::SinkWrite)?;
        let bytes = writer.finish().map_err(|_| Error::SinkWrite)?;
        let staging = self
            .registry
            .root()
            .join(format!("{}.pending", manifest.body_object));
        let final_path = self.registry.root().join(&manifest.body_object);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)
            .map_err(|_| Error::SinkWrite)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::SinkWrite)?;
        fs::rename(&staging, &final_path).map_err(|_| Error::SinkWrite)?;
        fs::File::open(self.registry.root().join("objects"))
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::SinkWrite)?;
        manifest.object_bytes = bytes.len() as u64;
        manifest.state = ObjectState::Retained;
        retention::persist_manifest(&self.registry, &manifest)?;
        Ok(())
    }
}
impl DatumSink for LocalSink {
    async fn write(&self, datum: CrawlDatum) -> Result<()> {
        self.write_durable(datum).map_err(|_| Error::SinkWrite)
    }
    async fn finish(&self) -> Result<()> {
        self.retention(false)?.ensure_success()?;
        retention::scan(&self.registry, &self.policy, self.clock.utc())?;
        Ok(())
    }
}
