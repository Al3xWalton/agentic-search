//! Runs bounded compliance commands without network access or the service's ticket owner.
//! Filesystem authority protects inputs and outputs; failures retain the fixed domain vocabulary.

#![deny(missing_docs)]

use super::{
    bounds::BoundKey,
    disk::{self, ComplianceHooks, NoHooks, OpenMode},
    export,
    journal::view::read_committed,
    metrics,
    model::{Entropy, SystemEntropy},
    record_types::{RecordEnvelope, TriggerKind},
    records::{self, open_records, RecordStore, RecordView},
    release::{self, ReleaseManifest},
    reviews, statement, Error, Result,
};
use crate::{
    config::{compliance::ValidatedComplianceConfig, ApiConfig},
    crawler::politeness::{Clock, SystemClock},
};
use clap::{Args, Subcommand, ValueEnum};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Private configuration shared by every command.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Private API TOML copy: nonsymlink path, owner-only parent 0700 and file 0600.
    #[arg(long)]
    pub config: PathBuf,
}

/// Private configuration plus a bounded JSON input file.
#[derive(Debug, Args)]
pub struct InputArgs {
    /// Private API configuration.
    #[command(flatten)]
    pub config: ConfigArgs,
    /// Private nonsymlink JSON input, with parent 0700 and file 0600.
    #[arg(long)]
    pub input: PathBuf,
}

/// Explicit attestation vocabulary; persisted spellings remain snake_case.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Trigger {
    /// The supplied Risk Profile changed.
    #[value(name = "risk-profile-changed")]
    RiskProfileChanged,
    /// A significant service change requires reassessment.
    #[value(name = "significant-change")]
    SignificantChange,
    /// Evidence indicates children use the service.
    #[value(name = "evidence-of-child-use")]
    EvidenceOfChildUse,
}

impl Trigger {
    fn kind(self) -> TriggerKind {
        match self {
            Self::RiskProfileChanged => TriggerKind::RiskProfileChanged,
            Self::SignificantChange => TriggerKind::SignificantChange,
            Self::EvidenceOfChildUse => TriggerKind::EvidenceOfChildUse,
        }
    }
}

/// Library-owned command subtree; every nested group requires a concrete operation.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate, retain or export immutable private record versions.
    Records {
        /// Required record operation.
        #[command(subcommand)]
        command: Records,
    },
    /// Inspect deadlines or create idempotent review work.
    Review {
        /// Required review operation.
        #[command(subcommand)]
        command: Review,
    },
    /// Retain integer monthly metrics from a live verified ticket prefix.
    Metrics {
        /// Private API configuration.
        #[command(flatten)]
        config: ConfigArgs,
        /// Strict UTC receipt month, YYYY-MM.
        #[arg(long)]
        month: String,
        /// Bounded operator alias claim.
        #[arg(long)]
        actor: String,
    },
    /// Validate prospective service changes without deploying them.
    Release {
        /// Required release operation.
        #[command(subcommand)]
        command: Release,
    },
    /// Render public policy from validated record selections.
    Statement {
        /// Required statement operation.
        #[command(subcommand)]
        command: Statement,
    },
    /// Inspect payload retention eligibility without purging anything.
    Retention {
        /// Required retention operation.
        #[command(subcommand)]
        command: Retention,
    },
}

/// Record operations with independent writer ownership.
#[derive(Debug, Subcommand)]
pub enum Records {
    /// Validate an envelope and immutable references without writing.
    Validate(InputArgs),
    /// Retain the next immutable version under the independent record owner.
    Add {
        /// Private configuration and envelope.
        #[command(flatten)]
        input: InputArgs,
        /// Bounded operator alias claim.
        #[arg(long)]
        actor: String,
    },
    /// Export every version to a new private directory; existing output is never replaced.
    Export {
        /// Private API configuration.
        #[command(flatten)]
        config: ConfigArgs,
        /// New output directory under a nonsymlink owner-only parent.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Review checks and explicit operator-attested causes.
#[derive(Debug, Subcommand)]
pub enum Review {
    /// List pending deadlines, including future ones, without writing.
    Check(ConfigArgs),
    /// Create only overdue annual or missing-assessment work; repeats reuse existing references.
    OpenDue {
        /// Private API configuration.
        #[command(flatten)]
        config: ConfigArgs,
        /// Bounded operator alias claim.
        #[arg(long)]
        actor: String,
    },
    /// Attest an explicit cause; repeating it at a later time does not create duplicate work.
    Trigger {
        /// Private API configuration.
        #[command(flatten)]
        config: ConfigArgs,
        /// Explicit cause; annual work is derived only by open-due.
        #[arg(long, value_enum)]
        kind: Trigger,
        /// Bounded reference to the attestation; never fetched.
        #[arg(long)]
        reference: String,
        /// Bounded operator alias claim.
        #[arg(long)]
        actor: String,
    },
}

/// Pure prospective release operations.
#[derive(Debug, Subcommand)]
pub enum Release {
    /// Require approved assessment updates for significant changes.
    Validate(InputArgs),
}

/// Public statement operations.
#[derive(Debug, Subcommand)]
pub enum Statement {
    /// Render Markdown to a new private file under a nonsymlink owner-only parent.
    Render {
        /// Private API configuration.
        #[command(flatten)]
        config: ConfigArgs,
        /// New Markdown file; existing paths are refused.
        #[arg(long)]
        out: PathBuf,
    },
}

/// Read-only retention operations; deletion uses the separate authenticated management surface.
#[derive(Debug, Subcommand)]
pub enum Retention {
    /// List closed, unpurged tickets at the inclusive configured calendar threshold.
    Due(ConfigArgs),
}

/// Injectable local seams; commands obtain time only from Clock::utc.
pub struct Seams {
    /// UTC source shared by validation, index writes and snapshots.
    pub clock: Arc<dyn Clock>,
    /// Independent record-salt source, never used by read-only commands.
    pub entropy: Arc<dyn Entropy>,
    /// Real file-open and persistence-stage observations.
    pub hooks: Arc<dyn ComplianceHooks>,
}

impl Default for Seams {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock::default()),
            entropy: Arc::new(SystemEntropy),
            hooks: Arc::new(NoHooks),
        }
    }
}

struct Context<'a> {
    config: ValidatedComplianceConfig,
    seams: &'a Seams,
}

impl Context<'_> {
    fn view(&self) -> Result<RecordView> {
        records::read_view(
            &self.config,
            self.seams.clock.as_ref(),
            self.seams.hooks.as_ref(),
        )
    }
    fn owner(&self) -> Result<RecordStore> {
        RecordStore::open(
            &self.config,
            self.seams.clock.clone(),
            self.seams.entropy.clone(),
            self.seams.hooks.clone(),
        )
    }
    fn now(&self) -> i64 {
        self.seams.clock.utc().timestamp()
    }
    fn input<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let bytes = read_input(path, self.config.settings().max_record_bytes, self.seams)?;
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidInput)
    }
}

fn read_input(path: &Path, maximum: u64, seams: &Seams) -> Result<Vec<u8>> {
    let file =
        open_records(path, OpenMode::Read, seams.hooks.as_ref()).map_err(|_| Error::Unavailable)?;
    disk::read_bounded(file, maximum).map_err(|_| Error::InvalidInput)
}

fn context<'a>(args: &ConfigArgs, seams: &'a Seams) -> Result<Context<'a>> {
    let bytes = read_input(&args.config, BoundKey::MaxRecordBytes.spec().max, seams)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidInput)?;
    let config: ApiConfig = toml::from_str(text).map_err(|_| Error::InvalidInput)?;
    config
        .v1
        .validate(&[config.host, config.prometheus_host, config.management_host])
        .map_err(|_| Error::InvalidInput)?;
    let config = config
        .compliance
        .validate(&config.v1.suppression_store_path)?;
    Ok(Context { config, seams })
}

impl Command {
    /// Runs the same injected implementation; main alone prints a returned fixed domain error.
    pub fn run(self) -> Result<()> {
        self.run_with(&Seams::default(), &mut io::stdout().lock())
    }

    /// Writes exactly one success JSON value and LF. Errors are returned, leaving stderr to main.
    pub fn run_with(self, seams: &Seams, stdout: &mut dyn Write) -> Result<()> {
        let value = self.execute(seams)?;
        let mut bytes = serde_json::to_vec(&value).map_err(|_| Error::Unavailable)?;
        bytes.push(b'\n');
        stdout.write_all(&bytes).map_err(|_| Error::Unavailable)?;
        stdout.flush().map_err(|_| Error::Unavailable)
    }

    fn execute(self, seams: &Seams) -> Result<Value> {
        match self {
            Self::Records { command } => command.execute(seams),
            Self::Review { command } => command.execute(seams),
            Self::Metrics {
                config,
                month,
                actor,
            } => {
                super::auth::actor(&actor)?;
                metrics::month_start(&month)?;
                let context = context(&config, seams)?;
                let snapshot =
                    read_committed(&context.config, seams.clock.as_ref(), seams.hooks.as_ref())?;
                let reference = metrics::persist(&mut context.owner()?, &snapshot, &month, &actor)?;
                Ok(json!({"record_ref":reference,"as_of_sequence":snapshot.sequence}))
            }
            Self::Release {
                command: Release::Validate(input),
            } => {
                let context = context(&input.config, seams)?;
                let manifest: ReleaseManifest = context.input(&input.input)?;
                release::validate_release(&manifest, &context.view()?)?;
                Ok(json!({"valid":true}))
            }
            Self::Statement {
                command: Statement::Render { config, out },
            } => render_statement(context(&config, seams)?, &out),
            Self::Retention {
                command: Retention::Due(config),
            } => {
                let context = context(&config, seams)?;
                let snapshot =
                    read_committed(&context.config, seams.clock.as_ref(), seams.hooks.as_ref())?;
                Ok(json!({"as_of_sequence":snapshot.sequence,
                    "items":metrics::retention_due(&snapshot, &context.config)?}))
            }
        }
    }
}

impl Records {
    fn execute(self, seams: &Seams) -> Result<Value> {
        match self {
            Self::Validate(input) => {
                let context = context(&input.config, seams)?;
                let record: RecordEnvelope = context.input(&input.input)?;
                records::validate_candidate(
                    &context.config,
                    &context.view()?,
                    &record,
                    context.now(),
                )?;
                Ok(json!({"valid":true}))
            }
            Self::Add { input, actor } => {
                super::auth::actor(&actor)?;
                let context = context(&input.config, seams)?;
                let record: RecordEnvelope = context.input(&input.input)?;
                records::validate_candidate(
                    &context.config,
                    &context.view()?,
                    &record,
                    context.now(),
                )?;
                let (reference, sequence) = context.owner()?.add(record, &actor)?;
                Ok(json!({"record_ref":reference,"sequence":sequence}))
            }
            Self::Export { config, out } => {
                let context = context(&config, seams)?;
                let receipt = export::export(
                    &context.view()?,
                    &out,
                    seams.clock.as_ref(),
                    seams.hooks.as_ref(),
                )?;
                Ok(json!({"versions":receipt.versions,"files":receipt.outputs.len() + 1}))
            }
        }
    }
}

impl Review {
    fn execute(self, seams: &Seams) -> Result<Value> {
        let (config, actor, trigger) = match self {
            Self::Check(config) => {
                let context = context(&config, seams)?;
                let result = reviews::freshness(&context.view()?, context.now())?;
                return Ok(
                    json!({"items":result.items,"late_completions":result.late_completions}),
                );
            }
            Self::OpenDue { config, actor } => (config, actor, None),
            Self::Trigger {
                config,
                kind,
                reference,
                actor,
            } => (config, actor, Some((kind, reference))),
        };
        super::auth::actor(&actor)?;
        let context = context(&config, seams)?;
        let now = context.now();
        let view = context.view()?;
        let items = match trigger {
            Some((kind, reference)) => reviews::triggered(&view, kind.kind(), &reference, now)?,
            None => reviews::freshness(&view, now)?.items,
        };
        let result = reviews::open_work(&mut context.owner()?, &items, now, &actor)?;
        serde_json::to_value(result).map_err(|_| Error::Unavailable)
    }
}

fn render_statement(context: Context<'_>, out: &Path) -> Result<Value> {
    let text = statement::render(&context.config, &context.view()?);
    let mut file = open_records(out, OpenMode::CreateNew, context.seams.hooks.as_ref())
        .map_err(|_| Error::Unavailable)?;
    file.write_all(text.as_bytes())
        .map_err(|_| Error::Unavailable)?;
    file.sync_all().map_err(|_| Error::Unavailable)?;
    disk::sync_parent(out).map_err(|_| Error::Unavailable)?;
    Ok(json!({"statement_version":context.config.settings().statement_version,"bytes":text.len()}))
}
