//! Converts validated v1 input to the HTTP-independent compliance owners and fixed errors.
//! The observation bridge forwards finite events only; it never exposes credentials or personal text.

use super::{
    error::{V1Error, V1Failure},
    suppression::canonical_identity,
    AdmissionLease, CappedBody, Observer, V1State,
};
use crate::{
    compliance::{
        self,
        auth::{AuthObserver, Authenticator},
        bounds::{self, BoundKey, TextClass},
        disk::{ComplianceHooks, NoHooks},
        model::{Asset, DocumentKey, Entropy, Intake, IntakeKind, SystemEntropy},
        rules::{NoRulesHooks, RulesHooks},
        tickets::{ComplianceStore, TicketObserver},
    },
    config::{compliance::ValidatedComplianceConfig, ApiConfig},
    crawler::politeness::{Clock, SystemClock},
    query::planner::bounds::InputError,
};
use axum::extract::Request;
use serde::de::DeserializeOwned;
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};

pub(super) struct ObservationBridge(RwLock<Arc<dyn Observer>>);
impl ObservationBridge {
    pub(super) fn replace(&self, observer: Arc<dyn Observer>) {
        *self.0.write().expect("observer bridge poisoned") = observer;
    }
}
impl TicketObserver for ObservationBridge {
    fn lookup(&self) {
        self.0
            .read()
            .expect("observer bridge poisoned")
            .compliance_lookup();
    }
    fn journal_write(&self) {
        self.0
            .read()
            .expect("observer bridge poisoned")
            .compliance_journal_write();
    }
}
impl AuthObserver for ObservationBridge {
    fn authentication_attempt(&self) {
        self.0
            .read()
            .expect("observer bridge poisoned")
            .authentication_attempt();
    }
    fn verifier_invoked(&self, expected: usize, presented: usize) {
        self.0
            .read()
            .expect("observer bridge poisoned")
            .authentication_verifier(expected, presented);
    }
}

/// Startup seams affect clocks, entropy and actual persistence observations without replacing guards.
pub struct ComplianceSeams {
    /// UTC source shared by journal transactions and serving activation.
    pub clock: Arc<dyn Clock>,
    /// Full-width entropy provider for capabilities and independent salts.
    pub entropy: Arc<dyn Entropy>,
    /// Actual private-file and transaction stages.
    pub hooks: Arc<dyn ComplianceHooks>,
    /// Actual atomic rules replacement stages.
    pub rules_hooks: Arc<dyn RulesHooks>,
}
impl Default for ComplianceSeams {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock::default()),
            entropy: Arc::new(SystemEntropy),
            hooks: Arc::new(NoHooks),
            rules_hooks: Arc::new(NoRulesHooks),
        }
    }
}

pub(super) struct Resources {
    /// Rendered startup response, retained independently of ticket availability.
    pub(super) publication: compliance::Result<Arc<super::statement::V1StatementResponse>>,
    pub(super) store: Arc<ComplianceStore>,
    pub(super) auth: Arc<Authenticator>,
    pub(super) bridge: Arc<ObservationBridge>,
    pub(super) config: ValidatedComplianceConfig,
}
/// Process-wide weak association keyed by suppression-owner Arc identity; no owner lifetime
/// is extended and no authoritative side database is created.
struct SharedResources {
    owner: Weak<super::suppression::SuppressionStore>,
    resources: Weak<Resources>,
}
/// Weak resource registry using the actual owner's path for derived sibling stores.
static SHARED: OnceLock<Mutex<Vec<SharedResources>>> = OnceLock::new();
impl Resources {
    /// Reuses owners by Arc identity and actual path, rejecting mismatched validated config.
    /// Caller seams are ignored on reuse; weak entries never extend an owner's lifetime.
    pub(super) fn for_store(
        config: &ApiConfig,
        owner: &Arc<super::suppression::SuppressionStore>,
        seams: ComplianceSeams,
    ) -> anyhow::Result<Arc<Self>> {
        // Reusing an already-open suppression owner must reuse its sibling owners as well.
        // Weak associations neither extend lock lifetimes nor create an authoritative side store.
        let mut actual = config.clone();
        actual.v1.suppression_store_path = owner.disk.path.clone();
        let validated = actual
            .compliance
            .validate(&actual.v1.suppression_store_path)?;
        let mut shared = SHARED
            .get_or_init(|| Mutex::new(Vec::new()))
            .lock()
            .map_err(|_| anyhow::anyhow!("compliance resource registry unavailable"))?;
        shared.retain(|entry| entry.owner.strong_count() > 0 && entry.resources.strong_count() > 0);
        for entry in shared.iter() {
            if entry
                .owner
                .upgrade()
                .is_some_and(|prior| Arc::ptr_eq(&prior, owner))
            {
                let resources = entry
                    .resources
                    .upgrade()
                    .ok_or(compliance::Error::Unavailable)?;
                if serde_json::to_value(resources.config.settings())?
                    != serde_json::to_value(validated.settings())?
                    || resources.config.store_dir() != validated.store_dir()
                {
                    return Err(compliance::Error::InvalidInput.into());
                }
                return Ok(resources);
            }
        }
        let resources = Arc::new(Self::load(validated, seams)?);
        shared.push(SharedResources {
            owner: Arc::downgrade(owner),
            resources: Arc::downgrade(&resources),
        });
        Ok(resources)
    }

    fn load(config: ValidatedComplianceConfig, seams: ComplianceSeams) -> anyhow::Result<Self> {
        let publication = load_publication(&config, &seams);
        compliance::records::validate_hosted(&config, &publication, seams.clock.utc().timestamp())?;
        let publication = publication.map(|view| {
            Arc::new(super::statement::V1StatementResponse {
                version: super::dto::V1Version::V1,
                statement_version: config.settings().statement_version.clone(),
                markdown: compliance::statement::render(&config, &view),
            })
        });
        let loaded = Authenticator::load(
            config.settings().admin_token_file.as_deref(),
            seams.hooks.as_ref(),
        );
        let writes_disabled = loaded.is_err();
        let auth = loaded.unwrap_or_else(|_| {
            tracing::warn!(
                "Compliance token unavailable; management and compliance writes disabled"
            );
            Authenticator::disabled()
        });
        let bridge = Arc::new(ObservationBridge(RwLock::new(Arc::new(super::NoObserver))));
        let store = ComplianceStore::open(
            &config,
            seams.clock,
            seams.entropy,
            seams.hooks,
            seams.rules_hooks,
            bridge.clone(),
            writes_disabled,
        )?;
        Ok(Self {
            publication,
            store: Arc::new(store),
            auth: Arc::new(auth),
            bridge,
            config,
        })
    }
}

fn load_publication(
    config: &ValidatedComplianceConfig,
    seams: &ComplianceSeams,
) -> compliance::Result<compliance::records::RecordView> {
    compliance::records::read_view(config, seams.clock.as_ref(), seams.hooks.as_ref())
}

impl From<compliance::Error> for V1Error {
    fn from(error: compliance::Error) -> Self {
        let failure = match error {
            compliance::Error::InvalidInput => return InputError::InvalidRequest.into(),
            compliance::Error::NotFound => V1Failure::NotFound,
            compliance::Error::InvalidTransition => V1Failure::InvalidTransition,
            compliance::Error::RetentionNotDue => V1Failure::RetentionNotDue,
            compliance::Error::Unavailable => V1Failure::ComplianceUnavailable,
            compliance::Error::Capacity => V1Failure::ComplianceCapacity,
            compliance::Error::RulesUnavailable => V1Failure::RulesUnavailable,
        };
        Self::failure(failure)
    }
}

pub(super) fn decode<T: DeserializeOwned>(
    request: &Request,
    state: &V1State,
) -> Result<T, V1Error> {
    let media = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !media
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return Err(V1Error::failure(V1Failure::UnsupportedMediaType));
    }
    let body = request
        .extensions()
        .get::<CappedBody>()
        .ok_or_else(|| V1Error::failure(V1Failure::InternalError))?;
    state.observer.json_decode();
    serde_json::from_slice(&body.0).map_err(|_| InputError::InvalidRequest.into())
}

pub(super) fn lease(request: &Request) -> Result<Arc<dyn Send + Sync>, V1Error> {
    request
        .extensions()
        .get::<AdmissionLease>()
        .map(|value| value.0.clone() as Arc<dyn Send + Sync>)
        .ok_or_else(|| V1Error::failure(V1Failure::InternalError))
}

pub(super) fn intake(
    report: super::report_dto::V1ReportFields,
    urls: Vec<String>,
    category: IntakeKind,
) -> Result<Intake, V1Error> {
    let assets = urls
        .into_iter()
        .map(|raw| {
            bounds::text(&raw, BoundKey::Url, TextClass::Label)?;
            let (url, id) =
                canonical_identity(&raw).map_err(|_| compliance::Error::InvalidInput)?;
            Asset::new(url, DocumentKey::parse(id.as_str())?)
        })
        .collect::<compliance::Result<Vec<_>>>()?;
    let intake = Intake {
        report: report.into(),
        assets,
        category,
    };
    compliance::tickets::validate_intake(&intake)?;
    Ok(intake)
}
