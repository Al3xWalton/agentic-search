//! Validates the single ingestion policy before any transport or persistent-store creation.
//! Integer units, restrictive defaults and unknown-field rejection prevent silent bypasses.
//! Legal approval is an operator attestation; this module does not establish its authenticity.

#![deny(missing_docs)]

use crate::crawler::{identity, politeness::*};
use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path, sync::Arc, time::Duration};

/// Validated identity inputs; the token and package version are fixed in the builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdentityConfig {
    /// Absolute HTTPS policy location without credentials, fragment or UA delimiters.
    pub policy_url: String,
    /// Bare ASCII mailbox or absolute HTTPS contact location.
    pub contact: String,
}
impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            policy_url: "https://github.com/Al3xWalton/agentic-search/blob/main/CRAWLER_POLICY.md"
                .into(),
            contact: "https://github.com/Al3xWalton/agentic-search/issues".into(),
        }
    }
}

/// Robots cache policy; unreachable snapshots use the fixed failure retry interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RobotsConfig {
    /// Usable snapshot lifetime in seconds, 1..=86,400; default 3,600.
    pub cache_secs: u64,
}
impl Default for RobotsConfig {
    fn default() -> Self {
        Self { cache_secs: 3600 }
    }
}

/// Per-host timing values; requests of all kinds share the same limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolitenessConfig {
    /// Request-start gap in milliseconds, 500..=86,400,000.
    pub gap_ms: u64,
    /// Simultaneously live host connections, 1..=2; default 1.
    pub max_concurrent_per_host: usize,
    /// Access-denial block in seconds, at least 86,400 and within UTC arithmetic.
    pub block_secs: u64,
    /// Maximum eligible retry count, 0..=3; the sample never retries a page.
    pub retry_budget: u8,
}
impl Default for PolitenessConfig {
    fn default() -> Self {
        Self {
            gap_ms: DEFAULT_HOST_GAP_MS,
            max_concurrent_per_host: DEFAULT_HOST_CONCURRENCY,
            block_secs: MIN_BLOCK_SECS,
            retry_budget: 3,
        }
    }
}

/// Raw-body and future serving retention policy; records have no automatic TTL here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// Raw-body maximum age from parse in days, 0..=30; zero forbids retention.
    pub raw_body_max_age_days: u16,
    /// Local snippet upper bound in Unicode scalar values, 0..=300.
    pub snippet_max_chars: u16,
    /// Future query-log maximum age in days, 0..=90; enforced by Story #588.
    pub query_log_max_age_days: u16,
    /// Future IPv4 query-log network prefix, exactly 24 bits.
    pub query_ip_v4_prefix: u8,
    /// Future IPv6 query-log network prefix, exactly 48 bits.
    pub query_ip_v6_prefix: u8,
    /// Requires salt rotation in the future query-log store.
    pub query_rotating_salt_required: bool,
    /// Must remain false; ingestion does not authorize a user-facing cached copy.
    pub cached_copy: bool,
    /// Must remain false; retained data cannot be used for profiling.
    pub profiling_allowed: bool,
    /// Must remain false; retained data cannot be used for advertising.
    pub advertising_allowed: bool,
}
impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            raw_body_max_age_days: 30,
            snippet_max_chars: 300,
            query_log_max_age_days: 90,
            query_ip_v4_prefix: 24,
            query_ip_v6_prefix: 48,
            query_rotating_salt_required: true,
            cached_copy: false,
            profiling_allowed: false,
            advertising_allowed: false,
        }
    }
}

/// Supplied policy-list categories; no page or person classifier is implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentClass {
    /// Terrorism policy list.
    Terrorism,
    /// Child sexual exploitation and abuse policy list.
    Csea,
    /// Assisting-suicide policy list.
    AssistingSuicide,
    /// Encouraging serious self-harm policy list.
    EncouragingSeriousSelfHarm,
    /// Threats, harassment and stalking policy list.
    ThreatsHarassmentStalking,
    /// Public-order and hate policy list.
    PublicOrderHate,
    /// Drugs policy list.
    Drugs,
    /// Firearms and weapons policy list.
    FirearmsWeapons,
    /// Illegal immigration and trafficking policy list.
    IllegalImmigrationTrafficking,
    /// Sexual exploitation policy list.
    SexualExploitation,
    /// Intimate-image offences and cyberflashing policy list.
    IntimateImageOffencesCyberflashing,
    /// Proceeds-of-crime policy list.
    ProceedsOfCrime,
    /// Fraud policy list.
    Fraud,
    /// Financial-services policy list.
    FinancialServices,
    /// Foreign-interference policy list.
    ForeignInterference,
    /// Animal-welfare policy list.
    AnimalWelfare,
    /// Primary-priority pornography policy list.
    Pornography,
    /// Primary-priority suicide-promotion policy list.
    SuicidePromotion,
    /// Primary-priority self-harm-promotion policy list.
    SelfHarmPromotion,
    /// Primary-priority eating-disorder-promotion policy list.
    EatingDisorderPromotion,
    /// Incomplete umbrella pending founder review of the s.62 taxonomy.
    PriorityS62PendingReview,
}
impl ContentClass {
    /// Returns whether the supplied class requires adult verification at serving time.
    pub fn requires_adult_verification(self) -> bool {
        matches!(
            self,
            Self::Pornography
                | Self::SuicidePromotion
                | Self::SelfHarmPromotion
                | Self::EatingDisorderPromotion
        )
    }
}

/// Restrictive content-list actions; only NeverCrawl blocks admission in this Story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentPolicy {
    /// Refuses the host before robots, DNS or network access.
    #[serde(rename = "never-crawl")]
    NeverCrawl,
    /// Stores the requirement for UK/unknown serving suppression in Story #588.
    #[serde(rename = "crawl-but-suppress-UK")]
    CrawlButSuppressUk,
    /// Stores the requirement for child-serving suppression in Story #588.
    #[serde(rename = "suppress-for-children")]
    SuppressForChildren,
    /// Stores the requirement for serving down-ranking in Story #588.
    #[serde(rename = "down-rank")]
    DownRank,
}

/// One versioned exact-host or label-boundary subdomain policy-list entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassRule {
    /// Unique stable policy-rule identifier; never raw page text.
    pub id: String,
    /// Canonical ASCII hostname without scheme, path or port.
    pub host: String,
    /// Includes only DNS label-boundary subdomains when true.
    #[serde(default)]
    pub include_subdomains: bool,
    /// Declared list category; classification is supplied by the policy owner.
    pub class: ContentClass,
    /// Action stored or enforced for every matching rule.
    pub policy: ContentPolicy,
}

/// Separate listing-site crawl budget; this is not a fifth content-policy action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListingPolicy {
    /// Canonical ASCII host of the listing site.
    pub host: String,
    /// Includes only label-boundary subdomains when true.
    #[serde(default)]
    pub include_subdomains: bool,
    /// Page attempts in a rolling 24-hour window, including failed attempts.
    #[serde(default = "one_attempt")]
    pub max_page_attempts_per_24h: u32,
}
fn one_attempt() -> u32 {
    1
}

/// One auditable exclusion-policy revision; the last entry describes the active version.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChange {
    /// Version that became active at this change.
    pub version: String,
    /// UTC time of the declared policy revision.
    pub date_utc: DateTime<Utc>,
    /// Human-authored reason for the policy revision.
    pub reason: String,
    /// Review reference supplied by the policy owner.
    pub review_ref: String,
}

/// Offline country-provider configuration seam; no production provider is implemented in S1.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Provider identifier; it must be supplied by an installed offline adapter.
    pub id: String,
    /// Version of the provider's dataset, required for each observation.
    pub version: String,
}

/// Conservative defaults consumed by serving in Story #588.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServingPolicy {
    /// Applies UK measures to both known UK and unknown users; must be true.
    pub uk_or_unknown_measures: bool,
    /// Must be "same-as-uk" until a separate reviewed serving policy exists.
    pub non_uk_policy: String,
    /// Treats a missing adult-verification signal as a child; must be true.
    pub missing_adult_is_child: bool,
}
impl Default for ServingPolicy {
    fn default() -> Self {
        Self {
            uk_or_unknown_measures: true,
            non_uk_policy: "same-as-uk".into(),
            missing_adult_is_child: true,
        }
    }
}

/// Versioned, initially empty exclusion lists; deny rules always take precedence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExclusionsConfig {
    /// Active nonempty version matching the last change-log entry.
    pub version: String,
    /// UTC revision time matching the last change-log entry.
    pub changed_at_utc: DateTime<Utc>,
    /// Nonempty owner-supplied revision history; the last entry is active.
    pub change_log: Vec<PolicyChange>,
    /// Allowed two-letter DNS suffixes; empty means unrestricted.
    pub cctld_allow: Vec<String>,
    /// Denied two-letter DNS suffixes, with priority over allow rules.
    pub cctld_deny: Vec<String>,
    /// Allowed declared language tags; empty means unrestricted.
    pub language_allow: Vec<String>,
    /// Denied declared language tags, with priority over allow rules.
    pub language_deny: Vec<String>,
    /// Allowed uppercase country-code shapes; unknown fails closed when restricted.
    pub hosting_country_allow: Vec<String>,
    /// Denied uppercase country-code shapes; unknown fails closed when restricted.
    pub hosting_country_deny: Vec<String>,
    /// Offline provider seam; configured geography requires an available adapter.
    pub hosting_country_provider: Option<ProviderConfig>,
    /// Supplied exact-host content-class policies; empty labels no real organizations.
    pub rules: Vec<ClassRule>,
    /// Rolling per-host listing budgets; empty means no listing-specific cap.
    pub listing_sites: Vec<ListingPolicy>,
    /// Stored conservative serving requirements; this module does not enforce serving.
    pub serving: ServingPolicy,
}
impl Default for ExclusionsConfig {
    fn default() -> Self {
        let changed_at_utc = DateTime::parse_from_rfc3339("2026-09-11T00:00:00Z")
            .expect("fixed UTC date")
            .with_timezone(&Utc);
        Self {
            version: "585.1".into(),
            changed_at_utc,
            change_log: vec![PolicyChange {
                version: "585.1".into(),
                date_utc: changed_at_utc,
                reason: "Initial empty lists; founder review pending".into(),
                review_ref: "Story #585".into(),
            }],
            cctld_allow: vec![],
            cctld_deny: vec![],
            language_allow: vec![],
            language_deny: vec![],
            hosting_country_allow: vec![],
            hosting_country_deny: vec![],
            hosting_country_provider: None,
            rules: vec![],
            listing_sites: vec![],
            serving: ServingPolicy::default(),
        }
    }
}

/// Approval record lifecycle; only Approved can issue a production permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalStatus {
    /// Assessment awaiting approval; cannot issue a permit.
    Draft,
    /// Assessment explicitly approved by its owner.
    Approved,
    /// Previously approved assessment withdrawn by its owner.
    Revoked,
}

/// Operator-supplied approval attestation; authenticity remains a deployment responsibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRecord {
    /// Unique assessment identifier matched to the selected DPIA.
    pub id: String,
    /// Approval lifecycle state; only Approved is accepted.
    pub status: ApprovalStatus,
    /// Nonempty approver identity supplied by the operator.
    pub approver: String,
    /// Approval UTC timestamp, which cannot be in the future at startup.
    pub approved_at_utc: DateTime<Utc>,
    /// Linked legitimate-interests assessment identifier.
    pub lia_id: String,
    /// Absolute HTTPS public summary location for that assessment.
    pub lia_summary_url: String,
    /// Linked Article 14 measures identifier.
    pub article14_measures_id: String,
    /// Policy version covered by the assessment.
    pub policy_version: String,
}

/// Production gate defaults; a sample or fixture is never a production approval.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProductionApproval {
    /// Selected DPIA identifier, absent until founder approval is supplied.
    pub dpia_id: Option<String>,
    /// Attestations against which the selected identifier is checked.
    pub approved_records: Vec<ApprovedRecord>,
    /// Operator attestation of cross-process host ownership; false refuses startup.
    pub distributed_host_lease_configured: bool,
}

/// Founder-owned publication inputs; absent content renders an explicit placeholder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyContent {
    /// Approved controller identity, absent while pending.
    pub controller_identity: Option<String>,
    /// Approved LIA summary HTTPS location, absent while pending.
    pub lia_summary_url: Option<String>,
    /// Private removal/delisting HTTPS route, absent while pending.
    pub removal_url: Option<String>,
    /// Online Safety reporting HTTPS route, absent while pending.
    pub osa_report_url: Option<String>,
    /// Private controller complaints HTTPS route, absent while pending.
    pub complaints_url: Option<String>,
    /// Founder-confirmed ICO complaints HTTPS link, absent while pending.
    pub ico_url: Option<String>,
    /// Approved Article 14 notice rationale, absent while pending.
    pub article14_measures: Option<String>,
    /// Deployed signed egress file HTTPS location, absent until follow-up A.
    pub egress_file_url: Option<String>,
}

/// Single source for crawling, local retention and deterministic policy rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IngestionPolicy {
    /// Nonempty policy version carried by all new records.
    pub version: String,
    /// Fixed-grammar identity locations used by every fetch.
    pub identity: IdentityConfig,
    /// Origin-specific robots cache lifetime.
    pub robots: RobotsConfig,
    /// Host timing bounds shared by all fetch kinds.
    pub politeness: PolitenessConfig,
    /// Raw-body limits and future serving retention contracts.
    pub retention: RetentionConfig,
    /// Versioned exclusion policy and listing budgets.
    pub exclusions: ExclusionsConfig,
    /// Attestations required before production side effects.
    pub production: ProductionApproval,
    /// Founder-owned publication content, explicit when absent.
    pub policy_content: PolicyContent,
}
impl Default for IngestionPolicy {
    fn default() -> Self {
        Self {
            version: "585.1".into(),
            identity: IdentityConfig::default(),
            robots: RobotsConfig::default(),
            politeness: PolitenessConfig::default(),
            retention: RetentionConfig::default(),
            exclusions: ExclusionsConfig::default(),
            production: ProductionApproval::default(),
            policy_content: PolicyContent::default(),
        }
    }
}

/// Immutable validated policy; only validation can construct this wrapper.
#[derive(Debug, Clone)]
pub struct ValidatedPolicy(Arc<IngestionPolicy>);
impl ValidatedPolicy {
    /// Returns immutable configuration without allowing mutation after validation.
    pub fn get(&self) -> &IngestionPolicy {
        &self.0
    }
    /// Returns a deterministic SHA-256 of serialized validated policy bytes.
    pub fn sha256(&self) -> String {
        let bytes = serde_json::to_vec(self.get()).expect("policy has serializable scalar fields");
        ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Non-convertible production capability issued only for a validated approval record.
#[derive(Debug)]
pub struct ProductionPermit {
    policy: ValidatedPolicy,
}
impl ProductionPermit {
    /// Returns the immutable policy associated with this approval lifecycle.
    pub fn policy(&self) -> &ValidatedPolicy {
        &self.policy
    }
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn language_tag(value: &str) -> bool {
    value.split('-').enumerate().all(|(i, part)| {
        !part.is_empty()
            && part.len() <= 8
            && part.bytes().all(|b| {
                if i == 0 {
                    b.is_ascii_alphabetic()
                } else {
                    b.is_ascii_alphanumeric()
                }
            })
    })
}
fn checked_duration(gap_ms: u64) -> Result<Duration> {
    ensure!(
        gap_ms <= 86_400_000,
        "ingestion.politeness.gap_ms exceeds 24 hours"
    );
    let nanos = gap_ms
        .checked_mul(1_000_000)
        .context("ingestion.politeness.gap_ms overflow")?;
    Ok(Duration::from_nanos(nanos))
}
fn validate_retention_bounds(r: &RetentionConfig) -> Result<()> {
    ensure!(
        r.raw_body_max_age_days <= 30
            && r.snippet_max_chars <= 300
            && r.query_log_max_age_days <= 90
            && r.query_ip_v4_prefix == 24
            && r.query_ip_v6_prefix == 48
            && r.query_rotating_salt_required
            && !r.cached_copy
            && !r.profiling_allowed
            && !r.advertising_allowed,
        "ingestion.retention violates bounds or required safeguards"
    );
    Ok(())
}
fn validate_exclusion_schema(e: &ExclusionsConfig) -> Result<()> {
    ensure!(
        nonempty(&e.version),
        "ingestion.exclusions.version is required"
    );
    let head = e
        .change_log
        .last()
        .context("ingestion.exclusions.change_log is empty")?;
    ensure!(
        head.version == e.version && head.date_utc == e.changed_at_utc,
        "ingestion.exclusions change-log head differs from policy"
    );
    for change in &e.change_log {
        ensure!(
            nonempty(&change.version) && nonempty(&change.reason) && nonempty(&change.review_ref),
            "ingestion.exclusions incomplete change-log entry"
        );
    }
    for code in e.cctld_allow.iter().chain(&e.cctld_deny) {
        ensure!(
            code.len() == 2 && code.bytes().all(|b| b.is_ascii_lowercase()),
            "ingestion.exclusions ccTLD must be two lowercase DNS letters"
        );
    }
    for code in e
        .hosting_country_allow
        .iter()
        .chain(&e.hosting_country_deny)
    {
        ensure!(
            code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()),
            "ingestion.exclusions country code must be two uppercase letters"
        );
    }
    for tag in e.language_allow.iter().chain(&e.language_deny) {
        ensure!(
            language_tag(tag),
            "ingestion.exclusions invalid language tag"
        );
    }
    if !e.hosting_country_allow.is_empty() || !e.hosting_country_deny.is_empty() {
        ensure!(
            e.hosting_country_provider.is_some(),
            "ingestion.exclusions country restrictions require an offline provider"
        );
    }
    if let Some(provider) = &e.hosting_country_provider {
        ensure!(
            nonempty(&provider.id) && nonempty(&provider.version),
            "ingestion.exclusions incomplete country provider"
        );
    }
    let mut ids = BTreeSet::new();
    for rule in &e.rules {
        ensure!(
            nonempty(&rule.id) && ids.insert(&rule.id) && valid_host(&rule.host),
            "ingestion.exclusions invalid or duplicate rule"
        );
    }
    for listing in &e.listing_sites {
        ensure!(
            valid_host(&listing.host),
            "ingestion.exclusions invalid listing host"
        );
    }
    ensure!(
        e.serving.uk_or_unknown_measures
            && e.serving.non_uk_policy == "same-as-uk"
            && e.serving.missing_adult_is_child,
        "ingestion.exclusions.serving must preserve conservative defaults"
    );
    Ok(())
}

impl IngestionPolicy {
    /// Validates direct or deserialized policy before transport/storage; returns field-only errors.
    pub fn validate(&self) -> Result<ValidatedPolicy> {
        ensure!(nonempty(&self.version), "ingestion.version is required");
        identity::build_user_agent(&self.identity)?;
        let cache_secs = self.robots.cache_secs;
        if cache_secs == 0 || cache_secs > MAX_ROBOTS_CACHE_SECS {
            bail!("ingestion.robots.cache_secs must be 1..=86400");
        }
        let gap_ms = self.politeness.gap_ms;
        if gap_ms < HARD_MIN_HOST_GAP_MS {
            bail!("ingestion.politeness.gap_ms must be at least 500");
        }
        checked_duration(gap_ms)?;
        ensure!(
            (1..=HARD_MAX_HOST_CONCURRENCY).contains(&self.politeness.max_concurrent_per_host),
            "ingestion.politeness.max_concurrent_per_host must be 1..=2"
        );
        ensure!(
            self.politeness.block_secs >= MIN_BLOCK_SECS
                && i64::try_from(self.politeness.block_secs)
                    .ok()
                    .and_then(chrono::TimeDelta::try_seconds)
                    .and_then(|d| Utc::now().checked_add_signed(d))
                    .is_some(),
            "ingestion.politeness.block_secs violates minimum or UTC arithmetic"
        );
        ensure!(
            self.politeness.retry_budget <= 3,
            "ingestion.politeness.retry_budget must be 0..=3"
        );
        validate_retention_bounds(&self.retention)?;
        validate_exclusion_schema(&self.exclusions)?;
        for location in [
            &self.policy_content.lia_summary_url,
            &self.policy_content.removal_url,
            &self.policy_content.osa_report_url,
            &self.policy_content.complaints_url,
            &self.policy_content.ico_url,
            &self.policy_content.egress_file_url,
        ]
        .into_iter()
        .flatten()
        {
            identity::validate_policy_url(location)?;
        }
        Ok(ValidatedPolicy(Arc::new(self.clone())))
    }

    /// Loads an explicit policy TOML file or complete crawler template with contextual path errors.
    pub fn load(path: &Path) -> Result<ValidatedPolicy> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("read ingestion config {}", path.display()))?;
        let value: toml::Value = toml::from_str(&source)
            .with_context(|| format!("parse ingestion config {}", path.display()))?;
        let policy: Self = if value.get("ingestion").is_some() {
            let config: super::CrawlerConfig = value
                .try_into()
                .with_context(|| format!("decode crawler config {}", path.display()))?;
            config.ingestion
        } else {
            value
                .try_into()
                .with_context(|| format!("decode ingestion config {}", path.display()))?
        };
        policy
            .validate()
            .with_context(|| format!("validate ingestion config {}", path.display()))
    }

    /// Issues a production permit only for a unique approved DPIA with matching linked assessments.
    /// `environment_id` is an optional DPIA_ID value and never overrides configuration.
    pub fn require_production_approval(
        &self,
        now: DateTime<Utc>,
        environment_id: Option<&str>,
    ) -> Result<ProductionPermit> {
        let policy = self.validate()?;
        let approval = &self.production;
        let id = approval
            .dpia_id
            .as_deref()
            .filter(|id| nonempty(id))
            .context("production requires selected dpia_id")?;
        ensure!(
            environment_id.is_none_or(|value| value == id),
            "DPIA_ID must equal configured dpia_id"
        );
        let matches: Vec<_> = approval
            .approved_records
            .iter()
            .filter(|record| record.id == id)
            .collect();
        ensure!(
            matches.len() == 1,
            "production requires exactly one matching assessment"
        );
        let record = matches[0];
        ensure!(
            record.status == ApprovalStatus::Approved
                && record.approved_at_utc <= now
                && nonempty(&record.approver)
                && nonempty(&record.lia_id)
                && nonempty(&record.article14_measures_id)
                && record.policy_version == self.version,
            "production assessment is incomplete, unapproved, future-dated or for another policy"
        );
        identity::validate_policy_url(&record.lia_summary_url)?;
        ensure!(
            approval.distributed_host_lease_configured,
            "production requires coordinated host ownership"
        );
        Ok(ProductionPermit { policy })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_validates_and_defaults_agree() {
        let path = std::path::PathBuf::from(
            std::env::var_os("STORY584_SCRATCH").expect("external scratch"),
        )
        .join(format!("ingestion-config-{}.toml", uuid::Uuid::new_v4()));
        let template = include_str!("../../../../configs/crawler/crawler.toml");
        std::fs::write(&path, template).unwrap();
        assert!(IngestionPolicy::load(&path).is_ok());
        std::fs::write(&path, format!("dry_run=true\n{template}")).unwrap();
        assert!(IngestionPolicy::load(&path).is_err());
        std::fs::remove_file(path).unwrap();
        let config: crate::config::CrawlerConfig =
            toml::from_str(include_str!("../../../../configs/crawler/crawler.toml")).unwrap();
        assert_eq!(
            config.ingestion.validate().unwrap().sha256(),
            IngestionPolicy::default().validate().unwrap().sha256()
        );
        for text in [
            "user_agent = { full = 'unsafe', token = 'other' }",
            "unsafe_override = true",
        ] {
            assert!(toml::from_str::<IngestionPolicy>(text).is_err());
        }
        assert!(toml::from_str::<crate::config::CrawlerConfig>(&format!(
            "dry_run=true\n{}",
            include_str!("../../../../configs/crawler/crawler.toml")
        ))
        .is_err());
    }

    #[test]
    fn dpia_guard() {
        let mut policy = IngestionPolicy::default();
        let now = Utc::now();
        assert!(policy.require_production_approval(now, None).is_err());
        policy.production.dpia_id = Some("assessment-1".into());
        policy.production.distributed_host_lease_configured = true;
        policy.production.approved_records.push(ApprovedRecord {
            id: "assessment-1".into(),
            status: ApprovalStatus::Approved,
            approver: "fixture approver".into(),
            approved_at_utc: now,
            lia_id: "lia-1".into(),
            lia_summary_url: "https://example.invalid/lia".into(),
            article14_measures_id: "notice-1".into(),
            policy_version: policy.version.clone(),
        });
        assert!(policy
            .require_production_approval(now, Some("assessment-1"))
            .is_ok());
        assert!(policy
            .require_production_approval(now, Some("other"))
            .is_err());
        for invalid in [ApprovalStatus::Draft, ApprovalStatus::Revoked] {
            let mut modified = policy.clone();
            modified.production.approved_records[0].status = invalid;
            assert!(modified.require_production_approval(now, None).is_err());
        }
        for i in 0..7 {
            let mut modified = policy.clone();
            match i {
                0 => modified.production.approved_records[0].approver.clear(),
                1 => modified.production.approved_records[0].lia_id.clear(),
                2 => modified.production.approved_records[0]
                    .article14_measures_id
                    .clear(),
                3 => modified.production.approved_records[0]
                    .policy_version
                    .clear(),
                4 => {
                    modified.production.approved_records[0].approved_at_utc =
                        now + chrono::TimeDelta::seconds(1)
                }
                5 => modified
                    .production
                    .approved_records
                    .push(modified.production.approved_records[0].clone()),
                6 => modified.production.distributed_host_lease_configured = false,
                _ => unreachable!(),
            }
            assert!(modified.require_production_approval(now, None).is_err());
        }
    }
}
