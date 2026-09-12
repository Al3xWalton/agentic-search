//! Applies versioned host, geographic, language and listing policy at admission and after parsing.
//! Denial wins; host matching uses DNS label boundaries. Country inference requires an explicit
//! provider and unresolved restricted countries fail closed. No content/person classifier exists.

#![deny(missing_docs)]

use super::{network::HostKey, Error, Result};
use crate::config::ingestion::{ContentClass, ContentPolicy, ExclusionsConfig};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use url::Url;

/// Lifecycle phase at which an exclusion was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExclusionPhase {
    /// Before robots, DNS or page admission.
    Frontier,
    /// After receiving and parsing an in-memory body, before any sink write.
    PostParse,
}
/// Bounded policy reason without raw publisher text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExclusionReason {
    /// Target is outside the sealed exact input scope.
    OutsideScope,
    /// A supplied host class has the never-crawl policy.
    NeverCrawl,
    /// The canonical host's country-code suffix is denied.
    CctldDenied,
    /// A nonempty country-code suffix allow-list did not match.
    CctldNotAllowed,
    /// A configured country restriction lacks an unambiguous provider result.
    CountryUnresolved,
    /// The address's known hosting country is denied.
    HostingCountryDenied,
    /// A known hosting country does not match the nonempty allow-list.
    HostingCountryNotAllowed,
    /// At least one declared language matches a deny entry.
    LanguageDenied,
    /// No declared language matches the nonempty allow-list.
    LanguageNotAllowed,
    /// The rolling host page-attempt budget has been consumed.
    ListingBudgetExhausted,
}
/// One matched supplied rule; all matches are retained even when another match denies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExclusionMatch {
    /// Validated configuration rule ID, without publisher content.
    pub rule_id: String,
    /// Phase at which the match was evaluated.
    pub phase: ExclusionPhase,
}
/// Reason that a hosting country could not be declared as known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CountryUnknownReason {
    /// No production country provider is implemented or configured.
    NoProvider,
    /// Address admission has not occurred for this target.
    NotResolved,
    /// The provider had no valid result for an admitted address.
    ProviderUnavailable,
    /// Different admitted addresses have different country results.
    ConflictingAddresses,
}
/// Explicit provider-backed hosting country observation, never inferred from a ccTLD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum HostingCountry {
    /// Provider supplied one unambiguous syntactically valid code for all admitted addresses.
    Known {
        /// Uppercase two-letter country code; provider owns its semantic validity.
        code: String,
        /// Exact configured provider version used for this observation.
        provider_version: String,
    },
    /// Country is unavailable for the explicit reason.
    Unknown {
        /// Typed absence cause, with no provider error text.
        reason: CountryUnknownReason,
    },
}
/// Offline address-country provider contract; production has no default implementation in Slice 1.
/// An owned loopback fixture may supply deterministic answers without authorizing any network.
pub trait HostingCountryProvider: Send + Sync {
    /// Stable provider identifier, exactly matching configuration.
    fn id(&self) -> &str;
    /// Dataset version, exactly matching configuration.
    fn version(&self) -> &str;
    /// Returns an optional uppercase two-letter code for the already admitted address.
    fn country(&self, address: IpAddr) -> Option<String>;
}
/// Full class-match result; non-never policies are stored for Story #588 serving enforcement.
#[derive(Debug, Clone, Default)]
pub struct ClassMatches {
    /// Every matched versioned rule ID, without input evidence.
    pub matches: Vec<ExclusionMatch>,
    /// Configured host classes only, never inferred content/person attributes.
    pub classes: Vec<ContentClass>,
    /// All supplied policies, with never-crawl taking precedence at admission.
    pub policies: Vec<ContentPolicy>,
}
/// Immutable exclusion evaluator shared by page, robots and auxiliary admission.
pub struct Exclusions {
    config: ExclusionsConfig,
    provider: Option<Arc<dyn HostingCountryProvider>>,
}
impl Exclusions {
    /// Validates the configured provider before any storage, DNS or worker startup.
    pub fn new(
        config: &ExclusionsConfig,
        provider: Option<Arc<dyn HostingCountryProvider>>,
    ) -> Result<Self> {
        match (&config.hosting_country_provider, &provider) {
            (None, None) => {}
            (Some(expected), Some(actual))
                if expected.id == actual.id() && expected.version == actual.version() => {}
            _ => return Err(Error::CountryProviderUnavailable),
        }
        Ok(Self {
            config: config.clone(),
            provider,
        })
    }
    /// Collects all exact/label-boundary supplied host rules before applying precedence.
    pub fn class_matches(&self, host: &HostKey) -> ClassMatches {
        let mut result = ClassMatches::default();
        for rule in &self.config.rules {
            if host_matches(host.as_str(), &rule.host, rule.include_subdomains) {
                result.matches.push(ExclusionMatch {
                    rule_id: rule.id.clone(),
                    phase: ExclusionPhase::Frontier,
                });
                if !result.classes.contains(&rule.class) {
                    result.classes.push(rule.class);
                }
                if !result.policies.contains(&rule.policy) {
                    result.policies.push(rule.policy);
                }
            }
        }
        result
    }
    fn never_crawl_matches(&self, host: &HostKey) -> bool {
        self.class_matches(host)
            .policies
            .contains(&ContentPolicy::NeverCrawl)
    }
    fn geo_scope_allows(&self, host: &HostKey) -> std::result::Result<(), ExclusionReason> {
        let suffix = host.as_str().rsplit('.').next().unwrap_or_default();
        if self.config.cctld_deny.iter().any(|s| s == suffix) {
            return Err(ExclusionReason::CctldDenied);
        }
        if !self.config.cctld_allow.is_empty()
            && !self.config.cctld_allow.iter().any(|s| s == suffix)
        {
            return Err(ExclusionReason::CctldNotAllowed);
        }
        Ok(())
    }
    /// Refuses never-crawl and suffix/language exclusions before robots or DNS.
    /// None means a first fetch with no prior language; its declaration is checked after parsing.
    pub fn frontier(&self, url: &Url, known_languages: Option<&[String]>) -> Result<ClassMatches> {
        let host = HostKey::from_url(url)?;
        if self.never_crawl_matches(&host) {
            return Err(Error::ExcludedByPolicy {
                reason: ExclusionReason::NeverCrawl,
                phase: ExclusionPhase::Frontier,
            });
        }
        self.geo_scope_allows(&host)
            .map_err(|reason| Error::ExcludedByPolicy {
                reason,
                phase: ExclusionPhase::Frontier,
            })?;
        if let Some(languages) = known_languages {
            self.language(languages, ExclusionPhase::Frontier)?;
        }
        Ok(self.class_matches(&host))
    }
    /// Resolves country only from already vetted connection addresses and the explicit offline provider.
    /// Unknown, conflicting and denied countries fail closed when any country restriction is active.
    pub fn addresses(&self, addresses: &[std::net::SocketAddr]) -> Result<HostingCountry> {
        let country = self.country(addresses);
        self.admit_country(&country)?;
        Ok(country)
    }
    pub(super) fn country(&self, addresses: &[std::net::SocketAddr]) -> HostingCountry {
        let mut country = HostingCountry::Unknown {
            reason: CountryUnknownReason::NoProvider,
        };
        if let Some(provider) = &self.provider {
            let mut codes = Vec::new();
            for address in addresses {
                let Some(code) = provider
                    .country(address.ip())
                    .filter(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase()))
                else {
                    codes.clear();
                    break;
                };
                codes.push(code);
            }
            country = if codes.is_empty() {
                HostingCountry::Unknown {
                    reason: CountryUnknownReason::ProviderUnavailable,
                }
            } else if codes.iter().any(|code| code != &codes[0]) {
                HostingCountry::Unknown {
                    reason: CountryUnknownReason::ConflictingAddresses,
                }
            } else {
                HostingCountry::Known {
                    code: codes[0].clone(),
                    provider_version: provider.version().into(),
                }
            };
        }
        country
    }
    pub(super) fn admit_country(&self, country: &HostingCountry) -> Result<()> {
        let reason = match country {
            HostingCountry::Unknown { .. }
                if !self.config.hosting_country_allow.is_empty()
                    || !self.config.hosting_country_deny.is_empty() =>
            {
                Some(ExclusionReason::CountryUnresolved)
            }
            HostingCountry::Known { code, .. }
                if self.config.hosting_country_deny.contains(code) =>
            {
                Some(ExclusionReason::HostingCountryDenied)
            }
            HostingCountry::Known { code, .. }
                if !self.config.hosting_country_allow.is_empty()
                    && !self.config.hosting_country_allow.contains(code) =>
            {
                Some(ExclusionReason::HostingCountryNotAllowed)
            }
            _ => None,
        };
        if let Some(reason) = reason {
            return Err(Error::ExcludedByPolicy {
                reason,
                phase: ExclusionPhase::Frontier,
            });
        }
        Ok(())
    }
    fn declared_language_allowed(
        &self,
        languages: &[String],
    ) -> std::result::Result<(), ExclusionReason> {
        if languages.iter().any(|language| {
            self.config
                .language_deny
                .iter()
                .any(|rule| language_matches(language, rule))
        }) {
            return Err(ExclusionReason::LanguageDenied);
        }
        if !self.config.language_allow.is_empty()
            && !languages.iter().any(|language| {
                self.config
                    .language_allow
                    .iter()
                    .any(|rule| language_matches(language, rule))
            })
        {
            return Err(ExclusionReason::LanguageNotAllowed);
        }
        Ok(())
    }
    /// Applies deny precedence over every declaration; a nonempty allow-list needs a declaration.
    pub fn language(&self, languages: &[String], phase: ExclusionPhase) -> Result<()> {
        self.declared_language_allowed(languages)
            .map_err(|reason| Error::ExcludedByPolicy { reason, phase })
    }
    /// Returns the most restrictive explicit listing budget, in page attempts per rolling 24h.
    pub fn listing_limit(&self, host: &HostKey) -> Option<u32> {
        self.config
            .listing_sites
            .iter()
            .filter(|rule| host_matches(host.as_str(), &rule.host, rule.include_subdomains))
            .map(|rule| rule.max_page_attempts_per_24h)
            .min()
    }
}
fn host_matches(host: &str, rule: &str, subdomains: bool) -> bool {
    host == rule
        || (subdomains
            && host
                .strip_suffix(rule)
                .is_some_and(|prefix| prefix.ends_with('.')))
}
fn language_matches(language: &str, rule: &str) -> bool {
    let language = language.to_ascii_lowercase();
    let rule = rule.to_ascii_lowercase();
    language == rule
        || language
            .strip_prefix(&rule)
            .is_some_and(|tail| tail.starts_with('-'))
}

/// Accepts a bounded BCP47-shaped declared language, without claiming registry validation.
pub fn declared_language(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() > 63
        || value.is_empty()
        || !value.split('-').all(|part| {
            !part.is_empty() && part.len() <= 8 && part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    {
        return None;
    }
    let first = value.split('-').next()?;
    if first.len() < 2 || !first.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}
