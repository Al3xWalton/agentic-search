//! Matches private hash-only URL and host lists using indexed lookups and DNS-label boundaries.
//! The only public metadata is the configured version and aggregate counts; raw lists are not exported.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey, TextClass},
    disk::{self, ComplianceHooks, ComplianceStage, OpenMode},
    model::{sha256, DocumentKey, Hex64},
    Error, Result,
};
use crate::config::compliance::ValidatedComplianceConfig;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    path::Path,
};

/// Aggregate access-audit metadata; no membership or personal input is included.
#[derive(Clone, Serialize)]
pub struct ListedMetadata {
    /// Validated operator version, or empty for absent local configuration.
    pub version: String,
    /// Count of URL hashes.
    pub url_count: u64,
    /// Count of host hashes.
    pub host_count: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListedData {
    pub(crate) version: String,
    pub(crate) url_hashes: Vec<Hex64>,
    pub(crate) host_hashes: Vec<Hex64>,
}

/// Reusable serving matcher; sorted sets are built once at load or snapshot replacement.
#[derive(Clone)]
pub struct ListedMatcher {
    data: ListedData,
    urls: BTreeSet<Hex64>,
    hosts: BTreeSet<Hex64>,
}

/// Request-local host suffix cache; each distinct normalized host is hashed once per request.
#[derive(Default)]
pub struct HostCache(BTreeMap<String, Vec<Hex64>>);

impl ListedMatcher {
    /// Returns an empty local matcher only for explicitly absent configuration.
    pub fn empty() -> Self {
        Self {
            data: ListedData {
                version: String::new(),
                url_hashes: Vec::new(),
                host_hashes: Vec::new(),
            },
            urls: BTreeSet::new(),
            hosts: BTreeSet::new(),
        }
    }

    /// Loads a configured private file; every invalid configured input is serving-critical.
    pub fn load(config: &ValidatedComplianceConfig, hooks: &dyn ComplianceHooks) -> Result<Self> {
        let Some(path) = config.settings().listed_hashes_file.as_deref() else {
            return Ok(Self::empty());
        };
        let file = open_listed(path, hooks).map_err(|_| Error::RulesUnavailable)?;
        let cap = BoundKey::ListFile
            .spec()
            .max
            .min(config.settings().max_rules_bytes);
        let bytes = disk::read_bounded(file, cap).map_err(|_| Error::RulesUnavailable)?;
        hooks
            .at(ComplianceStage::BeforeDecode)
            .map_err(|_| Error::RulesUnavailable)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FileSet {
            format_version: u64,
            version: String,
            url_hashes: Vec<Hex64>,
            host_hashes: Vec<Hex64>,
        }
        let loaded: FileSet =
            serde_json::from_slice(&bytes).map_err(|_| Error::RulesUnavailable)?;
        if loaded.format_version != 1 {
            return Err(Error::RulesUnavailable);
        }
        bounds::text(&loaded.version, BoundKey::Slug, TextClass::Slug)
            .map_err(|_| Error::RulesUnavailable)?;
        Self::from_data(
            ListedData {
                version: loaded.version,
                url_hashes: loaded.url_hashes,
                host_hashes: loaded.host_hashes,
            },
            config.settings().max_rules,
        )
    }

    pub(crate) fn from_data(data: ListedData, cap: u64) -> Result<Self> {
        if data.version.is_empty() {
            if !data.url_hashes.is_empty() || !data.host_hashes.is_empty() {
                return Err(Error::RulesUnavailable);
            }
        } else {
            bounds::text(&data.version, BoundKey::Slug, TextClass::Slug)
                .map_err(|_| Error::RulesUnavailable)?;
        }
        let count = (data.url_hashes.len() as u64)
            .checked_add(data.host_hashes.len() as u64)
            .ok_or(Error::RulesUnavailable)?;
        bounds::validate_range(count, 0, cap.min(BoundKey::ListEntries.spec().max))
            .map_err(|_| Error::RulesUnavailable)?;
        if !data.url_hashes.windows(2).all(|pair| pair[0] < pair[1])
            || !data.host_hashes.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(Error::RulesUnavailable);
        }
        let urls = data.url_hashes.iter().cloned().collect::<BTreeSet<_>>();
        let hosts = data.host_hashes.iter().cloned().collect::<BTreeSet<_>>();
        if !urls.is_disjoint(&hosts) {
            return Err(Error::RulesUnavailable);
        }
        Ok(Self { data, urls, hosts })
    }

    pub(crate) fn data(&self) -> &ListedData {
        &self.data
    }

    /// Returns only the aggregate audit fields, never an entry or a match result description.
    pub fn metadata(&self) -> ListedMetadata {
        ListedMetadata {
            version: self.data.version.clone(),
            url_count: self.urls.len() as u64,
            host_count: self.hosts.len() as u64,
        }
    }

    /// Denies a URL identity, its exact normalized host or any DNS-label parent.
    /// Canonical URLs are validated before this seam; an invalid URL fails closed.
    pub fn denies(
        &self,
        document: &DocumentKey,
        canonical_url: &str,
        cache: &mut HostCache,
    ) -> bool {
        if self
            .urls
            .contains(&Hex64::parse(document.as_str()).expect("validated document key"))
        {
            return true;
        }
        let Ok(parsed) = url::Url::parse(canonical_url) else {
            return true;
        };
        let Some(host) = parsed.host() else {
            return true;
        };
        let domain = matches!(host, url::Host::Domain(_));
        let spelling = host.to_string();
        let spelling = if domain {
            spelling.strip_suffix('.').unwrap_or(&spelling).to_owned()
        } else {
            spelling
        };
        let hashes = cache
            .0
            .entry(spelling.clone())
            .or_insert_with(|| host_hashes(&spelling, domain));
        if hashes.first().is_some_and(|full| self.hosts.contains(full)) {
            return true;
        }
        hashes
            .iter()
            .skip(1)
            .any(|parent| self.hosts.contains(parent))
    }
}

fn host_hashes(host: &str, domain: bool) -> Vec<Hex64> {
    let mut suffix = host;
    let mut hashes = Vec::new();
    loop {
        hashes.push(Hex64::parse(&sha256(&[suffix.as_bytes()])).expect("SHA256 is hexadecimal"));
        let Some((_, parent)) = suffix.split_once('.').filter(|_| domain) else {
            break;
        };
        suffix = parent;
    }
    hashes
}

fn open_listed(path: &Path, hooks: &dyn ComplianceHooks) -> io::Result<File> {
    disk::open_for(path, OpenMode::Read, hooks)
}
