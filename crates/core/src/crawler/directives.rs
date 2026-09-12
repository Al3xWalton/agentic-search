//! Parses bounded publisher directives and rights signals without fetching linked resources.
//! Restrictions merge monotonically across physical headers and metadata; invalid recognized
//! values fail closed. Signals are declarations, not licence interpretation or classifiers.

#![deny(missing_docs)]

use super::network::{safe_url_for_record, ResponseHeaders, SafeUrl};
use chrono::{DateTime, Utc};
use kuchiki::NodeRef;
use serde::{Deserialize, Serialize};
use url::Url;

/// Maximum number of sanitized directive observations retained per document.
pub const MAX_DIRECTIVES: usize = 256;

/// Origin of one sanitized publisher directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectiveSource {
    /// One physical X-Robots-Tag header occurrence.
    Header,
    /// A case-insensitive robots HTML meta element.
    MetaRobots,
    /// An exact case-insensitive AVASearchBot HTML meta element.
    MetaBot,
}

/// Recognized directive name, or a bounded safe unknown token without its raw value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectiveName {
    /// Prevent search-index admission.
    Noindex,
    /// Prevent frontier link extraction.
    Nofollow,
    /// Prevent cached-copy display.
    Noarchive,
    /// Prevent snippets.
    Nosnippet,
    /// Publisher character limit, still bounded by local policy.
    MaxSnippet,
    /// Prevent image indexing/storage.
    Noimageindex,
    /// UTC deadline after which indexing is prohibited.
    UnavailableAfter,
    /// Combined noindex and nofollow.
    None,
    /// Adds no restriction and cannot undo earlier directives.
    All,
    /// Adds no restriction and cannot undo noindex.
    Index,
    /// Adds no restriction and cannot undo nofollow.
    Follow,
    /// A physical header contained invalid bytes; its applicable restrictions fail closed.
    Invalid,
    /// Safe ASCII token only; arbitrary unknown directive values are discarded.
    Unknown(String),
}
/// Typed directive value; no raw header or invalid input is retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum DirectiveValue {
    /// A presence-only directive.
    Flag,
    /// Finite unsigned publisher cap; None represents the explicit -1 value.
    SnippetLimit(Option<u64>),
    /// Explicit-zone date normalized to UTC.
    Date(DateTime<Utc>),
    /// A recognized invalid value, whose cause is recorded separately.
    Invalid,
}
/// Sanitized parse-error code with no publisher text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectiveError {
    /// A physical compliance header was not entirely visible ASCII; raw bytes are discarded.
    InvalidHeaderBytes,
    /// Snippet limit is negative (other than -1), malformed or overflowing.
    InvalidSnippet,
    /// Date is invalid or lacks an explicit supported timezone.
    InvalidDate,
    /// More than 256 directives or rights URLs were observed.
    DirectiveLimit,
    /// Reservation is malformed or contradictory; treat it as reserved.
    InvalidReservation,
    /// Declared licence/policy/canonical URL could not be safely recorded.
    InvalidSignalUrl,
}
/// One bounded source observation, including recognized directives scoped to other agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectiveObservation {
    /// Physical header or HTML metadata source.
    pub source: DirectiveSource,
    /// Recognized or bounded unknown name.
    pub name: DirectiveName,
    /// Sanitized typed value only.
    pub value: DirectiveValue,
    /// Whether the unscoped, wildcard or exact bot directive applies here.
    pub applies: bool,
    /// Typed error without the offending input.
    pub parse_error: Option<DirectiveError>,
}
/// Monotonically combined effective restrictions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveDirectives {
    /// Any applicable noindex or none prevents index admission.
    pub noindex: bool,
    /// Any applicable nofollow or none prevents frontier extraction.
    pub nofollow: bool,
    /// Any noarchive prevents cached-copy display; local policy is always stricter.
    pub noarchive: bool,
    /// Any nosnippet makes the effective snippet cap zero.
    pub nosnippet: bool,
    /// Any noimageindex prevents image indexing.
    pub noimageindex: bool,
    /// Minimum finite cap; None adds no publisher cap.
    pub max_snippet: Option<u64>,
    /// Earliest valid explicit-zone removal deadline.
    pub unavailable_after_utc: Option<DateTime<Utc>>,
    /// An invalid applicable date prevents admission without inventing a timestamp.
    pub invalid_unavailable_after: bool,
    /// Resource limit reached; metadata-only and ineligible, never silently permissive.
    pub limit_exceeded: bool,
}
impl EffectiveDirectives {
    /// Restrictively combines another source; index/follow/all can never restore permission.
    pub fn restrictive_merge(&mut self, other: &Self) {
        self.noindex |= other.noindex;
        self.nofollow |= other.nofollow;
        self.noarchive |= other.noarchive;
        self.nosnippet |= other.nosnippet;
        self.noimageindex |= other.noimageindex;
        self.max_snippet = minimum(self.max_snippet, other.max_snippet);
        self.unavailable_after_utc =
            minimum(self.unavailable_after_utc, other.unavailable_after_utc);
        self.invalid_unavailable_after |= other.invalid_unavailable_after;
        self.limit_exceeded |= other.limit_exceeded;
    }
    /// Returns whether publisher directives permit index admission at this UTC instant.
    pub fn index_eligible(&self, now: DateTime<Utc>) -> bool {
        !self.noindex
            && !self.invalid_unavailable_after
            && !self.limit_exceeded
            && self
                .unavailable_after_utc
                .is_none_or(|deadline| now < deadline)
    }
}
fn minimum<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Publisher TDM reservation state; invalid declarations conservatively prohibit body retention.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TdmReservation {
    /// No declaration was observed.
    #[default]
    Absent,
    /// Exact value 0 was observed with no conflicting reservation.
    NotReserved,
    /// Exact value 1 was observed.
    Reserved,
    /// Invalid or contradictory value; operational effect is reserved.
    Invalid,
}
/// Metadata-only rights signals; none is a licence grant or permission to fetch a linked URL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RightsSignals {
    /// Sanitized absolute URLs resolved against the last fetched URL, capped at 256.
    pub license_urls: Vec<SafeUrl>,
    /// Rel-token licence presence, including an invalid URL whose body must remain restricted.
    pub license_present: bool,
    /// Restrictively merged TDM reservation.
    pub tdm_reservation: TdmReservation,
    /// Sanitized declared TDM policy URLs; never fetched here.
    pub tdm_policy_urls: Vec<SafeUrl>,
    /// TDM policy presence even when its declared URL was invalid.
    pub tdm_policy_present: bool,
    /// A reservation or policy header was observed.
    pub header_source: bool,
    /// A reservation or policy meta element was observed.
    pub meta_source: bool,
    /// A licence or policy rel token was observed in the DOM.
    pub link_source: bool,
    /// Sanitized parse errors; duplicates are unnecessary.
    pub parse_errors: Vec<DirectiveError>,
}
impl RightsSignals {
    /// Uses conservative index-only handling pending founder interpretation of rights signals.
    pub fn index_only(&self) -> bool {
        self.license_present
            || self.tdm_policy_present
            || matches!(
                self.tdm_reservation,
                TdmReservation::Reserved | TdmReservation::Invalid
            )
    }
    /// Restrictively merges previously observed rights, as required for conditional 304 responses.
    pub fn restrictive_merge(&mut self, other: &Self) {
        self.license_present |= other.license_present;
        self.tdm_policy_present |= other.tdm_policy_present;
        self.header_source |= other.header_source;
        self.meta_source |= other.meta_source;
        self.link_source |= other.link_source;
        self.tdm_reservation = merge_reservation(self.tdm_reservation, other.tdm_reservation);
        for url in &other.license_urls {
            if !self.license_urls.contains(url) {
                self.license_urls.push(url.clone());
            }
        }
        for url in &other.tdm_policy_urls {
            if !self.tdm_policy_urls.contains(url) {
                self.tdm_policy_urls.push(url.clone());
            }
        }
        for error in &other.parse_errors {
            add_error(&mut self.parse_errors, *error);
        }
        if self.license_urls.len() > MAX_DIRECTIVES || self.tdm_policy_urls.len() > MAX_DIRECTIVES {
            self.license_urls.truncate(MAX_DIRECTIVES);
            self.tdm_policy_urls.truncate(MAX_DIRECTIVES);
            add_error(&mut self.parse_errors, DirectiveError::DirectiveLimit);
        }
    }
}
fn merge_reservation(a: TdmReservation, b: TdmReservation) -> TdmReservation {
    use TdmReservation::*;
    match (a, b) {
        (Absent, value) | (value, Absent) => value,
        (NotReserved, NotReserved) => NotReserved,
        (Reserved, Reserved) => Reserved,
        _ => Invalid,
    }
}
fn add_error(errors: &mut Vec<DirectiveError>, error: DirectiveError) {
    if !errors.contains(&error) {
        errors.push(error);
    }
}

/// Parsed policy observations without raw HTML, raw headers or frontier links.
#[derive(Debug, Clone, Default)]
pub struct ParsedDirectives {
    /// Effective publisher restrictions.
    pub effective: EffectiveDirectives,
    /// Bounded typed directive observations, including non-applicable scopes.
    pub seen: Vec<DirectiveObservation>,
    /// Licence/TDM signals, without interpreting them as permissions.
    pub rights: RightsSignals,
    /// Any Cache-Control no-store occurrence forbids raw retention and validators.
    pub no_store: bool,
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-*".contains(&b))
}
fn directive_name(value: &str) -> DirectiveName {
    match value.to_ascii_lowercase().replace('_', "-").as_str() {
        "noindex" => DirectiveName::Noindex,
        "nofollow" => DirectiveName::Nofollow,
        "noarchive" => DirectiveName::Noarchive,
        "nosnippet" => DirectiveName::Nosnippet,
        "max-snippet" => DirectiveName::MaxSnippet,
        "noimageindex" => DirectiveName::Noimageindex,
        "unavailable-after" => DirectiveName::UnavailableAfter,
        "none" => DirectiveName::None,
        "all" => DirectiveName::All,
        "index" => DirectiveName::Index,
        "follow" => DirectiveName::Follow,
        _ => DirectiveName::Unknown(value.to_ascii_lowercase()),
    }
}
fn agent_applies(token: &str) -> bool {
    token == "*" || token.eq_ignore_ascii_case("AVASearchBot")
}
fn split_directives(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (position, c) in value.char_indices() {
        if c != ',' {
            continue;
        }
        let next = value[position + 1..].trim_start();
        let token = next.split([',', ':']).next().unwrap_or_default().trim();
        // A date's weekday comma is followed by day/month text, not a directive or agent token.
        if safe_token(token) {
            parts.push(value[start..position].trim());
            start = position + 1;
        }
    }
    parts.push(value[start..].trim());
    parts
}
fn validate_unavailable_after_timezone(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(date) = DateTime::parse_from_rfc3339(value) {
        return Some(date.with_timezone(&Utc));
    }
    let zone = value.split_ascii_whitespace().last()?;
    let explicit = matches!(zone, "GMT" | "UTC")
        || (zone.len() == 5
            && matches!(zone.as_bytes()[0], b'+' | b'-')
            && zone.as_bytes()[1..].iter().all(u8::is_ascii_digit));
    if !explicit {
        return None;
    }
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}
impl ParsedDirectives {
    fn parse_value(&mut self, value: &str, source: DirectiveSource) {
        let mut applies = true;
        for segment in split_directives(value) {
            let mut segment = segment;
            if source == DirectiveSource::Header {
                if let Some((prefix, rest)) = segment.split_once(':') {
                    if safe_token(prefix.trim())
                        && matches!(directive_name(prefix.trim()), DirectiveName::Unknown(_))
                    {
                        applies = agent_applies(prefix.trim());
                        segment = rest.trim();
                    }
                }
            }
            let (name, value) = segment.split_once(':').unwrap_or((segment, ""));
            let name = name.trim();
            if !safe_token(name) {
                continue;
            }
            let directive_count = self.seen.len() + 1;
            if directive_count > MAX_DIRECTIVES {
                self.effective.limit_exceeded = true;
                continue;
            }
            let name = directive_name(name);
            let mut effect = EffectiveDirectives::default();
            let mut error = None;
            let parsed = match name {
                DirectiveName::Noindex => {
                    effect.noindex = true;
                    DirectiveValue::Flag
                }
                DirectiveName::Nofollow => {
                    effect.nofollow = true;
                    DirectiveValue::Flag
                }
                DirectiveName::Noarchive => {
                    effect.noarchive = true;
                    DirectiveValue::Flag
                }
                DirectiveName::Nosnippet => {
                    effect.nosnippet = true;
                    DirectiveValue::Flag
                }
                DirectiveName::Noimageindex => {
                    effect.noimageindex = true;
                    DirectiveValue::Flag
                }
                DirectiveName::None => {
                    effect.noindex = true;
                    effect.nofollow = true;
                    DirectiveValue::Flag
                }
                DirectiveName::MaxSnippet => {
                    let value = value.trim();
                    if value == "-1" {
                        DirectiveValue::SnippetLimit(None)
                    } else if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                        if let Ok(limit) = value.parse::<u64>() {
                            effect.max_snippet = Some(limit);
                            DirectiveValue::SnippetLimit(Some(limit))
                        } else {
                            effect.max_snippet = Some(0);
                            error = Some(DirectiveError::InvalidSnippet);
                            DirectiveValue::Invalid
                        }
                    } else {
                        effect.max_snippet = Some(0);
                        error = Some(DirectiveError::InvalidSnippet);
                        DirectiveValue::Invalid
                    }
                }
                DirectiveName::UnavailableAfter => {
                    if let Some(date) = validate_unavailable_after_timezone(value.trim()) {
                        effect.unavailable_after_utc = Some(date);
                        DirectiveValue::Date(date)
                    } else {
                        effect.invalid_unavailable_after = true;
                        error = Some(DirectiveError::InvalidDate);
                        DirectiveValue::Invalid
                    }
                }
                DirectiveName::All
                | DirectiveName::Index
                | DirectiveName::Follow
                | DirectiveName::Invalid
                | DirectiveName::Unknown(_) => DirectiveValue::Flag,
            };
            if applies {
                self.effective.restrictive_merge(&effect);
            }
            self.seen.push(DirectiveObservation {
                source,
                name,
                value: parsed,
                applies,
                parse_error: error,
            });
        }
    }
}
fn reservation(rights: &mut RightsSignals, value: &str) {
    let value = match value.trim() {
        "0" => TdmReservation::NotReserved,
        "1" => TdmReservation::Reserved,
        _ => TdmReservation::Invalid,
    };
    rights.tdm_reservation = merge_reservation(rights.tdm_reservation, value);
    if rights.tdm_reservation == TdmReservation::Invalid {
        add_error(&mut rights.parse_errors, DirectiveError::InvalidReservation);
    }
}
fn signal_url(base: &Url, raw: &str) -> Option<SafeUrl> {
    if raw.is_empty()
        || raw.len() > 8192
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    let url = base.join(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    Some(safe_url_for_record(&url))
}
fn push_signal(urls: &mut Vec<SafeUrl>, errors: &mut Vec<DirectiveError>, base: &Url, value: &str) {
    if urls.len() >= MAX_DIRECTIVES {
        add_error(errors, DirectiveError::DirectiveLimit);
        return;
    }
    if let Some(url) = signal_url(base, value) {
        if !urls.contains(&url) {
            urls.push(url);
        }
    } else {
        add_error(errors, DirectiveError::InvalidSignalUrl);
    }
}

/// Parses every physical header occurrence, with independent agent scope for each occurrence.
/// No network or DOM work occurs; XML auxiliary responses can use this header-only contract.
pub fn parse_headers(headers: &ResponseHeaders, final_url: &Url) -> ParsedDirectives {
    let mut result = ParsedDirectives::default();
    if headers.invalid("x-robots-tag") {
        result.effective.noindex = true;
        result.effective.nofollow = true;
        result.seen.push(DirectiveObservation {
            source: DirectiveSource::Header,
            name: DirectiveName::Invalid,
            value: DirectiveValue::Invalid,
            applies: true,
            parse_error: Some(DirectiveError::InvalidHeaderBytes),
        });
    }
    for value in headers.all("x-robots-tag") {
        result.parse_value(value, DirectiveSource::Header);
    }
    result.no_store = headers.invalid("cache-control")
        || headers
            .all("cache-control")
            .iter()
            .flat_map(|v| v.split(','))
            .any(|part| {
                part.split('=')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("no-store")
            });
    for value in headers.all("tdm-reservation") {
        result.rights.header_source = true;
        reservation(&mut result.rights, value);
    }
    if headers.invalid("tdm-reservation") {
        result.rights.header_source = true;
        result.rights.tdm_reservation = TdmReservation::Reserved;
        add_error(
            &mut result.rights.parse_errors,
            DirectiveError::InvalidHeaderBytes,
        );
    }
    if headers.invalid("tdm-policy") {
        result.rights.header_source = true;
        result.rights.tdm_policy_present = true;
        add_error(
            &mut result.rights.parse_errors,
            DirectiveError::InvalidHeaderBytes,
        );
    }
    for value in headers.all("tdm-policy") {
        result.rights.header_source = true;
        result.rights.tdm_policy_present = true;
        push_signal(
            &mut result.rights.tdm_policy_urls,
            &mut result.rights.parse_errors,
            final_url,
            value.trim(),
        );
    }
    result
}
/// Parses HTML robots meta restrictions for the upstream noindex/nofollow compatibility bridge.
pub(crate) fn parse_meta(root: &NodeRef) -> ParsedDirectives {
    let mut result = ParsedDirectives::default();
    parse_meta_into(root, &mut result);
    result
}
fn parse_meta_into(root: &NodeRef, result: &mut ParsedDirectives) {
    for node in root.select("meta").expect("static meta selector") {
        let attrs = node.attributes.borrow();
        let Some(name) = attrs.get("name") else {
            continue;
        };
        let source = if name.eq_ignore_ascii_case("robots") {
            DirectiveSource::MetaRobots
        } else if name.eq_ignore_ascii_case("AVASearchBot") {
            DirectiveSource::MetaBot
        } else {
            continue;
        };
        if let Some(value) = attrs.get("content") {
            result.parse_value(value, source);
        }
    }
}
/// Extracts metadata policy signals from the existing HTML DOM, independently of frontier links.
pub(crate) fn parse_document(
    root: &NodeRef,
    headers: &ResponseHeaders,
    final_url: &Url,
) -> ParsedDirectives {
    let mut result = parse_headers(headers, final_url);
    parse_meta_into(root, &mut result);
    for node in root.select("meta").expect("static meta selector") {
        let attrs = node.attributes.borrow();
        let Some(name) = attrs.get("name") else {
            continue;
        };
        let value = attrs.get("content").unwrap_or_default();
        if name.eq_ignore_ascii_case("tdm-reservation") {
            result.rights.meta_source = true;
            reservation(&mut result.rights, value);
        }
        if name.eq_ignore_ascii_case("tdm-policy") {
            result.rights.meta_source = true;
            result.rights.tdm_policy_present = true;
            push_signal(
                &mut result.rights.tdm_policy_urls,
                &mut result.rights.parse_errors,
                final_url,
                value,
            );
        }
    }
    for node in root
        .select("link[rel], a[rel], area[rel]")
        .expect("static rel selector")
    {
        let attrs = node.attributes.borrow();
        let value = attrs.get("href").unwrap_or_default();
        for token in attrs
            .get("rel")
            .unwrap_or_default()
            .split_ascii_whitespace()
        {
            if token.eq_ignore_ascii_case("license") {
                result.rights.license_present = true;
                result.rights.link_source = true;
                push_signal(
                    &mut result.rights.license_urls,
                    &mut result.rights.parse_errors,
                    final_url,
                    value,
                );
            }
            if token.eq_ignore_ascii_case("tdm-policy") {
                result.rights.tdm_policy_present = true;
                result.rights.link_source = true;
                push_signal(
                    &mut result.rights.tdm_policy_urls,
                    &mut result.rights.parse_errors,
                    final_url,
                    value,
                );
            }
        }
    }
    result
}

/// Computes Unicode-scalar snippet cap: at most 300, with zero for denied or unlicensed news/paywall.
/// Slice 1 stores no snippet text; this is a serving contract for Story #588.
pub fn snippet_limit(
    directives: &EffectiveDirectives,
    local_limit: u16,
    news: bool,
    paywall: bool,
    publisher_permission: bool,
) -> u16 {
    if directives.nosnippet
        || directives.limit_exceeded
        || ((news || paywall) && !publisher_permission)
    {
        return 0;
    }
    let publisher_limit = directives.max_snippet.unwrap_or(u64::MAX);
    u64::from(local_limit).min(300).min(publisher_limit) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(values: &[&str]) -> ParsedDirectives {
        let mut headers = ResponseHeaders::default();
        for value in values {
            headers.observe("x-robots-tag", Some(value));
        }
        parse_headers(&headers, &Url::parse("https://fixture.invalid/").unwrap())
    }
    #[test]
    fn directive_merge() {
        let a = parse(&[
            "noindex, nofollow, max-snippet:20",
            "index, follow, max-snippet:100",
        ]);
        let b = parse(&[
            "index, follow, max-snippet:100",
            "noindex, nofollow, max-snippet:20",
        ]);
        assert_eq!(a.effective, b.effective);
        assert!(a.effective.noindex && a.effective.nofollow);
        assert_eq!(a.effective.max_snippet, Some(20));
    }
    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {failure_persistence: None, ..Default::default()})]
        #[test]
        fn directive_merge_prop(values in proptest::collection::vec(0_usize..8,1..32)) {
            let tokens=["noindex","index","nofollow","follow","none","max-snippet:9","max-snippet:-1","nosnippet"];
            let forward:Vec<_>=values.iter().map(|i|tokens[*i]).collect();
            let reverse:Vec<_>=forward.iter().rev().copied().chain(forward.iter().copied()).collect();
            proptest::prop_assert_eq!(parse(&forward).effective,parse(&reverse).effective);
        }
    }
    #[test]
    fn directive_date_grammar() {
        let parsed = parse(&["unavailable_after: Fri, 11 Sep 2026 12:00:00 GMT, nofollow"]);
        assert_eq!(
            parsed.effective.unavailable_after_utc,
            Some(
                DateTime::parse_from_rfc3339("2026-09-11T12:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc)
            )
        );
        assert!(parsed.effective.nofollow);
        for value in [
            "2026-09-11 12:00:00",
            "Fri, 11 Sep 2026 12:00:00",
            "tomorrow",
        ] {
            assert!(
                parse(&[&format!("unavailable_after: {value}")])
                    .effective
                    .invalid_unavailable_after
            );
        }
        assert!(
            !parse(&["unavailable_after: 2026-09-11T13:00:00+01:00"])
                .effective
                .invalid_unavailable_after
        );
    }
    #[test]
    fn directive_limits() {
        let input = vec!["index"; 257];
        let result = parse(&input);
        assert!(result.effective.limit_exceeded);
        assert!(!result.effective.index_eligible(Utc::now()));
        assert_eq!(result.seen.len(), 256);
        assert!(!parse(&input[..256]).effective.limit_exceeded);
    }
    #[test]
    fn snippet_policy() {
        let result = parse(&["max-snippet:999"]);
        assert_eq!(
            snippet_limit(&result.effective, 500, false, false, false),
            300
        );
        assert_eq!(snippet_limit(&result.effective, 300, true, false, false), 0);
        assert_eq!(snippet_limit(&result.effective, 300, false, true, false), 0);
        assert_eq!(
            snippet_limit(&result.effective, 300, true, false, true),
            300
        );
        for value in ["-2", "wat", "18446744073709551616"] {
            let result = parse(&[&format!("max-snippet:{value}")]);
            assert_eq!(
                snippet_limit(&result.effective, 300, false, false, false),
                0
            );
        }
    }
}
