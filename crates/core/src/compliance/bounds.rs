//! Centralizes inclusive numeric guards and text classes for intake, configuration and replay.
//! Limits are UTF-8 bytes, never character counts; resource reservations use checked arithmetic.

#![deny(missing_docs)]

use super::{Error, Result};

/// One literal bound, including its configured default when applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundSpec {
    /// Stable identifier for the shared validation binding.
    pub key: BoundKey,
    /// Default value; absent for a required caller value or a fixed width.
    pub default: Option<u64>,
    /// Inclusive lower limit in the stated units.
    pub min: u64,
    /// Inclusive upper limit in the stated units.
    pub max: u64,
    /// Units are bytes, items, events, months, seconds or years.
    pub unit: &'static str,
}

macro_rules! ranges {
    ($( $(#[$doc:meta])* $name:ident, $default:expr, $min:expr, $max:expr, $unit:literal; )*) => {
        /// Closed keys for all finite report and reserved record bounds.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub enum BoundKey { $( $(#[$doc])* $name, )* }
        /// Authoritative literal bounds; configuration narrows runtime capacities within these ceilings.
        pub const RANGE_SPECS: &[BoundSpec] = &[$(BoundSpec {
            key: BoundKey::$name, default: $default, min: $min, max: $max, unit: $unit,
        },)*];
    };
}

ranges! {
    /// Required delivery address bytes.
    Contact, None, 1, 254, "bytes";
    /// Required narrative text bytes.
    Narrative, None, 1, 4096, "bytes";
    /// Required reason text bytes.
    Reason, None, 1, 2048, "bytes";
    /// Required evidence text bytes.
    Evidence, None, 1, 1024, "bytes";
    /// Canonical URL bytes.
    Url, None, 1, 2048, "bytes";
    /// Distinct assets on an asset-bearing intake.
    Urls, None, 1, 16, "items";
    /// Name bytes, before normalization.
    Name, None, 1, 128, "bytes";
    /// Evidenced names on a delisting request.
    RequiredNames, None, 1, 8, "items";
    /// Evidenced names on other data-rights requests.
    OptionalNames, None, 0, 8, "items";
    /// Distinct normalized tokens in one name.
    NameTokens, None, 1, 16, "items";
    /// Operator alias bytes.
    Actor, None, 1, 64, "bytes";
    /// Person or service label bytes.
    Label, None, 1, 128, "bytes";
    /// Version or reference component bytes.
    Slug, None, 1, 64, "bytes";
    /// Opaque delivery attestation reference bytes.
    DeliveryRef, None, 1, 128, "bytes";
    /// Queue page items.
    QueueLimit, Some(20), 1, 50, "items";
    /// Complete journal row including its LF.
    JournalRow, None, 1, 8192, "bytes";
    /// Complete personal file including its LF.
    PayloadFile, None, 1, 65536, "bytes";
    /// Service-owned notice text combining separately bounded reasons and configured contacts.
    ServiceNotice, None, 1, 65536, "bytes";
    /// Extant personal files of one ticket.
    TicketPayload, None, 0, 1048576, "bytes";
    /// Complete configured listed file.
    ListFile, None, 1, 16777216, "bytes";
    /// Combined listed URL and host entries.
    ListEntries, None, 0, 100000, "items";
    /// Decoded bearer width.
    TokenBytes, None, 32, 32, "bytes";
    /// Decoded random ticket width.
    IdBytes, None, 32, 32, "bytes";
    /// Decoded independent commitment salt width.
    SaltBytes, None, 32, 32, "bytes";
    /// Wire hexadecimal width for all 256-bit values.
    HexBytes, None, 64, 64, "bytes";
    /// Bearer file with optional single final LF.
    TokenFile, None, 64, 65, "bytes";
    /// Nonempty variable record vectors reserved by configuration.
    RecordItems, None, 1, 64, "items";
    /// Optional variable record vectors reserved by configuration.
    OptionalRecordItems, None, 0, 64, "items";
    /// Nonempty record or statement change history.
    RecordHistory, None, 1, 32, "items";
    /// Optional review-trigger history.
    OptionalHistory, None, 0, 32, "items";
    /// Priority catalog slots, independently labelled by the operator.
    PriorityKinds, None, 17, 17, "items";
    /// Required children-risk classes in reserved record configuration.
    ChildrenClasses, None, 3, 3, "items";
    /// Required complete measures vocabulary cardinality.
    MeasureRows, None, 28, 28, "items";
    /// Optional distinct release-change kinds.
    ReleaseChanges, None, 0, 10, "items";
    /// Immediate intimate-image protection is the local default.
    IntimateMargin, Some(172800), 1, 172800, "seconds";
    /// Calendar months after closure before payload deletion.
    RetentionMonths, Some(36), super::clock::MIN_RETENTION_MONTHS as u64, 120, "months";
    /// Lifetime ticket count; purging never frees this capacity.
    MaxTickets, Some(10000), 1, 100000, "items";
    /// Total operational and lifecycle rows for each ticket.
    MaxTicketEvents, Some(256), 16, 256, "events";
    /// Lifetime journal bytes; archive and rollover remain a hosting gate.
    MaxJournalBytes, Some(268435456), 1048576, 2684354560, "bytes";
    /// Aggregate extant personal file bytes.
    MaxPayloadBytes, Some(268435456), 1048576, 2684354560, "bytes";
    /// Combined rules, markers and listed entries.
    MaxRules, Some(100000), 1, 100000, "items";
    /// Complete rules snapshot bytes.
    MaxRulesBytes, Some(16777216), 4096, 16777216, "bytes";
    /// All immutable record versions, reserved for the separate records implementation.
    MaxRecords, Some(10000), 1, 10000, "items";
    /// Complete individual record bytes, reserved in configuration.
    MaxRecordBytes, Some(1048576), 4096, 1048576, "bytes";
    /// All extant record version bytes, reserved in configuration.
    MaxRecordsBytes, Some(268435456), 1048576, 2684354560, "bytes";
    /// Stated reading-age target, without a measured usability claim.
    ReadingAge, Some(12), 8, 16, "years";
    /// Events reserved for completing started work and purge.
    ReservedEvents, Some(4), 4, 4, "events";
    /// Journal bytes reserved for completing started work and purge.
    ReservedJournalBytes, Some(65536), 65536, 65536, "bytes";
}

impl BoundKey {
    /// Returns this key's unique literal specification.
    pub fn spec(self) -> &'static BoundSpec {
        RANGE_SPECS
            .iter()
            .find(|spec| spec.key == self)
            .expect("complete bounds table")
    }
    /// Checks an integer against this key's inclusive specification.
    pub fn validate(self, value: u64) -> Result<()> {
        let spec = self.spec();
        validate_range(value, spec.min, spec.max)
    }
}

/// Enforces the single shared inclusive numeric boundary; inverted intervals also fail.
pub fn validate_range(value: u64, min: u64, max: u64) -> Result<()> {
    if value >= min && value <= max {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Closed character policies, applied identically on input and persisted content.
#[derive(Clone, Copy)]
pub enum TextClass {
    /// Allows LF and TAB in a narrative; all other controls are prohibited.
    Narrative,
    /// Prohibits every control character.
    Label,
    /// ASCII lowercase letters, digits and interior underscore, dot or hyphen.
    Slug,
    /// Exactly lowercase hexadecimal characters; width is validated separately.
    Hex,
}

/// Rejects empty or whitespace-only content without changing the caller's bytes.
pub fn nonblank(text: &str) -> Result<()> {
    if text.trim().is_empty() {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

/// Checks one of the closed character policies without allocating.
pub fn characters(text: &str, class: TextClass) -> Result<()> {
    let valid = text.chars().enumerate().all(|(index, ch)| match class {
        TextClass::Narrative => !ch.is_control() || ch == '\n' || ch == '\t',
        TextClass::Label => !ch.is_control(),
        TextClass::Slug => {
            ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || (index != 0 && matches!(ch, '_' | '.' | '-'))
        }
        TextClass::Hex => ch.is_ascii_digit() || ('a'..='f').contains(&ch),
    });
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

/// Applies the field's byte bound, shared nonblank guard and character policy.
pub fn text(value: &str, bound: BoundKey, class: TextClass) -> Result<()> {
    bound.validate(value.len() as u64)?;
    nonblank(value)?;
    characters(value, class)
}

/// Reserves a complete candidate's resource usage before any file is mutated.
/// The caller supplies an already validated cap and any reserved recovery headroom.
pub fn reserve(current: u64, additional: u64, maximum: u64, reserved: u64) -> Result<u64> {
    let total = current.checked_add(additional).ok_or(Error::Capacity)?;
    let limit = maximum.checked_sub(reserved).ok_or(Error::Capacity)?;
    validate_range(total, 0, limit).map_err(|_| Error::Capacity)?;
    Ok(total)
}
