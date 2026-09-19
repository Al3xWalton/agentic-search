//! Computes statutory UTC thresholds with checked seconds and original-instant calendar months.
//! The caller injects crawler::politeness::Clock and supplies only its UTC reading.

#![deny(missing_docs)]

use super::{Error, Result};
use chrono::{DateTime, Months, Utc};

/// Outer intimate-image period, measured from receipt in seconds.
pub const INTIMATE_PERIOD_SECONDS: i64 = 172800;
/// Initial data-rights response period in calendar months.
pub const DATA_RIGHTS_MONTHS: u32 = 1;
/// Additional calendar months allowed by a timely reasoned notice.
pub const EXTENSION_MONTHS: u32 = 2;
/// Data-protection complaint acknowledgement period in seconds, not calendar months.
pub const COMPLAINT_ACK_SECONDS: i64 = 2592000;
/// Reserved annual review freshness period in seconds.
pub const REVIEW_FRESHNESS_SECONDS: i64 = 31536000;
/// Reserved child-risk assessment period in calendar months.
pub const CHILD_RISK_MONTHS: u32 = 3;
/// Minimum calendar retention months after closure.
pub const MIN_RETENTION_MONTHS: u32 = 36;

/// Validates a representable UTC instant; callers reject future/backwards history separately.
pub fn instant(seconds: i64) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(seconds, 0).ok_or(Error::InvalidInput)
}

/// Adds elapsed seconds without integer wrap or an unrepresentable UTC result.
pub fn add_seconds(at: i64, seconds: i64) -> Result<i64> {
    let result = at.checked_add(seconds).ok_or(Error::InvalidInput)?;
    instant(result)?;
    Ok(result)
}

/// Adds the total calendar period to the original instant, retaining its UTC time of day.
pub fn add_months(at: i64, months: u32) -> Result<i64> {
    instant(at)?
        .checked_add_months(Months::new(months))
        .map(|date| date.timestamp())
        .ok_or(Error::InvalidInput)
}

/// Returns the absolute outer intimate-image deadline from immutable receipt.
pub fn intimate_due(received_at: i64) -> Result<i64> {
    add_seconds(received_at, INTIMATE_PERIOD_SECONDS)
}

/// Returns receipt plus the outer period minus the validated operator margin.
pub fn intimate_effective(received_at: i64, margin: u64) -> Result<i64> {
    super::bounds::BoundKey::IntimateMargin.validate(margin)?;
    add_seconds(intimate_due(received_at)?, -(margin as i64))
}

/// Counts an intimate-image action at the outer deadline as timely.
pub fn intimate_on_time(received_at: i64, actioned_at: i64) -> Result<bool> {
    Ok(actioned_at >= received_at && actioned_at <= intimate_due(received_at)?)
}

/// Computes the applicable data-rights deadline directly from its relevant-time epoch.
pub fn data_rights_due(relevant_at: i64, extended: bool) -> Result<i64> {
    let months = DATA_RIGHTS_MONTHS
        .checked_add(if extended { EXTENSION_MONTHS } else { 0 })
        .ok_or(Error::InvalidInput)?;
    add_months(relevant_at, months)
}

/// Reports lateness only after the applicable data-rights deadline.
pub fn data_rights_overdue(relevant_at: i64, extended: bool, now: i64) -> Result<bool> {
    Ok(now > data_rights_due(relevant_at, extended)?)
}

/// Returns the elapsed thirty-day acknowledgement threshold from immutable receipt.
pub fn complaint_ack_due(received_at: i64) -> Result<i64> {
    add_seconds(received_at, COMPLAINT_ACK_SECONDS)
}

/// Counts an acknowledgement at exactly thirty elapsed days as timely.
pub fn complaint_ack_on_time(received_at: i64, acknowledged_at: i64) -> Result<bool> {
    Ok(acknowledged_at >= received_at && acknowledged_at <= complaint_ack_due(received_at)?)
}

/// Returns the earliest payload deletion instant after closure for the validated policy.
pub fn retention_due(closed_at: i64, retention_months: u32) -> Result<i64> {
    super::bounds::BoundKey::RetentionMonths.validate(u64::from(retention_months))?;
    add_months(closed_at, retention_months)
}

/// Tests the inclusive retention threshold; lifecycle eligibility is checked by transitions.
pub fn retention_elapsed(closed_at: i64, retention_months: u32, now: i64) -> Result<bool> {
    Ok(now >= retention_due(closed_at, retention_months)?)
}
