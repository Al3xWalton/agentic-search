//! Probes immutable compliance records and verified read-only snapshots through real owners.
//! Synthetic fixtures observe filesystem effects before result variants and literal contents.

#![deny(missing_docs)]

#[path = "support/compliance.rs"]
/// Shared private fixtures retained unchanged for the existing compliance contracts.
pub mod support;

#[path = "support/compliance_records.rs"]
mod records_support;

mod contracts {
    #[test]
    fn record_failure_closes_publication_without_stopping_search() {
        super::records_support::publication_failure_contract();
    }

    #[test]
    fn retention_floor_preserves_superseded_records_and_audit_history() {
        super::records_support::retention_contract();
    }

    #[test]
    fn record_and_statement_text_cannot_inject_html_or_leak_secrets() {
        super::records_support::injection_contract();
    }

    #[test]
    fn compliance_cli_uses_real_validators_and_owner_locks() {
        super::records_support::cli_contract();
    }

    #[test]
    fn statement_sections_catalog_and_api_wrapper_are_complete() {
        super::records_support::statement_http_contract();
    }

    #[test]
    fn sample_statement_is_byte_locked_to_validated_inputs() {
        super::records_support::sample_statement_contract();
    }

    #[test]
    fn html_export_produces_every_version_safely() {
        super::records_support::export_contract();
    }

    #[test]
    fn monthly_metrics_use_fixed_integer_nearest_ranks() {
        super::records_support::metrics_contract();
    }

    #[test]
    fn hosted_startup_requires_approved_assessments_and_accountability() {
        super::records_support::hosted_contract();
    }

    #[test]
    fn release_changes_require_matching_approved_updates() {
        super::records_support::release_contract();
    }

    #[test]
    fn reviews_are_fresh_through_exactly_365_days() {
        super::records_support::annual_reviews_contract();
    }

    #[test]
    fn child_access_reviews_and_three_month_risk_deadlines_are_exact() {
        super::records_support::child_reviews_contract();
    }

    #[test]
    fn record_index_verifies_chain_checkpoint_and_recovery_boundaries() {
        super::records_support::index_contract();
    }

    #[test]
    fn record_versions_and_additions_are_immutable_and_journalled() {
        super::records_support::versions_contract();
    }

    #[test]
    fn record_schema_covers_every_risk_assessment_field() {
        super::records_support::schema_contract();
    }

    #[test]
    fn measures_cover_the_exact_supplied_code_vocabulary() {
        super::records_support::measures_contract();
    }

    #[test]
    fn ticket_snapshots_read_only_the_verified_committed_prefix() {
        super::records_support::snapshot_contract();
    }

    #[test]
    fn history_survives_a_statement_and_catalogue_version_change() {
        super::records_support::history_upgrade_contract();
    }
}
