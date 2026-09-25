//! Closed, content-free diagnostics shared by local publication and verification boundaries.

use std::fmt;

/// Shared named failure contract.
pub type Result<T> = std::result::Result<T, Error>;

/// Validation failures never contain key material or input contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Local I/O or file-type failure.
    Io,
    /// An inclusive input bound was exceeded.
    InputTooLarge,
    /// Invalid UTF-8, JSON, trailing input or recursion depth.
    JsonSyntax,
    /// An object repeated a decoded key.
    DuplicateKey,
    /// Invalid envelope fields or version.
    EnvelopeSchema,
    /// Invalid payload fields or version.
    PayloadSchema,
    /// Algorithm is not exactly Ed25519.
    Algorithm,
    /// Envelope omitted key_id.
    MissingKey,
    /// Identifier is not lowercase 64-hex.
    KeyId,
    /// Trusted map is not string to string.
    TrustedKeysSchema,
    /// Independent trusted set is empty.
    TrustedKeysEmpty,
    /// Encoding is not canonical padded standard base64.
    Base64,
    /// Public key is not 32 bytes.
    KeyLength,
    /// Registered identifier differs from the public-key digest.
    KeyIdentity,
    /// Identifier is absent from the independent trusted set.
    UntrustedKey,
    /// Signature is not 64 bytes.
    SignatureLength,
    /// Ed25519 authentication failed.
    Signature,
    /// Unsupported or inconsistent private DER.
    PrivateKey,
    /// Signing did not verify with the derived public key.
    SigningSelfCheck,
    /// Invalid strict UTC timestamp.
    Timestamp,
    /// Generation does not precede expiry.
    ValidityWindow,
    /// Clock precedes generation.
    NotYetValid,
    /// Clock is at or after expiry.
    Expired,
    /// Attested domain has an ambiguous or unsupported spelling.
    ControlledDomain,
    /// Advertised ranges are empty.
    RangesEmpty,
    /// A CIDR cannot parse.
    RangeInvalid,
    /// A CIDR has host bits or a noncanonical spelling.
    RangeNoncanonical,
    /// A canonical range is repeated.
    RangeDuplicate,
    /// Declared individual inventory is empty.
    InventoryEmpty,
    /// Declared individual address is repeated.
    InventoryDuplicate,
    /// Declared address belongs to no advertised range.
    IpOutsideRanges,
    /// Policy version has no non-whitespace content.
    PolicyVersion,
    /// Observed object has invalid fields or types.
    ObservedSchema,
    /// Independent observation is empty.
    ObservedEmpty,
    /// Observed address is repeated.
    ObservedDuplicate,
    /// Observed address is absent from inventory or ranges.
    ObservedIpMissing,
    /// Invalid fixture map schema or typed address.
    DnsFixture,
    /// Reverse lookup failed.
    PtrLookup,
    /// Reverse lookup returned no names.
    PtrEmpty,
    /// A returned name ends with a dot.
    PtrTrailingDot,
    /// A returned name has invalid spelling.
    PtrName,
    /// No returned name belongs to the attested domain.
    PtrDomain,
    /// Forward lookup failed.
    ForwardLookup,
    /// Forward lookup returned no addresses.
    ForwardEmpty,
    /// A returned name did not forward-confirm the original IP.
    ForwardMismatch,
}

impl Error {
    /// Stable machine-readable reason independent of library error prose.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Io => "io_error",
            Self::InputTooLarge => "input_too_large",
            Self::JsonSyntax => "json_syntax",
            Self::DuplicateKey => "duplicate_key",
            Self::EnvelopeSchema => "envelope_schema",
            Self::PayloadSchema => "payload_schema",
            Self::Algorithm => "algorithm_unsupported",
            Self::MissingKey => "missing_key",
            Self::KeyId => "key_id_invalid",
            Self::TrustedKeysSchema => "trusted_keys_schema",
            Self::TrustedKeysEmpty => "trusted_keys_empty",
            Self::Base64 => "base64_invalid",
            Self::KeyLength => "key_length",
            Self::KeyIdentity => "key_identity_mismatch",
            Self::UntrustedKey => "untrusted_key",
            Self::SignatureLength => "signature_length",
            Self::Signature => "signature_invalid",
            Self::PrivateKey => "private_key_invalid",
            Self::SigningSelfCheck => "signing_self_check",
            Self::Timestamp => "timestamp_invalid",
            Self::ValidityWindow => "validity_window_invalid",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::ControlledDomain => "controlled_domain_invalid",
            Self::RangesEmpty => "ranges_empty",
            Self::RangeInvalid => "range_invalid",
            Self::RangeNoncanonical => "range_noncanonical",
            Self::RangeDuplicate => "range_duplicate",
            Self::InventoryEmpty => "inventory_empty",
            Self::InventoryDuplicate => "inventory_duplicate",
            Self::IpOutsideRanges => "ip_outside_ranges",
            Self::PolicyVersion => "policy_version_empty",
            Self::ObservedSchema => "observed_schema",
            Self::ObservedEmpty => "observed_empty",
            Self::ObservedDuplicate => "observed_duplicate",
            Self::ObservedIpMissing => "observed_ip_missing",
            Self::DnsFixture => "dns_fixture_schema",
            Self::PtrLookup => "ptr_lookup_error",
            Self::PtrEmpty => "ptr_empty",
            Self::PtrTrailingDot => "ptr_trailing_dot",
            Self::PtrName => "ptr_name_invalid",
            Self::PtrDomain => "ptr_domain_mismatch",
            Self::ForwardLookup => "forward_lookup_error",
            Self::ForwardEmpty => "forward_empty",
            Self::ForwardMismatch => "forward_mismatch",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Error {}
