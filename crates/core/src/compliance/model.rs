//! Defines distinct ticket capabilities and canonical document keys without HTTP dependencies.
//! Randomness failures are final admission failures; salts and identifiers never use time fallback.

#![deny(missing_docs)]

use super::{
    bounds::{self, BoundKey, TextClass},
    Error, Result,
};
use ring::rand::SecureRandom;
use serde::{Deserialize, Deserializer, Serialize};

/// Fallible entropy source; production draws every requested byte from the operating system.
pub trait Entropy: Send + Sync + 'static {
    /// Fills the complete buffer, or fails admission before any write.
    fn fill(&self, bytes: &mut [u8]) -> Result<()>;
}

/// Production operating-system entropy, with no counter or timestamp fallback.
pub struct SystemEntropy;
impl Entropy for SystemEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        ring::rand::SystemRandom::new()
            .fill(bytes)
            .map_err(|_| Error::Unavailable)
    }
}

/// Encodes bytes as lowercase hexadecimal without depending on a second hash crate.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Computes a SHA-256 digest over the supplied domain-separated components.
pub fn sha256(parts: &[&[u8]]) -> String {
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    for part in parts {
        hash.update(part);
    }
    hex(hash.finish().as_ref())
}

/// Decodes a strict lowercase 256-bit value after validating its wire and decoded widths.
pub fn decode_hex(raw: &str) -> Result<[u8; 32]> {
    bounds::text(raw, BoundKey::HexBytes, TextClass::Hex)?;
    let mut decoded = [0; 32];
    for (pair, byte) in raw.as_bytes().as_chunks::<2>().0.iter().zip(&mut decoded) {
        let nibble = |ch: u8| {
            if ch.is_ascii_digit() {
                ch - b'0'
            } else {
                ch - b'a' + 10
            }
        };
        *byte = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    BoundKey::IdBytes.validate(decoded.len() as u64)?;
    Ok(decoded)
}

/// Validated lowercase SHA-256 or independent 32-byte random salt.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Hex64(String);
impl Hex64 {
    /// Validates exactly 64 lowercase hexadecimal bytes.
    pub fn parse(raw: &str) -> Result<Self> {
        decode_hex(raw)?;
        Ok(Self(raw.into()))
    }
    /// Draws an independent full-width salt and fails without fallback.
    pub fn random(entropy: &dyn Entropy) -> Result<Self> {
        let mut bytes = [0; 32];
        BoundKey::SaltBytes.validate(bytes.len() as u64)?;
        entropy.fill(&mut bytes)?;
        Ok(Self(hex(&bytes)))
    }
    /// Returns the validated disk representation; callers must not log personal salts.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Returns the decoded 32 bytes.
    pub fn bytes(&self) -> [u8; 32] {
        decode_hex(&self.0).expect("validated hex")
    }
}
impl<'de> Deserialize<'de> for Hex64 {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

/// Random status capability, distinct from a public URL hash.
///
/// ```compile_fail
/// use stract::compliance::model::{DocumentKey, TicketId};
/// fn capability(_: TicketId) {}
/// fn wrong_kind(key: DocumentKey) { capability(key); }
/// ```
///
/// ```compile_fail
/// use stract::compliance::model::{DocumentKey, TicketId};
/// fn document(_: DocumentKey) {}
/// fn wrong_kind(ticket: TicketId) { document(ticket); }
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct TicketId(Hex64);
impl TicketId {
    /// Draws all 32 identifier bytes exactly once; collisions are checked before admission.
    pub fn generate(entropy: &dyn Entropy) -> Result<Self> {
        let mut bytes = [0; 32];
        BoundKey::IdBytes.validate(bytes.len() as u64)?;
        let draw = entropy.fill(&mut bytes);
        draw?;
        Self::parse(&hex(&bytes))
    }
    /// Validates a raw path capability before lookup or percent decoding.
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(Self(Hex64::parse(raw)?))
    }
    /// Returns the exact lowercase capability; it grants only minimal ticket status.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl<'de> Deserialize<'de> for TicketId {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

/// Domain form of the existing public SHA-256 canonical URL identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct DocumentKey(Hex64);
impl DocumentKey {
    /// Validates a persisted document hash's exact width and grammar.
    pub fn parse(raw: &str) -> Result<Self> {
        Ok(Self(Hex64::parse(raw)?))
    }
    /// Returns the validated canonical-URL hash.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl<'de> Deserialize<'de> for DocumentKey {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(decoder)?).map_err(serde::de::Error::custom)
    }
}

/// Personal canonical URL paired with its independently verified operational hash.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "RawAsset")]
pub struct Asset {
    url: String,
    document_id: DocumentKey,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAsset {
    url: String,
    document_id: DocumentKey,
}
impl TryFrom<RawAsset> for Asset {
    type Error = Error;
    fn try_from(raw: RawAsset) -> Result<Self> {
        Self::new(raw.url, raw.document_id)
    }
}
impl Asset {
    /// Verifies canonical HTTP(S) text, credentials, fragment absence and exact hash agreement.
    pub fn new(url: String, document_id: DocumentKey) -> Result<Self> {
        bounds::text(&url, BoundKey::Url, TextClass::Label)?;
        if url.bytes().any(|b| b.is_ascii_whitespace() || b == b'\\') {
            return Err(Error::InvalidInput);
        }
        let parsed = url::Url::parse(&url).map_err(|_| Error::InvalidInput)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || parsed.as_str() != url
            || sha256(&[url.as_bytes()]) != document_id.as_str()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self { url, document_id })
    }
    /// Returns private canonical URL text for payload persistence or serving identity checks.
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Returns the nonpersonal-text operational document key.
    pub fn document_id(&self) -> &DocumentKey {
        &self.document_id
    }
}

macro_rules! vocabulary {
    ($(#[$doc:meta])* $name:ident { $( $(#[$item:meta])* $variant:ident => $wire:literal, )* }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum $name { $( $(#[$item])* #[serde(rename = $wire)] $variant, )* }
        impl $name {
            /// Returns the closed scalar spelling used by the journal and HTTP adapters.
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire,)* } }
            /// Rejects any spelling outside this closed vocabulary.
            pub fn parse(value: &str) -> Result<Self> {
                match value { $($wire => Ok(Self::$variant),)* _ => Err(Error::InvalidInput) }
            }
        }
    };
}

vocabulary! {
    /// Closed public reporting categories; the handler chooses this value, never the caller.
    Route {
        /// Suspected unlawful search content.
        IllegalContent => "illegal_content",
        /// Search content potentially harmful to children.
        HarmfulToChildren => "harmful_to_children",
        /// Declared intimate-image content and standing.
        IntimateImages => "intimate_images",
        /// Interested-person complaint about their website.
        SiteComplaint => "site_complaint",
        /// Rights-owner removal request.
        RightsRemoval => "rights_removal",
        /// Delisting, erasure or objection by a data subject.
        DataRights => "data_rights",
        /// Complaint about AVA's processing of personal data.
        DataProtectionComplaint => "data_protection_complaint",
        /// Complaint about AVA's online-safety duties.
        OnlineSafetyComplaint => "online_safety_complaint",
    }
}

vocabulary! {
    /// Requester's asserted relationship, not an authenticated identity.
    RequesterType {
        /// Acting for oneself.
        SelfPerson => "self",
        /// Acting for another person.
        Representative => "representative",
        /// Affected by the content or service.
        AffectedPerson => "affected_person",
        /// Operates the relevant website.
        SiteOperator => "site_operator",
        /// Claims ownership of relevant rights.
        RightsOwner => "rights_owner",
        /// Another claimed relationship.
        Other => "other",
    }
}

vocabulary! {
    /// Closed lifecycle; operational rows can preserve the current state.
    TicketState {
        /// Receipt recorded, internal admission incomplete.
        Received => "received",
        /// Acknowledgement durably prepared, whether or not a client received it.
        Acknowledged => "acknowledged",
        /// Requested identity or clarification evidence is pending.
        IdentityPending => "identity_pending",
        /// Automatically admitted to the review queue.
        Queued => "queued",
        /// A reviewed decision is durable.
        Decided => "decided",
        /// A rule-bearing grant completed durably.
        Actioned => "actioned",
        /// An authenticated appeal is pending.
        Appealed => "appealed",
        /// The original ticket's rules were reversed with durable markers.
        Reversed => "reversed",
        /// A reasoned appeal disposal upheld the original decision.
        Upheld => "upheld",
        /// Final closure; no reopening route exists.
        Closed => "closed",
    }
}

vocabulary! {
    /// Independent serving grounds; reversal blocks automated reapplication only on its ground.
    Ground {
        /// Unlawful-content report grant.
        IllegalContent => "illegal_content",
        /// Child-harm report grant.
        HarmfulToChildren => "harmful_to_children",
        /// Intimate-image provisional duty or grant.
        IntimateImages => "intimate_images",
        /// Rights-owner grant.
        RightsRemoval => "rights_removal",
        /// Name-scoped data-subject delisting.
        DataDelisting => "data_delisting",
        /// Global erasure of the reported assets at serving.
        DataErasure => "data_erasure",
        /// Global objection outcome for the reported assets.
        DataObjection => "data_objection",
    }
}

vocabulary! {
    /// Exact data-subject remedy requested at intake.
    RequestKind {
        /// Applies only to queries containing a complete evidenced name.
        Delisting => "delisting",
        /// Requests global removal at the serving seam.
        Erasure => "erasure",
        /// Objects to the relevant processing.
        Objection => "objection",
    }
}
vocabulary! {
    /// Evidenced source of a name used for a delisting rule.
    NameKind {
        /// Reported legal name.
        LegalName => "legal_name",
        /// Evidenced pseudonym or nickname.
        Pseudonym => "pseudonym",
    }
}
vocabulary! {
    /// Asserted statutory interest of a website complainant.
    Interest {
        /// Responsible person in the United Kingdom.
        ResponsibleUkPerson => "responsible_uk_person",
        /// United Kingdom incorporated body.
        UkIncorporatedBody => "uk_incorporated_body",
    }
}
vocabulary! {
    /// Allowed evidence requests and matching replies for data-rights tickets.
    IdentityEvent {
        /// Requests identity evidence without moving the deadline.
        RequestIdentity => "request_identity",
        /// Confirms identity and advances the relevant time.
        IdentityConfirmed => "identity_confirmed",
        /// Requests clarification without moving the deadline.
        RequestClarification => "request_clarification",
        /// Records clarification and advances the relevant time.
        ClarificationReceived => "clarification_received",
    }
}
vocabulary! {
    /// Permitted reasons for a data-rights extension.
    Necessity {
        /// The request is sufficiently complex to need more time.
        Complexity => "complexity",
        /// Request volume requires additional time.
        Volume => "volume",
    }
}
vocabulary! {
    /// Attested operator delivery channel; this code sends no communication.
    DeliveryChannel {
        /// Operator attests to email delivery.
        ManualEmail => "manual_email",
        /// Operator attests to a form communication.
        ManualForm => "manual_form",
        /// Operator attests to communication through an API client.
        ManualApi => "manual_api",
    }
}
vocabulary! {
    /// Nonpersonal decision vocabulary stored in chain rows.
    DecisionKind {
        /// The requested route-valid outcome was granted.
        Granted => "granted",
        /// A reasoned refusal with all three remedies.
        Refused => "refused",
        /// An intimate-image report was determined outside the content definition.
        NotIntimateImage => "not_intimate_image",
        /// An intimate-image reporter was determined to lack standing.
        NoStanding => "no_standing",
        /// A concluded same-route complaint was repeated without new information.
        ManifestlyUnfounded => "manifestly_unfounded",
    }
}

/// A required contact address held exclusively in personal payloads.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    /// Sole supported delivery-address method, validated as email.
    pub method: ContactMethod,
    /// Nonempty delivery address, at most 254 bytes; no SMTP validation or fetching.
    pub address: String,
}
vocabulary! {
    /// Closed contact method, without an actual delivery implementation.
    ContactMethod {
        /// An operator can communicate through the supplied email address.
        Email => "email",
    }
}

/// Required report fields shared by all eight categories.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportFields {
    /// Required contact retained only in personal payloads.
    pub contact: Contact,
    /// Required narrative of at most 4096 UTF-8 bytes.
    pub description: String,
    /// Claimed requester relationship, not authenticated identity.
    pub requester_type: RequesterType,
    /// Essential acknowledgements, notices and outcomes are never disabled by this flag.
    pub nonessential_opt_out: bool,
}
impl ReportFields {
    /// Validates all common byte and character bounds without writing or normalizing content.
    pub fn validate(&self) -> Result<()> {
        bounds::text(&self.contact.address, BoundKey::Contact, TextClass::Label)?;
        bounds::text(&self.description, BoundKey::Narrative, TextClass::Narrative)
    }
}

/// Name and supporting evidence, kept outside the journal and serving snapshots.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencedName {
    /// Nonempty name, at most 128 bytes and one to sixteen distinct tokenizer tokens.
    pub name: String,
    /// Claimed legal name or pseudonym.
    pub kind: NameKind,
    /// Required support, at most 1024 bytes.
    pub evidence: String,
}

/// Operator attestation stored privately; it is not evidence of actual recipient receipt.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    /// Manually attested communication channel.
    pub channel: DeliveryChannel,
    /// Bounded opaque operator reference, excluded from chain rows.
    pub reference: String,
}
impl Delivery {
    /// Enforces the private reference's byte and control-character bounds.
    pub fn validate(&self) -> Result<()> {
        bounds::text(&self.reference, BoundKey::DeliveryRef, TextClass::Label)
    }
}

/// Route-specific validated intake information, separate from canonical asset identity.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntakeKind {
    /// Report of potentially unlawful content.
    IllegalContent {
        /// Required explanation, at most 1024 bytes.
        suspected_illegality: String,
    },
    /// Report of potential harm to children.
    HarmfulToChildren {
        /// Required explanation, at most 1024 bytes.
        harm_description: String,
    },
    /// Three separate statutory declarations, each validated true before admission and replay.
    IntimateImages {
        /// Affirms that the reported material is intimate-image content.
        intimate_image_content: bool,
        /// Affirms that the reporter is the subject or authorised to act for them.
        subject_or_authorised: bool,
        /// Affirms good faith.
        good_faith: bool,
    },
    /// New independent interested-person complaint; the related capability is never publicly looked up.
    SiteComplaint {
        /// Asserted qualifying interest.
        interest: Interest,
        /// Optional syntactically validated original ticket reference.
        related_ticket_id: Option<TicketId>,
    },
    /// Rights-owner removal request.
    RightsRemoval {
        /// Required rights explanation.
        rights_basis: String,
        /// Required claimed authority.
        authority: String,
    },
    /// Data-subject remedy request.
    DataRights {
        /// Closed requested remedy.
        request_kind: RequestKind,
        /// Evidenced names, required and nonempty for delisting.
        names: Vec<EvidencedName>,
    },
    /// Complaint about AVA's processing of personal data.
    DataProtectionComplaint,
    /// Complaint about AVA's online-safety duties.
    OnlineSafetyComplaint,
}

/// Private, typed intake; assets must be canonical and distinct before admission.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intake {
    /// Required shared personal fields.
    pub report: ReportFields,
    /// Canonical assets; empty only for the two assetless complaint categories.
    pub assets: Vec<Asset>,
    /// Closed category-specific personal fields.
    pub category: IntakeKind,
}
impl Intake {
    /// Returns the category determined by the endpoint-specific adapter.
    pub fn route(&self) -> Route {
        match self.category {
            IntakeKind::IllegalContent { .. } => Route::IllegalContent,
            IntakeKind::HarmfulToChildren { .. } => Route::HarmfulToChildren,
            IntakeKind::IntimateImages { .. } => Route::IntimateImages,
            IntakeKind::SiteComplaint { .. } => Route::SiteComplaint,
            IntakeKind::RightsRemoval { .. } => Route::RightsRemoval,
            IntakeKind::DataRights { .. } => Route::DataRights,
            IntakeKind::DataProtectionComplaint => Route::DataProtectionComplaint,
            IntakeKind::OnlineSafetyComplaint => Route::OnlineSafetyComplaint,
        }
    }
    /// Returns the possible serving ground; complaint resolution itself installs no rule.
    pub fn ground(&self) -> Option<Ground> {
        match self.category {
            IntakeKind::IllegalContent { .. } => Some(Ground::IllegalContent),
            IntakeKind::HarmfulToChildren { .. } => Some(Ground::HarmfulToChildren),
            IntakeKind::IntimateImages { .. } => Some(Ground::IntimateImages),
            IntakeKind::RightsRemoval { .. } => Some(Ground::RightsRemoval),
            IntakeKind::DataRights { request_kind, .. } => Some(match request_kind {
                RequestKind::Delisting => Ground::DataDelisting,
                RequestKind::Erasure => Ground::DataErasure,
                RequestKind::Objection => Ground::DataObjection,
            }),
            _ => None,
        }
    }
    /// Returns the evidenced names in their original intake order.
    pub fn names(&self) -> &[EvidencedName] {
        match &self.category {
            IntakeKind::DataRights { names, .. } => names,
            _ => &[],
        }
    }
}

macro_rules! assessment {
    ($($(#[$doc:meta])* $field:ident),* $(,)?) => {
        /// Complete reasoned delisting assessment; no criterion can be omitted or left blank.
        #[derive(Clone, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct DelistingAssessment { $($(#[$doc])* pub $field: String,)* }
        impl DelistingAssessment {
            /// Validates each of the nineteen independent required reason fields.
            pub fn validate(&self) -> Result<()> {
                for value in [$(&self.$field,)*] {
                    bounds::text(value, BoundKey::Reason, TextClass::Narrative)?;
                }
                Ok(())
            }
        }
    };
}
assessment! {
    /// Assessment of the natural-person requirement.
    natural_person,
    /// Assessment of name-search applicability.
    name_search,
    /// Assessment of the person's public role.
    role_in_public_life,
    /// Assessment of childhood and associated protection.
    child,
    /// Assessment of accuracy.
    accuracy,
    /// Assessment of working-life relevance.
    working_life,
    /// Assessment of hate speech or defamation.
    hate_speech_or_defamation,
    /// Assessment of sensitive information.
    sensitive_data,
    /// Assessment of current relevance.
    currency,
    /// Assessment of prejudice.
    prejudice,
    /// Assessment of risk.
    risk,
    /// Assessment of the original publication basis.
    original_basis_of_publication,
    /// Assessment of journalistic context.
    journalistic_context,
    /// Assessment of legal power or duty to publish.
    legal_power_or_obligation_to_publish,
    /// Assessment of any criminal-offence information.
    criminal_offence,
    /// Assessment of offence seriousness.
    offence_seriousness,
    /// Assessment of elapsed time.
    time_elapsed,
    /// Assessment of spent status.
    spent_status,
    /// Overall reasoned decision.
    reasoned_decision,
}

/// Private reviewed disposition; route and lifecycle eligibility are checked by transitions.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    /// Grants the route-specific remedy.
    Granted {
        /// Required bounded reasons.
        reasons: String,
        /// Attested essential communication.
        delivery: Delivery,
        /// Required only for a name-delisting grant.
        assessment: Option<Box<DelistingAssessment>>,
    },
    /// Refuses the request with reasons and all three remedies.
    Refused {
        /// Required bounded reasons.
        reasons: String,
        /// Attested essential communication.
        delivery: Delivery,
    },
    /// Determines the reported content outside the intimate-image definition.
    NotIntimateImage {
        /// Required bounded reasons.
        reasons: String,
        /// Attested essential communication.
        delivery: Delivery,
    },
    /// Determines that the intimate-image reporter lacks standing.
    NoStanding {
        /// Required bounded reasons.
        reasons: String,
        /// Attested essential communication.
        delivery: Delivery,
    },
    /// Disregards only a concluded same-route complaint without new information.
    ManifestlyUnfounded {
        /// Reasons must explain the absence of new information.
        reasons: String,
        /// Attested essential communication.
        delivery: Delivery,
        /// Must match the configured policy version.
        policy_version: String,
        /// Must be duplicate_without_new_information.
        policy_clause: String,
        /// Authenticated reference to a closed complaint of the same route.
        duplicate_of: TicketId,
    },
}
impl Decision {
    /// Returns the nonpersonal scalar kind for the journal.
    pub fn kind(&self) -> DecisionKind {
        match self {
            Self::Granted { .. } => DecisionKind::Granted,
            Self::Refused { .. } => DecisionKind::Refused,
            Self::NotIntimateImage { .. } => DecisionKind::NotIntimateImage,
            Self::NoStanding { .. } => DecisionKind::NoStanding,
            Self::ManifestlyUnfounded { .. } => DecisionKind::ManifestlyUnfounded,
        }
    }
    /// Returns private reasons and the communication attestation, without logging them.
    pub fn communication(&self) -> (&str, &Delivery) {
        match self {
            Self::Granted {
                reasons, delivery, ..
            }
            | Self::Refused { reasons, delivery }
            | Self::NotIntimateImage { reasons, delivery }
            | Self::NoStanding { reasons, delivery }
            | Self::ManifestlyUnfounded {
                reasons, delivery, ..
            } => (reasons, delivery),
        }
    }
    /// Checks field bounds; policy and route checks remain in the shared transition guard.
    pub fn validate(&self) -> Result<()> {
        let (reasons, delivery) = self.communication();
        bounds::text(reasons, BoundKey::Reason, TextClass::Narrative)?;
        delivery.validate()?;
        if let Self::Granted {
            assessment: Some(assessment),
            ..
        } = self
        {
            assessment.validate()?;
        }
        if let Self::ManifestlyUnfounded {
            policy_version,
            policy_clause,
            ..
        } = self
        {
            bounds::text(policy_version, BoundKey::Slug, TextClass::Slug)?;
            bounds::text(policy_clause, BoundKey::Slug, TextClass::Slug)?;
        }
        Ok(())
    }
}
