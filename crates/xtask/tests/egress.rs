//! Offline independent cryptographic, inventory, DNS and command witnesses.

use ::egress::{Envelope, Error, TrustedKeys, VerifiedInventory};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime},
};

const PAYLOAD: &[u8] = include_bytes!("fixtures/egress/payload.json");
const OBSERVED: &[u8] = include_bytes!("fixtures/egress/observed.json");
const DNS: &[u8] = include_bytes!("fixtures/egress/dns.json");
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var_os("STORY584_SCRATCH").expect("owned scratch"));
        let root = root.canonicalize().unwrap();
        let path = root.join(format!(
            "egress-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn key(&self, bytes: &[u8]) -> PathBuf {
        let path = self.path("key.der");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Signer {
    der: Vec<u8>,
    key: Ed25519KeyPair,
    id: String,
}

impl Signer {
    fn new() -> Self {
        let der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(der.as_ref()).unwrap();
        let id = digest::digest(&digest::SHA256, key.public_key().as_ref())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Self {
            der: der.as_ref().to_vec(),
            key,
            id,
        }
    }

    fn trust_bytes(&self) -> Vec<u8> {
        bytes(&json!({self.id.clone(): STANDARD.encode(self.key.public_key().as_ref())}))
    }

    fn trust(&self) -> TrustedKeys {
        ::egress::parse_trusted_keys(&self.trust_bytes()).unwrap()
    }

    fn envelope(&self, payload: &[u8], algorithm: &str, id: &str) -> Envelope {
        let mut envelope = Envelope {
            schema_version: 1,
            algorithm: algorithm.into(),
            key_id: id.into(),
            payload_base64: STANDARD.encode(payload),
            signature_base64: String::new(),
        };
        envelope.signature_base64 = STANDARD.encode(self.key.sign(&oracle(&envelope, payload)));
        envelope
    }

    fn signed(&self, payload: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&self.envelope(payload, "Ed25519", &self.id)).unwrap()
    }

    fn verify(&self, payload: &[u8], now: SystemTime) -> ::egress::Result<VerifiedInventory> {
        ::egress::verify_file(&self.signed(payload), &self.trust(), now)
    }
}

fn oracle(envelope: &Envelope, payload: &[u8]) -> Vec<u8> {
    let fields = [
        envelope.schema_version.to_string().into_bytes(),
        envelope.algorithm.as_bytes().to_vec(),
        envelope.key_id.as_bytes().to_vec(),
        payload.to_vec(),
    ];
    let mut output = b"AVA-SEARCH-EGRESS-V1\n".to_vec();
    for field in fields {
        let length = u64::try_from(field.len()).unwrap();
        for shift in (0..8).rev() {
            output.push((length >> (shift * 8)) as u8);
        }
        output.extend(field);
    }
    output
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
fn t() -> SystemTime {
    instant("2026-09-24T12:00:00Z")
}
fn instant(raw: &str) -> SystemTime {
    DateTime::parse_from_rfc3339(raw).unwrap().into()
}
fn fresh() -> Vec<u8> {
    let mut p = value(PAYLOAD);
    let now = SystemTime::now();
    p["generated_at_utc"] = stamp(now - Duration::from_secs(60)).into();
    p["valid_until_utc"] = stamp(now + Duration::from_secs(3600)).into();
    bytes(&p)
}
fn stamp(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Nanos, true)
}
fn reason<T>(result: ::egress::Result<T>, expected: Error) {
    match result {
        Err(error) => assert_eq!(error.reason(), expected.reason()),
        Ok(_) => panic!("expected {}", expected.reason()),
    }
}
fn verify_envelope(signer: &Signer, envelope: &Envelope) -> ::egress::Result<VerifiedInventory> {
    ::egress::verify_file(&serde_json::to_vec(envelope).unwrap(), &signer.trust(), t())
}
fn payload_case(signer: &Signer, field: &str, replacement: Value, expected: Error) {
    let mut p = value(PAYLOAD);
    p[field] = replacement;
    reason(signer.verify(&bytes(&p), t()), expected);
}
fn dns_result(inventory: &VerifiedInventory, fixture: &Value) -> ::egress::Result<()> {
    ::egress::verify_dns(
        inventory,
        &::egress::FixtureResolver::from_json(&bytes(fixture)).unwrap(),
    )
}
fn ptr_fixture(name: &str) -> Value {
    let mut fixture = value(DNS);
    fixture["ptr"]["192.0.2.10"] = json!([name]);
    fixture["addresses"][name] = json!(["192.0.2.10"]);
    fixture
}

#[test]
fn egress_signature() {
    let s = Signer::new();
    let f = Fixture::new();
    let good = s.signed(PAYLOAD);
    f.write("valid.envelope.json", &good);
    f.write("trusted.json", &s.trust_bytes());
    assert!(::egress::verify_file(&good, &s.trust(), t()).is_ok());
    let mut e = ::egress::parse_envelope(&good).unwrap();
    let mut sig = STANDARD.decode(&e.signature_base64).unwrap();
    sig[0] ^= 1;
    e.signature_base64 = STANDARD.encode(sig);
    f.write("tampered-signature.json", &serde_json::to_vec(&e).unwrap());
    reason(verify_envelope(&s, &e), Error::Signature);
    e = ::egress::parse_envelope(&good).unwrap();
    e.payload_base64 = STANDARD.encode([PAYLOAD, b" "].concat());
    reason(verify_envelope(&s, &e), Error::Signature);
    let spaced = [b" \n".as_slice(), PAYLOAD, b"\n"].concat();
    assert!(s.verify(&spaced, t()).is_ok());
    let mut other = value(PAYLOAD);
    other["policy_version"] = "second".into();
    e = s.envelope(PAYLOAD, "Ed25519", &s.id);
    e.signature_base64 = s
        .envelope(&bytes(&other), "Ed25519", &s.id)
        .signature_base64;
    reason(verify_envelope(&s, &e), Error::Signature);
    let wrong = Signer::new().envelope(PAYLOAD, "Ed25519", &s.id);
    reason(verify_envelope(&s, &wrong), Error::Signature);
}

#[test]
fn egress_algorithm() {
    let s = Signer::new();
    assert!(s.verify(PAYLOAD, t()).is_ok());
    for algorithm in ["none", "ed25519", "RSA"] {
        reason(
            verify_envelope(&s, &s.envelope(PAYLOAD, algorithm, &s.id)),
            Error::Algorithm,
        );
    }
}

#[test]
fn egress_algorithm_type_reason() {
    let c = CommandFixture::new();
    assert!(c.verify(false).status.success());
    let mut envelope = value(&c.signer.signed(&c.payload));
    for algorithm in [Value::Null, json!(1), json!({}), json!("ed25519")] {
        envelope["algorithm"] = algorithm;
        c.rejected("envelope.json", &bytes(&envelope), Error::Algorithm);
    }
    envelope.as_object_mut().unwrap().remove("algorithm");
    c.rejected("envelope.json", &bytes(&envelope), Error::EnvelopeSchema);
}

#[test]
fn egress_missing_key() {
    let s = Signer::new();
    assert!(s.verify(PAYLOAD, t()).is_ok());
    let mut e = value(&s.signed(PAYLOAD));
    e.as_object_mut().unwrap().remove("key_id");
    reason(
        ::egress::verify_file(&bytes(&e), &s.trust(), t()),
        Error::MissingKey,
    );
    e["key_id"] = "".into();
    reason(
        ::egress::verify_file(&bytes(&e), &s.trust(), t()),
        Error::KeyId,
    );
    reason(
        verify_envelope(&s, &s.envelope(PAYLOAD, "Ed25519", &"a".repeat(64))),
        Error::UntrustedKey,
    );
    e = value(&s.signed(PAYLOAD));
    e["public_key_base64"] = STANDARD
        .encode(Signer::new().key.public_key().as_ref())
        .into();
    reason(
        ::egress::verify_file(&bytes(&e), &s.trust(), t()),
        Error::EnvelopeSchema,
    );
    reason(::egress::parse_trusted_keys(b"{}"), Error::TrustedKeysEmpty);
    let mismatch = json!({"a".repeat(64): STANDARD.encode(s.key.public_key().as_ref())});
    reason(
        ::egress::parse_trusted_keys(&bytes(&mismatch)),
        Error::KeyIdentity,
    );
}

#[test]
fn egress_expiry() {
    let s = Signer::new();
    let expiry = instant("2026-09-25T11:00:00Z");
    reason(s.verify(PAYLOAD, expiry), Error::Expired);
    reason(
        s.verify(PAYLOAD, expiry + Duration::from_secs(1)),
        Error::Expired,
    );
    assert!(s.verify(PAYLOAD, expiry - Duration::from_nanos(1)).is_ok());
    for generation in ["2026-09-25T11:00:00Z", "2026-09-26T11:00:00Z"] {
        payload_case(
            &s,
            "generated_at_utc",
            generation.into(),
            Error::ValidityWindow,
        );
    }
    for raw in [
        "2026-09-24t11:00:00Z",
        "2026-09-24 11:00:00Z",
        "2026-09-24T11:00:00z",
        "2026-09-24T11:00:00-00:00",
        "2026-09-24T11:00:00+01:00",
        "2026-09-24T11:00:60Z",
        "2026-09-24T11:00:00",
        "2026-09-24T11:00:00.Z",
        "2026-09-24T11:00:00.1234567890Z",
        "2026-02-30T11:00:00Z",
    ] {
        payload_case(&s, "generated_at_utc", raw.into(), Error::Timestamp);
    }
    let mut p = value(PAYLOAD);
    p["generated_at_utc"] = "2026-09-24T11:00:00.123456789+00:00".into();
    assert!(s.verify(&bytes(&p), t()).is_ok());
}

fn schemas(s: &Signer) {
    for version in [json!(0), json!(2), json!("1"), json!(1.0), json!(true)] {
        payload_case(s, "schema_version", version.clone(), Error::PayloadSchema);
        let mut e = value(&s.signed(PAYLOAD));
        e["schema_version"] = version;
        reason(
            ::egress::verify_file(&bytes(&e), &s.trust(), t()),
            Error::EnvelopeSchema,
        );
    }
    for source in [PAYLOAD.to_vec(), s.signed(PAYLOAD)] {
        let payload = source == PAYLOAD;
        let expected = if payload {
            Error::PayloadSchema
        } else {
            Error::EnvelopeSchema
        };
        let check = |v: Value| {
            if payload {
                reason(s.verify(&bytes(&v), t()), expected);
            } else {
                reason(::egress::verify_file(&bytes(&v), &s.trust(), t()), expected);
            }
        };
        let mut v = value(&source);
        v["unknown"] = true.into();
        check(v);
        let mut v = value(&source);
        v.as_object_mut().unwrap().remove("schema_version");
        check(v);
        let mut v = value(&source);
        v[if payload { "ranges" } else { "algorithm" }] = Value::Null;
        if payload {
            check(v);
        } else {
            reason(
                ::egress::verify_file(&bytes(&v), &s.trust(), t()),
                Error::Algorithm,
            );
        }
    }
}

fn auxiliary_schemas() {
    for raw in [
        b"null".as_slice(),
        b"{\"egress_ips\":null}",
        b"{\"egress_ips\":[],\"x\":1}",
    ] {
        reason(::egress::parse_observed(raw), Error::ObservedSchema);
    }
    for raw in [
        b"null".as_slice(),
        b"{\"ptr\":null,\"addresses\":{}}",
        b"{\"ptr\":{},\"addresses\":{},\"x\":1}",
        b"{\"ptr\":{\"bad\":[]},\"addresses\":{}}",
    ] {
        reason(::egress::FixtureResolver::from_json(raw), Error::DnsFixture);
    }
    for raw in [b"null".as_slice(), b"{\"a\":null}"] {
        reason(::egress::parse_trusted_keys(raw), Error::TrustedKeysSchema);
    }
    reason(
        ::egress::FixtureResolver::from_json(
            b"{\"ptr\":{\"192.0.2.10\":[],\"192.0.2.10\":[]},\"addresses\":{}}",
        ),
        Error::DuplicateKey,
    );
    reason(
        ::egress::parse_trusted_keys(b"{\"a\":null,\"\\u0061\":null}"),
        Error::DuplicateKey,
    );
}

fn bounds(s: &Signer) {
    let f = Fixture::new();
    let mut p = PAYLOAD.to_vec();
    p.resize(::egress::MAX_PAYLOAD_BYTES, b' ');
    assert!(s.verify(&p, t()).is_ok());
    p.push(b' ');
    reason(::egress::parse_payload(&p), Error::InputTooLarge);
    reason(
        ::egress::sign_payload(&p, b"bad", t()),
        Error::InputTooLarge,
    );
    let mut e = s.signed(PAYLOAD);
    e.resize(::egress::MAX_FILE_BYTES, b' ');
    assert!(::egress::verify_file(&e, &s.trust(), t()).is_ok());
    let file = f.write("bounded.json", &e);
    assert!(
        ::egress::read_bounded(&file, e.len()).unwrap() == e,
        "bounded read changed envelope bytes"
    );
    e.push(b' ');
    f.write("bounded.json", &e);
    reason(
        ::egress::read_bounded(&file, ::egress::MAX_FILE_BYTES),
        Error::InputTooLarge,
    );
    reason(::egress::parse_envelope(&e), Error::InputTooLarge);
}

#[test]
fn egress_schema() {
    let s = Signer::new();
    assert!(s.verify(PAYLOAD, t()).is_ok());
    schemas(&s);
    auxiliary_schemas();
    bounds(&s);
    for raw in [b"\xff".as_slice(), b"{} {}"] {
        reason(::egress::parse_payload(raw), Error::JsonSyntax);
    }
    for key in ["schema_version", "\\u0073chema_version"] {
        let raw = String::from_utf8(PAYLOAD.to_vec()).unwrap().replacen(
            '{',
            &format!("{{\"{key}\":1,"),
            1,
        );
        reason(s.verify(raw.as_bytes(), t()), Error::DuplicateKey);
    }
    let raw =
        String::from_utf8(s.signed(PAYLOAD))
            .unwrap()
            .replacen('{', "{\"schema_version\":1,", 1);
    reason(
        ::egress::verify_file(raw.as_bytes(), &s.trust(), t()),
        Error::DuplicateKey,
    );
    for bad in ["AA", "AA=", "AB==", "AA==\n", "__=="] {
        let mut e = s.envelope(PAYLOAD, "Ed25519", &s.id);
        e.signature_base64 = bad.into();
        reason(verify_envelope(&s, &e), Error::Base64);
    }
    for size in [63, 65] {
        let mut e = s.envelope(PAYLOAD, "Ed25519", &s.id);
        e.signature_base64 = STANDARD.encode(vec![0; size]);
        reason(verify_envelope(&s, &e), Error::SignatureLength);
    }
    payload_case(&s, "policy_version", " \t".into(), Error::PolicyVersion);
}

#[test]
fn egress_ptr_domain() {
    let s = Signer::new();
    let inventory = s.verify(PAYLOAD, t()).unwrap();
    assert!(dns_result(&inventory, &value(DNS)).is_ok());
    assert!(dns_result(&inventory, &ptr_fixture("egress.example.net")).is_ok());
    for name in ["notegress.example.net", "egress.example.net.invalid"] {
        reason(dns_result(&inventory, &ptr_fixture(name)), Error::PtrDomain);
    }
    let long = format!("{}.egress.example.net", "a".repeat(64));
    for name in [
        "UPPER.egress.example.net",
        "é.egress.example.net",
        "xn--a.egress.example.net",
        "a_b.egress.example.net",
        "a..egress.example.net",
        "",
        &long,
    ] {
        reason(dns_result(&inventory, &ptr_fixture(name)), Error::PtrName);
        payload_case(
            &s,
            "controlled_domain",
            name.into(),
            Error::ControlledDomain,
        );
    }
    reason(
        dns_result(&inventory, &ptr_fixture("egress.example.net.")),
        Error::PtrTrailingDot,
    );
}

#[test]
fn egress_ptr() {
    let s = Signer::new();
    let inventory = s.verify(PAYLOAD, t()).unwrap();
    assert!(dns_result(&inventory, &value(DNS)).is_ok());
    for (answer, error) in [
        (json!(["192.0.2.11"]), Error::ForwardMismatch),
        (json!([]), Error::ForwardEmpty),
    ] {
        let mut f = value(DNS);
        f["addresses"]["crawler-v4.egress.example.net"] = answer;
        reason(dns_result(&inventory, &f), error);
    }
    let mut f = value(DNS);
    f["ptr"]["192.0.2.10"] = json!(["crawler-v4.egress.example.net", "second.egress.example.net"]);
    f["addresses"]["second.egress.example.net"] = json!(["192.0.2.11"]);
    reason(dns_result(&inventory, &f), Error::ForwardMismatch);
    f["addresses"]["second.egress.example.net"] = json!(["192.0.2.11", "192.0.2.10"]);
    f["addresses"]["crawler-v6.egress.example.net"] = json!(["2001:db8::11", "2001:db8::10"]);
    assert!(dns_result(&inventory, &f).is_ok());
}

#[test]
fn egress_inventory() {
    let s = Signer::new();
    let inventory = s.verify(PAYLOAD, t()).unwrap();
    let observed = ::egress::parse_observed(OBSERVED).unwrap();
    assert!(::egress::verify_observed(&inventory, &observed).is_ok());
    let subset = ::egress::ObservedInventory {
        egress_ips: vec!["192.0.2.10".parse().unwrap()],
    };
    assert!(::egress::verify_observed(&inventory, &subset).is_ok());
    let f = Fixture::new();
    for ip in ["192.0.2.11", "198.51.100.10"] {
        let raw = bytes(&json!({"egress_ips":[ip]}));
        f.write("observed-missing.json", &raw);
        reason(
            ::egress::verify_observed(&inventory, &::egress::parse_observed(&raw).unwrap()),
            Error::ObservedIpMissing,
        );
    }
    for (ips, error) in [
        (json!([]), Error::ObservedEmpty),
        (
            json!(["192.0.2.10", "192.0.2.10"]),
            Error::ObservedDuplicate,
        ),
    ] {
        let raw = bytes(&json!({"egress_ips":ips}));
        reason(::egress::parse_observed(&raw), error);
        reason(
            ::egress::verify_observed(&inventory, &serde_json::from_slice(&raw).unwrap()),
            error,
        );
    }
    payload_case(&s, "egress_ips", json!([]), Error::InventoryEmpty);
    payload_case(
        &s,
        "egress_ips",
        json!(["192.0.2.10", "192.0.2.10"]),
        Error::InventoryDuplicate,
    );
}

#[test]
fn egress_ranges() {
    let s = Signer::new();
    assert!(s.verify(PAYLOAD, t()).is_ok());
    payload_case(
        &s,
        "egress_ips",
        json!(["198.51.100.10"]),
        Error::IpOutsideRanges,
    );
    for raw in ["192.0.2.1/24", "2001:0db8::/32"] {
        payload_case(&s, "ranges", json!([raw]), Error::RangeNoncanonical);
    }
    for raw in ["192.0.2.0/33", "2001:db8::/129", "192.0.2.0/024"] {
        payload_case(&s, "ranges", json!([raw]), Error::RangeInvalid);
    }
    payload_case(&s, "ranges", json!([]), Error::RangesEmpty);
    payload_case(
        &s,
        "ranges",
        json!(["192.0.2.0/24", "192.0.2.0/24"]),
        Error::RangeDuplicate,
    );
    for ranges in [
        json!(["0.0.0.0/0", "::/0"]),
        json!(["192.0.2.10/32", "2001:db8::10/128"]),
    ] {
        let mut p = value(PAYLOAD);
        p["ranges"] = ranges;
        assert!(s.verify(&bytes(&p), t()).is_ok());
    }
    let mut p = value(PAYLOAD);
    p["egress_ips"] = json!(["2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"]);
    assert!(s.verify(&bytes(&p), t()).is_ok());
}

#[test]
fn egress_dns_errors() {
    let s = Signer::new();
    let inventory = s.verify(PAYLOAD, t()).unwrap();
    assert!(dns_result(&inventory, &value(DNS)).is_ok());
    for null in [true, false] {
        let mut f = value(DNS);
        if null {
            f["ptr"]["192.0.2.10"] = Value::Null;
        } else {
            f["ptr"].as_object_mut().unwrap().remove("192.0.2.10");
        }
        reason(dns_result(&inventory, &f), Error::PtrLookup);
        let mut f = value(DNS);
        if null {
            f["addresses"]["crawler-v4.egress.example.net"] = Value::Null;
        } else {
            f["addresses"]
                .as_object_mut()
                .unwrap()
                .remove("crawler-v4.egress.example.net");
        }
        reason(dns_result(&inventory, &f), Error::ForwardLookup);
    }
    let mut f = value(DNS);
    f["ptr"]["192.0.2.10"] = json!([]);
    reason(dns_result(&inventory, &f), Error::PtrEmpty);
    f["ptr"]["192.0.2.10"] = json!(["crawler-v4.egress.example.net", "absent.egress.example.net"]);
    reason(dns_result(&inventory, &f), Error::ForwardLookup);
}

struct CommandFixture {
    fixture: Fixture,
    signer: Signer,
    payload: Vec<u8>,
}

impl CommandFixture {
    fn new() -> Self {
        let fixture = Fixture::new();
        let signer = Signer::new();
        let payload = fresh();
        fixture.write("payload.json", &payload);
        fixture.key(&signer.der);
        fixture.write("trusted.json", &signer.trust_bytes());
        fixture.write("observed.json", OBSERVED);
        fixture.write("dns.json", DNS);
        fixture.write("envelope.json", &signer.signed(&payload));
        Self {
            fixture,
            signer,
            payload,
        }
    }

    fn sign(&self, out: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("egress-sign")
            .arg("--payload")
            .arg(self.fixture.path("payload.json"))
            .arg("--key")
            .arg(self.fixture.path("key.der"))
            .arg("--out")
            .arg(out)
            .output()
            .unwrap()
    }

    fn verify(&self, no_home_tmp: bool) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xtask"));
        cmd.arg("egress-verify");
        for (flag, file) in [
            ("--file", "envelope.json"),
            ("--trusted-keys", "trusted.json"),
            ("--observed", "observed.json"),
            ("--dns-fixture", "dns.json"),
        ] {
            cmd.arg(flag).arg(self.fixture.path(file));
        }
        if no_home_tmp {
            cmd.env_remove("TMPDIR").env_remove("HOME");
        }
        cmd.output().unwrap()
    }

    fn rejected(&self, file: &str, bytes: &[u8], expected: Error) {
        let path = self.fixture.path(file);
        let saved = fs::read(&path).unwrap();
        fs::write(&path, bytes).unwrap();
        failed(self.verify(false), "egress-verify", expected);
        fs::write(path, saved).unwrap();
    }
}

fn failed(output: Output, command: &str, expected: Error) {
    assert_eq!(output.status.code(), Some(1));
    let err = String::from_utf8(output.stderr).unwrap();
    assert!(
        err.starts_with(&format!("{command}: {}", expected.reason())),
        "expected {}: {err}",
        expected.reason()
    );
    assert!(output.stdout.is_empty(), "rejection must not print success");
}

fn cli_negatives(c: &CommandFixture) {
    let mut e = c.signer.envelope(&c.payload, "Ed25519", &c.signer.id);
    let mut sig = STANDARD.decode(&e.signature_base64).unwrap();
    sig[0] ^= 1;
    e.signature_base64 = STANDARD.encode(sig);
    c.rejected(
        "envelope.json",
        &serde_json::to_vec(&e).unwrap(),
        Error::Signature,
    );
    for (field, replacement, expected) in [
        ("algorithm", json!("none"), Error::Algorithm),
        ("key_id", json!("a".repeat(64)), Error::UntrustedKey),
        ("schema_version", json!(2), Error::EnvelopeSchema),
        ("signature_base64", json!("AB=="), Error::Base64),
        (
            "signature_base64",
            json!(STANDARD.encode([0; 63])),
            Error::SignatureLength,
        ),
    ] {
        let mut e = value(&c.signer.signed(&c.payload));
        e[field] = replacement;
        c.rejected("envelope.json", &bytes(&e), expected);
    }
    let mut missing = value(&c.signer.signed(&c.payload));
    missing.as_object_mut().unwrap().remove("key_id");
    c.rejected("envelope.json", &bytes(&missing), Error::MissingKey);
    let duplicate = String::from_utf8(c.signer.signed(&c.payload))
        .unwrap()
        .replacen('{', "{\"schema_version\":1,", 1);
    c.rejected("envelope.json", duplicate.as_bytes(), Error::DuplicateKey);
    for (field, replacement, expected) in [
        ("egress_ips", json!([]), Error::InventoryEmpty),
        ("schema_version", json!(2), Error::PayloadSchema),
        ("ranges", json!([]), Error::RangesEmpty),
        ("policy_version", json!(""), Error::PolicyVersion),
        (
            "valid_until_utc",
            json!(stamp(SystemTime::now() - Duration::from_secs(1))),
            Error::Expired,
        ),
    ] {
        let mut p = value(&c.payload);
        p[field] = replacement;
        c.rejected("envelope.json", &c.signer.signed(&bytes(&p)), expected);
    }
    for (ips, expected) in [
        (json!([]), Error::ObservedEmpty),
        (json!(["192.0.2.11"]), Error::ObservedIpMissing),
        (
            json!(["192.0.2.10", "192.0.2.10"]),
            Error::ObservedDuplicate,
        ),
    ] {
        c.rejected(
            "observed.json",
            &bytes(&json!({"egress_ips":ips})),
            expected,
        );
    }
    c.rejected("trusted.json", b"{}", Error::TrustedKeysEmpty);
    c.rejected(
        "dns.json",
        &bytes(&ptr_fixture("notegress.example.net")),
        Error::PtrDomain,
    );
}

#[test]
fn egress_cli_round_trip() {
    let c = CommandFixture::new();
    let destination = c.fixture.path("envelope.json");
    let output = c.sign(&destination);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout).unwrap()
            == format!(
                "egress-sign: wrote {}; key_id={}; public_key_base64={}\n",
                destination.display(),
                c.signer.id,
                STANDARD.encode(c.signer.key.public_key().as_ref())
            ),
        "sign command output differs"
    );
    let e = ::egress::parse_envelope(&fs::read(destination).unwrap()).unwrap();
    assert!(
        STANDARD.decode(e.payload_base64).unwrap() == c.payload,
        "signed payload differs"
    );
    for no_home_tmp in [false, true] {
        let output = c.verify(no_home_tmp);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8(output.stdout).unwrap()
                == format!(
                    "egress-verify: verified key_id={} egress_ips=2 observed_ips=2\n",
                    c.signer.id
                ),
            "verify command output differs"
        );
    }
    cli_negatives(&c);
    let help = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(!String::from_utf8(help.stdout).unwrap().contains("keygen"));
}

#[test]
fn egress_key_length() {
    let s = Signer::new();
    assert!(::egress::parse_trusted_keys(&s.trust_bytes()).is_ok());
    for size in [31, 33] {
        let map = json!({"a".repeat(64): STANDARD.encode(vec![0; size])});
        reason(::egress::parse_trusted_keys(&bytes(&map)), Error::KeyLength);
    }
    for bad in ["AA", "AB==", "AA== ", "_A=="] {
        reason(
            ::egress::parse_trusted_keys(&bytes(&json!({"a".repeat(64):bad}))),
            Error::Base64,
        );
    }
    let public: [u8; 32] = s.key.public_key().as_ref().try_into().unwrap();
    assert!(::egress::key_id(&public) == s.id, "key identifier differs");
}

#[test]
fn egress_duplicate_payload() {
    let s = Signer::new();
    assert!(s.verify(PAYLOAD, t()).is_ok());
    for prefix in [
        "\"schema_version\":1,",
        "\"\\u0065gress_ips\":[],",
        "\"unknown\":{\"same\":1,\"same\":1},",
        "\"unknown\":{\"$serde_json::private::RawValue\":{\"x\":1,\"x\":1}},",
    ] {
        let p =
            String::from_utf8(PAYLOAD.to_vec())
                .unwrap()
                .replacen('{', &format!("{{{prefix}"), 1);
        reason(s.verify(p.as_bytes(), t()), Error::DuplicateKey);
    }
}

#[test]
fn egress_duplicate_envelope() {
    let s = Signer::new();
    let raw = s.signed(PAYLOAD);
    assert!(::egress::verify_file(&raw, &s.trust(), t()).is_ok());
    let e = value(&raw);
    for (key, original) in [
        ("key_id", "key_id"),
        ("\\u006bey_id", "key_id"),
        ("payload_base64", "payload_base64"),
        ("\\u0070ayload_base64", "payload_base64"),
    ] {
        let duplicate = String::from_utf8(raw.clone()).unwrap().replacen(
            '{',
            &format!("{{\"{key}\":{},", e[original]),
            1,
        );
        reason(
            ::egress::verify_file(duplicate.as_bytes(), &s.trust(), t()),
            Error::DuplicateKey,
        );
    }
    let mut e = e;
    e["public_key_base64"] = "unused".into();
    reason(
        ::egress::verify_file(&bytes(&e), &s.trust(), t()),
        Error::EnvelopeSchema,
    );
}

#[test]
fn egress_not_yet_valid() {
    let s = Signer::new();
    let generation = instant("2026-09-24T11:00:00Z");
    assert!(s.verify(PAYLOAD, generation).is_ok());
    reason(
        s.verify(PAYLOAD, generation - Duration::from_nanos(1)),
        Error::NotYetValid,
    );
    let c = CommandFixture::new();
    let mut p = value(&c.payload);
    p["generated_at_utc"] = stamp(SystemTime::now() + Duration::from_secs(60)).into();
    c.rejected(
        "envelope.json",
        &c.signer.signed(&bytes(&p)),
        Error::NotYetValid,
    );
}

#[test]
fn egress_signing_message() {
    let s = Signer::new();
    let e = s.envelope(PAYLOAD, "Ed25519", &s.id);
    let expected = oracle(&e, PAYLOAD);
    let actual = ::egress::signing_message(&e, PAYLOAD);
    assert!(
        actual == expected,
        "signing message differs from the specified layout"
    );
    assert!(
        &expected[..21] == b"AVA-SEARCH-EGRESS-V1\n",
        "signing domain differs"
    );
    assert!(
        expected[21..30] == [0, 0, 0, 0, 0, 0, 0, 1, b'1'],
        "signing schema frame differs"
    );
    assert_eq!(::egress::DEFAULT_LIFETIME_SECONDS, 86400);
    let signed = ::egress::sign_payload(PAYLOAD, &s.der, t()).unwrap();
    let envelope = ::egress::parse_envelope(&signed.bytes).unwrap();
    signature::UnparsedPublicKey::new(&signature::ED25519, s.key.public_key().as_ref())
        .verify(
            &expected,
            &STANDARD.decode(&envelope.signature_base64).unwrap(),
        )
        .unwrap();
    for field in ["id", "algorithm"] {
        let mut changed = e.clone();
        if field == "id" {
            changed.key_id = "a".repeat(64);
        } else {
            changed.algorithm = "none".into();
        }
        assert!(
            oracle(&changed, PAYLOAD) != expected,
            "changed field left signing message equal"
        );
        assert!(signature::UnparsedPublicKey::new(
            &signature::ED25519,
            s.key.public_key().as_ref()
        )
        .verify(
            &oracle(&changed, PAYLOAD),
            &STANDARD.decode(&e.signature_base64).unwrap()
        )
        .is_err());
    }
    let mut e = e;
    e.payload_base64 = STANDARD.encode(bytes(&value(PAYLOAD)));
    reason(verify_envelope(&s, &e), Error::Signature);
}

// Reusing only the generated seed exercises RFC 8410 v1 without checking in private material.
fn version_one(der: &[u8]) -> Vec<u8> {
    let seed = &der[16..48];
    assert!(
        der[12..16] == [0x04, 0x22, 0x04, 0x20],
        "PKCS8 seed framing differs"
    );
    let mut v1 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    v1.extend_from_slice(seed);
    v1
}

#[test]
fn egress_pkcs8() {
    let s = Signer::new();
    for der in [&s.der, &version_one(&s.der)] {
        let signed = ::egress::sign_payload(PAYLOAD, der, t()).unwrap();
        assert!(::egress::verify_file(&signed.bytes, &s.trust(), t()).is_ok());
    }
    let mut corrupt = s.der.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for der in [&corrupt[..], b"malformed", &s.der[..10]] {
        reason(::egress::sign_payload(PAYLOAD, der, t()), Error::PrivateKey);
    }
    let c = CommandFixture::new();
    c.fixture.write("payload.json", b"{}");
    fs::remove_file(c.fixture.path("key.der")).unwrap();
    failed(
        c.sign(&c.fixture.path("out.json")),
        "egress-sign",
        Error::PayloadSchema,
    );
}

#[derive(Default)]
struct Boundary {
    unsafe_blocks: Vec<syn::ExprUnsafe>,
}

impl<'ast> syn::visit::Visit<'ast> for Boundary {
    fn visit_expr_unsafe(&mut self, expression: &'ast syn::ExprUnsafe) {
        self.unsafe_blocks.push(expression.clone());
        syn::visit::visit_expr_unsafe(self, expression);
    }
}

#[test]
fn egress_system_adapter_boundary() {
    use quote::ToTokens;
    use syn::visit::Visit;
    let source = include_str!("../src/egress/system.rs");
    let parsed = syn::parse_file(source).unwrap();
    let mut boundary = Boundary::default();
    boundary.visit_file(&parsed);
    assert_eq!(boundary.unsafe_blocks.len(), 1);
    let block = &boundary.unsafe_blocks[0].block;
    assert_eq!(block.stmts.len(), 1);
    let syn::Stmt::Expr(syn::Expr::Call(call), _) = &block.stmts[0] else {
        panic!("unsafe boundary must contain only getnameinfo");
    };
    assert_eq!(
        call.func.to_token_stream().to_string(),
        "libc :: getnameinfo"
    );
    let args: Vec<_> = call
        .args
        .iter()
        .map(|a| a.to_token_stream().to_string())
        .collect();
    assert_eq!(
        args,
        [
            "pointer",
            "length",
            "host . as_mut_ptr ()",
            "host . len () as libc :: socklen_t",
            "std :: ptr :: null_mut ()",
            "0",
            "libc :: NI_NAMEREQD"
        ]
    );
    let tokens = parsed.to_token_stream().to_string();
    for expected in [
        "const NI_MAXHOST : usize = libc :: NI_MAXHOST as usize",
        "let mut host = [0 as libc :: c_char ; NI_MAXHOST]",
        ". position (| byte | * byte == 0)",
        "host [.. end]",
        "String :: from_utf8 (bytes)",
        "std :: mem :: size_of :: < libc :: sockaddr_in > () as libc :: socklen_t",
        "std :: mem :: size_of :: < libc :: sockaddr_in6 > () as libc :: socklen_t",
    ] {
        assert!(
            tokens.contains(expected),
            "missing bounded adapter token: {expected}"
        );
    }
    assert!(source.contains("/// # Safety"));
    assert!(!include_str!("../../core/Cargo.toml").contains("xtask"));
    assert!(!include_str!("../../egress/Cargo.toml").contains("xtask"));
    assert!(!include_str!("../../core/src/api/mod.rs").contains("SystemDnsResolver"));
    assert!(include_str!("../src/egress/mod.rs").contains("mod system;"));
}

fn atomic_failure(c: &CommandFixture, out: &Path, error: Error) {
    let before: Vec<_> = fs::read_dir(&c.fixture.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    failed(c.sign(out), "egress-sign", error);
    let after: Vec<_> = fs::read_dir(&c.fixture.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        before
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        after.into_iter().collect::<std::collections::BTreeSet<_>>(),
        "no orphan temporary file"
    );
}

#[test]
fn egress_sign_atomic() {
    let c = CommandFixture::new();
    let out = c.fixture.write("out.json", b"sentinel");
    let key = c.fixture.path("key.der");
    let original_key = fs::read(&key).unwrap();
    c.fixture.write("payload.json", b"{}");
    atomic_failure(&c, &out, Error::PayloadSchema);
    assert!(
        fs::read(&out).unwrap() == b"sentinel",
        "invalid payload replaced output"
    );
    c.fixture.write("payload.json", &c.payload);
    fs::write(&key, b"bad").unwrap();
    atomic_failure(&c, &out, Error::PrivateKey);
    assert!(
        fs::read(&out).unwrap() == b"sentinel",
        "invalid key replaced output"
    );
    fs::write(&key, &original_key).unwrap();
    atomic_failure(&c, &c.fixture.path("missing/out.json"), Error::Io);
    let link = c.fixture.path("link.json");
    std::os::unix::fs::symlink(&out, &link).unwrap();
    atomic_failure(&c, &link, Error::Io);
    assert!(
        fs::read(&out).unwrap() == b"sentinel",
        "symlink attempt replaced output"
    );
    let dir = c.fixture.path("directory");
    fs::create_dir(&dir).unwrap();
    atomic_failure(&c, &dir, Error::Io);
    atomic_failure(&c, &key, Error::Io);
    assert!(
        fs::read(&key).unwrap() == original_key,
        "failed publication changed key"
    );
    assert!(c.sign(&out).status.success());
    let bytes = fs::read(&out).unwrap();
    assert!(::egress::verify_file(&bytes, &c.signer.trust(), SystemTime::now()).is_ok());
    let envelope = ::egress::parse_envelope(&bytes).unwrap();
    assert!(
        STANDARD.decode(envelope.payload_base64).unwrap() == c.payload,
        "published payload differs"
    );
    assert_eq!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        fs::read(&key).unwrap() == original_key,
        "successful publication changed key"
    );
}
