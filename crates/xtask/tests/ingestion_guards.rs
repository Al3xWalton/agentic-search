//! Exercises ingestion guards against disposable source and diagnostic fixtures.
//! Tests never fetch, invoke Cargo recursively or change real manifests; rejected fixtures
//! carry exact file and line evidence. Temporary roots belong to this process and are removed.

#![deny(missing_docs)]

use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use xtask::ingestion;

static NEXT: AtomicUsize = AtomicUsize::new(0);
const BUILDER: &str = include_str!("fixtures/ingestion/ua/good.rs");
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let f = Self(
            PathBuf::from(std::env::var_os("STORY584_SCRATCH").unwrap()).join(format!(
                "ingestion-guard-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )),
        );
        fs::create_dir(&f.0).unwrap();
        f.write("crates/core/src/crawler/identity.rs", BUILDER);
        f
    }
    fn write(&self, path: &str, value: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }
    fn ua(&self) -> anyhow::Result<()> {
        ingestion::crawler_user_agent(&self.0)
    }
    fn probe(&self, code: &str) {
        self.write("crates/core/src/crawler/probe.rs", code);
        let error = self.ua().expect_err("accepted raw transport").to_string();
        assert!(
            error.contains("crawler-user-agent")
                && error.contains(".rs:")
                && error.contains("probe.rs"),
            "{error}"
        );
        self.write(
            "crates/core/src/crawler/probe.rs",
            "fn ordinary() { tracing::info!(\"safe\"); }",
        );
        self.ua().unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn ua_direct_client() {
    let f = Fixture::new();
    f.ua().unwrap();
    for code in [
        include_str!("fixtures/ingestion/ua/bad.rs"),
        "fn f() { let _: reqwest::Client = Default::default(); }",
        "fn f() { reqwest::get(url); }",
        "type Bad = reqwest::RequestBuilder;",
        "fn f() { reqwest::blocking::Client::new(); }",
        "type Bad = reqwest::ClientBuilder;",
        "use reqwest::header::HeaderMap;",
    ] {
        f.probe(code);
    }
}
#[test]
fn ua_aliases() {
    let f = Fixture::new();
    f.write(
        "crates/core/src/crawler/probe.rs",
        "use std::fmt::{self, Display}; use b as a; use a as b; fn ordinary() {} ",
    );
    f.ua().unwrap();
    f.write(
        "crates/core/src/crawler/identity.rs",
        &format!("{BUILDER}\nuse reqwest as r; use r::Client as C; fn escape() {{ C::new(); }}"),
    );
    assert!(f.ua().unwrap_err().to_string().contains("identity.rs:"));
    f.write(
        "crates/core/src/crawler/identity.rs",
        &format!("{BUILDER}\nuse reqwest as std; fn escape() {{ std::Client::new(); }}"),
    );
    assert!(f.ua().unwrap_err().to_string().contains("identity.rs:"));
    f.write("crates/core/src/crawler/identity.rs", BUILDER);
    for code in [
        "use reqwest as r; use r::Client as C; fn f() { C::new(); }",
        "use reqwest::{Client as C, blocking::{Client as B}}; type Alias = C; fn f() { B::new(); }",
        "use reqwest::Client; fn f() { let _: Client = Default::default(); }",
        "use reqwest::*; fn f() { Client::new(); }",
        "use reqwest as r; type C = r::Client; fn f() { C::default(); }",
    ] {
        f.probe(code);
    }
}
#[test]
fn ua_reexports() {
    let f = Fixture::new();
    f.write(
        "crates/core/src/crawler/identity.rs",
        &format!("{BUILDER}\npub use reqwest::Client as Raw;"),
    );
    assert!(f.ua().unwrap_err().to_string().contains("identity.rs:"));
    f.write("crates/core/src/crawler/identity.rs", BUILDER);
    f.probe("pub use reqwest::Client as Raw;");
    f.write(
        "crates/core/src/wrapper.rs",
        "pub use reqwest::Client as Wrapped;",
    );
    f.probe("use crate::wrapper::Wrapped; fn f() { Wrapped::new(); }");
    f.write(
        "crates/core/src/wrapper.rs",
        "pub struct Wrapped { client: reqwest::Client }",
    );
    f.probe("use crate::wrapper::Wrapped; fn f(x: Wrapped) {}");
}
#[test]
fn ua_macros_and_paths() {
    let f = Fixture::new();
    f.probe("macro_rules! spawn { () => { reqwest::Client::new() } }");
    f.probe("spawn_http!(client);");
    f.probe("#[spawn_http] fn client() {}");
    f.probe("#[derive(SpawnHttp)] struct Client;");
    f.probe("fn f() { println!(\"{:?}\", reqwest::Client::new()); }");
    f.write(
        "crates/core/src/hidden.rs",
        "fn f() { reqwest::Client::new(); }",
    );
    f.write(
        "crates/core/src/crawler/probe.rs",
        "#[path = \"../hidden.rs\"] mod hidden;",
    );
    let error = f.ua().unwrap_err().to_string();
    assert!(
        error.contains("hidden.rs:") && error.contains("crawler-user-agent"),
        "{error}"
    );
    f.write("crates/core/src/hidden.rs", "fn f() {}");
    f.ua().unwrap();
}
#[test]
fn ua_bypass_settings() {
    let f = Fixture::new();
    for header in ["authorization", "proxy-authorization", "cookie", "referer"] {
        f.write(
            "crates/core/src/crawler/identity.rs",
            &BUILDER.replace(".build()", &format!(".header(\"{header}\", value).build()")),
        );
        assert!(f.ua().unwrap_err().to_string().contains("identity.rs:"));
    }
    f.write(
        "crates/core/src/crawler/identity.rs",
        &BUILDER.replace(
            ".build()",
            ".header(reqwest::header::AUTHORIZATION, value).build()",
        ),
    );
    assert!(f.ua().is_err());
    for method in [
        "danger_accept_invalid_certs(true)",
        "danger_accept_invalid_hostnames(true)",
        "add_root_certificate(cert)",
        "use_preconfigured_tls(tls)",
        "cookie_store(true)",
        "proxy(proxy)",
        "basic_auth(user, pass)",
        "bearer_auth(token)",
    ] {
        f.write(
            "crates/core/src/crawler/identity.rs",
            &BUILDER.replace(".build()", &format!(".{method}.build()")),
        );
        let error = f.ua().unwrap_err().to_string();
        assert!(
            error.contains("identity.rs:") && error.contains("crawler-user-agent"),
            "{error}"
        );
    }
    f.write(
        "crates/core/src/crawler/identity.rs",
        &BUILDER.replace(
            ".user_agent(build_user_agent(identity)?)",
            ".user_agent(\"OtherBot\")",
        ),
    );
    assert!(f.ua().is_err());
    f.write("crates/core/src/crawler/identity.rs", BUILDER);
    f.ua().unwrap();
}
#[test]
fn dependency_deny() {
    let f = Fixture::new();
    f.write("Cargo.toml", "[workspace]\nmembers = []\n");
    f.write(
        "Cargo.lock",
        "version = 4\n[[package]]\nname = \"reqwest\"\nversion = \"0.12.0\"\n",
    );
    ingestion::crawler_dependency_deny(&f.0).unwrap();
    for manifest in [
        include_str!("fixtures/ingestion/dependencies/bad.toml"),
        "[dependencies]\nsafe = { package = \"bright_data\", version = \"=1.0.0\" }\n",
        "[target.'cfg(unix)'.build-dependencies]\nsafe = { git = \"https://example.invalid/residential_proxy\" }\n",
    ] {
        f.write("crates/core/Cargo.toml", manifest);
        assert!(ingestion::crawler_dependency_deny(&f.0).unwrap_err().to_string().contains("Cargo.toml"));
    }
    f.write(
        "crates/core/Cargo.toml",
        include_str!("fixtures/ingestion/dependencies/good.toml"),
    );
    f.write("Cargo.lock", "version = 4\n[[package]]\nname = \"safe\"\nversion = \"1.0.0\"\nsource = \"git+https://example.invalid/Anti_Captcha\"\n");
    assert!(ingestion::crawler_dependency_deny(&f.0).is_err());
}
fn policy() -> String {
    (1..=12)
        .map(|n| format!("## P{n:02} Heading\n\nContent\n\n"))
        .collect()
}
#[test]
fn policy_twelve_sections() {
    ingestion::policy_sections(include_str!("fixtures/ingestion/policy/good.txt")).unwrap();
    assert!(ingestion::policy_sections(include_str!("fixtures/ingestion/policy/bad.txt")).is_err());
    for n in 1..=12 {
        assert!(ingestion::policy_sections(
            &policy().replace(&format!("## P{n:02} Heading\n\nContent\n\n"), "")
        )
        .is_err());
    }
    assert!(ingestion::policy_sections(&(policy() + "## P01 duplicate\n\nbody\n")).is_err());
    assert!(ingestion::policy_sections(&policy().replacen("Content", "", 1)).is_err());
    let ids = ingestion::policy_sections(&policy().replacen(
        "Content",
        "[FOUNDER REQUIRED: identity]",
        1,
    ))
    .unwrap();
    assert_eq!(ids, vec!["P01"]);
}
fn changed() -> BTreeSet<String> {
    ["crates/core/src/crawler/new.rs".into()].into()
}
fn diagnostic(file: &str, code: &str) -> serde_json::Value {
    json!({"reason":"compiler-message","package_id":"path+file:///fixture#stract@0.1.0","target":{"name":"stract","kind":["lib"]},"message":{"level":"error","message":"fixture warning","code":{"code":code},"spans":[{"file_name":file,"is_primary":true,"expansion":null}]}})
}
#[test]
fn strict_clippy_touched() {
    let touched = changed();
    let bad: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ingestion/clippy/bad.json")).unwrap();
    assert!(ingestion::inspect_diagnostics(&format!("{bad}\n"), false, &touched).is_err());
    let mut warning = bad.clone();
    warning["message"]["level"] = json!("warning");
    assert!(ingestion::inspect_diagnostics(&format!("{warning}\n"), true, &touched).is_err());
    let inherited = diagnostic("crates/core/src/untouched.rs", "clippy::large_enum_variant");
    ingestion::inspect_diagnostics(&format!("{inherited}\n"), false, &touched).unwrap();
    let mut expanded = inherited.clone();
    expanded["message"]["spans"][0]["expansion"] = json!({"span":{"file_name":"crates/core/src/crawler/new.rs","is_primary":false,"expansion":null}});
    assert!(ingestion::inspect_diagnostics(&format!("{expanded}\n"), false, &touched).is_err());
    assert!(ingestion::inspect_diagnostics("", false, &touched).is_err());
    assert!(ingestion::inspect_diagnostics("not json\n", false, &touched).is_err());
    let unknown = diagnostic("crates/core/src/untouched.rs", "E0001");
    assert!(ingestion::inspect_diagnostics(&format!("{unknown}\n"), false, &touched).is_err());
    let docs = diagnostic("crates/core/src/crawler/new.rs", "missing_docs");
    assert!(ingestion::inspect_diagnostics(&format!("{docs}\n"), true, &touched).is_err());
}
#[test]
fn strict_clippy_coverage() {
    let artifact: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ingestion/clippy/good.json")).unwrap();
    let observed = ingestion::inspect_diagnostics(&artifact.to_string(), true, &changed()).unwrap();
    assert!(observed.contains("xtask:lib:xtask"));
    let required: BTreeSet<String> =
        ["stract:lib:stract".into(), "stract:bin:stract".into()].into();
    assert!(ingestion::ensure_coverage(&required, &BTreeSet::new()).is_err());
    ingestion::ensure_coverage(&required, &required).unwrap();
}
#[test]
fn strict_clippy_paths() {
    let mut paths = BTreeSet::new();
    for bytes in [
        b"a.rs\0b.rs\0".as_slice(),
        b"b.rs\0space name.rs\0",
        b"new\nline.rs\0",
    ] {
        ingestion::add_changed_paths(&mut paths, bytes).unwrap();
    }
    assert_eq!(paths.len(), 4);
    assert!(paths.contains("space name.rs") && paths.contains("new\nline.rs"));
    for invalid in [
        b"/absolute.rs\0".as_slice(),
        b"../outside.rs\0",
        b"invalid\xff.rs\0",
    ] {
        assert!(ingestion::add_changed_paths(&mut paths, invalid).is_err());
    }
}
#[test]
fn ingestion_ci_wiring() {
    let source = include_str!("../src/ci.rs");
    ingestion::ensure_ingestion_ci_wiring(source).unwrap();
    for call in [
        "crate::ingestion::crawler_user_agent(&root)?;",
        "crate::ingestion::crawler_dependency_deny(&root)?;",
        "crate::ingestion::crawler_policy_check(&root.join(\"CRAWLER_POLICY.md\"))?;",
        "crate::ingestion::strict_clippy_touched(None)?;",
    ] {
        assert_eq!(
            source.matches(call).count(),
            1,
            "fixture seam changed {call}"
        );
        assert!(ingestion::ensure_ingestion_ci_wiring(
            &source.replace(call, &format!("// {call}"))
        )
        .is_err());
    }
    assert!(ingestion::ensure_ingestion_ci_wiring(
        &source.replace("ingestion_guards", "other_guards")
    )
    .is_err());
    let swapped = source
        .replace("crate::ingestion::crawler_user_agent(&root)?;", "SWAP")
        .replace(
            "crate::ingestion::crawler_dependency_deny(&root)?;",
            "crate::ingestion::crawler_user_agent(&root)?;",
        )
        .replace("SWAP", "crate::ingestion::crawler_dependency_deny(&root)?;");
    assert!(ingestion::ensure_ingestion_ci_wiring(&swapped).is_err());
}
