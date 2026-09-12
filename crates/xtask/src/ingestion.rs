//! Enforces the crawler's closed HTTP boundary and local policy/CI contracts.
//! Syntax inspection rejects uninspectable transport code; it is a regression guard, not a Rust
//! compiler or proof against malicious build scripts. Diagnostics preserve paths and lines.
//! Clippy evidence is retained outside the repository and never hides touched-file warnings.

#![deny(missing_docs)]

use anyhow::{bail, ensure, Context, Result};
use proc_macro2::{Span, TokenStream, TokenTree};
use quote::ToTokens;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};
use syn::{
    spanned::Spanned,
    visit::{self, Visit},
    Item, UseTree,
};
use walkdir::WalkDir;

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}
fn imports(tree: &UseTree, prefix: &str, out: &mut Vec<(String, String, Span)>) {
    match tree {
        UseTree::Path(p) => imports(&p.tree, &format!("{prefix}{}::", p.ident), out),
        UseTree::Name(n) if n.ident == "self" => {
            let target = prefix.trim_end_matches("::");
            out.push((
                target.rsplit("::").next().unwrap_or(target).into(),
                target.into(),
                n.span(),
            ));
        }
        UseTree::Name(n) => out.push((
            n.ident.to_string(),
            format!("{prefix}{}", n.ident),
            n.span(),
        )),
        UseTree::Rename(n) => out.push((
            n.rename.to_string(),
            format!("{prefix}{}", n.ident),
            n.span(),
        )),
        UseTree::Glob(g) => out.push(("*".into(), prefix.trim_end_matches("::").into(), g.span())),
        UseTree::Group(g) => {
            for item in &g.items {
                imports(item, prefix, out);
            }
        }
    }
}
fn raw(path: &str) -> bool {
    let parts: Vec<_> = path.split("::").collect();
    parts.first() == Some(&"reqwest")
        && parts.iter().skip(1).any(|p| {
            matches!(
                *p,
                "Client" | "ClientBuilder" | "RequestBuilder" | "blocking" | "get"
            )
        })
}
fn resolve_import_alias(path: &str, aliases: &BTreeMap<String, String>) -> String {
    let mut value = path.to_owned();
    let mut visited = BTreeSet::new();
    for _ in 0..32 {
        let (head, tail) = value.split_once("::").unwrap_or((&value, ""));
        if matches!(head, "crate" | "self" | "super") || !visited.insert(head.to_owned()) {
            break;
        }
        let Some(replacement) = aliases.get(head) else {
            break;
        };
        let next = if tail.is_empty() {
            replacement.clone()
        } else {
            format!("{replacement}::{tail}")
        };
        if next == value {
            break;
        }
        value = next;
    }
    value
}
fn reject_raw_client_reference(path: &str) -> Result<()> {
    ensure!(path != "reqwest" && !raw(path), "raw HTTP client reference");
    Ok(())
}
fn reject_raw_client_reexport(path: &str) -> Result<()> {
    ensure!(!raw(path), "raw HTTP client re-export");
    Ok(())
}
fn reject_uninspectable_fetch_macro(name: &str) -> Result<()> {
    let allowed = [
        "anyhow",
        "anyhow::anyhow",
        "assert",
        "assert_eq",
        "assert_ne",
        "ensure",
        "env",
        "format",
        "format_args",
        "include_str",
        "matches",
        "panic",
        "println",
        "prop_assert_eq",
        "proptest",
        "proptest::prop_assert_eq",
        "proptest::proptest",
        "tokio::pin",
        "tokio::select",
        "tracing::debug",
        "tracing::error",
        "tracing::info",
        "vec",
    ];
    ensure!(allowed.contains(&name), "uninspectable fetch macro {name}");
    Ok(())
}
fn sensitive_header(name: &str) -> bool {
    ["authorization", "proxy-authorization", "cookie", "referer"].contains(&name)
}
fn bypass_setting(method: &str) -> bool {
    [
        "danger_accept_invalid_certs",
        "danger_accept_invalid_hostnames",
        "add_root_certificate",
        "use_preconfigured_tls",
        "cookie_store",
        "cookie_provider",
        "proxy",
        "basic_auth",
        "bearer_auth",
    ]
    .contains(&method)
}
struct Uses(Vec<(String, String, Span)>);
impl<'ast> Visit<'ast> for Uses {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        imports(&item.tree, "", &mut self.0);
    }
    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let syn::Type::Path(p) = item.ty.as_ref() {
            self.0
                .push((item.ident.to_string(), path_string(&p.path), item.span()));
        }
    }
}
struct Unit {
    path: PathBuf,
    module: String,
    syntax: syn::File,
    scoped: bool,
}
fn units(root: &Path) -> Result<Vec<Unit>> {
    let source = root.join("crates/core/src");
    ensure!(source.is_dir(), "crawler-user-agent: missing core source");
    let mut result = Vec::new();
    for entry in WalkDir::new(&source).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "crawler-user-agent: {}:1: source symlink",
                entry.path().display()
            );
        }
        if !entry.file_type().is_file() || entry.path().extension().is_none_or(|x| x != "rs") {
            continue;
        }
        let path = entry.path().strip_prefix(root)?.to_owned();
        let relative = entry.path().strip_prefix(&source)?.with_extension("");
        let mut names: Vec<_> = relative
            .iter()
            .map(|x| x.to_string_lossy().to_string())
            .collect();
        if names.last().is_some_and(|x| x == "mod" || x == "lib") {
            names.pop();
        }
        let module = format!("crate::{}", names.join("::"));
        let syntax = syn::parse_file(&fs::read_to_string(entry.path())?).with_context(|| {
            format!(
                "crawler-user-agent: {}:1: invalid Rust syntax",
                path.display()
            )
        })?;
        let scoped = path.starts_with("crates/core/src/crawler")
            || path.starts_with("crates/core/src/live_index/crawler");
        result.push(Unit {
            path,
            module,
            syntax,
            scoped,
        });
    }
    // Explicit path modules inherit the caller's transport boundary even outside the usual roots.
    for _ in 0..result.len() {
        let mut extra = Vec::new();
        struct Paths(Vec<String>);
        impl<'ast> Visit<'ast> for Paths {
            fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
                if a.path().is_ident("path") {
                    if let syn::Meta::NameValue(n) = &a.meta {
                        if let syn::Expr::Lit(l) = &n.value {
                            if let syn::Lit::Str(s) = &l.lit {
                                self.0.push(s.value());
                            }
                        }
                    }
                }
            }
        }
        for unit in result.iter().filter(|u| u.scoped) {
            let mut paths = Paths(Vec::new());
            paths.visit_file(&unit.syntax);
            for p in paths.0 {
                let path = root
                    .join(&unit.path)
                    .parent()
                    .unwrap()
                    .join(p)
                    .canonicalize()
                    .with_context(|| {
                        format!(
                            "crawler-user-agent: {}:1: unreadable path module",
                            unit.path.display()
                        )
                    })?;
                ensure!(
                    path.starts_with(source.canonicalize()?),
                    "crawler-user-agent: {}:1: path module escapes core source",
                    unit.path.display()
                );
                extra.push(path.strip_prefix(root.canonicalize()?)?.to_owned());
            }
        }
        let mut changed = false;
        for path in extra {
            let unit = result
                .iter_mut()
                .find(|u| u.path == path)
                .context("crawler-user-agent: path module was not inspected")?;
            if !unit.scoped {
                unit.scoped = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Ok(result)
}
fn aliases(unit: &Unit, exports: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut uses = Uses(Vec::new());
    uses.visit_file(&unit.syntax);
    let mut result = BTreeMap::new();
    for (name, value, _) in &uses.0 {
        if name != "*" {
            result.insert(name.clone(), value.clone());
        }
    }
    let original = result.clone();
    for _ in 0..32 {
        let old = result.clone();
        for (name, value) in &original {
            let value = resolve_import_alias(value, &old);
            let value = exports.get(&value).cloned().unwrap_or(value);
            result.insert(name.clone(), value);
        }
        if result == old {
            break;
        }
    }
    result
}
fn exports(units: &[Unit]) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for _ in 0..32 {
        let old = result.clone();
        for unit in units
            .iter()
            .filter(|u| !u.path.ends_with("crawler/identity.rs"))
        {
            let names = aliases(unit, &old);
            for (name, target) in &names {
                if raw(target) {
                    result.insert(format!("{}::{name}", unit.module), target.clone());
                }
            }
            for item in &unit.syntax.items {
                let name = match item {
                    Item::Struct(s) => Some(s.ident.to_string()),
                    Item::Fn(f) => Some(f.sig.ident.to_string()),
                    Item::Type(t) => Some(t.ident.to_string()),
                    _ => None,
                };
                if let Some(name) = name {
                    struct Raw<'a> {
                        names: &'a BTreeMap<String, String>,
                        found: bool,
                    }
                    impl<'ast> Visit<'ast> for Raw<'_> {
                        fn visit_path(&mut self, p: &'ast syn::Path) {
                            self.found |= raw(&resolve_import_alias(&path_string(p), self.names));
                            visit::visit_path(self, p);
                        }
                    }
                    let mut scan = Raw {
                        names: &names,
                        found: false,
                    };
                    scan.visit_item(item);
                    if scan.found {
                        result.insert(format!("{}::{name}", unit.module), "reqwest::Client".into());
                    }
                }
            }
        }
        if old == result {
            break;
        }
    }
    result
}
struct Scan<'a> {
    file: &'a Path,
    aliases: BTreeMap<String, String>,
    exports: &'a BTreeMap<String, String>,
    identity: bool,
    builder: bool,
    private_client_field: bool,
    test: bool,
    builders: usize,
    errors: Vec<String>,
}
impl Scan<'_> {
    fn error(&mut self, span: Span, error: impl std::fmt::Display) {
        self.errors.push(format!(
            "crawler-user-agent: {}:{}: {error}",
            self.file.display(),
            span.start().line
        ));
    }
    fn resolved(&self, path: &str) -> String {
        let path = resolve_import_alias(path, &self.aliases);
        self.exports.get(&path).cloned().unwrap_or(path)
    }
    fn check(&mut self, path: &str, span: Span) {
        let resolved = self.resolved(path);
        if self.identity
            && sensitive_header(
                &resolved
                    .rsplit("::")
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .replace('_', "-"),
            )
        {
            self.error(span, "crawler credential/cookie/referer header");
        }
        if self.identity && !raw(&resolved) {
            return;
        }
        if self.identity
            && ((self.builder && resolved == "reqwest::Client::builder")
                || (self.private_client_field && resolved == "reqwest::Client"))
        {
            return;
        }
        if let Err(error) = reject_raw_client_reference(&resolved) {
            self.error(span, error);
        }
    }
    fn tokens(&mut self, tokens: TokenStream) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        for (index, token) in tokens.iter().enumerate() {
            match token {
                TokenTree::Group(g) => self.tokens(g.stream()),
                TokenTree::Ident(id) => {
                    let mut path = id.to_string();
                    let mut i = index + 1;
                    while i + 2 < tokens.len()
                        && matches!(&tokens[i],TokenTree::Punct(p) if p.as_char()==':')
                        && matches!(&tokens[i+1],TokenTree::Punct(p) if p.as_char()==':')
                    {
                        let TokenTree::Ident(next) = &tokens[i + 2] else {
                            break;
                        };
                        path.push_str("::");
                        path.push_str(&next.to_string());
                        i += 3;
                    }
                    self.check(&path, id.span());
                }
                _ => {}
            }
        }
    }
}
impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        let name = path_string(attribute.path());
        if name == "derive" {
            let paths = attribute.parse_args_with(
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
            );
            match paths {
                Ok(paths) => {
                    for path in paths {
                        let name = path_string(&path);
                        if ![
                            "Debug",
                            "Clone",
                            "Copy",
                            "Default",
                            "PartialEq",
                            "Eq",
                            "PartialOrd",
                            "Ord",
                            "Hash",
                            "MaxSize",
                            "Serialize",
                            "Deserialize",
                            "serde::Serialize",
                            "serde::Deserialize",
                            "bincode::Encode",
                            "bincode::Decode",
                            "thiserror::Error",
                            "Error",
                        ]
                        .contains(&name.as_str())
                        {
                            if let Err(error) = reject_uninspectable_fetch_macro(&name) {
                                self.error(path.span(), error);
                            }
                        }
                    }
                }
                Err(error) => self.error(attribute.span(), error),
            }
        } else if ![
            "cfg",
            "doc",
            "deny",
            "repr",
            "path",
            "bincode",
            "serde",
            "default",
            "error",
            "from",
            "test",
            "tokio::test",
        ]
        .contains(&name.as_str())
        {
            if let Err(error) = reject_uninspectable_fetch_macro(&name) {
                self.error(attribute.span(), error);
            }
        }
    }
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if !self.identity && ident == "reqwest" {
            if let Err(error) = reject_raw_client_reference("reqwest") {
                self.error(ident.span(), error);
            }
        }
    }
    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        let old = self.test;
        self.test |= m.attrs.iter().any(|a| {
            a.path().is_ident("cfg") && a.meta.to_token_stream().to_string() == "cfg (test)"
        });
        visit::visit_item_mod(self, m);
        self.test = old;
    }
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        let old = self.builder;
        self.builder = self.identity && f.sig.ident == "build_http_client";
        if self.builder {
            self.builders += 1;
            if let Err(error) = inspect_builder(f) {
                self.error(f.span(), error);
            }
        }
        visit::visit_item_fn(self, f);
        self.builder = old;
    }
    fn visit_item_struct(&mut self, s: &'ast syn::ItemStruct) {
        let old = self.private_client_field;
        self.private_client_field = self.identity
            && s.ident == "HttpClient"
            && s.fields
                .iter()
                .all(|f| matches!(f.vis, syn::Visibility::Inherited));
        visit::visit_item_struct(self, s);
        self.private_client_field = old;
    }
    fn visit_path(&mut self, p: &'ast syn::Path) {
        self.check(&path_string(p), p.span());
        visit::visit_path(self, p);
    }
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        let mut entries = Vec::new();
        imports(&u.tree, "", &mut entries);
        for (name, target, span) in entries {
            if !self.identity && target.split("::").any(|part| part == "reqwest") {
                if let Err(error) = reject_raw_client_reference("reqwest") {
                    self.error(span, error);
                }
            }
            if name == "*" {
                let target = self.resolved(&target);
                // Existing Rayon/proptest preludes export iteration/test traits, never HTTP clients.
                if !(self.test && (target == "super" || target == "proptest::prelude"))
                    && !matches!(target.as_str(), "TdmReservation" | "rayon::prelude")
                {
                    self.error(span, "uninspectable glob import");
                }
            } else if !matches!(u.vis, syn::Visibility::Inherited) {
                if let Err(error) = reject_raw_client_reexport(&self.resolved(&target)) {
                    self.error(span, error);
                }
            } else {
                self.check(&target, span);
            }
        }
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let name = path_string(&m.path);
        if let Err(error) = reject_uninspectable_fetch_macro(&name) {
            self.error(m.span(), error);
        }
        self.tokens(m.tokens.clone());
    }
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        if matches!(
            m.method.to_string().as_str(),
            "header" | "insert" | "append"
        ) {
            if let Some(syn::Expr::Lit(value)) = m.args.first() {
                if let syn::Lit::Str(name) = &value.lit {
                    if sensitive_header(&name.value().to_ascii_lowercase()) {
                        self.error(m.span(), "crawler credential/cookie/referer header");
                    }
                }
            }
        }
        if bypass_setting(&m.method.to_string()) {
            self.error(m.span(), "crawler bypass setting");
        }
        visit::visit_expr_method_call(self, m);
    }
}
fn inspect_builder(f: &syn::ItemFn) -> Result<()> {
    struct Methods(BTreeMap<String, Vec<String>>);
    impl<'ast> Visit<'ast> for Methods {
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            self.0
                .entry(m.method.to_string())
                .or_default()
                .push(m.args.to_token_stream().to_string());
            visit::visit_expr_method_call(self, m);
        }
    }
    let mut methods = Methods(BTreeMap::new());
    methods.visit_block(&f.block);
    let fixed = [
        ("user_agent", "build_user_agent (identity) ?"),
        ("no_proxy", ""),
        ("referer", "false"),
        ("http1_only", ""),
        ("pool_max_idle_per_host", "0"),
        ("dns_resolver", "resolver"),
        ("redirect", "reqwest :: redirect :: Policy :: none ()"),
    ];
    for (name, argument) in fixed {
        ensure!(
            methods.0.get(name) == Some(&vec![argument.to_owned()]),
            "builder requires one fixed {name} assignment"
        );
    }
    ensure!(
        methods.0.keys().all(|name| !bypass_setting(name)),
        "builder bypass setting"
    );
    Ok(())
}
/// Inspects crawler sources, aliases and imported raw wrappers without compiling or making requests.
/// A valid tree has exactly one fixed builder; diagnostics name the guard, source file and line.
pub fn crawler_user_agent(root: &Path) -> Result<()> {
    let units = units(root)?;
    let exports = exports(&units);
    let mut count = 0;
    for unit in units.iter().filter(|u| u.scoped) {
        let mut scan = Scan {
            file: &unit.path,
            aliases: aliases(unit, &exports),
            exports: &exports,
            identity: unit.path == Path::new("crates/core/src/crawler/identity.rs"),
            builder: false,
            private_client_field: false,
            test: false,
            builders: 0,
            errors: Vec::new(),
        };
        scan.visit_file(&unit.syntax);
        count += scan.builders;
        if !scan.errors.is_empty() {
            bail!("{}", scan.errors.join("\n"));
        }
    }
    ensure!(
        count == 1,
        "crawler-user-agent: crates/core/src/crawler/identity.rs:1: expected exactly one builder"
    );
    println!(
        "crawler-user-agent: {} scoped Rust files passed",
        units.iter().filter(|u| u.scoped).count()
    );
    Ok(())
}

fn denied_dependency(name: &str, source: &str) -> bool {
    let value = format!("{name} {source}")
        .to_ascii_lowercase()
        .replace('_', "-");
    [
        "captcha",
        "recaptcha",
        "hcaptcha",
        "turnstile-solver",
        "2captcha",
        "anticaptcha",
        "anti-captcha",
        "capsolver",
        "proxy-rotation",
        "proxy-rotator",
        "rotating-proxy",
        "residential-proxy",
        "scraperapi",
        "scrapingbee",
        "brightdata",
        "bright-data",
        "oxylabs",
        "zenrows",
    ]
    .iter()
    .any(|pattern| value.contains(pattern))
}
fn dependency_tables(value: &toml::Value, in_dependencies: bool, errors: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) => {
            for (key, value) in table {
                if in_dependencies {
                    let package = value
                        .get("package")
                        .and_then(toml::Value::as_str)
                        .unwrap_or(key);
                    let source = value.get("git").and_then(toml::Value::as_str).unwrap_or("");
                    if denied_dependency(package, source) {
                        errors.push(format!("denied dependency {key}"));
                    }
                } else {
                    dependency_tables(
                        value,
                        matches!(
                            key.as_str(),
                            "dependencies" | "dev-dependencies" | "build-dependencies"
                        ),
                        errors,
                    );
                }
            }
        }
        toml::Value::Array(array) => {
            for value in array {
                dependency_tables(value, false, errors);
            }
        }
        _ => {}
    }
}
/// Parses workspace manifests and transitive lock packages, including renamed and git dependencies.
/// The deny list is a bounded regression guard; it does not certify unknown dependency intent.
pub fn crawler_dependency_deny(root: &Path) -> Result<()> {
    let mut count = 0;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            !matches!(
                e.file_name().to_str(),
                Some(".git" | ".spike" | "node_modules" | "target")
            )
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file()
            || !matches!(
                entry.file_name().to_str(),
                Some("Cargo.toml" | "Cargo.lock")
            )
        {
            continue;
        }
        let value: toml::Value = toml::from_str(&fs::read_to_string(entry.path())?)?;
        let mut errors = Vec::new();
        if entry.file_name() == "Cargo.lock" {
            for package in value
                .get("package")
                .and_then(toml::Value::as_array)
                .context("crawler-dependency-deny: lock packages missing")?
            {
                let name = package
                    .get("name")
                    .and_then(toml::Value::as_str)
                    .context("lock package name")?;
                let source = package
                    .get("source")
                    .and_then(toml::Value::as_str)
                    .unwrap_or("");
                if denied_dependency(name, source) {
                    errors.push(format!("denied lock package {name}"));
                }
            }
        } else {
            dependency_tables(&value, false, &mut errors);
        }
        ensure!(
            errors.is_empty(),
            "crawler-dependency-deny: {}: {}",
            entry.path().display(),
            errors.join("; ")
        );
        count += 1;
    }
    ensure!(
        count >= 2,
        "crawler-dependency-deny: manifests/lock missing"
    );
    println!("crawler-dependency-deny: {count} manifests/locks passed");
    Ok(())
}
/// Requires exactly twelve labelled, nonempty sections and returns IDs containing founder placeholders.
/// Placeholders count as visible content, never as evidence of legal adequacy.
pub fn policy_sections(text: &str) -> Result<Vec<String>> {
    let mut sections = BTreeMap::<String, String>::new();
    let mut current = None;
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            let id = heading
                .split_whitespace()
                .next()
                .context("empty policy section")?
                .to_owned();
            ensure!(
                sections.insert(id.clone(), String::new()).is_none(),
                "crawler-policy-check: duplicate {id}"
            );
            current = Some(id);
        } else if let Some(id) = &current {
            sections.get_mut(id).unwrap().push_str(line);
            sections.get_mut(id).unwrap().push('\n');
        }
    }
    let required_sections: Vec<_> = (1..=12).map(|n| format!("P{n:02}")).collect();
    ensure!(
        sections.len() == 12
            && required_sections
                .iter()
                .all(|id| sections.get(id).is_some_and(|body| !body.trim().is_empty())),
        "crawler-policy-check: twelve nonempty P01..P12 sections required"
    );
    Ok(sections
        .into_iter()
        .filter_map(|(id, body)| body.contains("[FOUNDER REQUIRED:").then_some(id))
        .collect())
}
/// Checks a local rendered policy file and prints all pending founder section IDs.
pub fn crawler_policy_check(file: &Path) -> Result<()> {
    let pending = policy_sections(&fs::read_to_string(file)?)?;
    println!(
        "crawler-policy-check: {} passed; founder placeholders: {}",
        file.display(),
        pending.join(", ")
    );
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git").current_dir(root).args(args).output()?;
    ensure!(
        output.status.success(),
        "strict-clippy-touched: git {args:?} failed"
    );
    Ok(output.stdout)
}
/// Parses NUL-delimited Git paths losslessly as UTF-8 and unions them with earlier observations.
/// Invalid encodings or absolute/parent paths fail closed rather than dropping touched files.
pub fn add_changed_paths(paths: &mut BTreeSet<String>, bytes: &[u8]) -> Result<()> {
    for path in bytes.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let path = std::str::from_utf8(path)?.to_owned();
        ensure!(
            !Path::new(&path).is_absolute()
                && Path::new(&path)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "strict-clippy-touched: invalid changed path"
        );
        paths.insert(path);
    }
    Ok(())
}
/// Unions every commit after base, staged/unstaged changes and untracked files.
/// Default base is merge-base with origin/main when different from HEAD, otherwise HEAD~1.
pub fn changed_files(root: &Path, base: Option<&str>) -> Result<BTreeSet<String>> {
    let head = String::from_utf8(git(root, &["rev-parse", "HEAD"])?)?
        .trim()
        .to_owned();
    let base = match base {
        Some(base) => String::from_utf8(git(
            root,
            &["rev-parse", "--verify", &format!("{base}^{{commit}}")],
        )?)?
        .trim()
        .to_owned(),
        None => {
            let merged = git(root, &["merge-base", "HEAD", "origin/main"])
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .map(|s| s.trim().to_owned());
            match merged {
                Some(value) if value != head => value,
                _ => String::from_utf8(git(root, &["rev-parse", "HEAD~1"])?)?
                    .trim()
                    .to_owned(),
            }
        }
    };
    println!("strict-clippy-touched: base={base} HEAD={head}");
    let mut paths = BTreeSet::new();
    for revision in String::from_utf8(git(root, &["rev-list", &format!("{base}..HEAD")])?)?.lines()
    {
        add_changed_paths(
            &mut paths,
            &git(
                root,
                &[
                    "diff-tree",
                    "--root",
                    "-m",
                    "--no-commit-id",
                    "--name-only",
                    "--no-renames",
                    "-r",
                    "-z",
                    revision,
                ],
            )?,
        )?;
    }
    for args in [
        vec!["diff", "--name-only", "--no-renames", "-z"],
        vec!["diff", "--cached", "--name-only", "--no-renames", "-z"],
        vec!["ls-files", "--others", "--exclude-standard", "-z"],
    ] {
        add_changed_paths(&mut paths, &git(root, &args)?)?;
    }
    Ok(paths)
}
fn diagnostic_touches_changed_file(span: &Value, changed: &BTreeSet<String>) -> bool {
    let path = span.get("file_name").and_then(Value::as_str).unwrap_or("");
    let root = crate::repository_root()
        .canonicalize()
        .unwrap_or_else(|_| crate::repository_root());
    let relative = Path::new(path)
        .strip_prefix(&root)
        .unwrap_or(Path::new(path))
        .to_string_lossy();
    changed.contains(relative.as_ref())
        || span
            .get("expansion")
            .and_then(|e| e.get("span"))
            .is_some_and(|s| diagnostic_touches_changed_file(s, changed))
}
fn target_key(value: &Value) -> Option<String> {
    let package = value.get("package_id")?.as_str()?;
    let (source, fragment) = package.rsplit_once('#')?;
    let package = fragment
        .split_once('@')
        .map(|(name, _)| name)
        .or_else(|| source.rsplit('/').next())?;
    let name = value.get("target")?.get("name")?.as_str()?;
    let kinds = value["target"]["kind"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(",");
    Some(format!("{package}:{kinds}:{name}"))
}
/// Inspects preserved Cargo JSON and returns targets observed through artifacts or diagnostics.
/// A failed compiler is accepted only with explicit enumerated inherited lint causes on untouched
/// files; malformed JSON, unexpected errors, missing-doc or touched spans always fail.
pub fn inspect_diagnostics(
    output: &str,
    success: bool,
    changed: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    let mut inherited = 0;
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let value: Value =
            serde_json::from_str(line).context("strict-clippy-touched: malformed Cargo JSON")?;
        let reason = value["reason"]
            .as_str()
            .context("strict-clippy-touched: missing Cargo reason")?;
        if matches!(reason, "compiler-artifact" | "compiler-message") {
            if let Some(key) = target_key(&value) {
                targets.insert(key);
            }
        }
        if reason != "compiler-message" {
            continue;
        }
        let message = &value["message"];
        let level = message["level"].as_str().context("diagnostic level")?;
        if !matches!(level, "warning" | "error") {
            continue;
        }
        let spans = message["spans"].as_array().context("diagnostic spans")?;
        ensure!(
            !spans
                .iter()
                .any(|s| diagnostic_touches_changed_file(s, changed)),
            "strict-clippy-touched: touched diagnostic: {message}"
        );
        let code = message["code"]["code"].as_str().unwrap_or("");
        let code = code
            .strip_prefix("clippy::")
            .map(|c| format!("clippy::{c}"))
            .unwrap_or_else(|| code.to_owned());
        if crate::ci::INHERITED_LINTS.contains(&code.as_str()) && !spans.is_empty() {
            inherited += 1;
            println!(
                "strict-clippy-touched: inherited {code}: {}",
                spans[0]["file_name"]
            );
        } else {
            bail!("strict-clippy-touched: unexpected diagnostic: {message}");
        }
    }
    ensure!(
        success || inherited > 0,
        "strict-clippy-touched: compiler failed without enumerated inherited diagnostics"
    );
    Ok(targets)
}
/// Requires evidence for every touched package target; empty or partial coverage fails closed.
pub fn ensure_coverage(required: &BTreeSet<String>, observed: &BTreeSet<String>) -> Result<()> {
    let missing: Vec<_> = required.difference(observed).collect();
    ensure!(
        missing.is_empty(),
        "strict-clippy-touched: targets not linted: {missing:?}"
    );
    Ok(())
}
fn clippy_run(
    root: &Path,
    args: &[&str],
    out: &Path,
    changed: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    println!(
        "strict-clippy-touched: cargo {args:?}; evidence {}",
        out.display()
    );
    let result = Command::new("cargo")
        .current_dir(root)
        .args(args)
        .output()?;
    fs::write(out.with_extension("jsonl"), &result.stdout)?;
    fs::write(out.with_extension("stderr"), &result.stderr)?;
    let mut log = fs::File::create(out.with_extension("log"))?;
    writeln!(log, "COMMAND cargo {args:?}\nCWD {}", root.display())?;
    log.write_all(&result.stdout)?;
    log.write_all(&result.stderr)?;
    writeln!(log, "\nEXIT {}", result.status.code().unwrap_or(128))?;
    ensure!(
        matches!(result.status.code(), Some(0 | 101)),
        "strict-clippy-touched: unexpected compiler termination"
    );
    inspect_diagnostics(
        std::str::from_utf8(&result.stdout)?,
        result.status.success(),
        changed,
    )
}
/// Runs strict Clippy without inherited allowances and retains raw JSON, stderr and command logs.
/// Separate touched-package invocations exclude dependency linting and must cover every target.
/// If inherited errors in a package's own library block its other targets, an additional pass caps
/// lint severity at warning solely to finish coverage. Every warning still passes the same rejection
/// rules; no allow flag suppresses diagnostics and compiler/type errors remain fatal.
pub fn strict_clippy_touched(base: Option<&str>) -> Result<()> {
    let root = crate::repository_root().canonicalize()?;
    let changed = changed_files(&root, base)?;
    ensure_ingestion_ci_wiring(&fs::read_to_string(root.join("crates/xtask/src/ci.rs"))?)?;
    let metadata = Command::new("cargo")
        .current_dir(&root)
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .output()?;
    ensure!(
        metadata.status.success(),
        "strict-clippy-touched: cargo metadata failed"
    );
    let metadata: Value = serde_json::from_slice(&metadata.stdout)?;
    let mut packages = BTreeMap::<String, BTreeSet<String>>::new();
    for package in metadata["packages"]
        .as_array()
        .context("metadata packages")?
    {
        let manifest = Path::new(
            package["manifest_path"]
                .as_str()
                .context("package manifest")?,
        );
        let directory = manifest
            .parent()
            .context("manifest directory")?
            .strip_prefix(&root)?;
        if !changed.iter().any(|p| Path::new(p).starts_with(directory)) {
            continue;
        }
        let name = package["name"].as_str().context("package name")?.to_owned();
        for target in package["targets"].as_array().context("package targets")? {
            if target
                .get("required-features")
                .and_then(Value::as_array)
                .is_some_and(|features| !features.is_empty())
            {
                continue;
            }
            let kinds = target["kind"]
                .as_array()
                .context("target kind")?
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",");
            if kinds == "custom-build" {
                continue;
            }
            packages.entry(name.clone()).or_default().insert(format!(
                "{name}:{kinds}:{}",
                target["name"].as_str().context("target name")?
            ));
        }
    }
    let evidence = crate::external_env("STORY584_ARTIFACT_DIR")?.join(format!(
        "strict-clippy-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir_all(&evidence)?;
    fs::write(
        evidence.join("changed-files.json"),
        serde_json::to_vec_pretty(&changed)?,
    )?;
    let workspace = clippy_run(
        &root,
        &[
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--message-format=json",
            "--",
            "-D",
            "warnings",
        ],
        &evidence.join("workspace"),
        &changed,
    );
    let mut errors = Vec::new();
    if let Err(error) = workspace {
        errors.push(error.to_string());
    }
    for (package, required) in packages {
        let args = [
            "clippy",
            "--locked",
            "-p",
            &package,
            "--all-targets",
            "--no-deps",
            "--message-format=json",
            "--",
            "-D",
            "warnings",
        ];
        match clippy_run(&root, &args, &evidence.join(&package), &changed) {
            Ok(observed) => {
                if ensure_coverage(&required, &observed).is_err() {
                    let mut coverage_args = args.to_vec();
                    coverage_args.extend(["--cap-lints", "warn"]);
                    match clippy_run(
                        &root,
                        &coverage_args,
                        &evidence.join(format!("{package}-coverage")),
                        &changed,
                    ) {
                        Ok(covered) => {
                            if let Err(error) = ensure_coverage(&required, &covered) {
                                errors.push(error.to_string());
                            }
                        }
                        Err(error) => errors.push(error.to_string()),
                    }
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    println!(
        "strict-clippy-touched: all touched targets verified; raw evidence {}",
        evidence.display()
    );
    Ok(())
}

/// Parses actual CI function bodies and verifies ingestion guards and strict lint placement.
/// Comments and string-only mentions cannot satisfy the wiring contract; no baseline SHA is pinned.
pub fn ensure_ingestion_ci_wiring(source: &str) -> Result<()> {
    let syntax = syn::parse_file(source)?;
    let function = |name: &str| {
        syntax
            .items
            .iter()
            .find_map(|item| match item {
                Item::Fn(f) if f.sig.ident == name => Some(f),
                _ => None,
            })
            .with_context(|| format!("ingestion-ci-wiring: missing {name}"))
    };
    let body = |name: &str| -> Result<Vec<String>> {
        Ok(function(name)?
            .block
            .stmts
            .iter()
            .map(|s| s.to_token_stream().to_string())
            .collect())
    };
    let all = body("ci_all")?;
    let find = |needle: &str| -> Result<usize> {
        let matches: Vec<_> = all
            .iter()
            .enumerate()
            .filter(|(_, s)| s.contains(needle))
            .map(|(n, _)| n)
            .collect();
        ensure!(
            matches.len() == 1,
            "ingestion-ci-wiring: expected one {needle}"
        );
        Ok(matches[0])
    };
    let positions = [
        find("\"guards\"")?,
        find("crate :: ingestion :: crawler_user_agent (& root) ?")?,
        find("crate :: ingestion :: crawler_dependency_deny (& root) ?")?,
        find(
            "crate :: ingestion :: crawler_policy_check (& root . join (\"CRAWLER_POLICY.md\")) ?",
        )?,
        find("\"ingestion_guards\"")?,
        find("source_offer () ?")?,
        find("check () ?")?,
    ];
    ensure!(
        positions.windows(2).all(|w| w[1] == w[0] + 1),
        "ingestion-ci-wiring: guard order changed"
    );
    let check = body("check")?;
    ensure!(
        check.len() >= 3
            && check[check.len() - 2] == "crate :: ingestion :: strict_clippy_touched (None) ? ;",
        "ingestion-ci-wiring: strict Clippy must finish check without a fixed base"
    );
    ensure!(
        check[..check.len() - 2]
            .iter()
            .any(|s| s.contains("\"npm\"") && s.contains("\"lint\"")),
        "ingestion-ci-wiring: frontend checks missing"
    );
    Ok(())
}
