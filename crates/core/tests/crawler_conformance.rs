//! Exercises the production library fetch path using only owned loopback HTTP fixtures.
//! No test permits arbitrary private addresses or contacts public DNS/HTTP services.
//! Ledger/storage witnesses extend these same fixtures, rather than constructing outcomes by hand.

#[path = "support/crawler_fixture.rs"]
mod crawler_fixture;
use crawler_fixture::{Fixture, Reply};
use stract::crawler::{network::HostKey, Error};

async fn expect_page(reply: Reply, kind: &str) -> stract::crawler::record::DocumentRecord {
    let fixture = Fixture::new();
    fixture.reply("/page", reply);
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), kind);
    let disk =
        stract::crawler::ledger::Ledger::read_rows(&fixture.root.join("ledger.jsonl")).unwrap();
    assert_eq!(disk.len(), 1);
    assert_eq!(disk[0].target_id, row.target_id);
    assert_eq!(disk[0].outcome.kind(), kind);
    let record = row.record;
    fixture.finish().await;
    record
}
async fn ticking_crawl(
    fixture: &Fixture,
    clock: &stract::crawler::politeness::ManualClock,
    path: &str,
) -> stract::crawler::ledger::LedgerRow {
    let crawl = fixture.crawl(path);
    tokio::pin!(crawl);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            tokio::select! {
                biased;
                result = &mut crawl => return result.unwrap(),
                _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => clock.advance(501).unwrap(),
            }
        }
    }).await.expect("manual-clock fixture completed")
}
macro_rules! page_outcome {
    ($name:ident, $reply:expr, $kind:literal) => {
        #[tokio::test]
        async fn $name() {
            expect_page($reply, $kind).await;
        }
    };
}
page_outcome!(
    outcome_saved_noindex,
    Reply::html("<title>Private index</title>").header("X-Robots-Tag", "noindex"),
    "saved-noindex"
);
page_outcome!(
    outcome_redirected_off_seed,
    Reply::new(302, "").header("Location", "http://outside.invalid/path"),
    "redirected-off-seed"
);
page_outcome!(
    outcome_redirect_invalid,
    Reply::new(301, ""),
    "redirect-invalid"
);
page_outcome!(
    outcome_invalid_content_type,
    Reply::new(200, "untyped"),
    "invalid-content-type"
);
page_outcome!(
    outcome_http_status,
    Reply::new(500, "upstream unavailable"),
    "http-status"
);
page_outcome!(outcome_gone, Reply::new(410, "removed"), "gone");
page_outcome!(outcome_empty_body, Reply::html(""), "empty-body");
page_outcome!(
    outcome_parsed_not_retained,
    Reply::html("<title>Reserved</title>").header("TDM-Reservation", "1"),
    "parsed-not-retained"
);
page_outcome!(
    outcome_body_read_failed,
    {
        let mut r = Reply::html("partial");
        r.declared_length = Some(500);
        r
    },
    "body-read-failed"
);
page_outcome!(
    outcome_content_too_large,
    {
        let mut r = Reply::html("too large");
        r.declared_length = Some(stract::crawler::MAX_CONTENT_LENGTH + 1);
        r
    },
    "content-too-large"
);
page_outcome!(
    outcome_timeout,
    {
        let mut r = Reply::html("slow");
        r.body_delay = std::time::Duration::from_secs(3);
        r
    },
    "timeout"
);

macro_rules! raw_outcome {
    ($name:ident, $raw:expr, $kind:literal) => {
        #[tokio::test]
        async fn $name() {
            let fixture = Fixture::new();
            let raw: String = $raw;
            let (row, _) = fixture.crawl_raw(&raw).await.unwrap();
            assert_eq!(row.outcome.kind(), $kind);
            assert!(row.fetch_attempts.is_empty());
            assert_eq!(fixture.requests.lock().unwrap().len(), 0);
            assert_eq!(fixture.client.ledger().rows().unwrap().len(), 1);
            fixture.finish().await;
        }
    };
}
raw_outcome!(outcome_invalid_url, "not a URL".into(), "invalid-url");
raw_outcome!(
    outcome_url_too_long,
    format!("http://a.fixture.invalid/{}", "a".repeat(8192)),
    "url-too-long"
);
raw_outcome!(
    outcome_scheme_refused,
    "ftp://a.fixture.invalid/page".into(),
    "scheme-refused"
);
raw_outcome!(
    outcome_port_refused,
    "http://a.fixture.invalid:1/page".into(),
    "port-refused"
);
raw_outcome!(
    outcome_refused_private_address,
    "http://127.0.0.1/page".into(),
    "refused-private-address"
);
raw_outcome!(
    outcome_ignored_extension,
    "http://a.fixture.invalid/image.PDF".into(),
    "ignored-extension"
);

macro_rules! robots_outcome {
    ($name:ident, $reply:expr, $kind:literal) => {
        #[tokio::test]
        async fn $name() {
            let fixture = Fixture::new();
            fixture.reply("/robots.txt", $reply);
            let row = fixture.crawl("/page").await.unwrap();
            assert_eq!(row.outcome.kind(), $kind);
            assert_eq!(fixture.requests.lock().unwrap().len(), 1);
            assert_eq!(row.fetch_attempts.len(), 1);
            assert!(row.body_object.is_none());
            fixture.finish().await;
        }
    };
}
robots_outcome!(
    outcome_robots_disallowed,
    Reply::new(200, "User-agent: *\nDisallow: /"),
    "robots-disallowed"
);
robots_outcome!(
    outcome_robots_unreachable,
    Reply::new(500, "Unavailable"),
    "robots-unreachable"
);
robots_outcome!(
    outcome_crawl_delay_exceeds_ceiling,
    Reply::new(200, "User-agent: *\nCrawl-delay: 61"),
    "crawl-delay-exceeds-ceiling"
);
robots_outcome!(
    outcome_host_blocked,
    Reply::new(403, "Forbidden"),
    "host-blocked"
);

#[tokio::test]
async fn outcome_tls_error() {
    let fixture = Fixture::new();
    let mut url = fixture.url("a.fixture.invalid", "/page");
    url.set_scheme("https").unwrap();
    let (row, _) = fixture.crawl_raw(url.as_str()).await.unwrap();
    assert_eq!(row.outcome.kind(), "tls-error");
    assert_eq!(row.fetch_attempts.len(), 1);
    assert_eq!(
        row.fetch_attempts[0].error,
        Some(stract::crawler::ledger::WireError::Tls)
    );
    assert!(row.record.http_status.is_none());
    fixture.finish().await;
}
#[tokio::test]
async fn outcome_connect_error() {
    let fixture = Fixture::with_resolver(
        manual_policy(),
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
        Some(std::sync::Arc::new(Answers::new(vec![vec![]]))),
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "connect-error");
    assert!(row.fetch_attempts.is_empty());
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}
#[tokio::test]
async fn outcome_already_crawled() {
    let fixture = Fixture::new();
    fixture.crawl("/page").await.unwrap();
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "already-crawled");
    assert!(row.fetch_attempts.is_empty());
    assert_eq!(fixture.client.ledger().rows().unwrap().len(), 2);
    fixture.finish().await;
}
#[tokio::test]
async fn outcome_domain_mismatch() {
    let fixture = Fixture::new();
    let rows = fixture
        .crawl_inputs(
            &[fixture.url("a.fixture.invalid", "/page").into()],
            stract::crawler::Domain::from("unrelated.invalid".to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(rows[0].0.outcome.kind(), "domain-mismatch");
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}
#[tokio::test]
async fn outcome_cancelled() {
    let fixture = Fixture::new();
    fixture.client.cancel();
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "cancelled");
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}
#[tokio::test]
async fn outcome_internal_error() {
    let fixture = Fixture::new();
    let path = fixture.root.join("host-state.json");
    if path.is_file() {
        std::fs::rename(&path, fixture.root.join("host-state.saved")).unwrap();
    }
    std::fs::create_dir(path).unwrap();
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "internal-error");
    assert!(row.fatal);
    fixture.finish().await;
}

macro_rules! flag_directive {
    ($name:ident, $flag:ident, $directive:literal) => {
        #[tokio::test]
        async fn $name() {
            for reply in [
                Reply::html("<title>Header</title>").header("X-Robots-Tag", $directive),
                Reply::html(&format!(
                    "<title>Meta</title><meta name='RoBoTs' content='{}'>",
                    $directive
                )),
            ] {
                let record = expect_page(reply, "saved").await;
                assert!(record.directives.$flag);
            }
        }
    };
}
flag_directive!(directive_nofollow, nofollow, "NoFollow");
flag_directive!(directive_noarchive, noarchive, "NoArchive");
flag_directive!(directive_nosnippet, nosnippet, "NoSnippet");
flag_directive!(directive_noimageindex, noimageindex, "NoImageIndex");
#[tokio::test]
async fn directive_max_snippet() {
    let record = expect_page(
        Reply::html("<title>Snippet</title>").header("X-Robots-Tag", "max-snippet: 17"),
        "saved",
    )
    .await;
    assert_eq!(record.directives.max_snippet, Some(17));
    assert_eq!(record.snippet_limit_chars, 17);
}
#[tokio::test]
async fn directive_unavailable_after() {
    let record = expect_page(
        Reply::html("<title>Expired</title>").header(
            "X-Robots-Tag",
            "unavailable_after: Wed, 01 Jan 2020 00:00:00 GMT",
        ),
        "saved-noindex",
    )
    .await;
    assert!(record.directives.unavailable_after_utc.is_some());
    assert!(!record.index_eligible);
}
#[tokio::test]
async fn directive_header_scope() {
    let record = expect_page(
        Reply::html("<title>Scoped</title>")
            .header("X-Robots-Tag", "OtherBot: noindex, nosnippet")
            .header("X-Robots-Tag", "AVASearchBot: nofollow")
            .header("X-Robots-Tag", "noarchive"),
        "saved",
    )
    .await;
    assert!(!record.directives.noindex && !record.directives.nosnippet);
    assert!(record.directives.nofollow && record.directives.noarchive);
    assert_eq!(record.directives_seen.len(), 4);
}
#[tokio::test]
async fn nofollow_effect() {
    let fixture = Fixture::new();
    fixture.reply("/page", Reply::html("<title>Links</title><a href='/next'>next</a><link rel='canonical' href='/canonical?q=1'>").header("X-Robots-Tag", "nofollow"));
    let (row, links) = fixture
        .crawl_raw(fixture.url("a.fixture.invalid", "/page").as_str())
        .await
        .unwrap();
    assert!(links.is_empty());
    assert!(row
        .record
        .rel_canonical
        .value()
        .unwrap()
        .as_str()
        .ends_with("/canonical?q=1"));
    fixture.finish().await;
}
#[tokio::test]
async fn rights_license() {
    let record = expect_page(Reply::html("<title>Licence</title><link rel='alternate LICENSE' href='/licence?grant=1'><a rel='license' href='/licence?grant=2'>terms</a>"), "parsed-not-retained").await;
    assert!(record.rights.license_present && record.index_only);
    assert_eq!(record.rights.license_urls.len(), 2);
    assert!(record.rights.license_urls[0].as_str().contains("grant=1"));
    assert_eq!(record.retained_body_bytes, 0);
}
#[tokio::test]
async fn rights_header() {
    let record = expect_page(
        Reply::html("<title>Header reservation</title>").header("TDM-Reservation", "1"),
        "parsed-not-retained",
    )
    .await;
    assert!(record.rights.index_only());
    assert_eq!(record.retained_body_bytes, 0);
}
#[tokio::test]
async fn rights_meta() {
    let record = expect_page(
        Reply::html("<title>Meta reservation</title><meta name='tdm-reservation' content='1'>"),
        "parsed-not-retained",
    )
    .await;
    assert!(record.rights.index_only());
    assert_eq!(record.retained_body_bytes, 0);
}
#[tokio::test]
async fn rights_policy() {
    let record = expect_page(
        Reply::html("<title>Policy</title><meta name='tdm-policy' content='/terms?version=1'>"),
        "parsed-not-retained",
    )
    .await;
    assert!(record.rights.index_only());
    assert_eq!(record.rights.tdm_policy_urls.len(), 1);
}
#[tokio::test]
async fn oversize_chunked() {
    let mut reply = Reply::new(200, vec![b' '; stract::crawler::MAX_CONTENT_LENGTH + 1]);
    reply.chunked = true;
    let record = expect_page(reply, "content-too-large").await;
    assert!(record.body_bytes.value().unwrap() > &(stract::crawler::MAX_CONTENT_LENGTH as u64));
    assert!(record.content_sha256.is_none());
}

async fn redirect_chain(length: usize, cycle: bool) -> Vec<stract::crawler::ledger::LedgerRow> {
    let fixture = Fixture::new();
    let urls: Vec<_> = (0..length)
        .map(|n| fixture.url("a.fixture.invalid", &format!("/r{n}")))
        .collect();
    for (n, url) in urls.iter().enumerate() {
        if n + 1 < length || cycle {
            fixture.reply(
                url.path(),
                Reply::new(302, "").header("Location", urls[(n + 1) % length].as_str()),
            );
        }
    }
    let rows = fixture
        .crawl_inputs(
            &urls
                .iter()
                .map(|u| u.as_str().to_owned())
                .collect::<Vec<_>>(),
            stract::crawler::Domain::from(&urls[0]),
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), length);
    assert_eq!(fixture.requests.lock().unwrap().len(), length + 1);
    let result: Vec<_> = rows.into_iter().map(|(row, _)| row).collect();
    assert_eq!(
        stract::crawler::ledger::Ledger::read_rows(&fixture.root.join("ledger.jsonl"))
            .unwrap()
            .len(),
        length
    );
    fixture.finish().await;
    result
}
#[tokio::test]
async fn outcome_redirected_to_seed() {
    let rows = redirect_chain(2, false).await;
    assert_eq!(rows[0].outcome.kind(), "redirected-to-seed");
    assert_eq!(
        rows[0].destination_target_id.as_ref(),
        Some(&rows[1].target_id)
    );
    assert_ne!(rows[0].record.final_url, rows[1].record.final_url);
    assert_eq!(rows[1].outcome.kind(), "saved");
}
#[tokio::test]
async fn outcome_redirect_loop() {
    let rows = redirect_chain(2, true).await;
    assert_eq!(rows[1].outcome.kind(), "redirect-loop");
    assert!(rows.iter().all(|row| row.body_object.is_none()));
}
#[tokio::test]
async fn outcome_redirect_limit() {
    let rows = redirect_chain(12, false).await;
    assert_eq!(rows[10].outcome.kind(), "redirect-limit");
    assert!(rows[..11].iter().all(|row| row.body_object.is_none()));
}
#[tokio::test]
async fn redirect_statuses() {
    for status in [301, 302, 303, 307, 308] {
        let fixture = Fixture::new();
        fixture.reply("/start", Reply::new(status, "").header("Location", "/end"));
        let rows = fixture
            .crawl_inputs(
                &[
                    fixture.url("a.fixture.invalid", "/start").into(),
                    fixture.url("a.fixture.invalid", "/end").into(),
                ],
                stract::crawler::Domain::from(fixture.url("a.fixture.invalid", "/")),
            )
            .await
            .unwrap();
        assert_eq!(rows[0].0.outcome.kind(), "redirected-to-seed");
        assert_eq!(rows[0].0.record.http_status.value(), Some(&status));
        assert!(rows[0].0.body_object.is_none());
        fixture.finish().await;
    }
}
#[tokio::test]
async fn redirect_scope() {
    let fixture = Fixture::new();
    fixture.reply(
        "/start",
        Reply::new(302, "").header("Location", "/unselected"),
    );
    let row = fixture.crawl("/start").await.unwrap();
    assert_eq!(row.outcome.kind(), "redirected-off-seed");
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    assert!(row
        .record
        .final_url
        .value()
        .unwrap()
        .as_str()
        .ends_with("/start"));
    fixture.finish().await;
}
#[tokio::test]
async fn mime_matrix() {
    for mime in [
        "text/html",
        "application/xhtml+xml",
        "TEXT/HTML; charset=UTF-8",
        "text/html; charset=unknown-fixture",
    ] {
        let record = expect_page(
            Reply::new(200, "<title>MIME</title>").header("Content-Type", mime),
            "saved",
        )
        .await;
        assert_eq!(record.charset_fallback, mime.ends_with("unknown-fixture"));
    }
    for mime in [
        "text/plain",
        "text/htmlish",
        "application/rss+xml",
        "text/html; charset",
        "",
    ] {
        expect_page(
            Reply::new(200, "<title>MIME</title>").header("Content-Type", mime),
            "invalid-content-type",
        )
        .await;
    }
    expect_page(
        Reply::html("<title>MIME</title>").header("Content-Type", "text/plain"),
        "invalid-content-type",
    )
    .await;
}
#[tokio::test]
async fn http_validators() {
    let mut fixture = Fixture::new();
    fixture.reply(
        "/page",
        Reply::html("<title>Conditional</title>")
            .header("ETag", "\"exact-v1\"")
            .header("Last-Modified", "Fri, 11 Sep 2026 12:00:00 GMT"),
    );
    fixture.crawl("/page").await.unwrap();
    fixture.restart().await;
    fixture.reply("/page", Reply::new(304, ""));
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "not-modified");
    let requests = fixture.requests.lock().unwrap().clone();
    let conditional = requests.last().unwrap();
    assert_eq!(
        conditional.headers.get("if-none-match").map(String::as_str),
        Some("\"exact-v1\"")
    );
    assert_eq!(
        conditional
            .headers
            .get("if-modified-since")
            .map(String::as_str),
        Some("Fri, 11 Sep 2026 12:00:00 GMT")
    );
    assert_eq!(
        row.fetch_attempts.last().unwrap().kind,
        stract::crawler::ledger::FetchKind::Conditional
    );
    fixture.finish().await;
    let invalid = expect_page(
        Reply::html("<title>Bounds</title>")
            .header("ETag", &"x".repeat(1025))
            .header("Last-Modified", "one")
            .header("Last-Modified", "two"),
        "saved",
    )
    .await;
    assert!(invalid.validators.etag.is_none() && invalid.validators.last_modified.is_none());
}
#[tokio::test]
async fn outcome_not_modified() {
    let mut fixture = Fixture::new();
    fixture.crawl("/page").await.unwrap();
    fixture.restart().await;
    fixture.reply("/page", Reply::new(304, ""));
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "not-modified");
    fixture.finish().await;
}
#[tokio::test]
async fn http_gone() {
    for status in [404, 410] {
        let mut fixture = Fixture::new();
        let first = fixture.crawl("/page").await.unwrap();
        let object = fixture.root.join(first.body_object.unwrap());
        fixture.restart().await;
        fixture.reply("/page", Reply::new(status, "gone"));
        let row = fixture.crawl("/page").await.unwrap();
        assert_eq!(row.outcome.kind(), "gone");
        assert!(!object.exists());
        let tombstone = row.record.tombstone.unwrap();
        assert_eq!(
            tombstone.scope,
            stract::crawler::record::TombstoneScope::Url
        );
        assert_eq!(
            (tombstone.delete_due_at_utc - tombstone.observed_at_utc).num_hours(),
            24
        );
        fixture.finish().await;
    }
}
#[tokio::test]
async fn record_contract() {
    use stract::crawler::record::{AbsenceReason, Observation};
    let fixture = Fixture::new();
    let url = fixture.url("a.fixture.invalid", "/page?exact=1");
    fixture.reply("/page?exact=1", Reply::html("<html lang='en-GB'><title>Σ title</title><meta property='og:site_name' content='Publisher'><link rel='canonical' href='/canonical?q=2'></html>"));
    let (row, _) = fixture.crawl_raw(url.as_str()).await.unwrap();
    let record = row.record;
    record.validate().unwrap();
    assert_eq!(record.requested_url.value().unwrap().as_str(), url.as_str());
    assert!(record
        .canonical_url
        .value()
        .unwrap()
        .as_str()
        .ends_with("/canonical?q=2"));
    assert_eq!(
        record.publisher_name.value().map(String::as_str),
        Some("Publisher")
    );
    assert_eq!(
        record.declared_language.value().map(String::as_str),
        Some("en-gb")
    );
    assert_eq!(record.title.value().map(String::as_str), Some("Σ title"));
    assert!(record.robots.value().unwrap().body_sha256.value().is_some());
    let mut invalid = record.clone();
    invalid.fetch_time_ms = Observation::absent(AbsenceReason::NotAttempted);
    assert!(invalid.validate().is_err());
    let mut invalid = record.clone();
    invalid.title = Observation::Present("x".repeat(513));
    assert!(invalid.validate().is_err());
    let mut invalid = record.clone();
    invalid.http_status = Observation::Present(999);
    assert!(invalid.validate().is_err());
    let mut invalid = record.clone();
    invalid.cached_copy = true;
    assert!(invalid.validate().is_err());
    let mut invalid = record.clone();
    invalid.content_sha256 = Observation::Present("wrong".into());
    assert!(invalid.validate().is_err());
    assert!(!serde_json::to_string(&record)
        .unwrap()
        .contains("set-cookie"));
    fixture.finish().await;
}
#[tokio::test]
async fn index_only_storage() {
    use stract::crawler::DatumSink;
    let fixture = Fixture::new();
    let row = fixture.crawl("/page").await.unwrap();
    let mut record = row.record;
    record.target_id = uuid::Uuid::new_v4().to_string();
    record.index_only = true;
    record.retained_body_bytes = 0;
    let datum = stract::crawler::CrawlDatum {
        record,
        url: fixture.url("a.fixture.invalid", "/page"),
        payload_type: stract::warc::PayloadType::Html,
        body: "<title>Forbidden body</title>".into(),
        fetch_time_ms: 1,
        date: chrono::Utc::now(),
    };
    assert!(fixture.client.local_sink().write(datum).await.is_err());
    assert_eq!(
        std::fs::read_dir(fixture.root.join("objects"))
            .unwrap()
            .count(),
        1
    );
    fixture.finish().await;
}
#[tokio::test]
async fn noindex_effect() {
    let fixture = Fixture::new();
    fixture.reply(
        "/page",
        Reply::html("<title>Hidden</title>").header("X-Robots-Tag", "noindex"),
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "saved-noindex");
    let warc = stract::warc::WarcFile::open(fixture.root.join(row.body_object.unwrap())).unwrap();
    let page: stract::entrypoint::indexer::IndexableWebpage =
        warc.records().next().unwrap().unwrap().into();
    assert!(!page.record.unwrap().index_eligible);
    fixture.finish().await;
}
fn never_policy() -> stract::config::ingestion::IngestionPolicy {
    use stract::config::ingestion::{ClassRule, ContentClass, ContentPolicy};
    let mut policy = manual_policy();
    policy.exclusions.rules.push(ClassRule {
        id: "fixture-never".into(),
        host: "a.fixture.invalid".into(),
        include_subdomains: true,
        class: ContentClass::Fraud,
        policy: ContentPolicy::NeverCrawl,
    });
    policy
}
#[tokio::test]
async fn exclusions_never() {
    let fixture = Fixture::with_policy(
        never_policy(),
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "excluded-by-policy");
    assert!(fixture.requests.lock().unwrap().is_empty());
    assert!(row.record.robots.is_none());
    assert_eq!(row.record.exclusion_matches[0].rule_id, "fixture-never");
    let url = fixture.url("not-a.fixture.invalid", "/allowed");
    let (row, _) = fixture.crawl_raw(url.as_str()).await.unwrap();
    assert_eq!(row.outcome.kind(), "saved");
    fixture.finish().await;
}
#[tokio::test]
async fn outcome_excluded_by_policy() {
    let fixture = Fixture::with_policy(
        never_policy(),
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "excluded-by-policy");
    assert!(row.fetch_attempts.is_empty());
    fixture.finish().await;
}
struct Country;
impl stract::crawler::exclusions::HostingCountryProvider for Country {
    fn id(&self) -> &str {
        "fixture-country"
    }
    fn version(&self) -> &str {
        "1"
    }
    fn country(&self, _: std::net::IpAddr) -> Option<String> {
        Some("GB".into())
    }
}
#[tokio::test]
async fn exclusions_geo() {
    let mut policy = manual_policy();
    policy.exclusions.cctld_deny = vec!["uk".into()];
    let fixture = Fixture::with_settings(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
        None,
        None,
        &["fixture.uk"],
    );
    let (row, _) = fixture
        .crawl_raw(fixture.url("fixture.uk", "/page").as_str())
        .await
        .unwrap();
    assert_eq!(row.outcome.kind(), "excluded-by-policy");
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
    let mut policy = manual_policy();
    policy.exclusions.hosting_country_deny = vec!["GB".into()];
    assert!(policy.validate().is_err());
    policy.exclusions.hosting_country_provider = Some(stract::config::ingestion::ProviderConfig {
        id: "fixture-country".into(),
        version: "1".into(),
    });
    let fixture = Fixture::with_settings(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
        None,
        Some(std::sync::Arc::new(Country)),
        &[],
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "excluded-by-policy");
    assert!(matches!(
        row.record.hosting_country,
        stract::crawler::exclusions::HostingCountry::Known { .. }
    ));
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}
#[tokio::test]
async fn exclusions_language() {
    let mut policy = manual_policy();
    policy.exclusions.language_deny = vec!["fr".into()];
    let mut fixture = Fixture::with_policy(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
    );
    fixture.reply(
        "/page",
        Reply::html("<html lang='fr-FR'><title>Language</title></html>"),
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "excluded-by-policy");
    assert!(row.body_object.is_none());
    assert_eq!(row.record.retained_body_bytes, 0);
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    fixture.restart().await;
    fixture.reply(
        "/different",
        Reply::html("<html lang='en'><title>Conflict</title></html>")
            .header("Content-Language", "fr"),
    );
    assert_eq!(
        fixture.crawl("/different").await.unwrap().outcome.kind(),
        "excluded-by-policy"
    );
    fixture.finish().await;
}
#[tokio::test]
async fn listing_budget() {
    let clock = std::sync::Arc::new(stract::crawler::politeness::ManualClock::new(
        chrono::Utc::now(),
    ));
    let mut policy = manual_policy();
    policy
        .exclusions
        .listing_sites
        .push(stract::config::ingestion::ListingPolicy {
            host: "a.fixture.invalid".into(),
            include_subdomains: false,
            max_page_attempts_per_24h: 1,
        });
    let mut fixture = Fixture::with_policy(policy, clock.clone(), 2);
    fixture.reply("/page", Reply::new(500, "failed attempt"));
    assert_eq!(
        ticking_crawl(&fixture, &clock, "/page")
            .await
            .outcome
            .kind(),
        "http-status"
    );
    fixture.restart().await;
    let row = ticking_crawl(&fixture, &clock, "/second").await;
    assert_eq!(row.outcome.kind(), "excluded-by-policy");
    assert!(row.fetch_attempts.is_empty());
    clock.advance(86_400_000).unwrap();
    assert_eq!(
        ticking_crawl(&fixture, &clock, "/third")
            .await
            .outcome
            .kind(),
        "saved"
    );
    fixture.finish().await;
}
#[tokio::test]
async fn retention_ttl() {
    use stract::crawler::retention;
    let clock = std::sync::Arc::new(stract::crawler::politeness::ManualClock::new(
        chrono::Utc::now(),
    ));
    let fixture = Fixture::with_policy(manual_policy(), clock.clone(), 2);
    let row = ticking_crawl(&fixture, &clock, "/page").await;
    let object = fixture.root.join(row.body_object.unwrap());
    let ledger = std::fs::read(fixture.root.join("ledger.jsonl")).unwrap();
    let until_expiry = (row.record.raw_expires_at_utc.unwrap() - fixture.client.clock().utc())
        .num_milliseconds() as u64;
    clock.advance(until_expiry - 1).unwrap();
    assert_eq!(
        fixture
            .client
            .local_sink()
            .retention(false)
            .unwrap()
            .deleted,
        0
    );
    clock.advance(1).unwrap();
    assert_eq!(
        fixture.client.local_sink().retention(true).unwrap().expired,
        1
    );
    assert!(object.exists());
    let report = fixture.client.local_sink().retention(false).unwrap();
    assert_eq!(report.deleted, 1);
    assert!(!object.exists());
    assert_eq!(
        std::fs::read(fixture.root.join("ledger.jsonl")).unwrap(),
        ledger
    );
    assert_eq!(
        std::fs::read_dir(fixture.root.join("manifests"))
            .unwrap()
            .count(),
        1
    );
    retention::scan(
        &fixture.client.host_registry(),
        fixture.client.policy(),
        fixture.client.clock().utc(),
    )
    .unwrap();
    fixture.finish().await;
}
#[tokio::test]
async fn retention_scan() {
    let fixture = Fixture::new();
    std::fs::write(fixture.root.join("objects/unmanaged"), b"owned sentinel").unwrap();
    let report = stract::crawler::retention::run(
        &fixture.client.host_registry(),
        fixture.client.policy(),
        fixture.client.clock().utc(),
        false,
    )
    .unwrap();
    assert_eq!(report.failed, 1);
    assert!(report.ensure_success().is_err());
    assert!(stract::crawler::retention::scan(
        &fixture.client.host_registry(),
        fixture.client.policy(),
        fixture.client.clock().utc()
    )
    .is_err());
    assert_eq!(
        std::fs::read(fixture.root.join("objects/unmanaged")).unwrap(),
        b"owned sentinel"
    );
    fixture.finish().await;
}
#[tokio::test]
async fn retention_containment() {
    for damage in ["foreign", "parent", "symlink", "hardlink"] {
        let clock = std::sync::Arc::new(stract::crawler::politeness::ManualClock::new(
            chrono::Utc::now(),
        ));
        let fixture = Fixture::with_policy(manual_policy(), clock.clone(), 2);
        let row = ticking_crawl(&fixture, &clock, "/page").await;
        let object = fixture.root.join(row.body_object.clone().unwrap());
        let sentinel = fixture.root.join("sentinel");
        std::fs::write(&sentinel, b"must remain").unwrap();
        let manifest_path = fixture
            .root
            .join(format!("manifests/{}.json", row.target_id));
        let mut manifest: stract::crawler::retention::ObjectManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        match damage {
            "foreign" => manifest.store_id = uuid::Uuid::new_v4().to_string(),
            "parent" => manifest.body_object = "objects/../sentinel".into(),
            "symlink" => {
                std::fs::remove_file(&object).unwrap();
                std::os::unix::fs::symlink(&sentinel, &object).unwrap();
            }
            "hardlink" => {
                std::fs::remove_file(&object).unwrap();
                std::fs::hard_link(&sentinel, &object).unwrap();
            }
            _ => unreachable!(),
        }
        std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        clock.advance(31 * 86_400_000).unwrap();
        let report = stract::crawler::retention::run(
            &fixture.client.host_registry(),
            fixture.client.policy(),
            fixture.client.clock().utc(),
            false,
        )
        .unwrap();
        assert!(report.failed > 0);
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"must remain");
        assert!(std::fs::symlink_metadata(&object).is_ok());
        fixture.finish().await;
    }
}
#[tokio::test]
async fn ledger_exactly_once() {
    let fixture = Fixture::new();
    let row = fixture.crawl("/page").await.unwrap();
    assert!(matches!(
        fixture.client.ledger().complete(row),
        Err(Error::DuplicateTarget)
    ));
    assert_eq!(
        stract::crawler::ledger::Ledger::read_rows(&fixture.root.join("ledger.jsonl"))
            .unwrap()
            .len(),
        1
    );
    fixture.finish().await;
}
#[tokio::test]
async fn ledger_failure_is_fatal() {
    let fixture = Fixture::new();
    fixture
        .client
        .ledger()
        .admit_next(
            stract::crawler::ledger::TargetKind::Seed,
            None,
            Some(&fixture.url("a.fixture.invalid", "/pending")),
        )
        .unwrap();
    assert!(matches!(
        fixture.client.ledger().finish(),
        Err(Error::LedgerIncomplete)
    ));
    fixture.finish().await;
}
#[tokio::test]
async fn ledger_recovery() {
    let mut fixture = Fixture::new();
    let target = fixture
        .client
        .ledger()
        .admit_next(
            stract::crawler::ledger::TargetKind::Seed,
            None,
            Some(&fixture.url("a.fixture.invalid", "/pending")),
        )
        .unwrap();
    fixture.restart().await;
    fixture.client.ledger().finish().unwrap();
    let rows =
        stract::crawler::ledger::Ledger::read_rows(&fixture.root.join("ledger.jsonl")).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_id, target.target_id);
    assert_eq!(rows[0].outcome.kind(), "cancelled");
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}

struct FailedSink;
impl stract::crawler::DatumSink for FailedSink {
    async fn write(&self, _: stract::crawler::CrawlDatum) -> Result<(), Error> {
        Err(Error::SinkWrite)
    }
    async fn finish(&self) -> Result<(), Error> {
        Ok(())
    }
}
#[tokio::test]
async fn outcome_sink_write_failed() {
    use stract::crawler::{ledger::TargetKind, Domain, JobExecutor, WorkerJob};
    let fixture = Fixture::new();
    let url = fixture.url("a.fixture.invalid", "/page");
    let config = toml::from_str(include_str!("../../../configs/crawler/crawler.toml")).unwrap();
    let mut executor = JobExecutor::new(
        WorkerJob {
            domain: Domain::from(&url),
            urls: Default::default(),
            wandering_urls: 0,
        },
        std::sync::Arc::new(config),
        std::sync::Arc::new(FailedSink),
        fixture.client.clone(),
    );
    let row = executor
        .process_raw_inputs(&[url.into()], TargetKind::Seed)
        .await
        .unwrap()
        .pop()
        .unwrap()
        .0;
    assert_eq!(row.outcome.kind(), "sink-write-failed");
    assert!(row.body_object.is_none());
    assert_eq!(row.record.retained_body_bytes, 0);
    fixture.client.ledger().finish().unwrap();
    assert_eq!(fixture.client.ledger().rows().unwrap().len(), 1);
    fixture.finish().await;
}
#[tokio::test]
async fn ledger_projection_failure() {
    let mut fixture = Fixture::new();
    std::fs::remove_file(fixture.root.join("ledger.jsonl")).unwrap();
    std::fs::create_dir(fixture.root.join("ledger.jsonl")).unwrap();
    assert!(matches!(
        fixture.crawl("/page").await,
        Err(Error::LedgerWrite)
    ));
    assert!(matches!(
        fixture.client.ledger().finish(),
        Err(Error::LedgerWrite)
    ));
    std::fs::remove_dir(fixture.root.join("ledger.jsonl")).unwrap();
    fixture.restart().await;
    fixture.client.ledger().finish().unwrap();
    let rows =
        stract::crawler::ledger::Ledger::read_rows(&fixture.root.join("ledger.jsonl")).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].outcome.kind(), "saved");
    fixture.finish().await;
}
#[test]
fn exclusions_schema() {
    let policy = manual_policy();
    for key in ["version", "change_log"] {
        let mut value = serde_json::to_value(&policy).unwrap();
        value["exclusions"][key] = if key == "version" {
            serde_json::json!("")
        } else {
            serde_json::json!([])
        };
        let parsed: stract::config::ingestion::IngestionPolicy =
            serde_json::from_value(value).unwrap();
        assert!(parsed.validate().is_err());
    }
    let mut invalid = policy.clone();
    invalid.exclusions.cctld_deny.push("GBR".into());
    assert!(invalid.validate().is_err());
    let mut invalid = policy.clone();
    invalid.exclusions.hosting_country_deny.push("uk".into());
    assert!(invalid.validate().is_err());
    let mut value = serde_json::to_value(&policy).unwrap();
    value["exclusions"]["unsafe_override"] = true.into();
    assert!(serde_json::from_value::<stract::config::ingestion::IngestionPolicy>(value).is_err());
    let mut invalid = never_policy();
    invalid
        .exclusions
        .rules
        .push(invalid.exclusions.rules[0].clone());
    assert!(invalid.validate().is_err());
}
#[test]
fn retention_config() {
    let policy = manual_policy();
    for (name, value) in [
        ("raw_body_max_age_days", serde_json::json!(31)),
        ("snippet_max_chars", serde_json::json!(301)),
        ("query_log_max_age_days", serde_json::json!(91)),
        ("cached_copy", serde_json::json!(true)),
        ("profiling_allowed", serde_json::json!(true)),
        ("advertising_allowed", serde_json::json!(true)),
        ("query_rotating_salt_required", serde_json::json!(false)),
        ("query_ip_v4_prefix", serde_json::json!(32)),
        ("query_ip_v6_prefix", serde_json::json!(128)),
    ] {
        let mut config = serde_json::to_value(&policy).unwrap();
        config["retention"][name] = value;
        let invalid: stract::config::ingestion::IngestionPolicy =
            serde_json::from_value(config).unwrap();
        assert!(invalid.validate().is_err(), "{name}");
    }
    assert!(serde_json::to_string(&policy)
        .unwrap()
        .find("ledger_max_age")
        .is_none());
}
fn approved_policy() -> stract::config::ingestion::IngestionPolicy {
    use stract::config::ingestion::{ApprovalStatus, ApprovedRecord};
    let mut policy = manual_policy();
    policy.production.dpia_id = Some("fixture-approval".into());
    policy.production.distributed_host_lease_configured = true;
    policy.production.approved_records.push(ApprovedRecord {
        id: "fixture-approval".into(),
        status: ApprovalStatus::Approved,
        approver: "fixture approver".into(),
        approved_at_utc: chrono::Utc::now() - chrono::TimeDelta::minutes(1),
        lia_id: "fixture-lia".into(),
        lia_summary_url: "https://example.invalid/lia".into(),
        article14_measures_id: "fixture-notice".into(),
        policy_version: policy.version.clone(),
    });
    policy
}
#[test]
fn dpia_guard() {
    let now = chrono::Utc::now();
    let valid = approved_policy();
    assert!(manual_policy()
        .require_production_approval(now, None)
        .is_err());
    assert!(valid
        .require_production_approval(now, Some("fixture-approval"))
        .is_ok());
    assert!(valid
        .require_production_approval(now, Some("wrong"))
        .is_err());
    for damage in 0..6 {
        let mut policy = valid.clone();
        match damage {
            0 => {
                policy.production.approved_records[0].status =
                    stract::config::ingestion::ApprovalStatus::Draft
            }
            1 => {
                policy.production.approved_records[0].approved_at_utc =
                    now + chrono::TimeDelta::days(1)
            }
            2 => policy.production.approved_records[0].lia_id.clear(),
            3 => policy.production.approved_records[0]
                .article14_measures_id
                .clear(),
            4 => policy
                .production
                .approved_records
                .push(policy.production.approved_records[0].clone()),
            5 => policy.production.distributed_host_lease_configured = false,
            _ => unreachable!(),
        }
        assert!(policy.require_production_approval(now, None).is_err());
    }
}
#[tokio::test]
async fn dpia_entrypoints() {
    let fixture = Fixture::new();
    let mut config: stract::config::CrawlerConfig =
        toml::from_str(include_str!("../../../configs/crawler/crawler.toml")).unwrap();
    config.local_store_path = fixture.root.join("production-never");
    let error = stract::crawler::Crawler::new(config).await.err().unwrap();
    assert!(error
        .to_string()
        .contains("production requires selected dpia_id"));
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let config = stract::config::LiveCrawlerConfig {
        crawled_db_path: fixture.root.join("live-db-never"),
        gossip: stract::config::GossipConfig {
            addr: reservation.local_addr().unwrap(),
            seed_nodes: Some(vec![]),
        },
        site_stats_path: fixture.root.join("stats-never"),
        host_centrality_path: fixture.root.join("centrality-never"),
        ingestion: manual_policy(),
        local_store_path: fixture.root.join("live-store-never"),
        num_worker_threads: 1,
        check_intervals: Default::default(),
        daily_budget: Default::default(),
        init_crawl_db: false,
    };
    let error = stract::entrypoint::live_index::crawler::run(config)
        .await
        .err()
        .unwrap();
    assert!(error
        .to_string()
        .contains("production requires selected dpia_id"));
    assert!(
        !fixture.root.join("production-never").exists()
            && !fixture.root.join("live-db-never").exists()
    );
    fixture.finish().await;
}
#[tokio::test]
async fn unledgered_transport_refused() {
    let fixture = Fixture::new();
    let mut config: stract::config::CrawlerConfig =
        toml::from_str(include_str!("../../../configs/crawler/crawler.toml")).unwrap();
    config.ingestion = approved_policy();
    config.local_store_path = fixture.root.join("approved-store");
    let client = stract::crawler::robot_client::RobotClient::new(&config).unwrap();
    // This witness never sends the returned builder, even when the guard is mutated.
    assert!(matches!(
        client
            .get(url::Url::parse("https://example.invalid/page").unwrap())
            .await,
        Err(Error::InternalInvariant)
    ));
    assert!(client.ledger().targets().unwrap().is_empty());
    drop(client);
    fixture.finish().await;
}

#[tokio::test]
async fn auxiliary_completion() {
    use stract::crawler::ledger::FetchKind;
    let fixture = Fixture::new();
    fixture.reply(
        "/feed",
        Reply::new(200, "<rss><channel/></rss>").header("Content-Type", "application/rss+xml"),
    );
    let feed = fixture
        .client
        .fetch_auxiliary(fixture.url("a.fixture.invalid", "/feed"), FetchKind::Feed)
        .await
        .unwrap();
    assert_eq!(feed.row.outcome.kind(), "parsed-not-retained");
    assert_eq!(feed.body.as_deref(), Some("<rss><channel/></rss>"));
    assert!(feed.row.body_object.is_none());
    assert_eq!(
        feed.row.fetch_attempts.last().unwrap().kind,
        FetchKind::Feed
    );
    fixture.reply(
        "/front",
        Reply::html("<title>Front</title><a href='/next'>Next</a>")
            .header("X-Robots-Tag", "nofollow"),
    );
    let front = fixture
        .client
        .fetch_auxiliary(
            fixture.url("a.fixture.invalid", "/front"),
            FetchKind::Frontpage,
        )
        .await
        .unwrap();
    assert!(front.links.is_empty());
    assert!(front.row.record.directives.nofollow);
    fixture.client.ledger().finish().unwrap();
    assert_eq!(fixture.client.ledger().rows().unwrap().len(), 2);
    fixture.finish().await;
}

#[tokio::test]
async fn outcome_saved() {
    let fixture = Fixture::new();
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "saved");
    assert_eq!(fixture.client.ledger().rows().unwrap().len(), 1);
    assert_eq!(row.fetch_attempts.len(), 2);
    assert!(row.record.retained_body_bytes > 0);
    let object = fixture.root.join(row.body_object.unwrap());
    assert!(object.is_file());
    let warc = stract::warc::WarcFile::open(object).unwrap();
    let records: Vec<_> = warc.records().collect();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0]
            .as_ref()
            .unwrap()
            .metadata
            .document
            .as_ref()
            .unwrap()
            .target_id,
        row.target_id
    );
    fixture.finish().await;
}

#[tokio::test]
async fn directive_noindex() {
    let fixture = Fixture::new();
    fixture.reply(
        "/page",
        Reply::html("<title>Header restriction</title>").header("X-Robots-Tag", "noindex"),
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert!(row.record.directives.noindex);
    assert!(!row.record.index_eligible);
    assert_eq!(row.outcome.kind(), "saved-noindex");
    fixture.finish().await;
}

#[tokio::test]
async fn no_store_storage() {
    let mut fixture = Fixture::new();
    let first = fixture.crawl("/page").await.unwrap();
    let object = fixture.root.join(first.body_object.unwrap());
    assert!(object.exists());
    fixture.restart().await;
    fixture.reply(
        "/page",
        Reply::html("<title>Private current page</title><p>not retained</p>")
            .header("Cache-Control", "public, NO-STORE")
            .header("ETag", "secret-validator"),
    );
    let row = fixture.crawl("/page").await.unwrap();
    assert_eq!(row.outcome.kind(), "parsed-not-retained");
    assert!(!object.exists());
    assert!(row.body_object.is_none());
    assert_eq!(row.record.retained_body_bytes, 0);
    assert!(row.record.validators.etag.is_none());
    assert_eq!(
        std::fs::read_dir(fixture.root.join("objects"))
            .unwrap()
            .count(),
        0
    );
    fixture.finish().await;
}

#[tokio::test]
async fn http_304() {
    let mut fixture = Fixture::new();
    fixture.reply(
        "/page",
        Reply::html("<title>Original</title>")
            .header("ETag", "\"v1\"")
            .header("Last-Modified", "Fri, 11 Sep 2026 12:00:00 GMT"),
    );
    let first = fixture.crawl("/page").await.unwrap();
    fixture.restart().await;
    fixture.reply("/page", Reply::new(304, ""));
    let second = fixture.crawl("/page").await.unwrap();
    assert_eq!(second.outcome.kind(), "not-modified");
    assert_eq!(first.record.content_sha256, second.record.content_sha256);
    assert_eq!(
        first.record.raw_expires_at_utc,
        second.record.raw_expires_at_utc
    );
    assert_eq!(first.record.parsed_at_utc, second.record.parsed_at_utc);
    assert!(second.body_object.is_none());
    assert_eq!(
        std::fs::read_dir(fixture.root.join("objects"))
            .unwrap()
            .count(),
        1
    );
    fixture.finish().await;
}

fn manual_policy() -> stract::config::ingestion::IngestionPolicy {
    let mut policy = stract::config::ingestion::IngestionPolicy::default();
    policy.politeness.gap_ms = 500;
    policy
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {cases: 8, failure_persistence: None, ..Default::default()})]
    #[test]
    fn robots_order_prop(paths in proptest::collection::vec(0_u8..8, 1..4)) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let fixture = Fixture::new();
            let mut reply = Reply::new(200, "User-agent: *\nAllow: /");
            reply.body_delay = std::time::Duration::from_millis(15);
            fixture.reply("/robots.txt", reply);
            let futures = paths.iter().map(|n| {
                let client = fixture.client.clone(); let url = fixture.url("a.fixture.invalid", &format!("/page-{n}"));
                async move { client.get(url).await.unwrap().send().await.unwrap().text().await.unwrap() }
            });
            futures::future::join_all(futures).await;
            let requests = fixture.requests.lock().unwrap().clone();
            assert_eq!(requests.len(), paths.len() + 1);
            assert_eq!(requests[0].target, "/robots.txt");
            assert_eq!(requests.iter().filter(|r| r.target == "/robots.txt").count(), 1);
            for pair in requests.windows(2) {
                assert!(pair[1].arrived.duration_since(pair[0].arrived) >= std::time::Duration::from_millis(500));
            }
            fixture.finish().await;
        });
    }
    #[test]
    fn robots_cache_clock_prop(ttl in 2_u64..86_401) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            use stract::crawler::{politeness::ManualClock, robots_txt::RobotsDecision};
            let clock = std::sync::Arc::new(ManualClock::new(chrono::Utc::now()));
            let mut policy = manual_policy(); policy.robots.cache_secs = ttl;
            let fixture = Fixture::with_policy(policy, clock.clone(), 2);
            fixture.reply("/robots.txt", Reply::new(200, "User-agent: *\nAllow: /"));
            fixture.reply("/robots.txt", Reply::new(200, "User-agent: *\nDisallow: /"));
            let url = fixture.url("a.fixture.invalid", "/page");
            let manager = fixture.client.robots_txt_manager();
            assert_eq!(manager.snapshot(&url).await.unwrap().decision, RobotsDecision::AllowRule);
            clock.advance(ttl * 1000 - 1).unwrap();
            assert_eq!(manager.snapshot(&url).await.unwrap().decision, RobotsDecision::AllowRule);
            clock.advance(1).unwrap();
            assert_eq!(manager.snapshot(&url).await.unwrap().decision, RobotsDecision::DisallowRule);
            assert_eq!(fixture.requests.lock().unwrap().len(), 2);
            fixture.finish().await;
        });
    }
}

#[tokio::test]
async fn transport_no_proxy() {
    if std::env::var_os("STORY585_PROXY_WITNESS_CHILD").is_some() {
        let fixture = Fixture::new();
        fixture.fetch("/page").await.unwrap();
        assert_eq!(fixture.requests.lock().unwrap().len(), 2);
        fixture.finish().await;
        return;
    }
    let fixture = Fixture::new();
    let endpoint = format!("http://{}", fixture.endpoint.address());
    let status = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "transport_no_proxy", "--nocapture"])
        .env("STORY585_PROXY_WITNESS_CHILD", "1")
        .env("HTTP_PROXY", &endpoint)
        .env("http_proxy", &endpoint)
        .env("HTTPS_PROXY", &endpoint)
        .env("https_proxy", &endpoint)
        .env("ALL_PROXY", &endpoint)
        .env("all_proxy", &endpoint)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .status()
        .await
        .unwrap();
    assert!(status.success());
    assert_eq!(fixture.requests.lock().unwrap().len(), 0);
    fixture.finish().await;
}

#[tokio::test]
async fn robots_cache_cap() {
    for seconds in [0, 86_401, u64::MAX] {
        let mut policy = manual_policy();
        policy.robots.cache_secs = seconds;
        assert!(policy.validate().is_err());
    }
    for seconds in [1, 3_600, 86_400] {
        let mut policy = manual_policy();
        policy.robots.cache_secs = seconds;
        assert!(policy.validate().is_ok());
    }
}

#[tokio::test]
async fn robots_4xx() {
    use stract::crawler::robots_txt::RobotsDecision;
    for status in [400, 401, 403, 404, 410, 429] {
        let fixture = Fixture::new();
        fixture.reply("/robots.txt", Reply::new(status, b""));
        let url = fixture.url("a.fixture.invalid", "/page");
        let snapshot = fixture
            .client
            .robots_txt_manager()
            .snapshot(&url)
            .await
            .unwrap();
        assert_eq!(snapshot.decision, RobotsDecision::AllowAllUnavailable);
        assert_eq!(snapshot.http_status.value(), Some(&status));
        assert_eq!(
            snapshot.body_sha256.value().map(String::as_str),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        let result = fixture.fetch("/page").await;
        assert_eq!(result.is_ok(), !matches!(status, 401 | 403 | 429));
        fixture.finish().await;
    }
}

#[tokio::test]
async fn robots_timeout() {
    let fixture = Fixture::with_policy(
        manual_policy(),
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        1,
    );
    let mut reply = Reply::new(200, "User-agent: *\nAllow: /");
    reply.body_delay = std::time::Duration::from_secs(2);
    fixture.reply("/robots.txt", reply);
    assert!(matches!(
        fixture.fetch("/page").await,
        Err(Error::RobotsUnreachable)
    ));
    let snapshot = fixture
        .client
        .robots_txt_manager()
        .snapshot(&fixture.url("a.fixture.invalid", "/page"))
        .await
        .unwrap();
    assert_eq!(snapshot.failure_code.as_deref(), Some("timeout"));
    assert!(snapshot.body_sha256.is_none());
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn robots_parser_failure() {
    for body in [
        b"User-agent: *\nCrawl-delay: -1\nAllow: /".as_slice(),
        b"User-agent: *\nCrawl-delay: NaN\nAllow: /",
        b"\xff\xfe",
    ] {
        let fixture = Fixture::new();
        fixture.reply("/robots.txt", Reply::new(200, body));
        assert!(fixture.fetch("/page").await.is_err());
        let snapshot = fixture
            .client
            .robots_txt_manager()
            .snapshot(&fixture.url("a.fixture.invalid", "/page"))
            .await
            .unwrap();
        assert_eq!(snapshot.failure_code.as_deref(), Some("parser-failure"));
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn robots_origin_isolation() {
    let fixture = Fixture::new();
    let http = fixture.url("a.fixture.invalid", "/page");
    fixture
        .client
        .robots_txt_manager()
        .snapshot(&http)
        .await
        .unwrap();
    let mut https = http.clone();
    https.set_scheme("https").unwrap();
    let snapshot = fixture
        .client
        .robots_txt_manager()
        .snapshot(&https)
        .await
        .unwrap();
    assert_eq!(
        snapshot.decision,
        stract::crawler::robots_txt::RobotsDecision::DisallowUnreachable
    );
    assert_eq!(snapshot.failure_code.as_deref(), Some("tls"));
    assert!(snapshot.body_sha256.is_none());
    assert_ne!(
        stract::crawler::network::OriginKey::from_url(&http).unwrap(),
        stract::crawler::network::OriginKey::from_url(&https).unwrap()
    );
    let mut port = http.clone();
    port.set_port(Some(http.port().unwrap().saturating_sub(1)))
        .unwrap();
    assert_ne!(
        stract::crawler::network::OriginKey::from_url(&http).unwrap(),
        stract::crawler::network::OriginKey::from_url(&port).unwrap()
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn robots_no_downgrade() {
    let fixture = Fixture::new();
    let mut url = fixture.url("a.fixture.invalid", "/page");
    url.set_scheme("https").unwrap();
    assert!(fixture.client.get(url).await.unwrap().send().await.is_err());
    assert_eq!(fixture.requests.lock().unwrap().len(), 0);
    fixture.finish().await;
}

#[tokio::test]
async fn robots_redirect_scope() {
    let fixture = Fixture::new();
    fixture.reply(
        "/robots.txt",
        Reply::new(302, "").header("Location", "http://unapproved.invalid/robots2.txt"),
    );
    let snapshot = fixture
        .client
        .robots_txt_manager()
        .snapshot(&fixture.url("a.fixture.invalid", "/page"))
        .await
        .unwrap();
    assert_eq!(snapshot.failure_code.as_deref(), Some("redirect-off-scope"));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
    let fixture = Fixture::new();
    fixture.reply(
        "/robots.txt",
        Reply::new(307, "").header("Location", "/declared"),
    );
    fixture.reply("/declared", Reply::new(200, "User-agent: *\nAllow: /"));
    fixture.fetch("/page").await.unwrap();
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    fixture.finish().await;
}

#[tokio::test]
async fn robots_expired_in_queue() {
    use stract::crawler::politeness::ManualClock;
    let clock = std::sync::Arc::new(ManualClock::new(chrono::Utc::now()));
    let mut policy = manual_policy();
    policy.robots.cache_secs = 1;
    policy.politeness.gap_ms = 2_000;
    let fixture = Fixture::with_policy(policy, clock.clone(), 2);
    fixture.reply("/robots.txt", Reply::new(200, "User-agent: *\nAllow: /"));
    fixture.reply("/robots.txt", Reply::new(200, "User-agent: *\nDisallow: /"));
    fixture
        .client
        .robots_txt_manager()
        .snapshot(&fixture.url("a.fixture.invalid", "/page"))
        .await
        .unwrap();
    let client = fixture.client.clone();
    let url = fixture.url("a.fixture.invalid", "/page");
    let task = tokio::spawn(async move { client.get(url).await?.send().await });
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    clock.advance(2_001).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    clock.advance(2_001).unwrap();
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::DisallowedPath)
    ));
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.target == "/robots.txt"));
    fixture.finish().await;
}

#[tokio::test]
async fn politeness_defaults() {
    let policy = stract::config::ingestion::IngestionPolicy::default();
    assert_eq!(policy.politeness.gap_ms, 10_000);
    assert_eq!(policy.politeness.max_concurrent_per_host, 1);
    let fixture = Fixture::with_policy(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
    );
    fixture.fetch("/page").await.unwrap();
    let requests = fixture.requests.lock().unwrap().clone();
    assert!(
        requests[1].arrived.duration_since(requests[0].arrived)
            >= std::time::Duration::from_secs(10)
    );
    assert_eq!(
        fixture
            .max_connections
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    fixture.finish().await;
}

#[tokio::test]
async fn throttle_load() {
    for concurrency in [1, 2] {
        let mut policy = manual_policy();
        policy.politeness.max_concurrent_per_host = concurrency;
        let fixture = Fixture::with_policy(
            policy,
            std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
            2,
        );
        let (a, b, c) = tokio::join!(
            fixture.fetch("/one"),
            fixture.fetch("/two"),
            fixture.fetch("/three")
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        for pair in fixture.requests.lock().unwrap().windows(2) {
            assert!(
                pair[1].arrived.duration_since(pair[0].arrived)
                    >= std::time::Duration::from_millis(500)
            );
        }
        assert!(
            fixture
                .max_connections
                .load(std::sync::atomic::Ordering::SeqCst)
                <= concurrency
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn crawl_delay_raises_gap() {
    let fixture = Fixture::new();
    fixture.reply(
        "/robots.txt",
        Reply::new(200, "User-agent: *\nCrawl-delay: 0.7501\nAllow: /"),
    );
    fixture.fetch("/one").await.unwrap();
    fixture.fetch("/two").await.unwrap();
    let requests = fixture.requests.lock().unwrap().clone();
    for pair in requests.windows(2) {
        assert!(
            pair[1].arrived.duration_since(pair[0].arrived)
                >= std::time::Duration::from_millis(751)
        );
    }
    fixture.finish().await;
}

#[tokio::test]
async fn crawl_delay_skip() {
    let fixture = Fixture::new();
    fixture.reply(
        "/robots.txt",
        Reply::new(200, "User-agent: *\nCrawl-delay: 60.001\nAllow: /"),
    );
    assert!(matches!(
        fixture.fetch("/page").await,
        Err(Error::CrawlDelayExceedsCeiling)
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}

async fn retry_after_case(status: u16) {
    use stract::crawler::politeness::{Clock, ManualClock};
    let clock = std::sync::Arc::new(ManualClock::new(chrono::Utc::now()));
    let fixture = Fixture::with_policy(manual_policy(), clock.clone(), 2);
    fixture.reply(
        "/robots.txt",
        Reply::new(status, "rate limited").header("Retry-After", "172800"),
    );
    let url = fixture.url("a.fixture.invalid", "/page");
    fixture
        .client
        .robots_txt_manager()
        .snapshot(&url)
        .await
        .unwrap();
    let state = fixture
        .client
        .host_registry()
        .state(&HostKey::from_url(&url).unwrap())
        .unwrap();
    assert_eq!(state.consecutive_rate_responses, 1);
    assert_eq!(
        state.retry_at_utc,
        Some(clock.utc() + chrono::TimeDelta::seconds(172800))
    );
    assert_eq!(state.blocked_until_utc.is_some(), status == 429);
    assert!(matches!(
        fixture.fetch("/page").await,
        Err(Error::HostBlocked)
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}
#[tokio::test]
async fn retry_after_429() {
    retry_after_case(429).await;
}
#[tokio::test]
async fn retry_after_503() {
    retry_after_case(503).await;
}
#[tokio::test]
async fn retry_after_dates() {
    use stract::crawler::politeness::{Clock, ManualClock};
    let now = chrono::DateTime::parse_from_rfc3339("2026-09-11T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let clock = std::sync::Arc::new(ManualClock::new(now));
    let fixture = Fixture::with_policy(manual_policy(), clock.clone(), 2);
    fixture.reply(
        "/robots.txt",
        Reply::new(503, "later")
            .header("Retry-After", "Fri, 11 Sep 2026 14:00:00 GMT")
            .header("Retry-After", "-5"),
    );
    let url = fixture.url("a.fixture.invalid", "/page");
    fixture
        .client
        .robots_txt_manager()
        .snapshot(&url)
        .await
        .unwrap();
    let state = fixture
        .client
        .host_registry()
        .state(&HostKey::from_url(&url).unwrap())
        .unwrap();
    assert_eq!(
        state.retry_at_utc,
        Some(clock.utc() + chrono::TimeDelta::hours(2))
    );
    assert!(state.retry_after_invalid);
    fixture.finish().await;
}

#[tokio::test]
async fn block_floor() {
    let mut policy = manual_policy();
    policy.politeness.block_secs = 86_399;
    assert!(policy.validate().is_err());
    host_block(403).await;
}

#[tokio::test]
async fn host_state_restart() {
    let mut fixture = Fixture::new();
    fixture.reply("/page", Reply::new(403, "denied"));
    fixture.fetch("/page").await.unwrap();
    let placeholder = Fixture::new();
    drop(std::mem::replace(
        &mut fixture.client,
        placeholder.client.clone(),
    ));
    fixture.client = stract::crawler::robot_client::RobotClient::loopback(
        &fixture.root,
        &manual_policy(),
        fixture.endpoint.clone(),
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
    )
    .unwrap();
    assert!(matches!(
        fixture.fetch("/next").await,
        Err(Error::HostBlocked)
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    placeholder.finish().await;
    fixture.finish().await;
}

#[tokio::test]
async fn challenge_rule() {
    for body in [
        "<article>CAPTCHA can ask you to verify you are human.</article>",
        "<script>verify you are human</script><div class='g-recaptcha'></div>",
        "<pre><form action='/challenge/a'>verify you are human</form></pre>",
        "<p>verify you are human</p><iframe src='https://recaptcha.net.evil.invalid/x'></iframe>",
    ] {
        let fixture = Fixture::new();
        fixture.reply("/page", Reply::html(body));
        fixture.fetch("/page").await.unwrap();
        fixture.fetch("/next").await.unwrap();
        fixture.finish().await;
    }
    for body in [
        "<p>Checking your browser</p><div class='h-captcha'></div>",
        "<p>Complete the security check</p><iframe src='https://a.recaptcha.net/widget'></iframe>",
    ] {
        let fixture = Fixture::new();
        fixture.reply("/page", Reply::html(body));
        assert!(matches!(
            fixture.fetch("/page").await,
            Err(Error::Challenge)
        ));
        assert!(matches!(
            fixture.fetch("/next").await,
            Err(Error::HostBlocked)
        ));
        fixture.finish().await;
    }
}

#[tokio::test]
async fn ssrf_address_matrix() {
    use stract::crawler::network::parse_fetch_url;
    for host in [
        "127.0.0.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.168.0.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[fc00::1]",
        "[fe80::1]",
    ] {
        assert!(matches!(
            parse_fetch_url(&format!("http://{host}/")),
            Err(Error::RefusedPrivateAddress)
        ));
    }
    assert!(parse_fetch_url("https://93.184.215.14/").is_ok());
    assert!(parse_fetch_url("https://[2606:4700:4700::1111]/").is_ok());
}

#[tokio::test]
async fn permit_through_body() {
    let fixture = Fixture::new();
    let mut body = Reply::html("<title>slow</title>");
    body.body_delay = std::time::Duration::from_millis(800);
    fixture.reply("/one", body);
    let (a, b) = tokio::join!(fixture.fetch("/one"), fixture.fetch("/two"));
    a.unwrap();
    b.unwrap();
    assert_eq!(
        fixture
            .max_connections
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    fixture.finish().await;
}

#[tokio::test]
async fn url_credentials() {
    use stract::crawler::network::parse_fetch_url;
    for raw in [
        "https://user:secret@a.fixture.invalid/",
        "https://@a.fixture.invalid/",
        "https://a.fixture.invalid/%zz",
    ] {
        assert!(matches!(parse_fetch_url(raw), Err(Error::InvalidUrl)));
    }
    let value =
        parse_fetch_url("https://a.fixture.invalid/Path?q=keep&utm_source=keep#drop").unwrap();
    assert_eq!(value.query(), Some("q=keep&utm_source=keep"));
    assert!(value.fragment().is_none());
}

#[tokio::test]
async fn ua_fetch_types() {
    use stract::crawler::ledger::FetchKind;
    let mut fixture = Fixture::new();
    fixture.reply(
        "/page",
        Reply::html("<title>Initial</title>").header("ETag", "\"version\""),
    );
    fixture.crawl("/page").await.unwrap();
    for (path, kind, mime) in [
        ("/feed", FetchKind::Feed, "application/rss+xml"),
        ("/sitemap", FetchKind::Sitemap, "application/xml"),
        ("/front", FetchKind::Frontpage, "text/html"),
    ] {
        fixture.reply(
            path,
            Reply::new(200, "<title>Auxiliary identity</title>").header("Content-Type", mime),
        );
        fixture
            .client
            .fetch_auxiliary(fixture.url("a.fixture.invalid", path), kind)
            .await
            .unwrap();
    }
    fixture.restart().await;
    fixture.reply("/page", Reply::new(304, ""));
    fixture.crawl("/page").await.unwrap();
    let expected = format!(
        "AVASearchBot/{} (+{}; {})",
        env!("CARGO_PKG_VERSION"),
        fixture.client.policy().get().identity.policy_url,
        fixture.client.policy().get().identity.contact
    );
    let requests = fixture.requests.lock().unwrap().clone();
    let pattern = regex::Regex::new(&format!(r"^AVASearchBot/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)? \(\+{}; {}\)$", regex::escape(&fixture.client.policy().get().identity.policy_url), regex::escape(&fixture.client.policy().get().identity.contact))).unwrap();
    assert_eq!(requests.len(), 7);
    for request in requests {
        assert_eq!(
            request.host,
            format!(
                "a.fixture.invalid:{}",
                fixture.url("a.fixture.invalid", "/").port().unwrap()
            )
        );
        assert_eq!(request.user_agent, expected);
        for forbidden in ["cookie", "authorization", "proxy-authorization", "referer"] {
            assert!(!request.headers.contains_key(forbidden));
        }
        assert!(pattern.is_match(&request.user_agent));
    }
    let rows =
        stract::crawler::ledger::Ledger::read_rows(&fixture.root.join("ledger.jsonl")).unwrap();
    let kinds: std::collections::BTreeSet<_> = rows
        .iter()
        .flat_map(|row| row.fetch_attempts.iter())
        .map(|attempt| serde_json::to_string(&attempt.kind).unwrap())
        .collect();
    assert_eq!(kinds.len(), 6);
    let live = stract::config::LiveCrawlerConfig {
        crawled_db_path: fixture.root.join("unused-db"),
        gossip: stract::config::GossipConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            seed_nodes: None,
        },
        site_stats_path: fixture.root.join("unused-stats"),
        host_centrality_path: fixture.root.join("unused-centrality"),
        ingestion: fixture.client.policy().get().clone(),
        local_store_path: fixture.root.join("unused-store"),
        num_worker_threads: 1,
        check_intervals: Default::default(),
        daily_budget: Default::default(),
        init_crawl_db: false,
    };
    let converted: stract::config::CrawlerConfig = live.into();
    assert_eq!(
        stract::crawler::identity::build_user_agent(&converted.ingestion.identity).unwrap(),
        expected
    );
    fixture.finish().await;
}

#[test]
fn outcome_register() {
    let declared: std::collections::BTreeSet<_> = stract::crawler::ledger::Outcome::ALL_KINDS
        .into_iter()
        .collect();
    let source = include_str!("crawler_conformance.rs");
    assert_eq!(declared.len(), 34);
    for kind in declared {
        assert!(
            source.contains(&format!("outcome_{}", kind.replace('-', "_"))),
            "missing scenario for {kind}"
        );
    }
}

#[test]
fn sample_frozen_seeds() {
    use stract::crawler::sample::{Seed, SeedScope};
    let seeds: Vec<Seed> =
        serde_json::from_str(include_str!("../../../.spike/data/seeds.json")).unwrap();
    assert!(SeedScope::frozen(&seeds).is_ok());
    let mut changed = seeds.clone();
    changed[0].url = "https://unselected.invalid/page".into();
    assert!(SeedScope::frozen(&changed).is_err());
    assert!(SeedScope::frozen(&seeds[..199]).is_err());
    let mut duplicate = seeds;
    duplicate[1] = duplicate[0].clone();
    assert!(SeedScope::frozen(&duplicate).is_err());
}
#[tokio::test]
async fn sample_exact_scope() {
    use stract::crawler::{
        politeness::SystemClock,
        sample::{self, Seed},
    };
    let fixture = Fixture::new();
    let frozen: Vec<Seed> =
        serde_json::from_str(include_str!("../../../.spike/data/seeds.json")).unwrap();
    let scope = sample::SeedScope::frozen(&frozen).unwrap();
    let mut neighbor = url::Url::parse(&frozen[0].url).unwrap();
    neighbor.set_path("/unselected");
    assert!(!scope.allows(&neighbor));
    fixture.reply(
        "/first",
        Reply::new(302, "").header("Location", "/unselected"),
    );
    let seeds = vec![
        Seed {
            url: fixture.url("a.fixture.invalid", "/first").into(),
            category: Some("fixture".into()),
        },
        Seed {
            url: fixture.url("a.fixture.invalid", "/second").into(),
            category: Some("fixture".into()),
        },
    ];
    let summary = sample::run_loopback(
        &seeds,
        &fixture.root.join("sample-store"),
        &manual_policy(),
        fixture.endpoint.clone(),
        std::sync::Arc::new(SystemClock::default()),
    )
    .await
    .unwrap();
    assert_eq!(summary.targets, 2);
    assert_eq!(summary.histogram.get("redirected-off-seed"), Some(&1));
    assert_eq!(summary.histogram.get("saved"), Some(&1));
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    assert!(!fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.target == "/unselected"));
    let mut endpoint = fixture.endpoint.clone();
    endpoint = endpoint
        .restrict_targets(&[fixture.url("a.fixture.invalid", "/first")])
        .unwrap();
    let client = stract::crawler::robot_client::RobotClient::loopback(
        &fixture.root.join("exact-store"),
        &manual_policy(),
        endpoint,
        std::sync::Arc::new(SystemClock::default()),
        2,
    )
    .unwrap();
    assert!(!client
        .scope()
        .contains_exact(&fixture.url("a.fixture.invalid", "/unselected")));
    assert!(matches!(
        client
            .get(fixture.url("a.fixture.invalid", "/unselected"))
            .await,
        Err(Error::OffScope)
    ));
    drop(client);
    fixture.finish().await;
}

#[tokio::test]
async fn known_language_frontier() {
    let mut policy = manual_policy();
    policy.exclusions.language_deny = vec!["fr".into()];
    let mut fixture = Fixture::with_policy(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
    );
    fixture.reply(
        "/page",
        Reply::html("<html lang='fr'><title>Denied language</title></html>"),
    );
    let first = fixture.crawl("/page").await.unwrap();
    assert_eq!(first.outcome.kind(), "excluded-by-policy");
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    fixture.restart().await;
    let second = fixture.crawl("/page").await.unwrap();
    assert_eq!(second.outcome.kind(), "excluded-by-policy");
    assert!(second.fetch_attempts.is_empty());
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    fixture.finish().await;
}

#[tokio::test]
async fn sample_fixture_reconcile_and_commands() {
    use stract::crawler::sample::{self, Seed};
    let fixture = Fixture::new();
    fixture.reply(
        "/robots.txt",
        Reply::new(200, include_str!("fixtures/ingestion/robots.txt")),
    );
    fixture.reply(
        "/page",
        Reply::html(include_str!("fixtures/ingestion/page.html")),
    );
    fixture.reply(
        "/reserved",
        Reply::html(include_str!("fixtures/ingestion/rights.html")),
    );
    let seeds: Vec<_> = ["/page", "/reserved"]
        .into_iter()
        .map(|path| Seed {
            url: fixture.url("a.fixture.invalid", path).into(),
            category: Some("fixture".into()),
        })
        .collect();
    let store = fixture.root.join("sample-run");
    let summary = sample::run_loopback(
        &seeds,
        &store,
        &manual_policy(),
        fixture.endpoint.clone(),
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
    )
    .await
    .unwrap();
    assert!(summary.complete);
    assert_eq!(summary.targets, 2);
    assert_eq!(summary.histogram.get("saved"), Some(&1));
    assert_eq!(summary.histogram.get("parsed-not-retained"), Some(&1));
    assert_eq!(summary.policy_publication_status, "pending");
    assert_eq!(summary.http_attempts, 3);
    let seeds_path = fixture.root.join("fixture-seeds.json");
    std::fs::write(&seeds_path, serde_json::to_vec(&seeds).unwrap()).unwrap();
    let log = fixture.root.join("fixture-spike.log");
    let lines = seeds
        .iter()
        .map(|seed| serde_json::json!({"event":"saved","url":seed.url}).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&log, lines).unwrap();
    let ledger = store.join(&summary.ledger_file);
    let reconciliation = sample::reconcile(
        &seeds_path,
        &log,
        Some(&ledger),
        &fixture.root.join("reconciliation.json"),
    )
    .unwrap();
    assert_eq!(reconciliation.baseline_saved, 2);
    assert_eq!(reconciliation.current_rows, 2);
    let rows = stract::crawler::ledger::Ledger::read_rows(&ledger).unwrap();
    let body = store.join(rows.iter().find_map(|row| row.body_object.clone()).unwrap());
    let out = fixture.root.join("inspect.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_stract"))
        .args(["crawler", "inspect-warc", "--warc"])
        .arg(&body)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!(
        "fixture inspect-warc: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let inspection: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out).unwrap()).unwrap();
    assert_eq!(inspection["documents"], 1);
    assert_eq!(inspection["extended_documents"], 1);
    assert_eq!(inspection["parse_errors"], 0);
    let mut shortened = manual_policy();
    shortened.retention.raw_body_max_age_days = 0;
    let config = fixture.root.join("retention.toml");
    std::fs::write(&config, toml::to_string(&shortened).unwrap()).unwrap();
    for dry_run in [true, false] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_stract"));
        command
            .args(["crawler", "retention", "--store"])
            .arg(&store)
            .arg("--config")
            .arg(&config);
        if dry_run {
            command.arg("--dry-run");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!(
            "fixture retention dry_run={dry_run}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["expired"], 1);
        assert_eq!(report["deleted"], if dry_run { 0 } else { 1 });
        assert_eq!(body.exists(), dry_run);
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_stract"))
        .args(["crawler", "sample", "--seeds"])
        .arg(&seeds_path)
        .arg("--out")
        .arg(fixture.root.join("refused-live"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!fixture.root.join("refused-live").exists());
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    fixture.finish().await;
}

#[tokio::test]
async fn sample_invalid_inputs() {
    use stract::crawler::sample::{self, Seed};
    let fixture = Fixture::new();
    let seeds = vec![
        Seed {
            url: "invalid raw input".into(),
            category: None,
        },
        Seed {
            url: "ftp://fixture.invalid/page".into(),
            category: None,
        },
        Seed {
            url: "http://a.fixture.invalid:1/page".into(),
            category: None,
        },
    ];
    let summary = sample::run_loopback(
        &seeds,
        &fixture.root.join("invalid-run"),
        &manual_policy(),
        fixture.endpoint.clone(),
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
    )
    .await
    .unwrap();
    assert!(summary.complete);
    assert_eq!(summary.targets, 3);
    assert_eq!(summary.http_attempts, 0);
    assert_eq!(summary.histogram.values().sum::<u64>(), 3);
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}
#[tokio::test]
async fn robots_singleflight() {
    let fixture = Fixture::new();
    let (a, b) = tokio::join!(fixture.fetch("/one"), fixture.fetch("/two"));
    a.unwrap();
    b.unwrap();
    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.target == "/robots.txt")
            .count(),
        1
    );
    assert_eq!(requests[0].target, "/robots.txt");
    fixture.finish().await;
}
#[tokio::test]
async fn robots_token() {
    for (body, allowed) in [
        (
            "User-agent: AVASearchBot\nDisallow: /\nUser-agent: *\nAllow: /",
            false,
        ),
        (
            "User-agent: AVASEARCHBOT\nAllow: /\nUser-agent: *\nDisallow: /",
            true,
        ),
        (
            "User-agent: AVASearchBotLonger\nDisallow: /\nUser-agent: *\nAllow: /",
            true,
        ),
    ] {
        let fixture = Fixture::new();
        fixture.reply("/robots.txt", Reply::new(200, body));
        let result = fixture.fetch("/page").await;
        assert_eq!(result.is_ok(), allowed);
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            if allowed { 2 } else { 1 }
        );
        fixture.finish().await;
    }
}
#[tokio::test]
async fn robots_5xx() {
    let fixture = Fixture::new();
    fixture.reply("/robots.txt", Reply::new(503, "unavailable"));
    assert!(matches!(
        fixture.fetch("/page").await,
        Err(Error::RobotsUnreachable)
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}
#[tokio::test]
async fn robots_hash() {
    let fixture = Fixture::new();
    let body = "User-agent: *\nAllow: /\n";
    fixture.reply("/robots.txt", Reply::new(200, body));
    fixture.fetch("/page").await.unwrap();
    let snapshot = fixture
        .client
        .robots_txt_manager()
        .snapshot(&fixture.url("a.fixture.invalid", "/page"))
        .await
        .unwrap();
    let expected = ring::digest::digest(&ring::digest::SHA256, body.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(snapshot.body_sha256.value(), Some(&expected));
    fixture.finish().await;
}
async fn host_block(status: u16) {
    let fixture = Fixture::new();
    fixture.reply("/page", Reply::new(status, "denied"));
    let response = fixture
        .client
        .get(fixture.url("a.fixture.invalid", "/page"))
        .await
        .unwrap()
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), status);
    drop(response);
    assert!(matches!(
        fixture.fetch("/next").await,
        Err(Error::HostBlocked)
    ));
    let state = fixture
        .client
        .host_registry()
        .state(&HostKey::from_url(&fixture.url("a.fixture.invalid", "/page")).unwrap())
        .unwrap();
    assert!(
        state
            .blocked_until_utc
            .unwrap()
            .signed_duration_since(chrono::Utc::now())
            .num_seconds()
            >= 86_399
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    fixture.finish().await;
}
#[tokio::test]
async fn host_blocks_401() {
    host_block(401).await;
}
#[tokio::test]
async fn host_blocks_403() {
    host_block(403).await;
}
#[tokio::test]
async fn host_blocks_429() {
    host_block(429).await;
}
#[tokio::test]
async fn host_blocks_challenge() {
    let fixture = Fixture::new();
    fixture.reply(
        "/page",
        Reply::html("<html><form action='/challenge/start'>Verify you are human</form></html>"),
    );
    assert!(matches!(
        fixture.fetch("/page").await,
        Err(Error::Challenge)
    ));
    assert!(matches!(
        fixture.fetch("/next").await,
        Err(Error::HostBlocked)
    ));
    fixture.finish().await;
}

struct Answers {
    values: std::sync::Mutex<std::collections::VecDeque<Vec<std::net::IpAddr>>>,
    calls: std::sync::atomic::AtomicUsize,
}
impl Answers {
    fn new(values: Vec<Vec<&str>>) -> Self {
        Self {
            values: std::sync::Mutex::new(
                values
                    .into_iter()
                    .map(|v| v.into_iter().map(|s| s.parse().unwrap()).collect())
                    .collect(),
            ),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}
impl stract::crawler::network::AddressResolver for Answers {
    fn lookup<'a>(&'a self, _host: &'a str) -> stract::crawler::network::LookupFuture<'a> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let result = {
            let mut values = self.values.lock().unwrap();
            if values.len() > 1 {
                values.pop_front().unwrap()
            } else {
                values.front().unwrap().clone()
            }
        };
        Box::pin(async move { Ok(result) })
    }
}
#[tokio::test]
async fn ssrf_mixed_dns() {
    let mut policy = stract::config::ingestion::IngestionPolicy::default();
    policy.politeness.gap_ms = 500;
    let resolver = std::sync::Arc::new(Answers::new(vec![vec!["93.184.215.14", "127.0.0.1"]]));
    let fixture = Fixture::with_resolver(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
        Some(resolver),
    );
    assert!(fixture.fetch("/page").await.is_err());
    assert!(fixture.requests.lock().unwrap().is_empty());
    fixture.finish().await;
}
#[tokio::test]
async fn ssrf_rebinding() {
    let mut policy = stract::config::ingestion::IngestionPolicy::default();
    policy.politeness.gap_ms = 500;
    let resolver =
        std::sync::Arc::new(Answers::new(vec![vec!["93.184.215.14"], vec!["127.0.0.1"]]));
    let fixture = Fixture::with_resolver(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        2,
        Some(resolver.clone()),
    );
    let snapshot = fixture
        .client
        .robots_txt_manager()
        .snapshot(&fixture.url("a.fixture.invalid", "/page"))
        .await
        .unwrap();
    assert_eq!(
        snapshot.decision,
        stract::crawler::robots_txt::RobotsDecision::AllowRule
    );
    assert_eq!(resolver.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(matches!(
        fixture.fetch("/page").await,
        Err(Error::RefusedPrivateAddress)
    ));
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}
#[tokio::test]
async fn robots_expiry() {
    use stract::crawler::{politeness::ManualClock, robots_txt::RobotsDecision};
    let clock = std::sync::Arc::new(ManualClock::new(chrono::Utc::now()));
    let mut policy = stract::config::ingestion::IngestionPolicy::default();
    policy.politeness.gap_ms = 500;
    policy.robots.cache_secs = 1;
    let fixture = Fixture::with_policy(policy, clock.clone(), 2);
    let url = fixture.url("a.fixture.invalid", "/page");
    fixture.reply("/robots.txt", Reply::new(200, "User-agent: *\nAllow: /"));
    fixture.reply("/robots.txt", Reply::new(200, "User-agent: *\nDisallow: /"));
    assert_eq!(
        fixture
            .client
            .robots_txt_manager()
            .snapshot(&url)
            .await
            .unwrap()
            .decision,
        RobotsDecision::AllowRule
    );
    clock.advance(999).unwrap();
    assert_eq!(
        fixture
            .client
            .robots_txt_manager()
            .snapshot(&url)
            .await
            .unwrap()
            .decision,
        RobotsDecision::AllowRule
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    clock.advance(1).unwrap();
    assert_eq!(
        fixture
            .client
            .robots_txt_manager()
            .snapshot(&url)
            .await
            .unwrap()
            .decision,
        RobotsDecision::DisallowRule
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    fixture.finish().await;
}
#[tokio::test]
async fn robots_recovery() {
    use stract::crawler::{politeness::ManualClock, robots_txt::RobotsDecision};
    let clock = std::sync::Arc::new(ManualClock::new(chrono::Utc::now()));
    let mut policy = stract::config::ingestion::IngestionPolicy::default();
    policy.politeness.gap_ms = 500;
    let fixture = Fixture::with_policy(policy, clock.clone(), 2);
    let url = fixture.url("a.fixture.invalid", "/page");
    fixture.reply("/robots.txt", Reply::new(503, "temporary"));
    assert_eq!(
        fixture
            .client
            .robots_txt_manager()
            .snapshot(&url)
            .await
            .unwrap()
            .decision,
        RobotsDecision::DisallowUnreachable
    );
    clock.advance(299_999).unwrap();
    assert_eq!(
        fixture
            .client
            .robots_txt_manager()
            .snapshot(&url)
            .await
            .unwrap()
            .decision,
        RobotsDecision::DisallowUnreachable
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    clock.advance(600_001).unwrap();
    assert_eq!(
        fixture
            .client
            .robots_txt_manager()
            .snapshot(&url)
            .await
            .unwrap()
            .decision,
        RobotsDecision::AllowRule
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    fixture.finish().await;
}
#[tokio::test]
async fn robots_size_limit() {
    let fixture = Fixture::new();
    fixture.reply("/robots.txt", Reply::new(200, vec![b' '; 512_001]));
    assert!(fixture.fetch("/page").await.is_err());
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    fixture.finish().await;
}
#[tokio::test]
async fn throttle_concurrency() {
    use std::sync::atomic::Ordering;
    let mut policy = stract::config::ingestion::IngestionPolicy::default();
    policy.politeness.gap_ms = 500;
    policy.politeness.max_concurrent_per_host = 2;
    let fixture = Fixture::with_policy(
        policy,
        std::sync::Arc::new(stract::crawler::politeness::SystemClock::default()),
        5,
    );
    for path in ["/a", "/b", "/c"] {
        let mut reply = Reply::html("<title>Fixture</title><p>bounded body</p>");
        reply.body_delay = std::time::Duration::from_millis(1100);
        fixture.reply(path, reply);
    }
    let (a, b, c) = tokio::join!(
        fixture.fetch("/a"),
        fixture.fetch("/b"),
        fixture.fetch("/c")
    );
    a.unwrap();
    b.unwrap();
    c.unwrap();
    assert!(fixture.max_connections.load(Ordering::SeqCst) <= 2);
    assert_eq!(fixture.max_connections.load(Ordering::SeqCst), 2);
    let requests = fixture.requests.lock().unwrap().clone();
    for pair in requests.windows(2) {
        assert!(
            pair[1].arrived.duration_since(pair[0].arrived)
                >= std::time::Duration::from_millis(500)
        );
    }
    fixture.finish().await;
}
#[tokio::test]
async fn robots_paths() {
    for path in [
        "/blocked/",
        "/blocked%2fchild",
        "//blocked//child",
        "/allowed/..%2fblocked/x",
        "/allowed/%2e%2e%2fblocked/x",
        "/allowed/%2E%2E/blocked/x",
        "/blocked/%2e/x",
        "/allowed/..%2f..%2fblocked/",
    ] {
        let fixture = Fixture::new();
        fixture.reply(
            "/robots.txt",
            Reply::new(
                200,
                "User-agent: *\nDisallow: /blocked/\nAllow: /blocked/index.html",
            ),
        );
        let result = fixture.fetch(path).await;
        if path == "/allowed/..%2f..%2fblocked/" {
            assert!(
                matches!(result, Err(Error::InvalidUrl)),
                "{path}: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(Error::DisallowedPath)),
                "{path}: {result:?}"
            );
        }
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn robots_dot_segments() {
    for path in [
        "/allowed/..%2fblocked/x",
        "/allowed/%2e%2e%2fblocked/x",
        "/allowed/%2E%2E/blocked/x",
        "/blocked/%2e/x",
        "/allowed/..%2f..%2fblocked/",
        "/allowed/%2e%2e%2f%2e%2e/x",
        "/allowed/x",
    ] {
        let fixture = Fixture::new();
        fixture.reply(
            "/robots.txt",
            Reply::new(200, "User-agent: *\nDisallow: /blocked/\nAllow: /allowed/"),
        );
        let result = fixture.fetch(path).await;
        if path == "/allowed/x" {
            assert!(result.is_ok());
            assert_eq!(fixture.requests.lock().unwrap().len(), 2);
        } else {
            if ["/allowed/..%2f..%2fblocked/", "/allowed/%2e%2e%2f%2e%2e/x"].contains(&path) {
                assert!(
                    matches!(result, Err(Error::InvalidUrl)),
                    "{path}: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(Error::DisallowedPath)),
                    "{path}: {result:?}"
                );
            }
            assert_eq!(fixture.requests.lock().unwrap().len(), 1, "{path}");
        }
        fixture.finish().await;
    }
}

#[tokio::test]
async fn invalid_header_bytes() {
    for name in [
        "x-robots-tag",
        "cache-control",
        "tdm-reservation",
        "tdm-policy",
        "content-type",
        "location",
        "etag",
        "last-modified",
        "retry-after",
        "cf-mitigated",
        "content-language",
    ] {
        let fixture = Fixture::new();
        let mut reply = Reply::html("<title>Header bytes</title><p>Owned body</p>")
            .raw_header(name, b"invalid-\xff-bytes");
        reply = match name {
            "location" => {
                reply.status = 302;
                reply.header(name, "/allowed")
            }
            "retry-after" => {
                reply.status = 429;
                reply.header(name, "1200")
            }
            "etag" => reply.header(name, "\"valid\""),
            "last-modified" => reply.header(name, "Wed, 01 Jan 2025 00:00:00 GMT"),
            "content-language" => reply.header(name, "en"),
            "tdm-reservation" => reply.header(name, "0"),
            _ => reply,
        };
        fixture.reply("/page", reply);
        let row = fixture.crawl("/page").await.unwrap();
        let record = &row.record;
        match name {
            "x-robots-tag" => {
                assert!(record.directives.noindex && record.directives.nofollow);
                assert!(!record.index_eligible);
                let seen = serde_json::to_value(&record.directives_seen).unwrap();
                assert!(seen
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["source"] == "header"
                        && v["name"] == "invalid"
                        && v["applies"] == true
                        && v["parse_error"] == "invalid-header-bytes"));
            }
            "cache-control" => assert_eq!(
                serde_json::to_value(record.body_retention).unwrap(),
                "no-store"
            ),
            "tdm-reservation" => {
                assert_eq!(
                    serde_json::to_value(record.rights.tdm_reservation).unwrap(),
                    "reserved"
                );
                assert!(serde_json::to_value(&record.rights.parse_errors)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("invalid-header-bytes")));
            }
            "tdm-policy" => assert!(record.rights.tdm_policy_present),
            "content-type" => {
                assert_eq!(row.outcome.kind(), "invalid-content-type");
                assert_eq!(
                    serde_json::to_value(&row.outcome).unwrap()["reason"],
                    "invalid-header-bytes"
                );
            }
            "location" => assert_eq!(row.outcome.kind(), "redirect-invalid"),
            "etag" => assert!(record.validators.etag.is_none()),
            "last-modified" => assert!(record.validators.last_modified.is_none()),
            "retry-after" => {
                assert!(record.retry_after_invalid);
                assert!(record.blocked_until_utc.is_some());
            }
            "cf-mitigated" => {
                assert_eq!(row.outcome.kind(), "http-status");
                assert_eq!(
                    serde_json::to_value(&row.outcome).unwrap()["reason"],
                    "challenge"
                );
                assert!(record.blocked_until_utc.is_some());
            }
            "content-language" => assert!(record.declared_language.is_none()),
            _ => unreachable!(),
        }
        if [
            "cache-control",
            "tdm-reservation",
            "tdm-policy",
            "content-type",
            "location",
            "retry-after",
            "cf-mitigated",
        ]
        .contains(&name)
        {
            assert!(row.body_object.is_none(), "{name}");
            assert_eq!(
                std::fs::read_dir(fixture.root.join("objects"))
                    .unwrap()
                    .count(),
                0,
                "{name}"
            );
        }
        let disk =
            stract::crawler::ledger::Ledger::read_rows(&fixture.root.join("ledger.jsonl")).unwrap();
        assert_eq!(
            serde_json::to_value(&disk[0]).unwrap(),
            serde_json::to_value(&row).unwrap()
        );
        fixture.finish().await;
    }
}
