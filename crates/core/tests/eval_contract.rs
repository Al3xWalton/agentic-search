// SPDX-License-Identifier: AGPL-3.0-only
//! Independent synthetic witnesses for frozen URL, metric, transport and local I/O contracts.
//! Fixtures contain no retained labels or learned answers; expected values are written directly.
//! Tests never contact a non-loopback endpoint or fetch a returned URL.

use serde_json::json;
use std::collections::HashSet;
use stract::eval::{
    self,
    labels::Label,
    metrics::{self, Row},
    normalize::normalize,
    EvalError, Planner, Suite,
};

macro_rules! normalization {
    ($name:ident, $raw:expr, $expected:expr) => {
        #[test]
        fn $name() {
            assert_eq!(normalize($raw).unwrap(), $expected);
        }
    };
}
normalization!(
    norm_host_lowercase,
    "https://EXAMPLE.test/Mixed",
    "example.test/Mixed"
);
normalization!(
    norm_one_www,
    "https://WWW.www.Example.test/",
    "www.example.test/"
);
normalization!(
    norm_ignores_scheme,
    "ftp://example.test:443/x",
    "example.test/x"
);
#[test]
fn norm_ports_python() {
    for scheme in ["http", "https"] {
        for port in [0, 80, 443] {
            assert_eq!(
                normalize(&format!("{scheme}://e.test:{port}/")).unwrap(),
                "e.test/"
            );
        }
    }
    assert_eq!(normalize("https://e.test:8080/").unwrap(), "e.test:8080/");
}
#[test]
fn norm_all_trailing_slashes_root() {
    for (raw, expected) in [
        ("https://e.test", "e.test/"),
        ("https://e.test////", "e.test/"),
        ("https://e.test/path///", "e.test/path"),
    ] {
        assert_eq!(normalize(raw).unwrap(), expected);
    }
}
normalization!(
    norm_path_case_literal,
    "https://e.test/Case/PATH/",
    "e.test/Case/PATH"
);
normalization!(
    norm_preserves_dot_segments,
    "https://e.test/a/../b/./;x",
    "e.test/a/../b/./;x"
);
normalization!(
    norm_query_form_decode,
    "https://e.test/?q=a+b%20c&u=%C3%A9&z=%FF",
    "e.test/?q=a+b+c&u=%C3%A9&z=%EF%BF%BD"
);
normalization!(
    norm_query_blanks,
    "https://e.test/?b=&a&&=x&",
    "e.test/?=x&a=&b="
);
normalization!(
    norm_query_duplicates,
    "https://e.test/?x=2&x=1&x=1",
    "e.test/?x=1&x=1&x=2"
);
normalization!(
    norm_tracking_casefold,
    "https://e.test/?UtM_A=x&GCLID=y&FbClId=z&keep=utm_a",
    "e.test/?keep=utm_a"
);
normalization!(
    norm_pairs_tuple_sort,
    "https://e.test/?b=0&a=z&a=A&a=0",
    "e.test/?a=0&a=A&a=z&b=0"
);
normalization!(
    norm_python_urlencode,
    "https://e.test/?q=~+%C3%A9%2f",
    "e.test/?q=~+%C3%A9%2F"
);
normalization!(
    norm_ampersand_only,
    "https://e.test/?a=1;b=2",
    "e.test/?a=1%3Bb%3D2"
);
normalization!(
    norm_omits_empty_query_delimiter,
    "https://e.test/?utm_x=a&fbclid=z",
    "e.test/"
);
#[test]
fn norm_malformed_url_errors() {
    for raw in [
        "https://e.test:cat/x",
        "https://e.test:65536/x",
        "https://[::1/x",
        "https://[wrong]/",
        "https://e.test:-1/",
    ] {
        assert_eq!(normalize(raw), Err(EvalError::InvalidUrl));
    }
}
normalization!(
    norm_ipv6_hostname_python,
    "https://[::1]:9000/x",
    "::1:9000/x"
);
normalization!(
    norm_ignores_fragment,
    "https://e.test/x#something?ignored=1",
    "e.test/x"
);
normalization!(
    norm_ignores_userinfo,
    "https://user:password@e.test/x",
    "e.test/x"
);
normalization!(
    norm_path_percent_literal,
    "https://e.test/%2f/%2F/é",
    "e.test/%2f/%2F/é"
);
normalization!(
    norm_preserves_interior_slashes,
    "https://e.test/a//b///",
    "e.test/a//b"
);

fn label(id: &str, answers: &[&str]) -> Label {
    Label {
        id: id.into(),
        category: "factual".into(),
        query: "synthetic compiler manual".into(),
        acceptable_urls: answers.iter().map(|s| (*s).into()).collect(),
        metadata: Default::default(),
    }
}
fn urls(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}
fn corpus(values: &[&str]) -> HashSet<String> {
    values.iter().map(|s| normalize(s).unwrap()).collect()
}
fn score(label: &Label, found: &[&str], latency: f64) -> Row {
    Row::score(
        label,
        &urls(found),
        &corpus(&["https://e.test/a", "https://e.test/b"]),
        latency,
        Some(2.0),
    )
    .unwrap()
}
#[test]
fn metric_cutoff_first() {
    let mut found = vec!["https://other.test/a"; 10];
    found.push("https://e.test/a");
    let row = score(&label("x", &["https://e.test/a"]), &found, 1.0);
    assert_eq!(row.recall_at_10, Some(0.0));
    assert_eq!(row.top10_urls.len(), 10);
}
#[test]
fn metric_recall_set_denominator() {
    let row = score(
        &label(
            "x",
            &["https://e.test/a", "https://e.test/b", "https://e.test/a/"],
        ),
        &["https://e.test/a"],
        1.0,
    );
    assert_eq!(row.recall_at_10, Some(0.5));
}
#[test]
fn metric_exact_page_identity() {
    let row = score(
        &label("x", &["https://e.test/a"]),
        &["https://e.test/b"],
        1.0,
    );
    assert_eq!(row.recall_at_10, Some(0.0));
}
#[test]
fn metric_matched_urls_raw_order() {
    let row = score(
        &label("x", &["https://e.test/a"]),
        &[
            "https://WWW.e.test/a/",
            "http://e.test/a",
            "https://e.test/b",
        ],
        1.0,
    );
    assert_eq!(
        row.matched_urls,
        urls(&["https://WWW.e.test/a/", "http://e.test/a"])
    );
}
#[test]
fn metric_sample_membership_slots() {
    let row = score(
        &label("x", &["https://e.test/a"]),
        &[
            "https://e.test/a",
            "https://e.test/a",
            "https://outside.test/",
        ],
        1.0,
    );
    assert_eq!(row.top10_urls_in_sample, 2);
}
#[test]
fn metric_mean_per_query() {
    let rows = [
        score(
            &label("a", &["https://e.test/a", "https://e.test/b"]),
            &["https://e.test/a"],
            1.0,
        ),
        score(
            &label("b", &["https://e.test/a"]),
            &["https://e.test/a"],
            2.0,
        ),
    ];
    assert_eq!(metrics::summary(&rows)["recall_at_10"], 0.75);
}
#[test]
fn metric_category_grouping() {
    let mut rows = vec![
        score(&label("a", &["https://e.test/a"]), &[], 1.0),
        score(
            &label("b", &["https://e.test/a"]),
            &["https://e.test/a"],
            2.0,
        ),
        score(
            &label("c", &["https://e.test/a"]),
            &["https://e.test/a"],
            3.0,
        ),
    ];
    rows[0].category = "recent_news".into();
    rows[2].category = "recent_news".into();
    let s = metrics::summary(&rows);
    assert_eq!(s["categories"][0]["category"], "recent_news");
    assert_eq!(s["categories"][0]["recall_at_10"], 0.5);
    assert_eq!(s["categories"][0]["attempted"], 2);
    assert_eq!(s["recall_at_10"], 2.0 / 3.0);
}
#[test]
fn metric_failure_denominators() {
    let l = label("x", &["https://e.test/a"]);
    let failed = Row::failed(&l, EvalError::Network, 30.0).unwrap();
    assert!(
        failed.latency_ms.is_none()
            && failed.recall_at_10.is_none()
            && failed.server_duration_ms.is_none()
    );
    assert!(failed.top10_urls.is_empty() && failed.matched_urls.is_empty());
    let s = metrics::summary(&[failed, score(&l, &[], 1.0)]);
    assert_eq!(s["attempted"], 2);
    assert_eq!(s["successful"], 1);
    assert_eq!(s["zero_results"], 1);
    assert_eq!(s["p95_ms"], 1.0);
}
#[test]
fn metric_zero_is_empty_top10() {
    assert!(
        !score(
            &label("x", &["https://e.test/a"]),
            &["https://other.test/"],
            1.0
        )
        .zero_results
    );
}
#[test]
fn metric_empty_summary_nulls() {
    let s = metrics::summary(&[]);
    for key in ["recall_at_10", "p50_ms", "p95_ms"] {
        assert!(s[key].is_null());
    }
    assert_eq!(s["zero_results"], 0);
}
#[test]
fn metric_p50_even_median() {
    assert_eq!(metrics::percentiles(&[9.0, 1.0, 5.0]).0, Some(5.0));
    assert_eq!(metrics::percentiles(&[9.0, 1.0, 5.0, 2.0]).0, Some(3.5));
}
#[test]
fn metric_p95_nearest_rank() {
    for (n, expected) in [(1, 1.0), (20, 19.0), (50, 48.0)] {
        assert_eq!(
            metrics::percentiles(&(1..=n).map(f64::from).collect::<Vec<_>>()).1,
            Some(expected)
        );
    }
}
fn complete(recall: f64, zeros: usize, latency: f64) -> Vec<Row> {
    (0..50)
        .map(|n| {
            let mut row = score(
                &label(&format!("id{n}"), &["https://e.test/a"]),
                &["https://e.test/a"],
                latency,
            );
            row.recall_at_10 = Some(recall);
            row.zero_results = n < zeros;
            row
        })
        .collect()
}
#[test]
fn acceptance_recall_strict() {
    let mut rows = (0..50)
        .map(|n| {
            score(
                &label(&format!("id{n}"), &["https://e.test/a"]),
                &[if n < 18 {
                    "https://e.test/a"
                } else {
                    "https://e.test/b"
                }],
                1.0,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(metrics::summary(&rows)["recall_at_10"], json!(18.0 / 50.0));
    assert_eq!(
        metrics::acceptance(&rows, Suite::HeldOut, Planner::On)["checks"]["recall_above_036"],
        false
    );
    rows[18] = score(
        &label("id18", &["https://e.test/a"]),
        &["https://e.test/a"],
        1.0,
    );
    assert_eq!(
        metrics::acceptance(&rows, Suite::HeldOut, Planner::On)["passed"],
        true
    );
}

#[test]
fn acceptance_zero_strict() {
    assert_eq!(
        metrics::acceptance(&complete(0.5, 5, 1.0), Suite::HeldOut, Planner::On)["checks"]
            ["zero_rate_below_010"],
        false
    );
    assert_eq!(
        metrics::acceptance(&complete(0.5, 4, 1.0), Suite::HeldOut, Planner::On)["passed"],
        true
    );
}
#[test]
fn acceptance_latency_strict() {
    assert_eq!(
        metrics::acceptance(&complete(0.5, 0, 50.0), Suite::HeldOut, Planner::On)["checks"]
            ["p95_below_50_ms"],
        false
    );
    assert_eq!(
        metrics::acceptance(&complete(0.5, 0, 49.999), Suite::HeldOut, Planner::On)["passed"],
        true
    );
}
#[test]
fn acceptance_complete_sample() {
    let mut rows = complete(0.5, 0, 1.0);
    rows.pop();
    assert_eq!(
        metrics::acceptance(&rows, Suite::HeldOut, Planner::On)["checks"]["all_50_successful"],
        false
    );
}
#[test]
fn acceptance_suite_specific() {
    let rows = complete(0.1, 19, 60.0);
    assert_eq!(
        metrics::acceptance(&rows, Suite::HeldOut, Planner::Off)["passed"],
        true
    );
    assert!(metrics::acceptance(&rows, Suite::Diagnostic, Planner::On)["passed"].is_null());
    assert_eq!(
        metrics::acceptance(&rows, Suite::HeldOut, Planner::On)["passed"],
        false
    );
}
#[test]
fn diff_identity_required() {
    let old = complete(0.5, 0, 1.0);
    let mut new = old.clone();
    new[0].query.push('x');
    assert_eq!(
        eval::diff::compare(&old, &new),
        Err(EvalError::IdentityMismatch)
    );
    new = old.clone();
    new.pop();
    assert_eq!(
        eval::diff::compare(&old, &new),
        Err(EvalError::IdentityMismatch)
    );
}
#[test]
fn diff_joins_ids() {
    let old = vec![
        score(
            &label("a", &["https://e.test/a"]),
            &["https://e.test/a"],
            1.0,
        ),
        score(&label("b", &["https://e.test/a"]), &[], 2.0),
    ];
    let mut new = old.clone();
    new.reverse();
    new[0] = score(
        &label("b", &["https://e.test/a"]),
        &["https://e.test/a"],
        3.0,
    );
    let diff = eval::diff::compare(&old, &new).unwrap();
    assert_eq!(diff["rows"][1]["id"], "b");
    assert_eq!(diff["rows"][1]["gained_matches"], json!(["e.test/a"]));
    assert_eq!(diff["rows"][1]["latency_delta_ms"], 1.0);
}
#[test]
fn runner_exact_spike_request() {
    let raw = "Please Find Mixed-CASE compiler errors?";
    assert_eq!(
        eval::runner::request(raw),
        json!({"query":raw,"numResults":10,"page":0,"flattenResponse":true,"countResultsExact":true})
    );
}
#[test]
fn endpoint_literal_loopback_only() {
    for raw in ["http://localhost:90", "http://example.test:80"] {
        assert_eq!(
            eval::endpoint::Endpoint::parse(raw),
            Err(EvalError::InvalidEndpoint)
        );
    }
    assert!(eval::endpoint::Endpoint::parse("http://127.0.0.1:80").is_ok());
    assert!(eval::endpoint::Endpoint::parse("http://[::1]:80/").is_ok());
}
#[test]
fn endpoint_no_address_normalization_bypass() {
    for raw in [
        "http://2130706433:80",
        "http://0177.0.0.1:80",
        "http://0x7f000001:80",
        "http://[::ffff:127.0.0.1]:80",
        "http://%31%32%37.0.0.1:80",
    ] {
        assert!(eval::endpoint::Endpoint::parse(raw).is_err());
        // Default ports disappear during URL normalization, hiding an unsafe parser order.
        let explicit = raw.replace(":80", ":57300");
        assert!(
            eval::endpoint::Endpoint::parse(&explicit).is_err(),
            "{explicit}"
        );
        assert!(
            eval::endpoint::Endpoint::shard(explicit.strip_prefix("http://").unwrap()).is_err()
        );
    }
}
#[test]
fn endpoint_base_shape() {
    for raw in [
        "https://127.0.0.1:80",
        "http://a@127.0.0.1:80",
        "http://127.0.0.1:80/x",
        "http://127.0.0.1:80?x",
        "http://127.0.0.1:80#x",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:80//",
    ] {
        assert!(eval::endpoint::Endpoint::parse(raw).is_err(), "{raw}");
    }
}

#[path = "support/eval_http.rs"]
mod eval_http;
struct Scratch(file_store::temp::TempDir);
impl std::ops::Deref for Scratch {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
impl AsRef<std::path::Path> for Scratch {
    fn as_ref(&self) -> &std::path::Path {
        self.0.as_ref()
    }
}
fn temporary() -> Scratch {
    Scratch(stract::gen_temp_dir().unwrap())
}
fn private_output(dir: &std::path::Path, name: &str) -> eval::output::Output {
    eval::output::Output::reserve(&dir.join(name), true).unwrap()
}
fn response_body() -> serde_json::Value {
    json!({"queryPlan":{"version":1,"mode":"staged","stages":[{"id":"strict","renderedQuery":"BOOL(must=TERM(test))","producedResults":true}]},"webpages":[{"url":"https://e.test/a","planStage":"strict"}],"searchDurationMs":2})
}
#[test]
fn runner_checks_plan_mode() {
    let value = response_body();
    assert!(eval::runner::response(&value, Planner::On).is_ok());
    assert_eq!(
        eval::runner::response(&value, Planner::Off),
        Err(EvalError::InvalidResponse)
    );
}
#[tokio::test]
async fn runner_client_wall_clock() {
    use std::time::Duration;
    let body = serde_json::to_vec(&response_body()).unwrap();
    let (endpoint, server) =
        eval_http::serve(vec![(200, body.clone(), Duration::from_millis(35))]).await;
    let dir = temporary();
    let out = private_output(&dir, "clock.json");
    let result = eval::runner::attempt(
        &endpoint,
        "Original QUERY",
        &out,
        0,
        Duration::from_secs(2),
        eval::runner::MAX_RESPONSE_BYTES,
    )
    .await
    .unwrap();
    assert!(result.elapsed_ms >= 30.0);
    assert_eq!(result.bytes, body);
    assert!(result.error.is_none());
    let (_, _, _, server_ms) =
        eval::runner::response(&serde_json::from_slice(&result.bytes).unwrap(), Planner::On)
            .unwrap();
    assert_eq!(server_ms, 2.0);
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, eval::runner::request("Original QUERY"));
    assert_eq!(requests[0].line, "POST /beta/api/search HTTP/1.1");
    assert!(requests[0]
        .headers
        .to_lowercase()
        .contains("accept-encoding: identity"));
    assert!(requests[0]
        .headers
        .to_lowercase()
        .contains("connection: close"));
}
#[tokio::test]
async fn runner_sequential_fresh_connections() {
    use std::time::Duration;
    let mut labels = vec![
        label("first", &["https://e.test/a"]),
        label("second", &["https://e.test/a"]),
        label("third", &["https://e.test/a"]),
    ];
    for row in &mut labels {
        row.query = format!("{} query", row.id);
    }
    let queries: Vec<_> = labels.iter().map(|l| l.query.clone()).collect();
    let fixture = CellFixture::new(labels);
    let body = serde_json::to_vec(&response_body()).unwrap();
    let (endpoint, server) =
        eval_http::serve(vec![(200, body, Duration::from_millis(10)); 3]).await;
    let result = fixture.command(&endpoint.base).output().await.unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let requests = server.await.unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|r| r.body["query"].as_str().unwrap())
            .collect::<Vec<_>>(),
        queries
    );
}
#[tokio::test]
async fn runner_no_retries() {
    use std::time::Duration;
    let (endpoint, server) = eval_http::serve(vec![(503, b"{}".to_vec(), Duration::ZERO)]).await;
    let dir = temporary();
    let out = private_output(&dir, "failure.json");
    let result = eval::runner::attempt(&endpoint, "compiler", &out, 0, Duration::from_secs(2), 100)
        .await
        .unwrap();
    assert_eq!(result.error, Some(EvalError::HttpStatus));
    assert_eq!(server.await.unwrap().len(), 1);
}
#[tokio::test]
async fn runner_total_timeout() {
    use std::time::Duration;
    assert_eq!(eval::runner::TIMEOUT_SECONDS, 60);
    let (endpoint, server) = eval_http::slow_stream().await;
    let dir = temporary();
    let out = private_output(&dir, "timeout.json");
    let result = eval::runner::attempt(
        &endpoint,
        "compiler",
        &out,
        0,
        Duration::from_millis(120),
        100,
    )
    .await
    .unwrap();
    assert_eq!(result.error, Some(EvalError::Timeout));
    assert_eq!(result.status, Some(200));
    assert_eq!(std::fs::read(&result.raw_path).unwrap(), result.bytes);
    assert!(result.elapsed_ms < 200.0);
    server.await.unwrap();
}
#[tokio::test]
async fn runner_response_byte_bound() {
    use std::time::Duration;
    let cap = eval::runner::MAX_RESPONSE_BYTES;
    let (endpoint, server) = eval_http::serve(vec![
        (200, vec![b'x'; cap], Duration::ZERO),
        (200, vec![b'x'; cap + 1], Duration::ZERO),
    ])
    .await;
    let dir = temporary();
    let out = private_output(&dir, "cap.json");
    let exact = eval::runner::attempt(&endpoint, "compiler", &out, 0, Duration::from_secs(10), cap)
        .await
        .unwrap();
    assert_eq!(exact.bytes.len(), cap);
    assert!(exact.error.is_none());
    let over = eval::runner::attempt(&endpoint, "compiler", &out, 1, Duration::from_secs(10), cap)
        .await
        .unwrap();
    assert_eq!(over.error, Some(EvalError::ResponseLimit));
    assert_eq!(over.status, Some(200));
    assert_eq!(over.bytes, vec![b'x'; cap]);
    assert_eq!(std::fs::read(&over.raw_path).unwrap(), over.bytes);
    server.await.unwrap();
}

#[tokio::test]
async fn runner_transport_failure_retains_evidence() {
    let (endpoint, server) = eval_http::truncated_body().await;
    let dir = temporary();
    let out = private_output(&dir, "truncated.json");
    let result = eval::runner::attempt(
        &endpoint,
        "compiler",
        &out,
        0,
        std::time::Duration::from_secs(5),
        100,
    )
    .await
    .unwrap();
    assert_eq!(result.error, Some(EvalError::Network));
    assert_eq!(result.status, Some(200));
    assert_eq!(result.bytes, b"partial");
    assert_eq!(std::fs::read(&result.raw_path).unwrap(), result.bytes);
    server.await.unwrap();
}
#[test]
fn output_create_new() {
    use std::io::Write;
    let dir = temporary();
    let path = dir.join("existing.json");
    let mut file = eval::output::create(&path).unwrap();
    file.write_all(b"untouched").unwrap();
    assert!(matches!(
        eval::output::Output::reserve(&path, true),
        Err(EvalError::OutputExists)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"untouched");
}
#[test]
fn output_absolute_normal_components() {
    let dir = temporary();
    for name in ["./bad.json", "a/../bad.json"] {
        assert!(eval::output::Output::reserve(&dir.join(name), true).is_err());
    }
    assert_eq!(
        eval::output::external(std::path::Path::new("relative.json"), &[]),
        Err(EvalError::Argument {
            argument: eval::Argument::Out,
            reason: eval::ArgumentReason::AbsoluteOutput
        })
    );
}
#[test]
fn output_no_symlink_components() {
    live_symlink_ancestors_are_rejected();
    let dir = temporary();
    let link = dir.join("link");
    std::os::unix::fs::symlink(dir.join("missing"), &link).unwrap();
    assert!(eval::output::Output::reserve(&link, false).is_err());
    assert!(eval::output::Output::reserve(&link.join("out.json"), false).is_err());
}
#[test]
fn output_external_no_alias() {
    let dir = temporary();
    let input = dir.join("input.json");
    eval::output::create(&input).unwrap();
    assert!(eval::output::external(&dir.join("out.json"), &[input]).is_err());
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("forbidden.json");
    assert!(eval::output::external(&repository, &[]).is_err());
}
#[test]
fn io_regular_files_only() {
    let dir = temporary();
    assert!(eval::input::read(&dir).is_err());
    assert!(eval::input::read(std::path::Path::new("/dev/null")).is_err());
    let fifo = dir.join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(eval::input::read(&fifo).is_err());
}
#[test]
fn output_ancestors_private_by_default() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temporary();
    let unsafe_dir = dir.join("writable");
    std::fs::create_dir(&unsafe_dir).unwrap();
    std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(eval::output::Output::reserve(&unsafe_dir.join("out.json"), true).is_err());
    let path = dir.join("private/tail/out.json");
    let output = eval::output::Output::reserve(&path, true).unwrap();
    output.finish(&json!({})).unwrap();
    assert_eq!(
        std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}
#[tokio::test]
async fn raw_paths_numeric_and_reserved() {
    raw_label_ids_do_not_select_paths().await;
    let dir = temporary();
    let out = private_output(&dir, "run.json");
    let (path, _) = out.raw(2).unwrap();
    assert_eq!(path.file_name().unwrap(), "0002.json");
    assert!(out.raw(2).is_err());
    assert!(out.raw(1000).is_err());
    assert!(matches!(
        eval::output::Output::reserve(&dir.join("run.json"), true),
        Err(EvalError::OutputExists)
    ));
}
#[test]
fn output_partial_run_not_complete() {
    failed_serialization_keeps_partial_without_completion();
    let dir = temporary();
    {
        let _out = private_output(&dir, "partial.json");
    }
    assert!(dir.join("partial.json").exists());
    assert!(!dir.join("partial.complete").exists());
}
#[test]
fn output_private_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temporary();
    let out = private_output(&dir, "mode.json");
    let (raw, _) = out.raw(0).unwrap();
    out.finish(&json!({})).unwrap();
    for path in [dir.join("mode.json"), dir.join("mode.complete"), raw] {
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn inputs_read_only_no_symlinks() {
    let dir = temporary();
    let input = dir.join("input");
    eval::output::create(&input).unwrap();
    let link = dir.join("linked");
    std::os::unix::fs::symlink(&input, &link).unwrap();
    assert!(eval::input::read(&link).is_err());
    let before = std::fs::metadata(&input).unwrap().modified().unwrap();
    eval::input::read(&input).unwrap();
    assert_eq!(
        std::fs::metadata(input).unwrap().modified().unwrap(),
        before
    );
}
#[test]
fn paths_reject_controls() {
    let dir = temporary();
    for control in ['\0', '\r', '\n', '\t', '\u{7f}'] {
        let path = dir.join(format!("name{control}.json"));
        assert!(eval::output::Output::reserve(&path, false).is_err());
        assert!(eval::input::read(&path).is_err());
    }
}
#[test]
fn eval_input_file_byte_bound() {
    let dir = temporary();
    let path = dir.join("large.json");
    let file = eval::output::create(&path).unwrap();
    file.set_len(eval::input::MAX_INPUT_BYTES + 1).unwrap();
    assert!(matches!(
        eval::input::read(&path),
        Err(EvalError::InputLimit)
    ));
}
#[test]
fn eval_url_byte_bound() {
    let prefix = "https://e.test/";
    let exact = format!(
        "{prefix}{}",
        "x".repeat(eval::input::MAX_URL_BYTES - prefix.len())
    );
    assert!(normalize(&exact).is_ok());
    assert_eq!(normalize(&(exact + "x")), Err(EvalError::UrlLimit));
}
#[test]
fn eval_shard_pair_bound() {
    let mut args = eval::index::Verify {
        shard: vec!["127.0.0.1:90".into()],
        expect_documents: vec![1],
        out: "unused".into(),
    };
    assert!(eval::index::pairs(&args).is_ok());
    args.expect_documents.clear();
    assert!(eval::index::pairs(&args).is_err());
    args.shard = (1..=9).map(|n| format!("127.0.0.1:{n}")).collect();
    args.expect_documents = vec![1; 9];
    assert!(eval::index::pairs(&args).is_err());
}

fn write_input(path: &std::path::Path, value: &serde_json::Value) -> String {
    use std::io::Write;
    let bytes = serde_json::to_vec(value).unwrap();
    eval::output::create(path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    eval::input::sha256(&bytes)
}
fn generic_labels(rows: Vec<Label>) -> serde_json::Value {
    json!({"status":"frozen","labeller":"synthetic-rater","corpus":{"fixture":true},"queries":rows})
}
fn read_fixture(value: serde_json::Value) -> Result<eval::labels::Labels, EvalError> {
    let dir = temporary();
    let path = dir.join("labels.json");
    let hash = write_input(&path, &value);
    eval::labels::Labels::read(&path, &hash)
}
#[test]
fn labels_hash_immutable() {
    use std::io::Write;
    let dir = temporary();
    let path = dir.join("labels.json");
    let hash = write_input(
        &path,
        &generic_labels(vec![label("x", &["https://e.test/a"])]),
    );
    assert!(eval::labels::Labels::read(&path, &"0".repeat(64)).is_err());
    let labels = eval::labels::Labels::read(&path, &hash).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b" ")
        .unwrap();
    assert_eq!(
        eval::input::verify(&labels.document.path, &hash),
        Err(EvalError::InputChanged)
    );
}
#[test]
fn labels_schema_strict_scoring_fields() {
    let base = generic_labels(vec![label("x", &["https://e.test/a"])]);
    assert!(read_fixture(base.clone()).is_ok());
    for field in ["id", "query", "category", "acceptable_urls"] {
        let mut bad = base.clone();
        bad["queries"][0][field] = json!(42);
        assert!(read_fixture(bad).is_err());
    }
    let mut duplicate = base.clone();
    duplicate["queries"] = json!([base["queries"][0].clone(), base["queries"][0].clone()]);
    assert!(read_fixture(duplicate).is_err());
    let mut metadata = base;
    metadata["corpus"] = json!("synthetic");
    metadata["optional"] = serde_json::Value::Null;
    assert!(read_fixture(metadata).is_ok());
}
fn heldout_fixture() -> serde_json::Value {
    let rows: Vec<_> = (1..=50)
        .map(|n| {
            let mut l = label(&format!("h{n:02}"), &[&format!("https://fixture.test/{n}")]);
            l.category = eval::labels::CATEGORIES[(n - 1) / 10].into();
            l
        })
        .collect();
    json!({"status":"frozen","labeller":eval::labels::SECOND_RATER,"frozen_at_utc":"2026-09-12T15:38:56Z","corpus":"synthetic only","queries":rows})
}
#[test]
fn heldout_fifty_balanced_second_rater() {
    let good = heldout_fixture();
    read_fixture(good.clone()).unwrap().protocol(true).unwrap();
    for field in ["status", "labeller", "frozen_at_utc"] {
        let mut bad = good.clone();
        bad[field] = json!("wrong");
        assert!(read_fixture(bad).unwrap().protocol(true).is_err());
    }
    let mut bad = good.clone();
    bad["queries"][0]["id"] = json!("h00");
    assert!(read_fixture(bad).unwrap().protocol(true).is_err());
    let mut bad = good;
    bad["queries"][0]["category"] = json!("image_bearing");
    assert!(read_fixture(bad).unwrap().protocol(true).is_err());
}
#[test]
fn labels_answers_in_corpus() {
    let labels = read_fixture(generic_labels(vec![label(
        "x",
        &["https://missing.test/a"],
    )]))
    .unwrap();
    let corpus = eval::labels::Corpus {
        urls: corpus(&["https://e.test/a"]),
        total: 1,
        files: vec![],
    };
    assert_eq!(
        labels.membership(&corpus, None),
        Err(EvalError::InvalidLabels)
    );
}
#[test]
fn heldout_answers_disjoint() {
    let mut bad = heldout_fixture();
    bad["queries"][1]["acceptable_urls"] = bad["queries"][0]["acceptable_urls"].clone();
    assert!(read_fixture(bad).unwrap().protocol(true).is_err());
    let labels = read_fixture(generic_labels(vec![label("x", &["https://e.test/a"])])).unwrap();
    let frozen = read_fixture(generic_labels(vec![label(
        "old",
        &["http://www.e.test/a/"],
    )]))
    .unwrap();
    let corpus = eval::labels::Corpus {
        urls: corpus(&["https://e.test/a"]),
        total: 1,
        files: vec![],
    };
    assert!(labels.membership(&corpus, Some(&frozen)).is_err());
}
#[test]
fn generic_labels_allow_multiple_answers() {
    let labels = read_fixture(generic_labels(vec![label(
        "x",
        &["https://e.test/a", "https://e.test/b"],
    )]))
    .unwrap();
    labels.protocol(false).unwrap();
    assert_eq!(labels.rows[0].answers().unwrap().len(), 2);
}
#[test]
fn eval_label_row_bound() {
    let rows: Vec<_> = (0..1000)
        .map(|i| label(&format!("x{i}"), &["https://e.test/a"]))
        .collect();
    assert!(read_fixture(generic_labels(rows.clone())).is_ok());
    let mut too_many = rows;
    too_many.push(label("extra", &["https://e.test/a"]));
    assert!(matches!(
        read_fixture(generic_labels(too_many)),
        Err(EvalError::LabelLimit)
    ));
}
#[test]
fn eval_answers_per_row_bound() {
    let mut l = label("x", &["https://e.test/a"]);
    l.acceptable_urls = (0..32).map(|n| format!("https://e.test/{n}")).collect();
    assert!(read_fixture(generic_labels(vec![l.clone()])).is_ok());
    l.acceptable_urls.push("https://e.test/extra".into());
    assert!(matches!(
        read_fixture(generic_labels(vec![l])),
        Err(EvalError::AnswerLimit)
    ));
}
#[test]
fn eval_corpus_record_byte_bound() {
    use std::io::Write;
    let dir = temporary();
    let path = dir.join("records.jsonl");
    let mut file = eval::output::create(&path).unwrap();
    file.write_all(&vec![b' '; eval::input::MAX_RECORD_BYTES - 1])
        .unwrap();
    file.write_all(b"\n").unwrap();
    assert_eq!(eval::input::records(&path, &mut 0, |_| Ok(())).unwrap(), 1);
    file.write_all(&vec![b' '; eval::input::MAX_RECORD_BYTES + 1])
        .unwrap();
    assert_eq!(
        eval::input::records(&path, &mut 0, |_| Ok(())),
        Err(EvalError::InputLimit)
    );
}
#[test]
fn eval_corpus_record_count_bound() {
    use std::io::Write;
    assert_eq!(eval::input::MAX_RECORDS, 1_000_000);
    let dir = temporary();
    let path = dir.join("records.jsonl");
    eval::output::create(&path)
        .unwrap()
        .write_all(b"{}\n{}\n{}\n")
        .unwrap();
    let mut total = 0;
    let mut visited = 0;
    assert_eq!(
        eval::input::records_with_limit(&path, &mut total, 2, |_| {
            visited += 1;
            Ok(())
        }),
        Err(EvalError::CorpusLimit)
    );
    assert_eq!((total, visited), (2, 2));
}
#[test]
fn corpus_url_zero_and_counts() {
    use std::io::Write;
    let dir = temporary();
    let path = dir.join("corpus.jsonl");
    eval::output::create(&path).unwrap().write_all(b"{\"url\":[\"https://e.test/a\",\"https://ignored.test/\"]}\n{\"url\":[\"http://www.e.test/a/\"]}\n").unwrap();
    let c = eval::labels::Corpus::read(&[path]).unwrap();
    assert_eq!(c.total, 2);
    assert_eq!(c.urls.len(), 1);
    assert!(c.urls.contains("e.test/a"));
    assert!(!c.urls.contains("ignored.test/"));
}
#[test]
fn spike_import_preserves_absent_provenance() {
    let labels = read_fixture(generic_labels(vec![label("x", &["https://e.test/a"])])).unwrap();
    let old = json!({"answer_set_sha256":labels.document.sha256,"rows":[{"id":"x","category":"factual","query":"synthetic compiler manual","answers":["https://e.test/a"],"stract":{"success":true,"recall_at_10":1.0,"latency_ms":3.25,"server_duration_ms":1.0,"top10_urls":["https://e.test/a"],"matched_urls":["https://e.test/a"],"top10_urls_in_sample":1},"firecrawl":{"ignored":true}}]});
    let rows = eval::diff::spike(&old, &labels).unwrap();
    assert_eq!(rows[0].recall_at_10, Some(1.0));
    assert_eq!(rows[0].latency_ms, Some(3.25));
    assert!(rows[0].stages.is_none() && rows[0].plan_stages.is_none());
}
#[test]
fn eval_templates_parse() {
    for config in [
        include_str!("../../../configs/eval/search-cc.toml"),
        include_str!("../../../configs/eval/search-seeds.toml"),
    ] {
        let _: stract::config::SearchServerConfig = toml::from_str(config).unwrap();
    }
    for (config, on) in [
        (include_str!("../../../configs/eval/api-off.toml"), false),
        (include_str!("../../../configs/eval/api-on.toml"), true),
    ] {
        let c: stract::config::ApiConfig = toml::from_str(config).unwrap();
        assert_eq!(c.agent_query_planning, on);
        assert!(!c.widgets.calculator_fetch_currencies_exchange);
        assert!(c.widgets.thesaurus_paths.is_empty());
    }
}

struct CellFixture {
    _dir: Scratch,
    labels: std::path::PathBuf,
    hash: String,
    corpus: std::path::PathBuf,
    service: std::path::PathBuf,
    index: std::path::PathBuf,
    config: std::path::PathBuf,
    out: std::path::PathBuf,
}
impl CellFixture {
    fn new(rows: Vec<Label>) -> Self {
        use std::io::Write;
        let dir = temporary();
        let source = dir.join("inputs");
        std::fs::create_dir(&source).unwrap();
        let labels = source.join("labels.json");
        let hash = write_input(&labels, &generic_labels(rows));
        let corpus = source.join("corpus.jsonl");
        eval::output::create(&corpus)
            .unwrap()
            .write_all(b"{\"url\":[\"https://e.test/a\"]}\n")
            .unwrap();
        let service = source.join("service.json");
        write_input(
            &service,
            &json!({"verified":true,"total_documents":1,"shards":[{"shard_id":0,"documents":1,"socket":"127.0.0.1:90"}]}),
        );
        let index = source.join("index.json");
        write_input(&index, &json!({"documents":1,"pre_open_files":[]}));
        let config = source.join("api.toml");
        eval::output::create(&config)
            .unwrap()
            .write_all(include_bytes!("../../../configs/eval/api-on.toml"))
            .unwrap();
        let out = dir.join("results/run.json");
        Self {
            _dir: dir,
            labels,
            hash,
            corpus,
            service,
            index,
            config,
            out,
        }
    }
    fn command(&self, endpoint: &str) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(env!("CARGO_BIN_EXE_stract"));
        c.args([
            "eval",
            "recall",
            "--suite",
            "diagnostic",
            "--cell",
            "synthetic",
            "--expect-planner",
            "on",
            "--endpoint",
            endpoint,
            "--labels-sha256",
            &self.hash,
        ])
        .arg("--labels")
        .arg(&self.labels)
        .arg("--corpus-jsonl")
        .arg(&self.corpus)
        .arg("--service-manifest")
        .arg(&self.service)
        .arg("--index-manifest")
        .arg(&self.index)
        .arg("--config")
        .arg(&self.config)
        .arg("--out")
        .arg(&self.out);
        c
    }
}
#[tokio::test]
async fn endpoint_no_proxy() {
    use std::time::Duration;
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let (endpoint, server) = eval_http::serve(vec![(
        200,
        serde_json::to_vec(&response_body()).unwrap(),
        Duration::ZERO,
    )])
    .await;
    let fixture = CellFixture::new(vec![label("x", &["https://e.test/a"])]);
    let result = fixture
        .command(&endpoint.base)
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("NO_PROXY", "")
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(server.await.unwrap().len(), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), proxy.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn endpoint_no_redirects() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_url = format!("http://{}/target", target.local_addr().unwrap());
    let redirect = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint =
        eval::endpoint::Endpoint::parse(&format!("http://{}", redirect.local_addr().unwrap()))
            .unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = redirect.accept().await.unwrap();
        let mut bytes = [0; 8192];
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
        socket.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {target_url}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let dir = temporary();
    let out = private_output(&dir, "redirect.json");
    let result = eval::runner::attempt(&endpoint, "compiler", &out, 0, Duration::from_secs(2), 100)
        .await
        .unwrap();
    assert_eq!(result.error, Some(EvalError::HttpStatus));
    assert_eq!(result.status, Some(302));
    server.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn preflight_before_network() {
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut invalid = label("bad", &["https://e.test/a"]);
    invalid.query = "compiler\u{200b}".into();
    let fixture = CellFixture::new(vec![label("good", &["https://e.test/a"]), invalid]);
    let result = fixture
        .command(&format!("http://{}", listener.local_addr().unwrap()))
        .output()
        .await
        .unwrap();
    assert!(!result.status.success());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    assert!(!fixture.out.with_extension("complete").exists());
}
#[test]
fn served_index_identity_required() {
    let corpus = eval::labels::Corpus {
        urls: HashSet::new(),
        total: 19463,
        files: vec![json!({"records":19285}), json!({"records":178})],
    };
    let service = json!({"verified":true,"total_documents":19463,"shards":[{"shard_id":0,"documents":19285,"socket":"127.0.0.1:57302"},{"shard_id":1,"documents":178,"socket":"127.0.0.1:57303"}]});
    let indexes = vec![
        json!({"manifest":{"documents":19285}}),
        json!({"manifest":{"documents":178}}),
    ];
    eval::runner::validate_identities(&corpus, &service, &indexes).unwrap();
    let mut wrong = service.clone();
    wrong["shards"][0]["shard_id"] = json!(1);
    assert!(eval::runner::validate_identities(&corpus, &wrong, &indexes).is_err());
    let mut wrong = service;
    wrong["shards"][0]["documents"] = json!(178);
    wrong["shards"][1]["documents"] = json!(19285);
    assert!(eval::runner::validate_identities(&corpus, &wrong, &indexes).is_err());
}
#[tokio::test]
async fn diagnostics_escape_untrusted_text() {
    let dir = temporary();
    let path = dir.join("payload\nINJECTED\tNAME.json");
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_stract"))
        .args([
            "eval",
            "verify-service",
            "--shard",
            "127.0.0.1:90",
            "--expect-documents",
            "1",
            "--out",
        ])
        .arg(&path)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("INJECTED"));
    assert!(stderr.contains("--out") && stderr.contains("path has forbidden components"));
}
#[tokio::test]
async fn all_eval_commands_share_writer() {
    use std::io::Write;
    let fixture = CellFixture::new(vec![label("x", &["https://e.test/a"])]);
    eval::output::create(&fixture.out)
        .unwrap()
        .write_all(b"untouched")
        .unwrap();
    let indexdir = fixture._dir.join("copied-index");
    std::fs::create_dir(&indexdir).unwrap();
    let commands: Vec<Vec<std::ffi::OsString>> = vec![
        vec![
            "eval".into(),
            "diff".into(),
            "--before".into(),
            fixture.service.clone().into(),
            "--after".into(),
            fixture.index.clone().into(),
        ],
        vec![
            "eval".into(),
            "validate-labels".into(),
            "--labels".into(),
            fixture.labels.clone().into(),
            "--labels-sha256".into(),
            fixture.hash.clone().into(),
            "--corpus-jsonl".into(),
            fixture.corpus.clone().into(),
        ],
        vec![
            "eval".into(),
            "inspect-index".into(),
            "--index".into(),
            indexdir.into(),
        ],
        vec![
            "eval".into(),
            "verify-service".into(),
            "--shard".into(),
            "127.0.0.1:90".into(),
            "--expect-documents".into(),
            "1".into(),
        ],
    ];
    for args in commands {
        let result = tokio::process::Command::new(env!("CARGO_BIN_EXE_stract"))
            .args(args)
            .arg("--out")
            .arg(&fixture.out)
            .output()
            .await
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("OutputExists"));
        assert_eq!(std::fs::read(&fixture.out).unwrap(), b"untouched");
    }
    let result = fixture
        .command("http://127.0.0.1:90")
        .output()
        .await
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("OutputExists"));
}

#[test]
fn runner_timing_boundaries() {
    use std::{cell::Cell, io::Write, rc::Rc};
    struct Writer(Rc<Cell<bool>>);
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.set(true);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let written = Rc::new(Cell::new(false));
    let mut writer = Writer(written.clone());
    let elapsed = eval::runner::write_timed(&mut writer, b"response", || {
        assert!(written.get(), "clock sampled before raw write");
        17.25
    })
    .unwrap();
    assert_eq!(elapsed, 17.25);
}

#[test]
fn live_symlink_ancestors_are_rejected() {
    let dir = temporary();
    let actual = dir.join("actual");
    std::fs::create_dir(&actual).unwrap();
    let link = dir.join("linked");
    std::os::unix::fs::symlink(&actual, &link).unwrap();
    assert!(eval::output::Output::reserve(&link.join("out.json"), false).is_err());
    assert!(!actual.join("out.json").exists());
}

#[test]
fn failed_serialization_keeps_partial_without_completion() {
    struct Fails;
    impl serde::Serialize for Fails {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let _ = serializer.serialize_str("partial")?;
            Err(serde::ser::Error::custom("synthetic writer failure"))
        }
    }
    let dir = temporary();
    let out = private_output(&dir, "failed.json");
    assert_eq!(out.finish(&Fails), Err(EvalError::Io));
    assert!(!std::fs::read(dir.join("failed.json")).unwrap().is_empty());
    assert!(!dir.join("failed.complete").exists());
}

async fn raw_label_ids_do_not_select_paths() {
    use std::time::Duration;
    let ids = ["../chosen\n", "ordinary"];
    let fixture = CellFixture::new(
        ids.iter()
            .map(|id| label(id, &["https://e.test/a"]))
            .collect(),
    );
    let body = serde_json::to_vec(&response_body()).unwrap();
    let (endpoint, server) = eval_http::serve(vec![(200, body, Duration::ZERO); 2]).await;
    let result = fixture.command(&endpoint.base).output().await.unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(server.await.unwrap().len(), 2);
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.out).unwrap()).unwrap();
    let raw = fixture.out.with_extension("raw");
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(value["rows"][i]["id"], *id);
        assert_eq!(
            value["rows"][i]["raw_path"],
            raw.join(format!("{i:04}.json")).to_str().unwrap()
        );
    }
    assert_eq!(std::fs::read_dir(raw).unwrap().count(), 2);
    assert!(!fixture.out.parent().unwrap().join("chosen\n.json").exists());
}

#[test]
fn paired_acceptance_requires_complete_retention() {
    let before =
        json!({"suite":"held-out", "planner_expectation":"off", "acceptance":{"passed":true}});
    let after =
        json!({"suite":"held-out", "planner_expectation":"on", "acceptance":{"passed":true}});
    let mut pair = json!({"complete_successful_pair":true,"previous_matches_retained":true,"protected_matches_retained":true,"recall_delta":0.2});
    assert_eq!(
        eval::diff::paired_acceptance(&before, &after, &pair).unwrap()["passed"],
        true
    );
    for key in ["complete_successful_pair", "protected_matches_retained"] {
        pair[key] = json!(false);
        assert_eq!(
            eval::diff::paired_acceptance(&before, &after, &pair).unwrap()["passed"],
            false
        );
        pair[key] = json!(true);
    }
    for failed_side in [true, false] {
        let mut old = before.clone();
        let mut new = after.clone();
        if failed_side {
            old["acceptance"]["passed"] = json!(false);
        } else {
            new["acceptance"]["passed"] = json!(false);
        }
        assert_eq!(
            eval::diff::paired_acceptance(&old, &new, &pair).unwrap()["passed"],
            false
        );
    }
    pair["previous_matches_retained"] = json!(false);
    let verdict = eval::diff::paired_acceptance(&before, &after, &pair).unwrap();
    assert_eq!(verdict["passed"], true);
    assert_eq!(verdict["recall_gain_observed"], true);
    pair["recall_delta"] = json!(-0.1);
    let verdict = eval::diff::paired_acceptance(&before, &after, &pair).unwrap();
    assert_eq!(verdict["passed"], true);
    assert_eq!(verdict["recall_gain_observed"], false);
    assert_eq!(verdict["review_required"], true);
    assert_eq!(
        eval::diff::paired_acceptance(&json!({}), &after, &pair).unwrap()["claimed"],
        false
    );
    assert!(eval::diff::paired_acceptance(&json!({"suite":"frozen"}), &after, &pair).is_err());
}

#[test]
fn spike_import_rejects_inconsistent_rows() {
    let labels = read_fixture(generic_labels(vec![label("x", &["https://e.test/a"])])).unwrap();
    let consistent = json!({"answer_set_sha256":labels.document.sha256,"rows":[{"id":"x","category":"factual","query":"synthetic compiler manual","answers":["https://e.test/a"],"stract":{"success":true,"recall_at_10":1.0,"latency_ms":3.25,"server_duration_ms":1.0,"top10_urls":["https://e.test/a"],"matched_urls":["https://e.test/a"],"top10_urls_in_sample":1}}]});
    let mut bad = consistent.clone();
    bad["rows"][0]["stract"]["top10_urls"] = json!(["https://e.test/b"]);
    bad["rows"][0]["stract"]["matched_urls"] = json!([]);
    assert!(matches!(
        eval::diff::spike(&bad, &labels),
        Err(EvalError::IdentityMismatch)
    ));
    let mut bad = consistent.clone();
    bad["rows"][0]["stract"]["matched_urls"] = json!(["https://e.test/b"]);
    assert!(matches!(
        eval::diff::spike(&bad, &labels),
        Err(EvalError::IdentityMismatch)
    ));
    let row = eval::diff::spike(&consistent, &labels).unwrap().remove(0);
    assert_eq!(row.recall_at_10, Some(1.0));
    assert_eq!(row.latency_ms, Some(3.25));
    assert_eq!(row.top10_urls, ["https://e.test/a"]);
    assert_eq!(row.matched_urls, ["https://e.test/a"]);
    for (field, value) in [
        ("success", json!("true")),
        ("success", json!(null)),
        ("latency_ms", json!(-1.0)),
        ("latency_ms", json!("3.25")),
        ("top10_urls_in_sample", json!(2)),
        ("top10_urls_in_sample", json!(null)),
        ("top10_urls", json!(vec!["https://e.test/a"; 11])),
        ("matched_urls", json!(null)),
        ("recall_at_10", json!(null)),
    ] {
        let mut bad = consistent.clone();
        bad["rows"][0]["stract"][field] = value;
        assert!(
            matches!(
                eval::diff::spike(&bad, &labels),
                Err(EvalError::IdentityMismatch)
            ),
            "{field}"
        );
    }
}

#[test]
fn spike_import_rejects_scored_failure_rows() {
    let labels = read_fixture(generic_labels(vec![label("x", &["https://e.test/a"])])).unwrap();
    let valid = json!({"answer_set_sha256":labels.document.sha256,"rows":[{"id":"x","category":"factual","query":"synthetic compiler manual","answers":["https://e.test/a"],"stract":{"success":false,"recall_at_10":null,"latency_ms":null,"server_duration_ms":null,"top10_urls":[],"matched_urls":[],"top10_urls_in_sample":0,"zero_results":false,"failed_attempt_ms":12.5,"error":"timeout"}}]});
    for (field, value) in [
        ("recall_at_10", json!(1.0)),
        ("top10_urls", json!(["https://e.test/a"])),
        ("latency_ms", json!(0)),
        ("server_duration_ms", json!(0)),
        ("matched_urls", json!(["https://e.test/a"])),
        ("top10_urls", json!(null)),
        ("matched_urls", json!({})),
        ("top10_urls_in_sample", json!(1)),
        ("top10_urls_in_sample", json!(null)),
        ("zero_results", json!(true)),
        ("zero_results", json!(null)),
        ("failed_attempt_ms", json!(-1.0)),
        ("failed_attempt_ms", json!(null)),
        ("failed_attempt_ms", json!("12.5")),
        ("error", json!("")),
        ("error", json!(null)),
        ("error", json!(12)),
        ("success", json!(null)),
        ("success", json!("false")),
    ] {
        let mut bad = valid.clone();
        bad["rows"][0]["stract"][field] = value;
        assert!(
            matches!(
                eval::diff::spike(&bad, &labels),
                Err(EvalError::IdentityMismatch)
            ),
            "{field}"
        );
    }
    let row = eval::diff::spike(&valid, &labels).unwrap().remove(0);
    assert!(!row.success);
    assert_eq!(row.recall_at_10, None);
    assert_eq!(row.latency_ms, None);
    assert_eq!(row.server_duration_ms, None);
    assert_eq!(row.failed_attempt_ms, Some(12.5));
    assert!(row.top10_urls.is_empty() && row.matched_urls.is_empty());
    assert_eq!(row.top10_urls_in_sample, 0);
    assert!(!row.zero_results && row.error.is_some());
    let mut sparse = valid.clone();
    for field in [
        "recall_at_10",
        "latency_ms",
        "server_duration_ms",
        "top10_urls",
        "matched_urls",
        "top10_urls_in_sample",
        "zero_results",
    ] {
        sparse["rows"][0]["stract"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    sparse["rows"][0]["stract"]["failed_attempt_ms"] = json!(0);
    assert!(!eval::diff::spike(&sparse, &labels).unwrap()[0].success);
    for field in ["success", "failed_attempt_ms", "error"] {
        let mut missing = valid.clone();
        missing["rows"][0]["stract"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            matches!(
                eval::diff::spike(&missing, &labels),
                Err(EvalError::IdentityMismatch)
            ),
            "missing {field}"
        );
    }
}

#[test]
fn spike_import_keeps_duplicate_slots() {
    let answers = ["https://e.test/a", "https://e.test/b"];
    let labels = read_fixture(generic_labels(vec![label("x", &answers)])).unwrap();
    let top10 = [
        "https://e.test/a",
        "https://e.test/c",
        "https://e.test/d",
        "https://e.test/a",
        "https://e.test/e",
        "https://e.test/f",
        "https://e.test/g",
        "https://e.test/h",
        "https://e.test/i",
        "https://e.test/j",
    ];
    let matched = ["https://e.test/a", "https://e.test/a"];
    let old = json!({"answer_set_sha256":labels.document.sha256,"rows":[{"id":"x","category":"factual","query":"synthetic compiler manual","answers":answers,"stract":{"success":true,"recall_at_10":0.5,"latency_ms":3.25,"top10_urls":top10,"matched_urls":matched,"top10_urls_in_sample":10}}]});
    let row = eval::diff::spike(&old, &labels).unwrap().remove(0);
    assert!(row.success);
    assert_eq!(row.recall_at_10, Some(1.0 / answers.len() as f64));
    assert_eq!(row.top10_urls.len(), 10);
    assert_eq!(row.top10_urls, top10);
    assert_eq!(row.matched_urls, matched);
    assert_eq!(row.top10_urls_in_sample, 10);
}

#[test]
fn index_manifest_limits_entries_and_depth() {
    use eval::index::{walk_bounded, MAX_INDEX_DEPTH};
    let dir = temporary();
    for n in 0..4 {
        std::fs::write(dir.join(format!("{n}.txt")), b"fixture").unwrap();
    }
    let mut files = vec![];
    assert_eq!(
        walk_bounded(&dir, &dir, &mut files, 3, MAX_INDEX_DEPTH, 0),
        Err(EvalError::InputLimit)
    );
    assert!(files.is_empty());
    std::fs::remove_file(dir.join("3.txt")).unwrap();
    walk_bounded(&dir, &dir, &mut files, 3, MAX_INDEX_DEPTH, 0).unwrap();
    assert_eq!(files.len(), 3);
    let deep = temporary();
    let mut tail = deep.to_path_buf();
    for _ in 0..17 {
        tail.push("d");
        std::fs::create_dir(&tail).unwrap();
    }
    let mut files = vec![];
    assert_eq!(
        walk_bounded(&deep, &deep, &mut files, 100, MAX_INDEX_DEPTH, 0),
        Err(EvalError::InputLimit)
    );
    assert!(files.is_empty());
    let dirs = temporary();
    for n in 0..4 {
        std::fs::create_dir(dirs.join(n.to_string())).unwrap();
    }
    assert_eq!(
        walk_bounded(&dirs, &dirs, &mut vec![], 3, MAX_INDEX_DEPTH, 0),
        Err(EvalError::InputLimit)
    );
}

#[test]
fn corpus_change_after_read_is_detected() {
    use std::fs::{File, FileTimes};
    let dir = temporary();
    let paths: Vec<_> = ["one.jsonl", "two.jsonl"]
        .iter()
        .map(|name| dir.join(name))
        .collect();
    for path in &paths {
        std::fs::write(path, b"{\"url\":[\"https://e.test/a\"]}\n").unwrap();
    }
    let corpus = eval::labels::Corpus::read(&paths).unwrap();
    corpus.verify_unchanged().unwrap();
    let before = eval::input::file_identity(&paths[1]).unwrap();
    let times = std::fs::metadata(&paths[1]).unwrap();
    std::fs::write(&paths[1], b"{\"url\":[\"https://e.test/b\"]}\n").unwrap();
    File::options()
        .write(true)
        .open(&paths[1])
        .unwrap()
        .set_times(
            FileTimes::new()
                .set_modified(times.modified().unwrap())
                .set_accessed(times.accessed().unwrap()),
        )
        .unwrap();
    assert_eq!(eval::input::file_identity(&paths[1]).unwrap(), before);
    assert_eq!(corpus.verify_unchanged(), Err(EvalError::InputChanged));
}

#[test]
fn external_requires_product_root() {
    if std::env::var_os("STRACT_ROOT_WITNESS_CHILD").is_some() {
        let dir = temporary();
        assert_eq!(
            eval::output::external(&dir.join("out.json"), &[]),
            Err(EvalError::IdentityMismatch)
        );
        return;
    }
    let dir = temporary();
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(dir.as_ref())
        .status()
        .unwrap()
        .success());
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "external_requires_product_root", "--nocapture"])
        .env("STRACT_ROOT_WITNESS_CHILD", "1")
        .current_dir(dir.as_ref())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stdout)
    );
    assert!(eval::output::external(
        &std::env::current_dir()
            .unwrap()
            .join("forbidden-output.json"),
        &[]
    )
    .is_err());
}

#[test]
fn attempt_over_deadline_is_failed() {
    use eval::runner::finish_attempt;
    assert_eq!(
        finish_attempt(60_000.1, 60_000.0, None),
        Some(EvalError::Timeout)
    );
    assert_eq!(finish_attempt(59_999.9, 60_000.0, None), None);
    assert_eq!(finish_attempt(60_000.0, 60_000.0, None), None);
    assert_eq!(
        finish_attempt(70_000.0, 60_000.0, Some(EvalError::HttpStatus)),
        Some(EvalError::HttpStatus)
    );
}

#[tokio::test]
async fn inspect_index_names_the_scratch_rule() {
    let dir = temporary();
    let temporary_boundary = dir.join("temporary-boundary");
    let index = dir.join("index-copy");
    std::fs::create_dir(&temporary_boundary).unwrap();
    std::fs::create_dir(&index).unwrap();
    let result = tokio::process::Command::new(env!("CARGO_BIN_EXE_stract"))
        .args(["eval", "inspect-index", "--index"])
        .arg(&index)
        .arg("--out")
        .arg(dir.join("results/manifest.json"))
        .env("TMPDIR", &temporary_boundary)
        .output()
        .await
        .unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("--index") && error.contains("canonical temporary directory"),
        "{error}"
    );
}
