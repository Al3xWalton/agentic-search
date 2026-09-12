//! Exercises the production library fetch path using only owned loopback HTTP fixtures.
//! No test permits arbitrary private addresses or contacts public DNS/HTTP services.
//! Ledger/storage witnesses extend these same fixtures, rather than constructing outcomes by hand.

#[path = "support/crawler_fixture.rs"]
mod crawler_fixture;
use crawler_fixture::{Fixture, Reply};
use stract::crawler::{network::HostKey, Error};

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
        assert_eq!(snapshot.http_status, Some(status));
        assert_eq!(
            snapshot.body_sha256.as_deref(),
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
    let fixture = Fixture::new();
    fixture.fetch("/page").await.unwrap();
    let expected = format!(
        "AVASearchBot/{} (+{}; {})",
        env!("CARGO_PKG_VERSION"),
        fixture.client.policy().get().identity.policy_url,
        fixture.client.policy().get().identity.contact
    );
    let requests = fixture.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(request.user_agent, expected);
    }
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
    assert_eq!(snapshot.body_sha256, Some(expected));
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
