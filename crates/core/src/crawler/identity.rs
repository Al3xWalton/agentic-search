//! Defines the crawler's fixed identity and the sole HTTP client construction boundary.
//! Callers supply validated contact locations, never a token or version override.
//! Publication and controller approval belong to deployment, not this module.

#![deny(missing_docs)]

use crate::config::ingestion::IdentityConfig;
use anyhow::{ensure, Result};
use std::time::Duration;
use url::Url;

/// Fixed case-sensitive product token used for robots group selection.
pub const ROBOTS_TOKEN: &str = "AVASearchBot";

/// Validates a policy/contact HTTPS location without logging its contents.
/// Rejects userinfo, fragments, control characters, whitespace and UA delimiters.
pub fn validate_policy_url(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && !value
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || "();".contains(c)),
        "identity location contains invalid characters"
    );
    let url = Url::parse(value)
        .map_err(|_| anyhow::anyhow!("identity location is not an absolute URL"))?;
    ensure!(
        url.scheme() == "https"
            && url.domain().is_some_and(|host| !host.is_empty())
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && !value.split('/').nth(2).unwrap_or_default().contains('@'),
        "identity location must be HTTPS without userinfo or fragment"
    );
    Ok(())
}

fn validate_contact(value: &str) -> Result<()> {
    if value.starts_with("https://") {
        return validate_policy_url(value);
    }
    ensure!(
        value.is_ascii()
            && !value.bytes().any(|b| b.is_ascii_whitespace()
                || b.is_ascii_control()
                || b"();:/\\".contains(&b)),
        "identity contact contains invalid characters"
    );
    let (local, domain) = value
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("identity contact must be email or HTTPS"))?;
    ensure!(
        !local.is_empty()
            && !domain.contains('@')
            && domain.contains('.')
            && domain.split('.').all(|label| !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "identity contact has invalid mailbox shape"
    );
    Ok(())
}

/// Builds exactly the fixed product token, this package's version and validated identity inputs.
/// Errors contain field descriptions only; no caller can override the full user-agent.
pub fn build_user_agent(identity: &IdentityConfig) -> Result<String> {
    let policy_url = &identity.policy_url;
    let contact = &identity.contact;
    validate_policy_url(policy_url)?;
    validate_contact(contact)?;
    Ok(format!(
        "{}{}{}",
        "AVASearchBot/",
        env!("CARGO_PKG_VERSION"),
        format_args!(" (+{}; {})", policy_url, contact)
    ))
}

/// Constructs the crawler HTTP client with a fixed identity and no browser/proxy bypass features.
/// The timeout covers request and connect in seconds; address admission is the transport's responsibility.
pub(super) fn build_http_client(
    identity: &IdentityConfig,
    timeout: Duration,
    resolver: std::sync::Arc<super::network::VettedResolver>,
) -> Result<HttpClient> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("text/html"),
    );
    headers.insert(
        reqwest::header::ACCEPT_LANGUAGE,
        reqwest::header::HeaderValue::from_static("en-US,en;q=0.9,*;q=0.8"),
    );
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .default_headers(headers)
        .no_proxy()
        .referer(false)
        .http1_only()
        .pool_max_idle_per_host(0)
        .dns_resolver(resolver)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(build_user_agent(identity)?)
        .build()
        .map_err(|_| anyhow::anyhow!("crawler HTTP client initialization failed"))?;
    Ok(HttpClient { client })
}

/// Keeps the raw client private to the sole transport boundary.
pub(super) struct HttpClient {
    client: reqwest::Client,
}

impl reqwest::dns::Resolve for super::network::VettedResolver {
    fn resolve(&self, name: hyper::client::connect::dns::Name) -> reqwest::dns::Resolving {
        let result = self.admitted(name.as_str());
        Box::pin(async move {
            match result {
                Ok(addresses) => Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs),
                Err(_) => Err(
                    Box::new(std::io::Error::other("unadmitted crawler DNS name"))
                        as Box<dyn std::error::Error + Send + Sync>,
                ),
            }
        })
    }
}

fn transport_error(error: reqwest::Error) -> super::Error {
    if error.is_timeout() {
        return super::Error::Timeout;
    }
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    while let Some(source) = cause {
        if source.is::<native_tls::Error>() {
            return super::Error::TlsError;
        }
        cause = source.source();
    }
    if error.is_connect() {
        super::Error::ConnectError
    } else {
        super::Error::ResponseBodyReadFailed
    }
}

impl HttpClient {
    pub(super) async fn send(
        &self,
        url: Url,
        validators: &[(String, String)],
    ) -> super::Result<HttpResponse> {
        #[cfg(test)]
        {
            let _ = (&self.client, url, validators);
            Err(super::Error::TestNetworkDisabled)
        }
        #[cfg(not(test))]
        {
            let mut request = self.client.get(url);
            for (name, value) in validators {
                request = request.header(name, value);
            }
            let response = request.send().await.map_err(transport_error)?;
            let mut headers = super::network::ResponseHeaders::default();
            for name in [
                "content-type",
                "content-length",
                "location",
                "x-robots-tag",
                "tdm-reservation",
                "tdm-policy",
                "cache-control",
                "etag",
                "last-modified",
                "content-language",
                "retry-after",
                "cf-mitigated",
            ] {
                for value in response.headers().get_all(name).iter() {
                    headers.observe(name, value.to_str().ok());
                }
            }
            Ok(HttpResponse { response, headers })
        }
    }
}

/// Keeps the raw response private while the outer wrapper owns the host permit.
pub(super) struct HttpResponse {
    response: reqwest::Response,
    headers: super::network::ResponseHeaders,
}
impl HttpResponse {
    pub(super) fn status(&self) -> u16 {
        self.response.status().as_u16()
    }
    pub(super) fn headers(&self) -> &super::network::ResponseHeaders {
        &self.headers
    }
    pub(super) async fn chunk(&mut self) -> super::Result<Option<Vec<u8>>> {
        self.response
            .chunk()
            .await
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(transport_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unit_send_refused() {
        let resolver = std::sync::Arc::new(super::super::network::VettedResolver::new(
            std::sync::Arc::new(NoLookup),
        ));
        let client =
            build_http_client(&IdentityConfig::default(), Duration::from_secs(1), resolver)
                .unwrap();
        assert!(matches!(
            client
                .send(Url::parse("https://never.fixture.invalid/").unwrap(), &[])
                .await,
            Err(super::super::Error::TestNetworkDisabled)
        ));
    }
    struct NoLookup;
    impl super::super::network::AddressResolver for NoLookup {
        fn lookup<'a>(&'a self, _: &'a str) -> super::super::network::LookupFuture<'a> {
            panic!("unit send must refuse before DNS")
        }
    }

    #[test]
    fn ua_format() {
        let identity = IdentityConfig::default();
        assert_eq!(
            build_user_agent(&identity).unwrap(),
            format!(
                "AVASearchBot/{} (+{}; {})",
                env!("CARGO_PKG_VERSION"),
                identity.policy_url,
                identity.contact
            )
        );
    }

    #[test]
    fn ua_version() {
        let ua = build_user_agent(&IdentityConfig::default()).unwrap();
        assert!(ua.starts_with(&format!("AVASearchBot/{} ", env!("CARGO_PKG_VERSION"))));
        let grammar = regex::Regex::new(r"^AVASearchBot/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)? \(\+https://[^ ;()]+; https://[^ ;()]+\)$").unwrap();
        assert!(grammar.is_match(&ua));
    }

    #[test]
    fn ua_policy_validation() {
        for value in [
            "",
            "http://example.org/",
            "https:///",
            "https://user@example.org/",
            "https://example.org/#x",
            "https://example.org/(x)",
            "https://example.org/;x",
            "https://example.org/\r\nX: x",
            " https://example.org/",
        ] {
            let identity = IdentityConfig {
                policy_url: value.into(),
                ..IdentityConfig::default()
            };
            assert!(
                build_user_agent(&identity).is_err(),
                "accepted invalid policy location"
            );
        }
        assert!(build_user_agent(&IdentityConfig::default()).is_ok());
    }

    #[test]
    fn ua_contact_validation() {
        for value in [
            "",
            "mailto:bot@example.org",
            "a@@example.org",
            "a@localhost",
            "@example.org",
            "bot@",
            "bot@example.org;x",
            "bot@example.org\n",
            "http://example.org/",
        ] {
            let identity = IdentityConfig {
                contact: value.into(),
                ..IdentityConfig::default()
            };
            assert!(
                build_user_agent(&identity).is_err(),
                "accepted invalid contact"
            );
        }
        let identity = IdentityConfig {
            contact: "bot@example.org".into(),
            ..IdentityConfig::default()
        };
        assert!(build_user_agent(&identity).is_ok());
    }
}
