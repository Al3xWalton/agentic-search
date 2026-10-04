# Paper providers

Agentic Search runs standalone. Paper search is optional, with no built-in corpus, endpoint,
credential, cache or hosted-service dependency. An operator selects one provider at startup.
Missing or false `scholarly` preserves web search. A true value selects only that provider:

```json
{"query":"Cedar research","page":0,"num_results":20,"scholarly":true}
```

No provider returns HTTP 503 with this JSON body, without a web fallback:

```json
{"version":"v1","error":{"code":"scholarly_unavailable","message":"The scholarly provider is unavailable"}}
```

Paper queries retain their original text. They accept 1–64 maximal Unicode alphanumeric runs,
at most 4096 UTF-8 bytes, and no non-whitespace control characters. Web operators and ranking
do not apply. Page numbers are zero-based 0–99; counts are 1–20, default 20. `scholarly` must be
a boolean: null, strings and numbers are invalid. Scholarly bound violations return 400
`invalid_request`, as do invalid booleans
and unknown request fields. Country and adult treatment retain the web
contract, including conservative defaults. Every known OpenAlex, DOI and OA URL independently
passes current local suppression and compliance checks. Filtering may shorten or empty a page;
there is no refill. The next-page hint describes the provider's page before local filtering.

## Operator setup

Choose exactly one alternative in API TOML. Unknown fields and mixed provider fields fail startup.
Relative paths resolve from the process startup working directory. Rotation requires a restart.

```toml
[v1.paper_provider]
kind = "openalex"
api_key_file = "secrets/openalex.key"
```

OpenAlex uses `GET https://api.openalex.org/works`. The user's key is sent only in one sensitive
`Authorization: Bearer <key>` header, never in a URL. The search text, one-based page and count
are encoded as `search`, `page`, and `per_page`. Encoded request URLs exceeding 4094 bytes are
refused locally as unavailable; escaping can make the effective query limit lower than 4096.
A page whose one-based page times count exceeds 10000 is also refused locally. There are no
retries, credit purchases, quota polling or provider failovers. At the October 2026 API contract,
OpenAlex provides a $1 daily allowance per account and charges $1 per 1000 searches; operators
manage their own account and budget. These figures are context, not a code-enforced quota.

Alternatively, select any compatible scholar v1 service explicitly:

```toml
[v1.paper_provider]
kind = "http"
endpoint = "https://papers.example/v1/search"
bearer_token_file = "secrets/papers.token"
```

HTTPS uses ordinary certificate and hostname verification with TLS 1.2 or newer. HTTP is allowed
only for literal loopback IP addresses, for example `http://127.0.0.1:9000/v1/search`. The complete
canonical endpoint must end in exactly `/v1/search`, without credentials, query or fragment.
`localhost` and other DNS names do not qualify for cleartext. No service is selected implicitly.

Credential files must be regular, owned by the effective user, single-link and mode 0600.
Terminal symlinks, FIFOs and devices are refused using the opened descriptor. Container-mounted
secrets must first be copied to an owned, single-link 0600 file. OpenAlex keys contain 1–1024
printable non-space ASCII bytes. HTTP tokens contain exactly 64 lowercase hexadecimal bytes.
Either may have one terminal LF; CR, whitespace and additional lines are invalid. Do not place
secrets inline in TOML or command arguments. API configuration is bounded to 1 MiB and must be
a regular file; API config symlinks are accepted. Invalid API TOML prints
`Error: API configuration is invalid`; an invalid provider
prints `Error: Paper provider configuration is invalid`, both with exit status 1.

## Compatible service protocol

The connector sends one POST with `Content-Type: application/json`, `Accept: application/json`,
`Accept-Encoding: identity`, `Connection: close` and one sensitive bearer header. Its strict body
has exactly `query` (string), `page` (zero-based integer) and `num_results` (integer). It sends no
country, cookies, caller headers or private local policy. Authentication belongs to the service.

A 200 response is an object with exactly two required keys: `results` (ordered array) and
`next_page` (null or exactly the requested page plus one, never greater than 99). Each hit has
exactly six required keys: `id`, `url`, `domain`, `title`, `snippet` and `scholarly`. `id` is the
64 lowercase hexadecimal SHA-256 of the canonical URL, recomputed locally. `url` equals the
scholarly OpenAlex ID; `domain` is exactly `openalex.org`. Title is nonblank, at most 500 Unicode
scalars and 2000 UTF-8 bytes; snippet is exactly empty. Web results omit `scholarly` entirely.

Scholarly attribution has exactly eight required keys; nullable keys cannot be omitted:

| Key | Contract |
| --- | --- |
| `openalex_id` | Canonical `https://openalex.org/W` followed by digits, at most 64 ASCII bytes |
| `doi` | Null or canonical HTTPS `doi.org` URL with a valid `10.` registrant and suffix |
| `oa_url` | Null or canonical HTTP(S) DNS-host URL, with no userinfo or fragment |
| `authors` | Ordered 0–100 nonblank names, each at most 256 scalars and 1024 UTF-8 bytes |
| `publication_year` | Integer 1–9999 |
| `venue` | Null or a nonblank name within the author-name bounds |
| `snapshot_date` | Valid ten-byte `YYYY-MM-DD` source date; HTTP services must supply a date |
| `metadata_license` | Exactly `CC0-1.0` |

DOI and OA URLs are each at most 2048 UTF-8 bytes. Live OpenAlex metadata uses a null snapshot
date; it never invents a retrieval date. Metadata licensing grants no rights to abstracts or
linked content. Neither connector downloads papers, reconstructs abstracts or follows OA links.
A compatible service sending excerpts is refused until a later contract explicitly permits them.

All known HTTP errors require exactly `{"error":"<name>"}` with the matching status:

| Status | Name |
| --- | --- |
| 400 | `invalid-request` |
| 401 | `unauthenticated` |
| 404 | `not-found` |
| 405 | `method-not-allowed` |
| 413 | `body-too-large` |
| 429 | `busy` |
| 500 | `internal` |
| 503 | `unavailable` |
| 504 | `deadline` |

Valid remote deadline maps to local 504 `request_timeout`; other valid remote errors map to 503
`scholarly_unavailable`. Malformed successful or recognized error responses map to 500
`invalid_result`. Unknown HTTP statuses and all non-200 OpenAlex statuses map to unavailable.
Remote error prose, headers and bodies are never forwarded. Media must be application/json,
optionally with charset=utf-8; content encoding must be absent or identity. This applies to HTTP
successes and recognized errors, and to OpenAlex successes. Bodies of every status remain bounded.

OpenAlex ignores unrelated fields within parsing limits. Missing/null/blank/oversize titles,
missing/null/out-of-range years, excessive or invalid authors, blank or oversized venues,
and invalid DOI/OA candidates drop
the entire record. Invalid or repeated IDs, malformed envelopes, excess raw records, impossible
counts and parser failures reject the page. Pagination still uses `meta.count` after record drops.
Unknown HTTP keys and duplicate JSON keys are refused.

## Bounds and logging

Four operations share nonqueued admission across listeners built from one resource bundle.
Cancellation releases capacity. Connect is bounded to 3 seconds, headers to 12 seconds, gaps
between body chunks to 5 seconds and the whole operation to 15 seconds. The reqwest backstop is
16 seconds. The outer v1 request timeout can be shorter. No serving lock is held during I/O;
final live gates remain held through bounded response serialization.

Outbound JSON is at most 32768 bytes. Every remote body is cumulatively capped at 4194304 bytes,
including chunked and error bodies, regardless of Content-Length. Accepted parsed headers have
at most 32 values and 16384 total name/value bytes. The locked Hyper parser has its own larger
417792-byte buffer and 100-header ceiling before these checks; the application cap does not
claim to bound pre-parse allocation. JSON has at most 32 container levels and 262144 tokens,
counting keys, scalars and container delimiters, including ignored fields. Each serialized hit
is at most 131072 bytes; complete paper responses are at most 4194304 bytes. Overflow returns
a complete fixed error rather than a partial response.

Transport has no proxy discovery, redirects, cookie store, automatic decoding, Referer or idle
connection pool. Its future suppresses diagnostics across construction, send, read and decode.
The stock binary also applies an immutable transport-target filter. Embedders must apply
`transport_log_allowed` to every tracing sink and log-facade bridge before constructing providers;
arbitrary global loggers outside that policy are outside the contract. Never instrument provider
arguments or print raw transport failures. Config, query, page, secrets and built-in providers
have opaque Debug output. Dependency debug and trace records compile out of release builds;
redaction witnesses exercise debug builds where those records exist.

## Rust extension

Implement the public `PaperProvider: Send + Sync` trait. `PaperQuery::try_new` validates input;
its `query()`, `page()` and `num_results()` accessors retain the original request.
`PaperPage::try_new`
validates attributed hits and the page hint. Construct metadata using validated
`ScholarlyAttribution` deserialization and `AttributedResult::try_from_paper`. Return one of the
closed `PaperProviderError` variants without source chains. Providers are trusted in-process Rust:
they must cooperate with cancellation and avoid blocking or logging private input.

```rust
use futures::future::BoxFuture;
use stract::api::v1::scholarly::{PaperPage, PaperProvider, PaperProviderError, PaperQuery};

struct Empty;
impl PaperProvider for Empty {
    fn search(&self, _query: PaperQuery) -> BoxFuture<'_, Result<PaperPage, PaperProviderError>> {
        Box::pin(async { PaperPage::try_new(Vec::new(), None) })
    }
}
```

Attach `Arc::new(Empty)` with `V1Resources::with_paper_provider`, then use
`V1State::from_resources` and `v1::compose_api`. Reuse the resource bundle for additional listeners
to share admission and provider ownership. Custom providers receive the same final count, hint,
attribution, suppression, compliance and output checks; they cannot bypass local serving rules.
