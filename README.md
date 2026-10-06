# agentic-search

A search engine for AI agents. `agentic-search` crawls the web as a named,
polite bot under a published crawler policy, keeps only what a page allows it to
keep, indexes it, and answers HTTP queries with ranked results an agent can act
on. It is a Rust fork of the archived [Stract](https://github.com/StractOrg/stract)
engine, offered under AGPL-3.0-only.

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) 1.98.0, pinned by
  `rust-toolchain.toml` together with rustfmt, clippy and the
  `wasm32-unknown-unknown` target
- Linux: `build-essential clang pkg-config libssl-dev liburing-dev`
- macOS: the Xcode command-line tools
- Optional, for the web frontend only: Node 20.10.0 and wasm-pack 0.15.0

No model, API key or dataset is required to build.

## To build

```sh
git clone --recurse-submodules https://github.com/Al3xWalton/agentic-search.git
cd agentic-search
cargo build --locked --release
```

The binary is `target/release/stract`.

## To run

Fetch the development fixtures and build a small index from them. This
downloads two sample WARC files into `data/`.

```sh
target/release/stract configure
```

Start one search node and the API, each in its own terminal.

```sh
target/release/stract search-server configs/search_server.toml
target/release/stract api configs/api.toml
```

Query it.

```sh
curl -X POST http://localhost:3000/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query":"cedar","page":0,"num_results":10,
       "country":"unknown","adult_verified":false,"scholarly":false}'
```

This returns a JSON object with the ranked results. The interactive API
reference is served at `/api/docs/swagger` and the OpenAPI document at
`/api/docs/openapi.json`. The legacy namespaces are permanently retired; see
[the migration contract](docs/legacy-api-retirement.md).

## Options

See the published v1 schema at `/api/docs/openapi.json` for the supported request
fields, bounds and response contract. Listener annotations identify management-only operations.

## Crawling

The crawler identifies itself as `AVASearchBot` on every request. It reads
`robots.txt` before any URL on an origin and caches the answer for at most 24
hours, keeps at least 500 ms between requests to one host and at most two
connections to it (compiled in; configuration can only be more polite), honours
`noindex`, `nofollow`, `noarchive`, `nosnippet`, `max-snippet` and
`noimageindex` from headers and meta tags, records the rights signals a page
carries, and stops crawling a host for 24 hours after a 401, 403, 429 or a bot
challenge. Every outcome, including every non-save, is written to a ledger with
its reason. The published policy is [`CRAWLER_POLICY.md`](CRAWLER_POLICY.md),
served by the API at `/.well-known/ava-search-crawler`.

Production crawling is disabled until an approved data-protection record is
configured; the crawler refuses to start without one. A bounded research sample
runs against a frozen 200-seed list into a store outside the repository:

```sh
target/release/stract crawler sample --seeds <seeds.json> --out <external-directory>
```

Other crawler commands:

- `stract crawler reconcile`: explain every seed's outcome from the ledger, offline.
- `stract crawler inspect-warc`: count and parse the records of a local WARC file.
- `stract crawler retention`: delete raw page bodies past their retention limit (at most 30 days) from a managed store.
- `stract crawler policy-render`: render the crawler policy from validated configuration.

## How it works

- The crawler writes WARC files and, for each document, a typed record of the
  directives, rights signals and HTTP semantics it saw. A page that reserves its
  rights is kept as metadata only.
- The indexer builds a [Tantivy](https://github.com/quickwit-oss/tantivy)
  inverted index per shard, with host and page centrality computed from the web
  graph.
- Search nodes serve the shards. The API discovers them over gossip, fans a query
  out, merges the results and ranks them with text, centrality, freshness and
  tracker signals, and with the optic and host rankings the request supplies.
- Everything runs from the one `stract` binary.

## Development

`cargo xtask ci-all` runs the same gates as CI: workflow lint, the toolchain pin,
developer-path and notice checks, the crawler identity, dependency and policy
guards, the source offer, fmt, check, clippy, the wasm and frontend builds, a
release build, the workspace tests, licences, SBOM and secrets. The frontend
steps need Node 20.10.0 and wasm-pack 0.15.0.

`stract eval --help` describes local recall evaluation; `configs/eval/` contains loopback
templates whose index paths must point to independent temporary copies.

[CONTRIBUTING.md](CONTRIBUTING.md) is historical upstream guidance. Its Stract
CLA and commit instructions are not Agentic Search policy.

## Upstream

Derived from [StractOrg/stract](https://github.com/StractOrg/stract) at its
archived base 8ac40b02 (`8ac40b023e0a49f55cdd5b599841ea46d0503ec9`). The full
upstream history, [NOTICE](NOTICE) and the
[sample-optics](https://github.com/StractOrg/sample-optics) submodule are
retained. Stract was built on Tantivy, bootstrapped on
[Common Crawl](https://commoncrawl.org) data, and funded through
[NGI0 Entrust](https://nlnet.nl/entrust), a fund established by
[NLnet](https://nlnet.nl) with financial support from the European Commission's
[Next Generation Internet](https://ngi.eu) programme.

The `.spike` directory holds frozen research evidence (labels and
measurements). Its `<WORKSPACE>` placeholders must be adapted in a scratch copy
before a rerun.

## License

AGPL-3.0-only. See [LICENSE.md](LICENSE.md), [NOTICE](NOTICE), the
[source offer](SOURCE_OFFER.md) and the running
[source endpoint](./.well-known/ava-search-source). Subdirectory licence
exceptions and upstream notices are retained; this offer does not rewrite
upstream "or later" wording. If you fork Agentic Search, set the package
`repository` and `SOURCE_OFFER.md` to your own corresponding source.

## Contact

Use this repository's [GitHub issues](https://github.com/Al3xWalton/agentic-search/issues).
