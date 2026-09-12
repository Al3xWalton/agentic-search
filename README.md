# Agentic Search

Agentic Search is AVA's open-source web retrieval service for AI agents, built on the archived Stract engine and consumed over HTTP.

[![CI](https://github.com/Al3xWalton/agentic-search/actions/workflows/ci.yaml/badge.svg)](https://github.com/Al3xWalton/agentic-search/actions/workflows/ci.yaml)

## Inherited capabilities

- Keyword search that respects your search query.
- Fully independent search index with its own crawler.
- Advanced query syntax (`site:`, `intitle:` etc.).
- DDG-style [!bang syntax](https://duckduckgo.com/bang)
- Wikipedia and stackoverflow sidebar
- De-rank websites with third-party trackers
- Use [optics](https://github.com/StractOrg/sample-optics/blob/main/quickstart.optic) to almost endlessly customize your search results.
  - Limit your searches to blogs, indieweb, educational content etc.
  - Customize how signals are combined during search for the final search result
- Prioritize links (centrality) from the sites you trust.
- Explore the web and find sites similar to the ones you like.
- And much more!

## Build

```sh
git clone --recurse-submodules https://github.com/Al3xWalton/agentic-search.git
cd agentic-search
cargo build --locked --release
```

Rust is pinned to 1.98.0 with rustfmt, clippy and the wasm32-unknown-unknown target.
Linux requires `build-essential clang pkg-config libssl-dev liburing-dev` (install with apt).
macOS requires the Xcode command-line toolchain and SDK. No model or data is required to
compile. `just configure` and `just setup` download/build optional development fixtures;
they are not CI prerequisites. Starting the full API requires configured search nodes.
Optional frontend tooling uses Node 20.10.0 and wasm-pack 0.15.0: build
`crates/client-wasm` with `wasm-pack build --target web --locked` before running
`npm ci`, `npm run check` and `npm run lint` in `frontend`.

[CONTRIBUTING.md](CONTRIBUTING.md) is historical upstream guidance. Its Stract CLA and
commit instructions are not newly adopted Agentic Search policy.

## Upstream

Derived from [StractOrg/stract](https://github.com/StractOrg/stract), archived base 8ac40b02
(full commit 8ac40b023e0a49f55cdd5b599841ea46d0503ec9). The full upstream history and notices
are retained. See [NOTICE](NOTICE) and the retained
[sample-optics submodule](https://github.com/StractOrg/sample-optics).
Frozen `.spike` evidence retains labels and measurements. Its `<WORKSPACE>` placeholders
require explicit adaptation in a scratch copy before a future rerun.

## License

Agentic Search offers its source under AGPL-3.0-only. See [LICENSE.md](LICENSE.md),
[NOTICE](NOTICE), the [source offer template](SOURCE_OFFER.md) and the running
[source endpoint](./.well-known/ava-search-source). Subdirectory licence exceptions and
upstream notices are retained; this offer does not rewrite upstream “or later” wording.

If you fork Agentic Search, set the package `repository` and `SOURCE_OFFER.md` to your own corresponding source.

The bounded sample runner is `stract crawler sample --seeds <seeds.json> --out <external-directory>`; it accepts only the frozen 200-seed scope.
Read the [crawler policy](CRAWLER_POLICY.md); hosted policy publication and founder-owned content are pending while production crawling is disabled.
Production crawling requires an approved DPIA with linked LIA and Article 14 measures; see the crawler configuration template.
## Contact

Use this repository's [GitHub issues](https://github.com/Al3xWalton/agentic-search/issues).

# 🏆 Thank you!

We truly stand on the shoulders of giants and this project would not have been even remotely feasible without them. An especially huge thank you to

- The authors and contributors of Tantivy for providing the inverted index library on which Stract is built.
- The commoncrawl organization for crawling the web and making the dataset readily available. Even though we have our own crawler now, commoncrawl has been a huge help in the early stages of development.

## Upstream historical funding

Upstream Stract was previously funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund established by [NLnet](https://nlnet.nl) with financial support from the European Commission's [Next Generation Internet](https://ngi.eu) program. Learn more at the [NLnet project page](https://nlnet.nl/project/Stract).

<div>
  <a href="https://nlnet.nl"><img align=center src="assets/nlnet/banner.png" alt="NLnet foundation logo" width="20%" /></a>
  &nbsp;
  &nbsp;
  <a href="https://nlnet.nl/entrust"><img align=center src="assets/nlnet/NGI0_tag.svg" alt="NGI Zero Logo" width="20%"/></a>
</div>
