from pathlib import Path
import datetime
root=Path(__file__).resolve().parents[1]
report=Path('<WORKSPACE>/story-573-reports')
headline='Hybrid verdict — Rust 1.98.0 built successfully in 180.454 s with zero dependency fixes; measured CC indexing extrapolates to 1.399 wall-hours and 23.752 GiB per million indexed pages; known-answer recall@10 was 36% for Stract versus Firecrawl N/A (HTTP 402/429).'
s=f'''{headline}

# Story 573 — final spike record

Executed 9 September 2026 on the requested Mac. Evidence and artifacts are local; nothing was published or deployed. The recommendation is to retain the working Stract ingestion/index/service core in an AGPL service, while building new agent query planning and a separate image retrieval pipeline. It is a foundation decision, not approval to replace live retrieval or a claim of parity with Firecrawl.

## Stage status and deliverables

| Stage | Final status | Outcome | Deliverable |
|---|---|---|---|
| 1 Build | Complete | Unmodified macOS stable 1.95.0 and requested 1.98.0 passed; zero dependency fixes; native crawler/webgraph compiled | [Build table and error ledger](build-report.md) |
| 2 Crawl + CC indexing | Complete, bounded sample | 178/200 seed pages saved; one 909 MB WARC; 19,285 CC + 178 seed documents indexed; resource measurements recorded | [Raw and per-million costs](cost-table.md) |
| 3 Fifty queries | Stract complete; Firecrawl blocked | Frozen 50 labels, Stract 18/50; p50 3.712 ms / p95 12.350 ms; Firecrawl 0 successful calls from 50 attempts | [Recall/latency tables](recall-latency.md), [answer set](queries-answer-set.json) |
| 4 Image attachment assessment | Complete | Code paths/line ranges, missing image pipeline, proposed CLIP/index/API boundary | [Image assessment](image-attach-assessment.md) |
| 5 Verdict + first Epic | Complete with explicit limits | Hybrid; separate AGPL service; preliminary 24–38 engineer-day Epic including contingency | This report |

The report folder contains exactly those six contracted files. The pre-existing `SPIKE-BRIEF.md` was moved intact to `{root}/SPIKE-BRIEF.md`. Full-history upstream clone is at `{root.parent}`; build targets, Cargo downloads, WARC, indexes, scripts and raw outputs are under `.spike/`.

## Evidence driving the choice

The dependency-maintenance objection did not materialize in this run. Upstream `8ac40b023e0a49f55cdd5b599841ea46d0503ec9` built without changes to engine source or Cargo.lock: stable/dev 102.984 s, 1.98/release 180.454 s. The native crawler and webgraph are in the compiled core. A rewrite to escape a broken build is not supported by these results. Linux, UI/frontend, distributed crawler coordinator and optional ML stack were not validated.

Ingestion is usable: the single CC file indexed 19,285 documents in 97.095 s, 114.458 CPU s, 2.967 GiB peak process RSS and 491,827,567 logical index bytes. That is 1.399 wall-hours/M, 1.649 CPU-hours/M and 23.752 GiB/M of index by direct arithmetic. Download plus indexing of that file normalizes to 5.400 wall-hours/M of indexed output, excluding inspection/label tooling. The seed crawl's much slower 346.421 wall-hours/M reflects polite waits and host distribution; its normalized compressed WARC size is 71.371 GiB/M. These separate denominators and all formulas are in the cost table. No production operating bill or million-page RAM requirement was measured.

Default retrieval is insufficient for the requested agent prose: 18/50 known answers in top ten, including 0/10 news and 2/10 each technical/commerce, with 19 zero-result queries. Every labelled answer was actually indexed. Ten selected misses became hits when shortened to keywords after the experiment, and the query planner has restrictive conjunctions. This supports prioritizing query construction/candidate recall. It does not prove a fix, and the incomplete relevance labels penalize useful alternate URLs; the 36% result must not be relabelled as comprehensive answer quality.

Images require substantial new work despite existing image storage utilities. DOM parsing, robots checks, WARC ingestion, lexical metadata, optics and API routing are reusable; general candidates/alt-context provenance, separate image fetch scheduling, CLIP inference, ANN retrieval, atomic metadata/vector generations and image-specific filters are absent. The attachment assessment distinguishes observed source from proposals.

## Assumptions and limits

1. **Toolchain:** upstream has no numerical pin; its CI requests `stable`, resolved here to already-installed 1.95.0. The requested already-installed 1.98.0 was separately built. Different dev/release profiles and cache states prevent a compiler performance comparison. No global Rust/package installation was made.
2. **Scope of build:** headless `stract` binary/core, including crawler/webgraph, compiled natively. This is not a full workspace/frontend test, Linux build, dependency security audit, or proof of archived hosted fixture availability. `just configure` was deliberately replaced with local configs to avoid unrelated downloads/off-scratch writes. Warnings remain.
3. **Crawler:** exactly 200 selected public page URLs, no link expansion, upstream robots client, minimum two seconds, at most four domains concurrently, domain-serial scheduling, skip excessive delays, 20-second timeout/retry limit one. Robots.txt requests are additional necessary checks. A local sink replaces S3/coordinator integration. There are 178 saved pages, two known robots denials and 20 unexplained no-save outcomes because release logging omits detailed failures.
4. **Corpus:** the first official CC-MAIN-2026-34 WARC path was chosen before contents were inspected, and downloaded whole. Its August 7 captures are combined with September 9 seed captures. This is one segment file and a deliberate seed set, not a representative web sample. Actual index document counts are used; raw `text/html` counts differ because of accepted XHTML/unknown types and index exclusions.
5. **Serving features:** baseline lexical engine, empty centrality, no webgraph/backlinks, optional ML/reranking/safety models, spellchecker or external fallback; two loopback shards. Results cannot represent the former hosted Stract configuration.
6. **Ground truth:** one manually reviewed known acceptable exact URL per query, one agent rater, no independent human adjudication, not exhaustive relevance. All answers are indexed (45 seeds, five CC commerce pages). Fixed URL normalization, no domain credit and no top-ten backfill. Balanced categories are constructed rather than sampled from AVA traffic.
7. **Label selection:** unavailable or unsupported targets were revised before retrieval and the final JSON was committed and hashed before both paths. News comprises seven Rust posts, one Mozilla post and two NASA stories within the combined corpus range, all from seed captures. Product q26 is labelled for page identity despite inconsistent flavour text. Image-bearing labels use captured content/markup, not fetched image bytes or CLIP relevance.
8. **Comparison:** Firecrawl would search the live web using US/web/top-ten defaults, while Stract searches the sample. Only the same sample-present known answers would earn recall credit; other valid live URLs could score zero. Provider failures leave recall/latency N/A, not zero, and no comparative winner is established.
9. **Timing/resources:** one run per operation/query; elapsed, child CPU and largest-child RSS. Build RSS is not the sum of compiler processes. Query latency includes loopback connection plus response artifact write, with partly warmed caches, no load test. p50 is median, p95 nearest rank; zero-result queries are included. Disk is final logical/allocated output, not physical I/O or true peak temporary disk. Seed indexing has up to one-second poll overhead; original disk-monitor defects and later correction are documented without changing old measurements.
10. **Scaling:** per-million values are explicit linear ratios, with successful-output denominators except download's response denominator. RAM is a process high-water mark; literal normalized RAM is shown only to satisfy the requested arithmetic and is not a sizing model. Fixed index/Bloom overhead, merges, domain mix, concurrency, image storage/inference, freshness and higher scale are unmeasured. Build caches, raw exports and HTML sidecars are research overhead. Money/cloud/energy costs were not measured.
11. **Diagnostic selection:** the ten successful keyword reruns were chosen after seeing failures and answers; they are causal clues, not a revised 50-query score or a general expected gain.
12. **Blocked baseline:** authenticated CLI status fell from 245 to −35 credits during the observed interval, but no successful search/creditsUsed envelope exists; concurrent account use cannot be excluded, so charges attributable to this spike are unknown. The original runner mistakenly continued after the first 402; the corrected runner stops on 402/429 and prevents overwrite. No further baseline calls, top-up or billing changes followed.
13. **Estimate status:** Epic engineering days below are planning judgment from the identified code surfaces and measured problems, not observed development throughput or a delivery commitment. Image and production operating costs remain unmeasured.

## Blocked and unmeasured work

**Firecrawl recall/latency is the only blocked execution stage.** CLI v1.19.27 authenticated successfully; 50 exact search attempts returned ten HTTP 402s and forty HTTP 429s, no result bodies. Pre/post status and per-query errors are preserved. Diagnosis included CLI help/status and read-only installed command/client source inspection. Completing it requires an external account/provider credit/rate-state change; autonomous retries would not supply valid evidence. No substitute result set was invented.

The 20 unsuccessful seed saves have no exact per-URL failure reason at the release log level; all targets/outcomes are retained. True peak temporary disk, million-page memory/capacity, Linux runtime, frontend/distributed service integration, richer ranking models, image retrieval and monetary costs were not measured. The latter items are either optional/conditional or expressly outside this spike; their omission does not imply success.

## AGPL boundary and ownership

The search service remains a **separate open-source AGPL-3.0 network service**. AVA's engine consumes a documented HTTP/JSON API; no Stract core is linked or copied into the engine. Keep ingestion, indexes, image workers, ranking and their service implementation on the AGPL side. Network separation supports the intended architectural boundary but is not a blanket license exemption for tightly coupled derivative code.

Publish the exact modified Corresponding Source **no later than the first external beta**, with a prominent source offer available to remote users of that running version. Include the source, interface definitions and scripts needed to build/install/run the covered service, dependencies/submodule references and modifications. The obligation applies when the modified service is offered remotely; do not treat beta naming as permission to delay an earlier applicable offer. This reading follows the [upstream AGPL license, especially section 13](https://github.com/StractOrg/stract/blob/8ac40b023e0a49f55cdd5b599841ea46d0503ec9/LICENSE.md) (local `LICENSE.md:536–550`; Corresponding Source definition at `:130–141`).

The vendored `crates/tantivy` is marked AGPL-3.0 in its current manifest, despite `ORIGINAL_LICENSE` being MIT. A rewrite cannot simply copy Stract's modified Tantivy and call it MIT. Clean-room architectural reuse or separately sourced upstream MIT code would require a file-level provenance/license review; that is not necessary to justify keeping this service AGPL.

The orchestrator, not this spike, would create a public AVA-owned repository. Because the hybrid retains Stract code, that repository must contain:

- Full upstream history and identifiable base commit, preserved upstream copyright/attribution, submodule provenance and license exceptions.
- AVA Search naming/README/package/service identity, while keeping AGPL-3.0 and existing notices; clear scope and source-offer links.
- A pinned tested Rust toolchain, Cargo.lock, reproducible native and subsequently validated Linux build instructions/CI, required dependency declarations and all service modifications.
- Source and build/install/interface files for crawler, ingestion, text query planning/ranking, public/admin API and future image components that form the covered service; configuration templates without secrets.
- Benchmark scripts, frozen labels and reproducibility metadata with appropriate data provenance; no private AVA engine source, credentials, private operational configuration or bulk third-party crawl/index artifacts committed as application source.

Nothing was published and no GitHub repository was created here.

## First Epic — measured foundation, preliminary effort

Size: **20–32 engineer-days of scoped work + 4–6 days contingency = 24–38 engineer-days** (roughly 5–8 working weeks for one engineer). These are explicit planning estimates, not measurements. The Epic delivers a reproducible AGPL foundation and a bounded image feasibility result, not whole-web production search.

| Stage | Estimated engineer-days | Work grounded in this spike | Concrete exit evidence |
|---|---:|---|---|
| Reproducible service and source boundary | 2–3 | Pin 1.98, preserve history/license, isolate fixtures, document native requirements, establish Linux CI | Clean native/Linux builds and source-offer/build manifest |
| Bounded ingestion reliability | 3–5 | Preserve robots/rates; expose the 20 unexplained failures; validate redirects, MIME handling and empty-centrality defaults; measure several batch sizes on retained sample | Per-target outcome ledger, no off-seed fetches, repeatable counts and process/disk measurements |
| Agent query planning | 5–8 | Examine restrictive conjunctions, add controlled entity/phrase/keyword planning and fallback; preserve exact query provenance | Frozen 50 regression plus new held-out labels; candidate/recall breakdown, no answer-aware evaluation rewrite |
| Image feasibility slice | 5–8 | Extract candidate metadata from retained WARC/seed HTML; bounded image fetch/CLIP/vector trial only in newly authorized scope; compare candidate/rerank/API choices | Measured extraction coverage, model/version/data provenance, image relevance/latency/storage table and selected backend |
| API and operational contract | 2–3 | Version text/image DTOs, source attribution, failure semantics, local resource limits, idempotent ingest/delete boundaries | Standalone service contract tests; external engine adapter design only until separately authorized |
| Independent evaluation and go/no-go | 3–5 | Second-rater labels; rerun affordable baseline after provider repair with fail-fast credit cap; evaluate image slice and text recall before public beta | Comparable successful baseline, held-out result table, measured resource limits and explicit release gate |

Build effort is small because no upstream dependency repairs were needed; release compilation itself took three minutes here. More budget goes to query recall (32 known-answer misses), ingestion observability (22 no-save targets), image components absent from source, and evaluation validity. Contingency covers archived dependencies/platform drift and data/model integration, not a known compile failure.

Initial proposed gates, to ratify in Epic planning: improve held-out known-answer recall over this baseline without sacrificing the factual/image-bearing cohorts; obtain a successful live baseline before claiming parity; measure incremental batches before buying million-page capacity; and establish image relevance/provenance before adding an image endpoint to an external beta. No production deadline, minimum recall target or backend is claimed proven by this spike.

## Execution journal and verification

- 20:06 UTC: initialized progress report, cloned full upstream history, inspected docs/CI/toolchain and existing decision context; report folder constrained to six files.
- 20:09–20:12: unmodified stable build passed, followed by requested 1.98 release build; zero dependency changes. Full logs retained.
- Stage 2: selected the first CC path before content inspection; downloaded one WARC, crawled only the 200 seeds with robots/rates, saved 178 pages; image source assessment completed while the bounded run progressed.
- Stage 2 completion: both local index jobs succeeded; exported actual documents and audited WARC counts/capture dates; 19,463 total indexed documents.
- 20:25: froze/committed the 50 reviewed labels before retrieval; Stract completed 50 HTTP-200 queries, Firecrawl failed all 50. Metrics preserve those failures and the provider-balance discrepancy.
- 20:28: completed the selected keyword diagnostics and stopped the three owned local services. Subsequent checks found all recorded PIDs absent and all eight loopback TCP ports closed; no `stract-spike-*` Docker containers exist and none were created.
- Finalization: generated cost/recall tables from raw JSON, recorded harness mistakes without relabelling upstream failures, and retained compact local evidence alongside the full unmodified upstream history. All downloaded/built/indexed artifacts stay in `.spike/`; no AVA product repository access, production deployment or image implementation occurred.

Final verdict: **hybrid**. Keep the measured working AGPL ingestion/index/API foundation; develop and evaluate agent query planning and image retrieval as substantial new service components. A wholesale rewrite has no build-cost justification from this run, while an unchanged fork has not met the agent retrieval need. The missing Firecrawl baseline limits the competitive conclusion, and every reported number is tied to retained command output or explicitly labelled arithmetic/effort estimation.
'''
(report/'REPORT-573.md').write_text(s)
p=report/'build-report.md';t=p.read_text();t=t.replace('Query candidates are provisional until verified against captured and indexed content; final answers are frozen before either benchmark path runs.','Query candidates were verified against captured and indexed content; final answers were frozen and committed before either benchmark path ran.')
t=t.replace('Runtime/indexing fixes, any additional validation, and the final local evidence commit are recorded below as execution proceeds.','''## Completed runtime validation

Both native index jobs and all 50 JSON API queries succeeded without further engine/runtime fixes. The Rust harness also enumerated both indexes (19,285 CC + 178 seed documents) and read all 21,174 CC records with zero parser errors. These execution checks cover the spike's ingestion/search path, not the full upstream unit/integration suite or frontend. No broad upstream test suite was run because optional hosted fixtures and unrelated components were outside the bounded benchmark.

Additional benchmark-control issues were preserved and corrected for future runs: the Firecrawl loop originally continued after provider 402/429 failures; it now stops and refuses to overwrite existing run evidence. CC disk sampling was incorrectly enabled only inside the child environment (peak temporary disk unmeasured); seed sampled peak omitted the final snapshot (final size separately verified). The measurement script now includes final disk in future sampled peaks. These changes do not alter recorded raw metrics, dependency versions or engine behavior.

The buildable upstream commit is `8ac40b023e0a49f55cdd5b599841ea46d0503ec9`. Local commit `8e1ddc116a64dbe0777b3e0f49c6842965960a91` adds the bounded harness/configuration and frozen 50-answer set; its only upstream-manifest change is the example target. The final evidence commit is identified in `.spike/data/final-validation.json` and the final handoff. No commit was pushed. All source file/line references in the assessment use the upstream commit.''')
p.write_text(t)
print(headline)
