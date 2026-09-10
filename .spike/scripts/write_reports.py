"""Render Story 573 reports from recorded evidence; does not rerun network or engine jobs."""
from pathlib import Path
import json, datetime, hashlib, subprocess
root=Path(__file__).resolve().parents[1]
report=Path('<WORKSPACE>/story-573-reports')
m=json.loads((root/'data/metrics.json').read_text())
disk=json.loads((root/'data/disk-final.json').read_text())
metrics={n:json.loads((root/'logs'/f'{n}.json').read_text()) for n in ['seed-crawl','seed-index','cc-download','cc-index']}
rows=[]
for name,n,output in [('seed-crawl',178,'data/seeds.warc.gz'),('seed-index',178,'data/index-seeds'),('cc-download',21174,'data/cc-sample.warc.gz'),('cc-index',19285,'data/index-cc')]:
 d=metrics[name];f=1e6/n
 rows.append({'stage':name,'pages_denominator':n,'wall_seconds':d['wall_seconds'],'cpu_seconds':d['cpu_user_seconds']+d['cpu_system_seconds'],'peak_rss_bytes':d['peak_rss_bytes'],'disk_logical_bytes':disk[output]['logical_bytes'],'disk_allocated_bytes':disk[output]['allocated_bytes_du_k'],'wall_hours_per_million':d['wall_seconds']*f/3600,'cpu_hours_per_million':(d['cpu_user_seconds']+d['cpu_system_seconds'])*f/3600,'disk_gib_per_million':disk[output]['logical_bytes']*f/2**30,'rss_arithmetic_gib_per_million_not_capacity':d['peak_rss_bytes']*f/2**30})
(root/'data/cost-metrics.json').write_text(json.dumps(rows,indent=2)+'\n')
def link(name):return f'[{name}]({root}/logs/{name})'
cost='''# Crawl and indexing costs

These are measured single-run resource costs on the Mac described in `build-report.md`, not cloud prices or whole-web capacity forecasts. **CC indexing: 19,285 documents in 97.095 wall seconds, 114.458 CPU seconds, 2.967 GiB peak RSS, 491,827,567 logical index bytes.** Normalized indexing is 1.399 wall-hours, 1.649 CPU-hours and 23.752 GiB of index per million successfully indexed documents.

## Raw measurements

| Stage | Page denominator | Wall s | CPU s (user + system) | Peak process RSS GiB | Output logical bytes | Output allocated bytes (du -k) |
|---|---:|---:|---:|---:|---:|---:|
'''
for d in rows:cost+=f"| {d['stage']} | {d['pages_denominator']:,} | {d['wall_seconds']:.3f} | {d['cpu_seconds']:.3f} | {d['peak_rss_bytes']/2**30:.4f} | {d['disk_logical_bytes']:,} | {d['disk_allocated_bytes']:,} |\n"
cost+='''
Crawl denominator is 178 saved pages from 200 scheduled unique URLs, so failed/denied attempts are included in time per successful page. Seed indexing inserted all 178. Download denominator is 21,174 WARC response records (one page response per URL), not 63,523 total WARC records. CC index denominator is the **19,285 actual stored documents**, verified by enumerating the index, not a MIME-based guess. Seed and CC outputs total 19,463 documents and unique normalized URLs.

## Arithmetic normalization

For each row, `factor = 1,000,000 / pages_denominator`; `wall hours/M = wall_seconds × factor / 3600`; `CPU hours/M = (user_seconds + system_seconds) × factor / 3600`; `disk GiB/M = output_logical_bytes × factor / 2^30`.

| Stage | Wall hours/M | CPU hours/M | Output GiB/M |
|---|---:|---:|---:|
'''
for d in rows:cost+=f"| {d['stage']} | {d['wall_hours_per_million']:.3f} | {d['cpu_hours_per_million']:.3f} | {d['disk_gib_per_million']:.3f} |\n"
cc=metrics['cc-index'];dl=metrics['cc-download'];den=19285
cost+=f'''
For the same CC output denominator (19,285 indexed documents), **download + index** was {dl['wall_seconds']+cc['wall_seconds']:.3f} wall seconds and {dl['cpu_user_seconds']+dl['cpu_system_seconds']+cc['cpu_user_seconds']+cc['cpu_system_seconds']:.3f} CPU seconds: {(dl['wall_seconds']+cc['wall_seconds'])*1e6/den/3600:.3f} wall-hours/M and {(dl['cpu_user_seconds']+dl['cpu_system_seconds']+cc['cpu_user_seconds']+cc['cpu_system_seconds'])*1e6/den/3600:.3f} CPU-hours/M. Retaining both compressed WARC and index scales arithmetically to {(disk['data/cc-sample.warc.gz']['logical_bytes']+disk['data/index-cc']['logical_bytes'])*1e6/den/2**30:.3f} GiB/M. This sum excludes the separate inventory/export/label review work.

RAM is a high-water mark, not an additive per-page cost. The requested literal arithmetic `peak_RSS × 1,000,000 / N / 2^30` yields the values below, **which must not be used to size RAM for one million pages**:

| Stage | Arithmetic peak-RSS GiB/M; not a capacity forecast |
|---|---:|
'''
for d in rows:cost+=f"| {d['stage']} | {d['rss_arithmetic_gib_per_million_not_capacity']:.3f} |\n"
cost+='''
The tiny seed index's 1.813 GiB RSS versus CC's 2.967 GiB demonstrates substantial fixed/batch overhead. `crates/core/src/entrypoint/indexer/worker.rs:252` configures a large fixed Bloom filter; allocator reservation, committed memory, batches and index buffers complicate scaling. No million-page memory high-water mark was measured. Four-domain polite crawl throughput is especially sensitive to host distribution and network/robots delays; 346.421 wall-hours/M is the observed seed ratio, not a whole-web forecast. No money, electricity, cloud rate, bandwidth bill or CLIP cost was measured.

## Bounded crawl and sample provenance

The frozen 200 URLs are in `.spike/data/seeds.json` (news, docs, products, how-to, government, factual/reference and image-bearing pages). The local Rust harness uses upstream `JobExecutor`/`RobotClient`, `wandering_urls = 0`, at most four distinct root domains concurrently, serial requests within each domain, minimum two seconds, and declared crawl delay when greater. It skips robots delays over 30 seconds; request timeout is 20 seconds and retry limit one. UA is `AVA-StractSpike/0.1 (bounded public-page research; no link expansion)`, with robots token `AVA-StractSpike`. Robots preflight and ordinary robots checks issue robots.txt requests in addition to the 200 allowed page targets. The sink rejects off-list datums and empty redirect records. No recursive frontier, images or off-list page content was fetched.

178 saved pages, two explicit robots denials (Sony and Steam Deck), and 20 further URLs with no saved page. Release `max_level_info` suppresses debug-only failure details, so exact causes for those 20 are **not known**; they are not silently called robots denials. Framework's 10-second crawl delay was honored. The seed WARC is 13,640,930 bytes; the extra saved HTML is 84,958,123 bytes, kept for label inspection and excluded from WARC/index storage totals.

The first entry in the official [CC-MAIN-2026-34 WARC manifest](https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-34/warc.paths.gz) was selected before inspecting content. Exactly one complete WARC file was downloaded; this was not a whole crawl or segment directory:

```
crawl-data/CC-MAIN-2026-34/segments/1786091384908.68/warc/CC-MAIN-20260807101845-20260807131845-00000.warc.gz
```

Download URL is `https://data.commoncrawl.org/` plus that path. Bytes: 909,108,907. SHA-256: `2c7f95cbbb7d1111fc0599e9badffd9f7a1a3b5ec2f1214d022ab8bf82678e87`. Capture times: 2026-08-07 10:19:29–13:04:31 UTC. Raw inventory: 63,523 records = one warcinfo + 21,174 each of request, response and metadata; 21,174 unique response URLs, including 19,267 `text/html` and 1,559 `application/xhtml+xml`. Upstream parser inventory read all 21,174 triplets with zero parse errors.

The index count need not equal raw `text/html`: `crates/core/src/entrypoint/indexer/job.rs:79–91` also admits unrecognized payload types (`None`), including XHTML, while worker preparation rejects noindex and empty titles. Its URL parsing/normalization also changes some stored URLs. Actual stored-document enumeration is authoritative; no claim that every rejected record's cause was audited.

## Configuration and reproducibility

Both local index jobs use batch size 512, auto-commit 5,000, one WARC file, an empty host-centrality store, no page centrality/webgraph, no embedding/LambdaMART/safety models and no minimum clean-word cutoff. The original release `stract indexer search` command built the indexes; no indexer source modifications were needed. Missing-centrality warnings are expected. This is the headless lexical baseline, not a reconstructed hosted Stract deployment.

Commands below are run from the workspace. Full argv, CPU and RSS data are in the linked JSON logs; `.spike/scripts/measure.py` wraps commands with a fresh child resource measurement.

```sh
python3 .spike/scripts/measure.py seed-crawl env TMPDIR="$PWD/.spike/tmp" RUST_LOG=stract::crawler=debug .spike/target-1.98/release/examples/spike crawl .spike/data/seeds.json .spike/data
python3 .spike/scripts/measure.py cc-index env SPIKE_DISK_PATH="$PWD/.spike/data/index-cc" TMPDIR="$PWD/.spike/tmp" RUST_LOG=stract=info .spike/target-1.98/release/stract indexer search .spike/configs/index-cc.toml
SPIKE_DISK_PATH="$PWD/.spike/data/index-seeds" python3 .spike/scripts/measure.py seed-index env TMPDIR="$PWD/.spike/tmp" RUST_LOG=stract=info .spike/target-1.98/release/stract indexer search .spike/configs/index-seeds.toml
```

Download used `curl --fail --location --retry 2 --max-time 1800 URL --output .spike/data/cc-sample.warc.gz --write-out '\\nhttp=%{http_code} bytes=%{size_download} seconds=%{time_total}\\n'`, launched inside the measured Python subprocess. The original inline wrapper's argv is `python3 -`; `.spike/data/cc-selection.json` and download output preserve the exact selected path and transfer result. Do not rerun these commands over retained indexes without selecting fresh output paths.

`getrusage(RUSAGE_CHILDREN)` CPU totals include descendants; peak RSS is the largest individual child, not a sum across concurrent processes. Runtime crawler/indexer jobs are single Rust processes with threads; build RSS has a different scope as documented separately. CC disk monitoring was accidentally enabled only in the child environment, so **CC peak temporary disk was not measured**. Final logical/allocated disk was independently measured. Seed wall time includes up to one second of disk-poll scheduling overhead; its intermediate disk high-water field omitted final output. The harness was corrected after measurements to include final disk in future sampled peaks; original records remain intact. Neither row claims a measured true peak temporary disk. macOS block-I/O counters are not used as evidence of zero physical I/O.

Caches/build targets are separate development overhead, not per-page engine costs. Final logical bytes: Cargo cache 306,642,789; stable target 5,657,284,960; 1.98 target 7,202,344,478. Raw index exports, parser inventories, HTML sidecars and query logs are research artifacts excluded from output index size. `.spike/data/disk-final.json` records both logical and allocated storage. Index/WARC artifacts remain local for reproducibility.

A single post-benchmark serving-RSS snapshot was 106,976 KiB (CC shard) + 50,272 KiB (seed shard) + 39,504 KiB (API) = 192.141 MiB. It is neither a peak nor a production sizing result. All services were stopped after benchmarking.

## Evidence

'''
for n in ['seed-crawl','seed-index','cc-download','cc-index']:
 cost+=f'- {link(n+".json")} and {link(n+".log")}\n'
cost+=f'- [Raw WARC inventory]({root}/data/cc-stats.json), [calculated cost data]({root}/data/cost-metrics.json), [disk snapshot]({root}/data/disk-final.json), [serving RSS]({root}/logs/serving-rss.log).\n'
(report/'cost-table.md').write_text(cost)

recall='''# Known-answer recall and latency

**Stract: 18/50 = 36% recall@10; p50 3.712 ms, p95 12.350 ms. Firecrawl: not measured — zero successful searches, ten HTTP 402 and forty HTTP 429 failures.** A failed provider call is not zero recall and its failure latency is not search latency.

## Fixed experiment

There are exactly 50 manually labelled, agent-style queries: ten each factual, how-to/technical, product/commerce, recent news and image-bearing. Every known answer was checked against captured text and the actual index export before retrieval. One rater (Codex), no independent human adjudication. Image-bearing labels additionally cite relevant image-resource markup in the captured parent page. No image bytes were fetched and this is not an image-search relevance evaluation.

Ground truth is one **known acceptable exact page** per query, not an exhaustive relevance set. All 50 answers are present among 19,463 indexed documents: 45 seed pages and five commerce answers from CC. Thus sample answer coverage is 100%. The answer set was frozen at 2026-09-09T20:25:35.869736+00:00, committed locally at `8e1ddc116a64dbe0777b3e0f49c6842965960a91`, and SHA-256 is `14ff433c807326a0b37ed984d7e69638e3c4d0fcdfc67923f3122a9c1be8df5e`. The report JSON and committed `.spike/queries-answer-set.json` are identical.

URL normalization lowercases host, strips leading www, ignores http/https and fragment, removes trailing slash except root, drops utm_*, gclid and fbclid parameters, sorts remaining parameters, and retains path case and meaningful parameters. No blanket domain credit. Compute each query's recall as `|normalized top-10 URLs ∩ known acceptable URLs| / |known acceptable URLs|`; average across 50. With one answer each this is also known-answer hit rate@10. Missing result slots receive no credit; no filtering/backfilling before top ten.

**Firecrawl searches the live web; Stract searches only this sample.** The intended comparison scores both against the same sample-present known answers. A useful live page at an unlabelled URL would receive no credit, so even a successful run would not measure unrestricted live-web answer quality. No valid superiority claim over Firecrawl can be made from this blocked run.

## Measured results

| Category | Queries | Stract known answers in top 10 | Recall@10 | p50 ms | p95 ms | Zero-result queries | Firecrawl recall / latency |
|---|---:|---:|---:|---:|---:|---:|---|
'''
for cat,vals in [('All',m['modes'])]+list(m['categories'].items()):
 s=vals['stract'];recall+=f"| {cat.replace('_',' ')} | {s['attempts']} | {round(s['recall_at_10']*s['successes'])}/{s['attempts']} | {s['recall_at_10']:.0%} | {s['p50_ms']:.3f} | {s['p95_ms']:.3f} | {s['zero_results']} | N/A: provider rejected requests |\n"
recall+='''
All 50 Stract calls returned HTTP 200. The client sent one sequential request per query to `POST http://127.0.0.1:57300/beta/api/search` with `{"query": "…", "numResults": 10, "page": 0, "flattenResponse": true, "countResultsExact": true}`. Two loopback shards served CC and seeds with the unmodified release engine. No custom optics, centrality, webgraph, optional embedding models, LambdaMART, spellchecker or external result fallback was enabled. Upstream default lexical ranking and query planning were retained.

Latency is client elapsed wall time, including a fresh HTTP connection and writing the small raw JSON response; it is not pure engine CPU time or WAN latency. Server `searchDurationMs` is preserved per response. p50 is the median; p95 is nearest rank `sorted[ceil(0.95 × n) − 1]`. One pass only, no concurrency/load test, no confidence claim. A prior unrelated `canberra` smoke query and earlier index exports warmed some caches; this is neither a controlled cold-cache nor fully warmed benchmark. The 19 zero-result calls also make a low overall latency easier to achieve.

Five inaccessible commerce seeds were replaced with actual CC products, and two unavailable targets plus one unsupported factual wording were revised **before either search run**. News labels cover seven Rust announcements, one Mozilla announcement and two NASA stories, dated within the combined August 7–September 9 corpus range; all news answers came from the September 9 seed captures, not the August 7 CC file. This deliberate balanced set is not a representative production traffic sample. Product q26 has inconsistent flavour wording in captured title/body; it is labelled for product-page identity only, as recorded in its rationale. No product claims are endorsed.

## Firecrawl blocker and exact attempts

Installed CLI v1.19.27 was authenticated. Before the benchmark, `firecrawl --status` reported 245/1,000 credits and concurrency 0/2. The same 50 frozen query strings were attempted with:

```sh
firecrawl search "<query>" --limit 10 --sources web --country US --timeout 60000 --json -o ".spike/.firecrawl/<query-id>.json"
```

The actual absolute output paths and arguments are in `.spike/data/firecrawl-runs.json`; working directory `.spike`, TMPDIR `.spike/tmp`, `FIRECRAWL_NO_SEARCH_FEEDBACK=1`. No scrape-content option was used. Country US is a declared baseline default for these English-language queries; it was not tuned per answer.

The first request already failed HTTP 402. The original runner continued all 50: ten 402s then forty 429s, no result JSON. This was a benchmark-control mistake: it should have stopped on the first credit/rate rejection. The retained runner now stops on 402/429 and refuses to overwrite existing evidence; **it was not rerun**. CLI status afterward still showed authentication but −35/1,000 credits. The observed balance difference is −280; these error envelopes provide no `creditsUsed`, and concurrent account activity cannot be ruled out, so the spike's actual credit charge is unknown. No top-up, billing change, credential change or alternate paid service was used. CLI source inspection confirms failed API calls expose only the error message. The baseline cannot complete without an external account/provider state change; no failed-attempt timing is reported as successful search performance.

## Query-level results

`Hit` is the fixed known-answer URL, not an assessment that all other results were irrelevant. The JSON answer set includes the exact acceptable URL and captured-content rationale for every row.

| ID | Query | Known-answer hit@10 | Results returned | Stract ms | Firecrawl error |
|---|---|---:|---:|---:|---|
'''
for row in m['rows']:
 s=row['stract'];err=row['firecrawl']['error'].split()[-1];q=row['query'].replace('|','\\|')
 recall+=f"| {row['id']} | {q} | {int(s['recall_at_10'])} | {len(s['top10_urls'])} | {s['latency_ms']:.3f} | HTTP {err} |\n"
recall+='''
## Diagnostic interpretation; not a replacement score

After the fixed run, ten hand-chosen misses were rerun as shorter keyword queries: q11 `python venv`, q12 `python json`, q13 `read_to_string`, q21 `vanilla pods`, q25 `Felix First Class`, q27 `S203U-C15`, q32 `Rust 1.98.1`, q33 `rustup 1.29.1`, q36 `arrayref`, q38 `Firefox release cadence`. All ten retrieved their known answer in the top ten. These were selected with knowledge of the answers, so they do **not** establish a new overall recall score or predict recovery for the other misses.

They show that those ten failures are not missing-corpus failures. Source inspection supports investigating query construction: `crates/core/src/query/plan/mod.rs:235–299` builds and combines term plans, including `.and` at line 298; `crates/core/src/query/plan/node.rs:79–100` maps conjunction to Tantivy `Must`, while alternatives map to `Should`. Full agent prose can therefore impose restrictive terms. This is an evidence-backed investigation priority, not proof that every failure has one cause. Candidate generation/query planning should be evaluated before training a reranker; a reranker cannot recover absent candidates.

## Evidence and reproduction

'''
recall+=f'''- [Frozen answer set](<{report}/queries-answer-set.json>), [calculated metrics with returned URLs]({root}/data/metrics.json).
- [Stract run metadata]({root}/data/stract-runs.json), [Firecrawl attempted commands]({root}/data/firecrawl-runs.json), raw `.spike/data/stract-q01.json` through `stract-q50.json`, and `.spike/logs/firecrawl-q01.log` through `firecrawl-q50.log`.
- {link('firecrawl-setup.log')}, {link('firecrawl-status-after.log')}, [post-hoc keyword diagnostics]({root}/data/keyword-diagnostics.json).
- `.spike/scripts/evaluate.py` recomputes metrics entirely from retained artifacts. `.spike/scripts/benchmark.py` is the runner, with the later fail-fast/no-overwrite correction described above. Serving configurations are in `.spike/configs/`; services are stopped and cleanup verified.
'''
(report/'recall-latency.md').write_text(recall)
print('wrote cost-table.md and recall-latency.md')
