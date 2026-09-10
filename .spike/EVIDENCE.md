# Story 573 local evidence

Upstream: 8ac40b023e0a49f55cdd5b599841ea46d0503ec9, full history retained.
Frozen ground-truth commit: 8e1ddc116a64dbe0777b3e0f49c6842965960a91.
All evidence is local; no publication or production deployment was performed.

The six deliverables are at:
`<WORKSPACE>/story-573-reports/`

- `logs/`: measured argv, elapsed/CPU/RSS and complete command output, including failures.
- `queries-answer-set.json`: frozen manually reviewed known-answer labels, identical to report JSON.
- `data/metrics.json`: computed 50-query result table; Firecrawl failures remain null, not zero recall.
- `data/cost-metrics.json` and `disk-final.json`: arithmetic resource normalization and storage observations.
- `data/stract-q*.json`: raw Stract responses; `firecrawl-runs.json` and error logs retain provider rejection evidence.
- `configs/`: local-only indexing and two-shard serving configurations.
- `scripts/`: bounded crawler example and Python measurement, labelling, evaluation and reporting tools.

Heavy WARC/index/build artifacts and page exports are retained on disk but ignored by Git. Seed manifest and frozen labels identify the sampled content. The bulk third-party corpus is not part of the source handoff.

`python3 .spike/scripts/evaluate.py` recomputes metrics offline from retained local index exports and result bodies. `write_reports.py` renders cost/recall tables from evidence. `write_main_report.py` writes the interpretive report and build completion section. These do not issue network requests. Report-relative paths assume the originally requested workspace.

`benchmark.py` was corrected AFTER the original run to refuse overwriting evidence and stop at the first Firecrawl HTTP 402/429. Original run: 50 failed requests; no successful baseline and no subsequent rerun. `measure.py` was corrected afterward to include final disk in sampled peaks; original measurements are unchanged. See report caveats.

All three owned loopback services were stopped; no Docker containers were created. `data/final-cleanup.json` records checks. `data/final-validation.json` (local, not committed, because it includes the evidence commit hash) records the final handoff validation.
