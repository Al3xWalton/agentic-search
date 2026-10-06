# Legacy API retirement

Story #662 permanently retires the public `/beta` and `/improvement` HTTP namespaces.
Use `/v1/search` for document search. There is no switch, alternate listener or legacy alias.
The public API still serves its favicon and source, crawler-policy and egress publications.

```sh
curl -X POST http://localhost:3000/v1/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"cedar","page":0,"num_results":10,
       "country":"unknown","adult_verified":false,"scholarly":false}'
```

The supported OpenAPI document is `/api/docs/openapi.json`; Swagger UI is
`/api/docs/swagger`. It contains all v1 operations, including their listener annotations,
and the three well-known GET operations. Management operations still require the separate
management listener and retain their existing authentication requirements. Publication does
not make those operations available on the public listener.

## Refusal contract

The public router returns `410 Gone` for `/beta`, `/beta/`, all `/beta/*` descendants,
`/improvement`, `/improvement/` and all `/improvement/*` descendants. This includes unknown
descendants, former docs and assets, search, widget, sidebar, spellcheck, autosuggest,
webgraph, exports, entity images, query storage and click recording.

GET, POST, PUT, PATCH, DELETE and OPTIONS return exactly these bytes, without a final LF:

```json
{"error":{"code":"legacy_api_retired","message":"Use the v1 API"}}
```

HEAD returns the same status with an empty body. Responses have `Content-Type: application/json`,
`Cache-Control: no-store` and the normal `Source-Offer` header. They contain no redirect,
query identifier, result or `X-Api-Version`. Compression and CORS preflight do not alter this
contract. Nonmatching case, encoded prefixes and near-prefix paths retain the empty 404.
Management HTTP and metrics retain empty 404s for the old namespaces; management `/v1/search`
retains the v1 not-found envelope.

The handler extracts only the HTTP method. It never polls, decodes or logs the body, parses
URLs, constructs query vectors, invokes a searcher or schedules storage. Even an empty body
or a one-byte body is refused, as are million-byte queries and chunked input.

HTTP can refuse a request before its upload finishes. A client that continues sending a large
body may see a transport error after that early refusal. `Expect: 100-continue` lets it receive
the refusal before sending the body.

## Storage and startup

Accepted query-store body bytes: **zero**. Queued stored queries: **zero**. Retained
query-queue bytes: **zero**. The HTTP handlers, event types, item queue and Scylla worker
are removed; their upstream files retain only their original notices and retirement docs.
No replacement storage system or reported-zero counter supplies this invariant.
This does not bound HTTP parser, connection, transport or total process memory.

Remove every `[query_store_db]` table from operator configuration. The shape remains accepted
by configuration parsing solely to give a fixed migration diagnostic. Every configured value
is rejected before resource, cluster or listener work, both by the stock binary and direct
Rust router construction. With backtraces disabled the CLI exits 1 with exactly:

```text
Error: query_store_db has been retired
```

No credentials appear in that diagnostic. No database connection, schema change, migration
or deletion is attempted. Existing database data is untouched. The old
`max_concurrent_searches` setting no longer limits any route; v1 uses
`[v1] max_concurrent_requests`. Its existing request and ingest limits are unchanged.

## Deliberate compatibility breaks

The following inventory uses pre-retirement base `13f29159` anchors. Story #598 owns these
remaining clients and obsolete machinery; it must not reintroduce the retired HTTP surface.

| Consumer | Consequence |
| --- | --- |
| `frontend/src/lib/api/index.ts:112,120,122,166` | Search, autosuggest and webgraph retired. |
| `frontend/src/lib/improvements.ts:15,17,40,47` | Query and click telemetry is refused. |
| `frontend/src/routes/search/ResultLink.svelte:37` | Click beacons are refused. |
| `frontend/src/routes/search/Entity.svelte:19,68` | Entity image requests are retired. |
| `frontend/package.json:17` | The inherited OpenAPI generation URL is obsolete. |
| `tools/annotate-results/src/routes/annotate/[slug]/+page.server.ts:13` | Retired. |
| `tools/ranking-diff/src/lib/stores.ts:54` | Beta calls fail. |
| `ltr/stract.py:3` | The beta client requires separate removal or migration. |
| `scripts/generate_nsfw_dataset.py:5071` | The inherited beta caller is obsolete. |
| `docs/api/src/pages/index.tsx:7` | The beta docs link is obsolete. |
| `docs/api/docusaurus.config.ts:96` | The beta docs link is obsolete. |
| `crates/core/src/eval/runner.rs:67,132,163,175,183` | Current beta recall runs cannot succeed. |
| `crates/core/src/eval/features.rs:2829` | The shared beta measurement attempt cannot succeed. |
| `crates/core/examples/stage1/capture.rs:1587` | Historical synthetic beta protocol remains. |

The evaluator needs `queryPlan`, `webpages`, `planStage` and `searchDurationMs`; v1 deliberately
does not supply that protocol. Changing only its URL would misrepresent measurements.
Historical evaluator tests, sealed #589 results and offline result rescoring remain valid
for their historical contracts. Future #589 runs retain supported v1 columns and omit legacy
beta columns. A supported evaluation transport and provenance design needs a separate Story.
Old binaries may be used only for authorised isolated historical replay, never to serve users
around retirement. Historical beta goldens and private generators describe formats, not live
HTTP availability; the v1 golden remains unchanged.

The available private engine revision supplied with the brief establishes a v1 ingest
consumer, but no query-client source anchor. This Story makes no independent engine query
integration claim. The local inventory is not a traffic survey of unknown external clients
or database readers.

## Remaining work and scope

Story #624's public entity-image exposure is superseded when verified #662 merges. Private
legacy library functions are not claimed repaired. Story #598 retains the frontend, Python
bindings, non-Rust tools and CI replacement, obsolete docs clients, unshared handler/types
and unused Scylla dependency cleanup.

These additional legacy-only items remain for #598 (base anchors):

| Item | Base anchor |
| --- | --- |
| Startup autosuggest construction | `crates/core/src/api/mod.rs:208-214` |
| Searcher warm-up | `crates/core/src/api/mod.rs:238-246` |
| State graph, suggestions, similar hosts, counters | `crates/core/src/api/mod.rs:79-87` |
| `max_concurrent_searches` | `crates/core/src/config/mod.rs:324` |
| `top_phrases_for_autosuggest`, `max_similar_hosts` | `crates/core/src/config/mod.rs:307-311` |
| Legacy metric groups (below) | `crates/core/src/entrypoint/api.rs:44-80` |

Those groups are `stract_search_requests`, `stract_daily_active_users`
and `stract_explore_requests`.

Residual, outside SB-01: native search-server RPC (`entrypoint/search_server.rs:118`; sample
bind `0.0.0.0:3002`, `configs/search_server.toml:6`) and the API's native management
`TopKeyphrases` (`entrypoint/api.rs:103-125`; sample bind `0.0.0.0:3011`, `configs/api.toml:8`)
are internal cluster protocols, not public HTTP routes. They return ungated retrieval or
index key phrases and must be kept off untrusted networks. This is not claimed closed here.

This change addresses SB-01 and SB-02 only. Other findings, release approvals, deployment
decisions and physical document erasure remain outside this Story.
