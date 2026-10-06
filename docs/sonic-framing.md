# Sonic peer framing

Sonic limits encoded request and response bodies to 67,108,864 bytes (64 MiB) by default.
The native-width header is excluded. Equality is accepted; zero permits zero-byte encodings
such as unit. The same policy governs local encoding and incoming frame admission.

The reader parses a stack-resident native `usize` header, checks its declaration, and only
then starts reading the body. Body storage starts empty. Reads offer at most 16,384 bytes
and never extend past the current frame. Storage grows only after bytes arrive, using
fallible geometric reservations whose requested capacity cannot exceed the declaration.
Both raw read paths share this implementation.

Bincode decoding has a separate 268,435,456-byte (256 MiB) claim budget and must consume the
entire body. The budget bounds bincode's *live* claim, not the decoded size of the frame.
`Vec<u8>` and `String` keep their byte claims, but `Vec<T>` claims `len * size_of::<T>()` up
front and gives one element's claim back as each element is decoded. Each container is
therefore checked against the budget on its own, and the containers of one frame together can
hold far more: one 8,388,635-byte frame of three nested `BatchGet` key lists keeps 268,435,488
bytes, and a full 64 MiB frame of the same shape about 2 GiB. A cumulative per-frame budget
needs a bincode decoder hook that the locked revision does not expose. It is tracked as issue
#669; the founder approved deferring it to a bincode change on 2026-10-06.
A claim is not a heap measurement either: allocator overhead, serde-decoded fields (which make
no claims) and custom decoders that do not claim sit outside it. A frame within 64 MiB can
still exceed the budget, especially for types with large inline variants. Raising a service's
encoded cap does not raise this independent budget.

## Source policy

Existing services inherit the default; the DHT service overrides it (see Sizing evidence).
A service can declare a source-level override:

```rust,ignore
sonic_service!(SomeService, [First, Second], max_frame_body_bytes = 128 * 1024 * 1024);
```

This example value is illustrative; the only shipping override is the DHT service's.
The macro is imported from `crate::distributed::sonic::service::sonic_service`.
The generated associated constant flows through service bind, timed/default clients and
retries. Pools and replication clients use these same constructors.
Raw callers can use `Server::bind_with_limit`,
`Connection::create_with_timeout_and_limit` and `create_with_timeout_retry_and_limit`.
There is no TOML/runtime override or per-message-kind policy.

## Errors and connection ownership

An incoming oversized declaration returns `BodyTooLarge { body_size, max_size }` before body
reads or reservations. An oversized outgoing value returns the same variant locally before
any header byte is written. Its reported size is the first attempted encoded size and can
be a lower bound on the complete value. Values are never silently truncated or split.
The remote peer ordinarily sees `IO(UnexpectedEof)` for a refused local response: the wire
has no error envelope carrying the other peer's size error.

Invalid bodies return `Decode`, decoder budget failures return `Decode(LimitExceeded)`, and
trailing bytes return `TrailingBytes { consumed, body_size }`. Other encoding failures return
`Encode`; failed bounded reservations return `Allocation`. Partial headers/bodies return
`IO(UnexpectedEof)`. Returned framing errors and owned exchange timeouts drop the actual
socket. A retained failed owner returns `ConnectionClosed` on its next operation; pools
reject it. A successful exchange clears the pending-response flag and remains reusable.
Externally cancelling a request future still requires discarding its owner.

New error variants have fixed Display messages. Display carries no frame text, but Debug
and `source()` may carry bincode detail, including up to four body bytes or serde messages.
Existing Debug logging in `sonic/replication.rs` remains a follow-up.

## Wire and rollout

The header remains native `usize` bytes in native byte order. Standard bincode integer
encoding and service variant order are unchanged. Same-architecture, same-schema old/new
peers can exchange ordinary frames accepted by the new cap, decoder budget and full-consumption
rule. There is no policy negotiation or general cross-version/cross-architecture guarantee.
Old receivers retain the original framing defects. Coordinate the upgrade and align peer caps;
a mixed deployment does not provide cluster-wide protection.

## Sizing evidence

The 64 MiB default is a policy choice, not a measured traffic percentile or a maximum legitimate
message size. Source context includes 20 default search results, 275-character desired snippets,
at most 300 v2 retrieval pointers, a 32 MiB crawler content limit and 512-item indexing batches.
Unrestricted strings, arbitrary indexing vectors and unlimited webgraph results have no proven
finite maximum. A 512-page batch with 32 MiB bodies is 16 GiB before metadata.

The W10 loopback witness sends these complete synthetic values through production sonic and
measures their standard bincode body lengths. The 4 KiB and 16 KiB fields are synthetic
assumptions, not measured production facts.

| Synthetic value | Encoded body bytes |
| --- | ---: |
| 20 records, 16-byte titles, 275-byte snippets | 5,921 |
| 300 records, 16-byte titles, 4 KiB text | 1,235,201 |
| `IndexWebpages` envelope, 512 pages with 16 KiB bodies | 8,403,982 |
| `IndexWebpages` envelope, 1 page with a 32 MiB body | 33,554,476 |
| 4096 `(u64, HyperLogLog<64>)` pairs | 278,029 |
| Projection: that batch body times 300 append entries | 83,408,700 |

The last row is a synthetic batch-body projection (the product of one measured batch and 300
entries), not a measured append frame. It exceeds the 67,108,864-byte default, so a lagging DHT
follower receiving 300 such batches in one `AppendEntries` frame would be refused.
The DHT service therefore declares its own cap, `MAX_DHT_FRAME_BODY_BYTES` = 134,217,728 bytes
(128 MiB) in `ampc/dht/network/mod.rs`: about 1.6x the projection. Raft payloads decode through
serde and make no bincode claims, so the 256 MiB decoder budget does not bound them. Real shard
counts and follower lag are not established, so this is headroom for the projected case, not a
proof that every DHT frame fits.

| Service | Body cap (bytes) |
| --- | ---: |
| DHT (`ampc::dht::network::Server`) | 134,217,728 |
| Every other sonic service and raw caller | 67,108,864 |

Openraft defaults permit 300 append entries and 3 MiB snapshot chunks. Harmonic-centrality
batches scale with shard count times 4096; these measurements do not establish a universal
DHT envelope maximum.

## Limits and follow-ups

The bounds cover declared/retained encoded bodies and ordinary decoder byte claims. They do
not bound allocator rounding, transient old-plus-new Vec storage, aggregate connections,
indefinite server reads, custom Encode/Decode work, zero-sized-element loops, decoded object
graphs or serde visitor allocation. No process RSS or aggregate CPU guarantee follows.

Framing errors are connection-local in the raw and service layers. Successfully decoded but
unexpected OneOrMany/Wrapper response shapes still reach separate unwraps in `sonic/service.rs`.
Broader admission controls and these response-shape checks are F04 follow-ups.
`ampc/server.rs:73,89` propagates response errors out of its worker loop (`:113–116`), and
`ampc/dht_conn.rs:183,193,216,225,229` unwraps client errors, and `ampc/dht/network/raft.rs`
panics on any sonic error other than a timeout, formatting it with `Debug`. Those application
effects are also F04 follow-ups; they are not made connection-local by this change. The raw AMPC
server handles one accepted connection at a time with no read deadline, so one stalled peer
blocks every other AMPC client. `ampc/dht/store.rs:437` decodes peer-supplied snapshot bytes
with no claim limit; it is not a sonic read path. These residuals are tracked in issue 667.

The DHT client loops in `ampc/dht/network/api.rs` and `raft.rs` match `Error` exhaustively. They
retry `ConnectionClosed` with the other transport errors and return `Decode`, `Encode`,
`Allocation` and `TrailingBytes` at once, like `BodyTooLarge`.

The live-index crawler retries all indexing failures once per second
(`live_index/crawler/mod.rs:91,102`). A permanently oversized batch can stall indefinitely.
Caller batching and retry policy remain the F06 follow-up. The DHT service is the only
service with a cap override. The now-unused bytemuck dependency is retained because
dependency changes are outside this Story.
