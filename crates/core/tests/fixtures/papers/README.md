# Synthetic paper fixtures

These records were authored for offline contract tests. No API, corpus, real credential or private
implementation supplied their contents. Work IDs begin W9999, DOIs use 10.5555, and resource hosts
are reserved example domains. OpenAlex and doi.org are necessary identity literals, never contacted.

`openalex-page.json` has two ordered works, different title/display_name values, Unicode author
names, null optionals, landing/PDF/OA alternatives, ignored fields and a pagination count.
`openalex-empty.json` supplies a count-zero terminal page. `http-page.json` independently encodes
the same source metadata with all six hit keys, all eight attribution keys, CC0-1.0 and a source
snapshot date. `http-empty.json` explicitly includes a null next_page. `openalex-expected.json`
is the full expected local v1 value, including empty snippets and a null live snapshot date.

The generation recipe is to author those metadata values, hash the literal canonical OpenAlex
URLs with SHA-256, and assemble the expected envelopes independently of connector code. There is
no mapper-under-test call in the recipe. The witnesses compare complete values and preserve
author and result order. SHA-256 hashes of the shipped fixture bytes:

| File | SHA-256 |
| --- | --- |
| http-empty.json | 04c6ce3e0f2520b2a0597052fa19698ce11857f21202800c360b64ac0a99a36a |
| http-page.json | e3ecb45d2c1a5a00c5f251fb614d4e5d484e8a0b2bb2d993c0e4a08ded2f0d9d |
| openalex-empty.json | 8d83d2a672bbbe717722a8809d479bd1cc242ac1884f96e421ca8fdbab8e4590 |
| openalex-expected.json | 8857253a23d11693f13fe8a7fe09fd3c84b5dd6b0e74474599d85c9acd29436c |
| openalex-page.json | 8a875f6af4430aeb98549023d198d4bdb261fb92551842e50b6ee3b1f29ffec8 |

The production-path witnesses create variations in memory: exact/over byte and scalar limits,
invalid fields and identities, missing/null keys, repeated keys, depth/token caps, record drops,
status/error mismatches, wrong valid tokens, reflected redirects, split bodies, parsed header
limits and delays. Their servers bind only owned loopback sockets and collect request bytes in
memory. Assertions use content-free markers. A sealed synthetic TLS identity is embedded as DER
bytes in the Rust test module; the client control trusts only its test root and checks a reserved
hostname. No fixture installs trust globally or disables verification in production.
