# AVA Search crawler policy

Bounded research sample only; production disabled; founder approvals pending.

Policy version: 585.1. Source: https://github.com/Al3xWalton/agentic-search. Policy URL: https://github.com/Al3xWalton/agentic-search/blob/main/CRAWLER_POLICY.md.

Identity: AVASearchBot/0.1.0 (+https://github.com/Al3xWalton/agentic-search/blob/main/CRAWLER_POLICY.md; https://github.com/Al3xWalton/agentic-search/issues)

## P01 Controller identity

[FOUNDER REQUIRED: controller identity]

## P02 Contact

Crawler contact: https://github.com/Al3xWalton/agentic-search/issues. Public issues are not a confidential rights channel; private controller contact is pending founder approval.

## P03 Purpose

Building a search index for AVA from publicly accessible pages. No profiling, advertising, images, favicons or user-facing cached copies are enabled by this ingestion slice.

## P04 Lawful basis and LIA

Intended basis: legitimate interests, subject to an approved DPIA and linked LIA. No completed assessment is asserted. [FOUNDER REQUIRED: approved LIA summary URL]. Production also requires linked Article 14 measures and a distributed host-ownership attestation.

## P05 Data categories

Public page text and metadata; exact operational URLs including queries; access, robots, directives and rights signals; bounded diagnostics and per-target outcomes. Credentials and fragments are removed from recorded URLs. [FOUNDER REQUIRED: confirm exact data categories]

## P06 Retention

Maximum raw bodies: 30 days from the original parse, without renewal on 304. Snippets: at most 300 characters and any stricter publisher limit; news or paywalled content gets zero absent explicit permission. Query logs: at most 90 days, IPv4 /24, IPv6 /48, rotating salt required: true. Serving enforcement is owned by #588. User-facing cached copy: false. Ledger and document metadata have no TTL in this slice; these diagnostic URLs remain operational records. Raw objects are removed on expiry, no-store, rights reservation or deletion signals; deletion failures fail the run.

## P07 Robots, directives and opting out

AVASearchBot checks robots before requests and revalidates queued snapshots. Maximum usable robots: 3600 seconds (hard cap 86400 seconds); unreachable robots deny access and retry no earlier than 300 seconds. 4xx robots permit parsing semantics while 401/403/429 still block the host. Gap: 10000 ms; concurrency: 1 per host; hard ceiling: 500 ms and 2 connections. Publisher Crawl-delay raises the gap; above 60 seconds the target is skipped. Access refusals and challenges block for at least 86400 seconds (floor 86400 seconds). Retry-After and bounded backoff can extend deadlines. All applicable X-Robots-Tag and robots/AVASearchBot meta directives merge restrictively: noindex, nofollow, noarchive, nosnippet, noimageindex, max-snippet and unavailable_after. Invalid dates and exceeded directive limits are ineligible. Rights/TDM reservations and licence signals are stored; restricted bodies are not retained. Exclusions version: 585.1. Never-crawl matches are applied before DNS and robots; request a rule using the contact or pending private removal route. Conditional requests, redirects, feeds and sitemaps share identity, address checks, host limits and outcome accounting.

## P08 Egress verification

Signed egress publication and DNS verification are pending follow-up A and deployment. [FOUNDER REQUIRED: stable signed egress URL]. Once deployed, verify the configured trusted-key signature, validity period and inventory; forward-confirm reverse DNS against an AVA-controlled domain. Do not treat an unsigned or missing inventory as verified.

## P09 Removal and delisting

Request removal or delisting through [FOUNDER REQUIRED: private removal/delisting route]. A public issue is not a private rights channel.

## P10 Online Safety reports

Online Safety reports: [FOUNDER REQUIRED: OSA report route]. No report route is asserted as operational by this source rendering.

## P11 Complaints to AVA and ICO

You may complain to AVA using [FOUNDER REQUIRED: private controller complaints route]. Separately, you may complain to the ICO: [FOUNDER REQUIRED: confirmed ICO complaints link].

## P12 Public sources and Article 14 measures

Sources are publicly accessible pages; public availability does not remove data-protection duties. Measures and notice rationale: [FOUNDER REQUIRED: approved Article 14 measures and notice rationale]. Production remains disabled until the selected founder-approved DPIA links the LIA and Article 14 measures for this policy version.
