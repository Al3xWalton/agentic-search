# Agentic Search source offer

This committed document is a template. The running [source endpoint](./.well-known/ava-search-source)
identifies the actual build; every API response carries its source URL in `Source-Offer`.
The build renders this document with literal values for distribution alongside the service.
Unknown builds are not approved for external release. No deployment is made by this template.

The source is offered under AGPL-3.0-only. See [LICENSE.md](LICENSE.md), [NOTICE](NOTICE)
and the [public repository](https://github.com/Al3xWalton/agentic-search).
Retained upstream notices and subdirectory licence exceptions remain applicable.
Clone with recursive submodules: build, installation and interface scripts and referenced
submodule contents are part of Corresponding Source. A GitHub archive alone does not include them.
Before external use, the release owner must publish a tag resolving to the exact built revision,
verify unauthenticated source access, and distribute the rendered offer and dependency notices.

This offer is the builder's attestation. The resolver prevents accidental misattribution
from nested archives, dirty or moved worktrees, symlinked Git metadata or checked inputs,
and foreign history missing the build inputs. It cannot defeat a builder deliberately
tracking identical inputs who could also edit the constants or binary; that is out of scope.
Forks must set their package `repository` and `SOURCE_OFFER.md` to their own corresponding
source; the build derives its source URL from the package metadata.

<!-- source-offer-contract:start -->
```text
licence=AGPL-3.0-only
source_url=https://github.com/Al3xWalton/agentic-search/tree/{revision}
revision={revision}
revision_source={revision_source}
```
<!-- source-offer-contract:end -->
