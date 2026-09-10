#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${STORY584_ARTIFACT_DIR:?external artifacts required}"
cargo about generate --fail -c scripts/licenses/licenses.toml scripts/licenses/template.hbs > "$STORY584_ARTIFACT_DIR/licenses.html"
test -s "$STORY584_ARTIFACT_DIR/licenses.html"
