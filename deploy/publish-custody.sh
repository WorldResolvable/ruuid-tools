#!/usr/bin/env bash
#
# (Re)generate this issuer's published custody bundle from its own on-disk
# certificates and serve it at <webroot>/.well-known/uuid-custody.json.
#
# Cron it (e.g. daily) AND run it right after every `ruuid rotate`, so the
# published bundle always reflects the current custody chain. Reads only
# *-cert.pem files — never the private keys.
#
# Usage:  [RUUID_WEBROOT=/usr/share/nginx/html] [RUUID_SEALS=~/.ruuid/seals] \
#           deploy/publish-custody.sh
set -euo pipefail

WEBROOT="${RUUID_WEBROOT:-/usr/share/nginx/html}"
SEALS="${RUUID_SEALS:-$HOME/.ruuid/seals}"
OUT="$WEBROOT/.well-known/uuid-custody.json"

mkdir -p "$WEBROOT/.well-known"
ruuid custody --publish --seals "$SEALS" --out "$OUT"

n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["certificates"]))' "$OUT" 2>/dev/null || echo '?')"
echo "published $n certificate(s) -> $OUT"
