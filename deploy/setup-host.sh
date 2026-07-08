#!/usr/bin/env bash
#
# Provision an RUUID issuer host: acme.sh + webroot/.well-known + nginx config.
# Idempotent-ish and safe to re-run. The cloud-level prerequisites (a static
# public IP, reverse DNS / PTR, and the *.rotate.<domain> wildcard record) are
# NOT scriptable here — see docs/DEPLOY.md, and run deploy/preflight.sh to
# check them before sealing.
#
# Usage:
#   RUUID_DOMAIN=uuid.zone [RUUID_WEBROOT=/usr/share/nginx/html] \
#     [RUUID_NGINX_CONF=/etc/nginx/conf.d/ruuid.conf] \
#     [RUUID_ACME_EMAIL=you@example.com] deploy/setup-host.sh
set -euo pipefail

DOMAIN="${RUUID_DOMAIN:?set RUUID_DOMAIN=your.domain}"
WEBROOT="${RUUID_WEBROOT:-/usr/share/nginx/html}"
NGINX_CONF="${RUUID_NGINX_CONF:-/etc/nginx/conf.d/ruuid.conf}"
ACME_EMAIL="${RUUID_ACME_EMAIL:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { printf '\n== %s ==\n' "$*"; }

say "webroot + .well-known ($WEBROOT)"
sudo mkdir -p "$WEBROOT/.well-known/acme-challenge"

say "acme.sh"
if [ ! -x "$HOME/.acme.sh/acme.sh" ]; then
    curl -fsS https://get.acme.sh | sh -s -- ${ACME_EMAIL:+--accountemail "$ACME_EMAIL"}
else
    echo "already installed at $HOME/.acme.sh/acme.sh"
fi
"$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

say "nginx config -> $NGINX_CONF"
if [ "$WEBROOT" != "/usr/share/nginx/html" ]; then
    echo "NOTE: webroot is not the example default; edit 'root' lines in"
    echo "      $NGINX_CONF to use $WEBROOT after this runs."
fi
# Substitute only the domain (no slashes -> safe sed).
sed "s/uuid\.zone/$DOMAIN/g" "$HERE/nginx-ruuid.conf.example" \
    | sudo tee "$NGINX_CONF" >/dev/null
if sudo nginx -t; then
    sudo systemctl reload nginx || sudo service nginx reload || true
else
    echo "nginx -t failed; review $NGINX_CONF (TLS cert paths, webroot) and reload."
fi

cat <<EOF

Host bits done. Remaining, in order (see docs/DEPLOY.md):
  1. deploy/preflight.sh          # confirm A / PTR / wildcard / reachability
  2. issue the webserver TLS cert (see nginx-ruuid.conf.example header)
  3. ruuid seal $DOMAIN's IP $DOMAIN --pre-rotate --no-domain-cert \\
         --webroot $WEBROOT [--production]
  4. deploy/publish-custody.sh    # publish /.well-known/uuid-custody.json (cron it)
EOF
