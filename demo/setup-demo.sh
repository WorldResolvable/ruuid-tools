#!/usr/bin/env bash
#
# One-time setup for the bundled RUUID demo:
#
#   1. Generate the self-signed cert the local anchor uses for HTTPS
#      (delegated to demo/gen-cert.sh).
#   2. Add an /etc/hosts entry mapping demo.example.com to 127.0.0.1
#      so the demo's HTTP fetches reach the local anchor via the
#      system resolver, without any DNS-override plumbing in the CLI.
#
# Idempotent: skips either step if it's already been done. Run as
# root (e.g. `sudo make setup-demo`).

set -e -u

if [ "$(id -u)" -ne 0 ]; then
    echo "error: setup-demo must be run with sudo" >&2
    echo "  try: sudo make setup-demo" >&2
    exit 1
fi

HERE=$(dirname "$0")

# Step 1: anchor cert.
if [ -f /etc/ruuid/anchor-cert.pem ]; then
    echo "keeping existing /etc/ruuid/anchor-cert.pem (delete it first to regenerate)"
else
    bash "$HERE/gen-cert.sh"
fi

# Step 2: /etc/hosts entries. One line per demo hostname — the parent
# domain plus the four scheme-demo subdomains used by cases #8–#9C
# (data:, file://, did:web:, did:uuid:). Each line is tagged so we
# can tell our entries from anything an operator may have added by
# hand. fetch_url_body uses the system resolver, which is why each
# subdomain has to be in /etc/hosts even though the demo anchor also
# synthesises A records for them.
HOSTS_TAG="# ruuid demo"
DEMO_HOSTS=(
    demo.example.com
    data.demo.example.com
    file.demo.example.com
    did.demo.example.com
    uuid.demo.example.com
)
for host in "${DEMO_HOSTS[@]}"; do
    line="127.0.0.1   $host  $HOSTS_TAG"
    if grep -qE "^\s*127\.0\.0\.1\s.*\b${host//./\\.}\b" /etc/hosts; then
        echo "/etc/hosts already maps $host to 127.0.0.1 (leaving as-is)"
    else
        printf '\n%s\n' "$line" >> /etc/hosts
        echo "added '$line' to /etc/hosts"
    fi
done
