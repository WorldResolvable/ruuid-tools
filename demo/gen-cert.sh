#!/usr/bin/env bash
#
# Generate a self-signed combined cert+key PEM for `ruuid anchor`'s
# HTTPS demo mode. Anchor and the CLI auto-detect this file at
# /etc/ruuid/anchor-cert.pem (or ./anchor-cert.pem in a repo-local
# fallback) and enable HTTPS when it's present.
#
# Usage: gen-cert.sh [OUTPUT_PATH]
#   Default OUTPUT_PATH is /etc/ruuid/anchor-cert.pem (requires root).
#
# Always (re)generates — callers decide whether to skip if the file
# already exists. The cert lasts 10 years (3650 days).
#
# SAN coverage:
#   demo.example.com         — the parent demo hostname.
#   *.example.com            — peers of demo.example.com (e.g. legacy.example.com).
#   *.demo.example.com       — the demo-subdomain hosts used by
#                              cases #8–#9C (data., file., did.,
#                              uuid.). TLS wildcards only match a
#                              single label, so a wildcard at this
#                              depth has to be listed separately from
#                              *.example.com.
#   localhost, 127.0.0.1     — direct-IP / loopback access.

set -e -u

OUT=${1:-/etc/ruuid/anchor-cert.pem}

mkdir -p "$(dirname "$OUT")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:2048 \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" \
    -days 3650 -nodes \
    -subj '/CN=ruuid-anchor-demo' \
    -addext 'subjectAltName=DNS:demo.example.com,DNS:*.example.com,DNS:*.demo.example.com,DNS:localhost,IP:127.0.0.1' \
    >/dev/null 2>&1

cat "$tmp/cert.pem" "$tmp/key.pem" > "$OUT"
chmod 0644 "$OUT"
echo "wrote $OUT"
