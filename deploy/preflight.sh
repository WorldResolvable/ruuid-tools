#!/usr/bin/env bash
#
# Check the DNS / reachability prerequisites an RUUID issuer host needs before
# `ruuid seal`. Read-only; makes no changes. Non-zero exit if any check fails.
#
# Usage:  RUUID_DOMAIN=uuid.zone [RUUID_IP=1.2.3.4] deploy/preflight.sh
set -uo pipefail

DOMAIN="${RUUID_DOMAIN:?set RUUID_DOMAIN=your.domain}"
IP="${RUUID_IP:-$(dig +short "$DOMAIN" A | head -1)}"
CUSTODY_HOST="custody.$DOMAIN"
fail=0
ok()   { printf '  ok:   %s\n' "$1"; }
bad()  { printf '  FAIL: %s\n' "$1"; fail=1; }

printf 'domain=%s ip=%s custody=%s\n\n== DNS ==\n' "$DOMAIN" "$IP" "$CUSTODY_HOST"

[ -n "$IP" ] && ok "A record $DOMAIN -> $IP" || bad "A record for $DOMAIN (set RUUID_IP)"

ptr="$(dig +short -x "$IP" 2>/dev/null | head -1)"
[ "${ptr%.}" = "$DOMAIN" ] \
    && ok "PTR $IP -> $DOMAIN" \
    || bad "PTR $IP -> '$ptr' (want $DOMAIN; set reverse DNS on the IP)"

# Bare marker: needs its OWN record — the wildcard below does NOT cover its
# own parent (used by `seal --ct-marker`).
mk_ip="$(dig +short "$CUSTODY_HOST" 2>/dev/null | tail -1)"
[ "$mk_ip" = "$IP" ] \
    && ok "custody marker $CUSTODY_HOST -> $IP" \
    || bad "custody marker $CUSTODY_HOST resolves to '$mk_ip' (want $IP; add $CUSTODY_HOST. CNAME $DOMAIN.)"

# Wildcard: covers every custody command name at any depth
# (k<base32>.rotate.custody.<domain>, future types).
wc_ip="$(dig +short "ruuid-preflight.$CUSTODY_HOST" 2>/dev/null | tail -1)"
[ "$wc_ip" = "$IP" ] \
    && ok "wildcard *.$CUSTODY_HOST -> $IP" \
    || bad "wildcard *.$CUSTODY_HOST resolves to '$wc_ip' (want $IP; add *.$CUSTODY_HOST)"

printf '\n== reachability ==\n'
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://$DOMAIN/.well-known/acme-challenge/ruuid-preflight" 2>/dev/null)"
[ -n "$code" ] && [ "$code" != "000" ] \
    && ok "port 80 challenge path reachable for $DOMAIN (HTTP $code)" \
    || bad "port 80 challenge path not reachable for $DOMAIN"

wcode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "http://ruuid-preflight.$CUSTODY_HOST/.well-known/acme-challenge/x" 2>/dev/null)"
[ -n "$wcode" ] && [ "$wcode" != "000" ] \
    && ok "port 80 challenge path reachable for *.$CUSTODY_HOST (HTTP $wcode)" \
    || bad "port 80 challenge path not reachable for *.$CUSTODY_HOST (catch-all server?)"

printf '\n== tooling ==\n'
command -v ruuid >/dev/null && ok "ruuid on PATH" || bad "ruuid not on PATH (pip install -e .)"
command -v openssl >/dev/null && ok "openssl present" || bad "openssl not found"
[ -x "$HOME/.acme.sh/acme.sh" ] && ok "acme.sh present" \
    || bad "acme.sh not at ~/.acme.sh/acme.sh (run deploy/setup-host.sh, or pass --acme)"

printf '\n%s\n' "$([ "$fail" -eq 0 ] && echo 'PREFLIGHT OK' || echo 'PREFLIGHT FAILED')"
exit "$fail"
