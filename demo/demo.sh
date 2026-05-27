#!/usr/bin/env bash
# End-to-end RUUID demo using the `ruuid` CLI.

set -e -u

LOG=/tmp/demo.log
DIR=$(dirname "$0")
ZONE=${1:-$DIR/demo-zone.json}
if [ ! -f "$ZONE" ]; then
    echo "error: zone file $ZONE not found" >&2
    exit 1
fi


# Probe for an existing DNS server on 127.0.0.1:53. dig returns 0 if
# any response comes back (even NXDOMAIN), non-zero on timeout/refused.
if dig @127.0.0.1 +time=1 +tries=1 +short +notcp . NS >/dev/null 2>&1; then
    echo "using already-running ruuid anchor on 127.0.0.1:53"
else
    if [ "$(id -u)" -ne 0 ]; then
        echo "cannot start anchor without sudo"
        exit 1
    fi
    if [ ! -f /etc/ruuid/anchor-cert.pem ] && [ ! -f anchor-cert.pem ]; then
        echo "no anchor-cert.pem" >&2
        exit 1
    fi
    echo "ruuid anchor logging to $LOG (zone: $ZONE)"
    ruuid anchor --zone "$ZONE" 2>"$LOG" &
    PID=$!
    cleanup () { kill "$PID" 2>/dev/null || true; }
    trap cleanup EXIT INT TERM
    sleep 0.5
fi


function heading() {
    echo
    echo ========================================
    echo $1
    echo
}


ru=$(ruuid generate 192.0.2.42 0xABCDEF012345 --type 1)
heading "#1A  IPv4 tag, DNS registry"
ruuid resolve --verbose $ru

heading "#1B IPv4 tag, HTTPS registry"
ruuid resolve --verbose --registry https://demo.example.com/ $ru

heading "#1C IPv4 tag, DoH registry"
ruuid resolve --verbose --registry doh://demo.example.com/dns-query $ru

heading "#2  IPv4, type 2 not in document → falls through to type 0 default"
ruuid resolve --verbose $(ruuid generate 198.51.100.7 0x1234 --type 2)

heading "#3  IPv6 sensor — §7.3 identifier, template splits via <day>"
ruuid resolve --verbose $(ruuid generate 2001:db8:abcd:1234::1 0x64FABCDEF --type 3)

heading "#4  IPv6 event, alias_to redirects to /<type>/<identifier>"
ruuid resolve --verbose $(ruuid generate 2001:db8:abcd::1 0x123456789ABC --type 4)

heading "#5  IPv4, type 5 missing → falls through to type 0 default"
ruuid resolve --verbose $(ruuid generate 192.0.2.42 0xCAFE --type 5)

heading "#6  IPv4 widget, alias_to redirect"
ruuid resolve --verbose $(ruuid generate 203.0.113.50 0xDEADBEEF1234 --type 6)

heading "#7  IPv4 unknown type falls to type 0 default"
ruuid resolve --verbose $(ruuid generate 198.51.100.20 0xC0FFEE --type 8)

heading "#8  UUID document inlined in a data: URI"
ruuid resolve --verbose $(ruuid generate 198.51.100.99 0xDA7A --type 1)

heading "#9A  UUID document served from a file:// URI"
ruuid resolve --verbose $(ruuid generate 198.51.100.100 0xF11E --type 1)

heading "#9B UUID document referenced by a did:web URI"
ruuid resolve --verbose $(ruuid generate 198.51.100.101 0x5300CAFEBEEF --type 1)

heading "#9C UUID document referenced by a did:uuid URI"
ruuid resolve --verbose $(ruuid generate 198.51.100.102 0xABCDEF012345 --type 1)

ru=$(ruuid generate 203.0.113.99 0x5300CAFEBEEF --type 1)
heading "#10A  UUID document + referent homed in an S3 bucket"
ruuid resolve --verbose --registry doh://127.0.0.1/dns-query $ru

heading "#10B registry-phase lookup also homed in the S3 bucket"
ruuid resolve --verbose --registry http://ruuid.s3-website-us-east-1.amazonaws.com/ $ru
