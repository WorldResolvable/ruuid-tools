# ruuid-tools

Python library and command-line tools for
[Resolvable UUIDs](https://github.com/WorldResolvable/ruuid-draft). Provides a `ruuid` CLI with
`generate`, `resolve`, `parse`, `document`, `records`, `anchor`, and (experimental) `seal`
subcommands, a Python API, and a demo.

## Install

```
make deps
```

This installs the package (and its runtime + test dependencies) into
`~/.local/` via `pip install --user -e ".[test]"`. The CLI entry point
lands at `~/.local/bin/ruuid`; make sure `~/.local/bin` is on your
`$PATH`.

## Command-line use

```
$ ruuid generate 192.0.2.42 42
00000000-002a-8200-8002-c000022a0000

$ ruuid generate 192.0.2.42                   # day_count + random sequence
000147ec-a4f1-8200-8002-c000022a0000

$ ruuid generate 192.0.2.42 --opaque           # plain 48-bit random
fc18a374-9d3b-8200-8002-c000022a0000

$ ruuid generate 192.0.2.42 0xABCDEF --type 7
00000000-abcdef-8200-8072-c000022a0000

$ ruuid resolve 00000000-002a-8200-8002-c000022a0000
reverse_name:      42.2.0.192.in-addr.arpa
domain:            ...
uuid_document_uri: ...
referent_uri:      ...
```

`generate` outputs the RUUID that corresponds to the IPv4 /32 or
IPv6 /64 network prefix and an optional 48-bit identifier (decimal
or `0x`-hex). When the identifier is omitted, it is constructed per
the recommended scheme in I-D §7.3: 20-bit count of days since
2025-01-01 UTC, followed by a 28-bit cryptographically random
sequence. Pass `--opaque` to get a plain 48-bit random value
instead. `--type` defaults to 0.

`resolve` parses the RUUID provided in the positional argument, and
uses the system DNS resolver to obtain the URI of the UUID document.
If the UUID document is not resolved, or does not specify the referent
URI template, the default referent template per the spec is used.  The
identifer referent URI may then be resolved, as determined by the --follow
option.

Output modes:

- **default** — prints just the UUID-document URI, one line, no caption,
  pipeable into `curl` etc.
- **`--follow`** / **`--follow=referent`** — HTTP-GETs the referent URI
  and writes its body to stdout. Bare `--follow` defaults to this.
- **`--follow=document`** — HTTP-GETs the UUID document and writes its
  body (raw JSON) to stdout. Pipeable straight into `jq`.
- **`--follow=referent_uri`** — stops at the referent URI string and
  prints it (no HTTP GET of the referent URI).
  Useful when you want the URL but not the content.
- **`--verbose` / `-v`** — prints everything `resolve` gathered: the
  annotated `reverse_name` / `domain` / `uuid_document_uri` /
  `referent_uri` detail block, followed by the JSON of the fetched
  UUID document, followed by the body of the dereferenced referent
  URI. Useful for inspection; not pipeable.

`--follow`'s fetch exits non-zero with an error to stderr if the
target URL is unreachable or returns a non-success response.

Pass `--nameserver HOST[:PORT]` to point at a non-system DNS server
(e.g. a local `ruuid anchor` on the loopback). The override applies
to BOTH the protocol-level DNS lookups (PTR + URI/TXT at `_uuid.<domain>`)
AND the HTTP(S) host resolution for the doc/referent fetches — so
URLs like `https://branch-office.example.com/...` reach a local
`ruuid anchor` without `/etc/hosts` edits.

`anchor` runs a long-lived daemon that serves DNS (PTR + URI/TXT at
`_uuid.<domain>`, both UDP and TCP) and HTTP (UUID documents + stub
referents) for a JSON zone file. Default ports are 53 and 80; the
sudo path is the easiest:

```
$ sudo ruuid anchor --zone demo/demo-zone.json

$ ruuid anchor --zone demo/demo-zone.json \
              --dns-port 5353 --http-port 8080   # non-privileged
```

`--rrtype URI` and `--rrtype TXT` restrict the records published at
`_uuid.<domain>` to one type only (default is both). Useful for
testing a resolver's URI-preferred and TXT-fallback paths in
isolation.

The zone file is **domain-keyed**: each entry under `domains` has a
`domain`, a list of `anchors` (the IP addresses sharing the domain), and either a `service`
array (CID service entries: `id`, `type`, `serviceEndpoint`) that becomes the
UUID document's service array verbatim, or a `uuid_document_uri` (for
documents hosted off the domain's own server — `data:`, `file://`,
`did:web:`, `did:plc:`, `did:uuid:`, or any HTTP(S) URL). The
document's `id` is the URI it's served at: `uuid_document_uri` if
set, otherwise
`https://<domain>/.well-known/uuid-document.json`. Sibling IP
addresses sharing a domain share one UUID document — the spec's "one
UUID document per `_uuid.<domain>`" property expressed structurally.

The `ruuid anchor` daemon synthesises an A (or AAAA) record for every host mentioned in
the zone (the domain itself plus any `serviceEndpoint` URL host),
pointing at its bind IP, so a resolver using `ruuid anchor` as its DNS server
reaches the published URLs over HTTP(S) without `/etc/hosts` edits.
Routing inside the daemon uses the Host header to dispatch to the right
domain.

**Optional HTTPS.** If a combined-cert+key PEM file exists at
`/etc/ruuid/anchor-cert.pem` (preferred) or `./anchor-cert.pem` (repo-
local fallback) when the daemon starts, it wraps its HTTP server socket in
TLS and serves HTTPS instead of HTTP. The CLI uses the same two paths
when verifying responses (with hostname checking disabled, since the
demo cert is shared across many demo hostnames). `sudo make
install-global` generates the global cert for you; remove it to go
back to HTTP. No flags, no env vars — the presence of the file is
the switch.

ruuid anchor can be used with tools such as dig.

```
dig @localhost _uuid.branch-office.example
```

To hit the same URLs from `curl`, point it at the demo cert with
`--cacert` (and `--resolve` if the hostname isn't in `/etc/hosts` or
your system resolver):

```
curl --cacert /etc/ruuid/anchor-cert.pem \
     --resolve branch-office.example:443:127.0.0.1 \
     https://branch-office.example/.well-known/uuid-document.json
```

Installing the cert into the system trust store (`update-ca-trust`
on Fedora, `update-ca-certificates` on Debian) would let you drop
`--cacert`, but `--cacert` is the lightweight path that doesn't
touch system trust.

### Sealing a genesis proof (experimental)

`seal` establishes a **CT-anchored genesis proof**: durable, third-party-
checkable evidence that the issuer of an RUUID controlled the anchor —
*as of the day of issuance* — even after the IP prefix, its reverse zone,
or the domain later change hands. It addresses the *commandeering*
problem: DNS authenticates the **current** operator and carries no
continuity across a transfer, so a later holder of a transferred prefix
can serve an authentic-looking but unauthorized resolution.

```
$ ruuid seal 198.51.100.99 data.example.com
sealed:            002280cb-000f-8200-8002-c63364630000
did:               did:uuid:002280cb-000f-8200-8002-c63364630000
environment:       STAGING (untrusted; real CT logging requires --production)
ip:                198.51.100.99
domain:            data.example.com
ptr:               99.100.51.198.in-addr.arpa -> data.example.com  (verified)
challenge:         tls-alpn-01
anchor day:        2026-07-07 (day_count=552)
subject key id:    DD:0B:18:D0:4C:25:...
ip cert:           2026-07-07..2026-07-14  serial 0D3603EE...
domain cert:       2026-07-07..2026-10-05  serial 10898BC9...
artifacts:         ~/.ruuid/seals/002280cb-000f-8200-8002-c63364630000
```

`seal <address> <domain>` proves, as of the anchor day, that the issuer
held all three of:

1. **routing control of the IP** — an IP-SAN Let's Encrypt certificate,
   validated by HTTP-01 or TLS-ALPN-01. (This is *routing* control — you
   answered the CA's probe at the IP — not reverse-zone control; LE offers
   no DNS-01 challenge over `in-addr.arpa`. Routing control is the
   harder-to-spoof signal, so anchoring on it is a feature.)
2. **the reverse-zone → domain mapping** — verified locally at seal time
   (the PTR line above) and recorded in the manifest.
3. **control of the domain** — a same-key `dNSName` certificate.

Both certificates are signed by **one RSA key**, so they share a Subject
Key Identifier that links them in Certificate Transparency. They are
logged in CT, so a third party can later find them (e.g. on crt.sh) and
confirm control on the RUUID's anchor day. The proof is **historical, not
live**: CT is append-only and backdate-proof, and the RUUID's `day_count`
is immutable in its own bits, so a party who acquires the prefix *later*
can get a valid cert but never one dated back to the anchor day. One
short-lived cert therefore anchors an entire minting batch — there is no
renewal treadmill.

`seal` mints an RUUID whose `day_count` falls inside the IP cert's
validity window and writes a UUID document that commits to the key (a
`publicKeyJwk` verification method) and the proof (a
`CTAnchoredGenesisProof` service entry with the SKI, the certs' CT
coordinates, and the PTR result). Everything lands under
`~/.ruuid/seals/<uuid>/` (override with `--out`): `key.pem`, the two CSRs
and certs, `uuid-document.json`, and a `seal.json` manifest.

**Prerequisites.** `seal` shells out to [`acme.sh`](https://github.com/acmesh-official/acme.sh)
(pass `--acme PATH` if it isn't on `$PATH`) and to `openssl`. Real
issuance requires the machine running `seal` to actually answer Let's
Encrypt's challenge **at the target IP** (port 443 for TLS-ALPN-01, or 80
for HTTP-01) — so it must run on the host that holds the address.

**Zero downtime on a live host.** The default `auto` challenge uses a
standalone listener, which needs to bind 443 or 80 — a conflict if the
host already runs a web server. Pass `--webroot DIR` to serve the HTTP-01
challenge from that running server instead (`acme.sh -w DIR`): no port
takeover, no downtime. The server must serve
`DIR/.well-known/acme-challenge/` for **both** the domain and the bare IP
— if the site is reverse-proxied, add a static carve-out, e.g. for Apache:

```apache
Alias /.well-known/acme-challenge/ /var/www/acme-challenge/
<Directory /var/www/acme-challenge/>
    Require all granted
    ProxyPass !
</Directory>
```

**Staging by default.** `seal` uses the Let's Encrypt **staging** endpoint
unless you pass `--production`. Staging exercises the identical ACME flow
from an untrusted root and test CT logs, so you can dry-run the pipeline
anywhere; `--production` issues real, publicly-CT-logged certificates —
the ones that make the proof meaningful to third parties.

Options: `--type N` (RUUID type field), `--day DATE` (anchor day; must
fall inside the IP cert window and not be in the future),
`--challenge {auto,http-01,tls-alpn-01}` (default `auto` prefers
TLS-ALPN-01, which needs no port-80 takeover), `--webroot DIR` (serve the
HTTP-01 challenge from a running web server — zero downtime; see above),
`--no-domain-cert` (certify
only the IP; domain control then rests on the local PTR check alone),
`--nameserver HOST[:PORT]` (resolver for the PTR check),
`--key-bits N`, and `--out DIR`.

> **Experimental.** This command prototypes the genesis-proof profile from
> the Verifiable Custody Chains design notes ahead of its `-01` write-up;
> the UUID-document proof shape in particular is expected to evolve.

### Wire-format probes

If you're writing your own RUUID generator or resolver in another
language, point `dig` and `curl` at a running `ruuid anchor` to see
what spec-conformant bytes look like on the wire. The examples below
assume the bundled demo zone and a local `ruuid anchor` on default ports:

```
$ sudo ruuid anchor --zone demo/demo-zone.json
```

**DNS — PTR of the reverse name:**

```
$ dig @127.0.0.1 42.2.0.192.in-addr.arpa PTR +short
branch-office.example.com.
```

**DNS — URI at `_uuid.<domain>` is the resolver's first query:**

```
$ dig @127.0.0.1 _uuid.branch-office.example.com URI +short
10 1 "https://branch-office.example.com/.well-known/uuid-document.json"
```

The resolver issues URI first; if URI returns nothing, it falls back
to TXT (with the `v=ruuid1 ` prefix). It does not use ANY -- RFC 8482
lets recursive resolvers return minimised answers to ANY, so it isn't
reliable on public DNS infrastructure. The daemon still answers ANY for
`dig ANY`-style debugging:

```
$ dig @127.0.0.1 _uuid.demo.example.com ANY +short +notcp
10 1 "https://demo.example.com/.well-known/uuid-document.json"
"v=ruuid1 https://demo.example.com/.well-known/uuid-document.json"
```

**HTTP — fetch the UUID document:** (a W3C DID document; per-type
referent templates live in `service` entries )

```
$ curl --silent --cacert /etc/ruuid/anchor-cert.pem \
       https://demo.example.com/.well-known/uuid-document.json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:uuid:00000000-0000-8200-8002-c000022a0000",
  "alsoKnownAs": [...other DIDs under the same network prefix...],
  "service": [
    {"id": "#1", "type": "tag",
     "serviceEndpoint": "https://demo.example.com/tag/<identifier>"}
  ]
}
```

**HTTP — fetch a referent (stub):**

```
$ curl --silent --cacert /etc/ruuid/anchor-cert.pem \
       https://demo.example.com/tag/abcdef012345
{
  "domain": "demo.example.com",
  "type_id": "1",
  "type_name": "tag",
  "identifier": "abcdef012345"
}
```

**HTTP — alias_to triggers a 302:**

```
$ curl --silent -i --cacert /etc/ruuid/anchor-cert.pem \
       --resolve campus.example:443:127.0.0.1 \
       https://campus.example/events/123456789abc
HTTP/1.0 302 Found
Location: https://events.example.com/4/123456789abc
Content-Length: 0
```

`tests/test_vectors.json` collects these (and the encoding /
decoding / template-substitution algorithms) into a single
machine-readable fixture so an implementation in any language can
load it and self-test against the same expected outputs.

By default a GET on a referent URL returns a small JSON stub. A
type entry may instead set `alias_to` to a template URL (with
the same `<identifier>` / `<type>` / `<network>` / `<uuid>` /
`<domain>` placeholders);
the daemon then returns `302 Found` with the expanded URL in
`Location:`, designating that URL as the canonical alias for the
referent. (HTTP 302 is the mechanism; "alias" is the identity-
level intent — one identifier, a preferred URI elsewhere.) A real
upstream HTTP server can then serve the actual referent content
while DNS+document resolution stays here.

See `demo-zone.json` for a sample zone covering several domains,
including a zero-config one that publishes only a PTR and one
service entry with an `alias_to`. Any domain with a `service` array
(or a `uuid_document_uri`) publishes both a URI and a TXT record at
`_uuid.<domain>`; the resolver in this package queries URI first and
falls back to TXT, so either suffices.

## Run the tests

```
make test
```

## Run the demo

```
sudo make install-global       # one-time, makes ruuid sudo-findable
sudo make demo
```

`sudo make install-global` is a one-time setup: it installs `ruuid`
into the system Python and drops a self-signed cert at
`/etc/ruuid/anchor-cert.pem`. After that, `demo/demo.sh` just starts
`ruuid anchor` on default ports 53 (DNS) and 443 (HTTPS) — hence the
sudo. Both `ruuid anchor` and the CLI auto-detect the global cert,
so resolution runs over TLS end to end. The URLs in the output look
like real production URLs (`https://branch-office.example/...`, no
port suffixes, verified against a trusted cert). The daemon's
startup messages go to `demo.log`.

## Beyond the demo: deploying RUUID DNS

`ruuid anchor` is intentionally a single-process Python demo daemon —
it's fine for "show me the resolution pipeline working" but not for
serving real DNS traffic. If you want `ruuid anchor` on default ports (53/443)
so the URLs don't carry port suffixes, the one-command path is:

```
sudo make install-global
```

This installs `ruuid` into the system Python, dropping the launcher
at `/usr/local/bin/ruuid` so root can find it. After that
`sudo ruuid anchor --zone /path/to/zone.json` runs on 53/80 without
any further env-var or PATH gymnastics. Reverse with
`sudo make uninstall-global`.

Two upgrade paths once a deployment grows past prototyping:

**Small / development deployment: dnsmasq.** Replace `ruuid anchor`
with [dnsmasq](https://thekelleysoftware.com/dnsmasq/doc.html) — a
small C-based DNS forwarder that handles caching, upstream
forwarding, and static records, integrates cleanly with system DNS,
and serves real traffic loads. dnsmasq has first-class support for
TXT records via the `txt-record=` directive, so the RUUID
TXT-with-`v=ruuid1`-prefix path is what dnsmasq-backed deployments
use:

```
# In dnsmasq.conf:
address=/branch-office.example/192.0.2.42
ptr-record=42.2.0.192.in-addr.arpa,branch-office.example
txt-record=_uuid.branch-office.example,"v=ruuid1 https://branch-office.example/.well-known/uuid-document.json"
```

(URI records are also possible via dnsmasq's generic `dns-rr=` flag
with hex-encoded RDATA, but TXT records are easier to write and
dnsmasq supports them natively.) Serve the UUID document over normal
HTTPS via whatever web server is convenient (nginx, Caddy, etc.).

**Production-scale deployment.** Use a full authoritative DNS server
(BIND, NSD, PowerDNS, Knot) with proper zone files. URI records are
first-class in zone-file syntax across these servers, so the
URI-record path is the better choice in those environments. Host the UUID document
behind your normal web infrastructure.

In both cases `ruuid generate` and `ruuid resolve` continue to work
unchanged — only the publishing-side infrastructure changes.

## Library use

Everything in `ruuid.__all__` is a public, importable API: identifier
generation (`new_ruuid`, `RUUID`), the registry-phase `Resolver` and its
pluggable `Transport` (`DnsTransport`, `DohTransport`), the
document/referent helpers, and the end-to-end `resolve_ruuid`.

```python
from ruuid import new_ruuid, resolve_ruuid

ru = new_ruuid("192.0.2.42", type_id=42)
print(str(ru))                          # canonical UUID textual form

out = resolve_ruuid(ru, follow="referent_uri")
print(out["domain"], out["referent_uri"])
```

**Full API reference: [docs/API.md](docs/API.md)** — every call, its
arguments, return shapes, and examples.

## DIF Universal Resolver driver

[`uni-resolver-driver/`](uni-resolver-driver/) packages the `did:uuid` resolution pipeline as a
[DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver)
driver — a small HTTP container answering
`GET /1.0/identifiers/<did:uuid:...>`. It needs no `ruuid anchor` and
no zone of its own; it resolves against the DNS the container is
pointed at (system resolver by default, or a `dns://` / `doh://`
endpoint). See [`uni-resolver-driver/README.md`](uni-resolver-driver/README.md) for build, run,
and Universal Resolver registration.

```
docker build -f uni-resolver-driver/Dockerfile -t universalresolver/driver-did-uuid .
docker run --rm -p 8080:8080 universalresolver/driver-did-uuid
curl http://localhost:8080/1.0/identifiers/did:uuid:00000000-0001-8200-8002-341632100000
```

That identifier is anchored to a real published PTR (`52.22.50.16` →
`riverscape.info`) and resolves live — see
[`examples/riverscape.info/`](examples/riverscape.info/).

## Layout

```
ruuid/                 the library (core, generate, resolve, anchor, cli, driver)
docs/API.md            library API reference
uni-resolver-driver/   DIF Universal Resolver driver for did:uuid (Dockerfile, README)
tests/                 pytest test suite (fake DNS server in conftest.py)
demo/demo.sh           end-to-end bash demo driving the ruuid CLI
demo/demo-zone.json    zone file for the demo's `ruuid anchor` instance
pyproject.toml         package metadata, dependencies, CLI entry point
```
