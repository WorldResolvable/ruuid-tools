# ruuid-tools

Python library and command-line tools for
[Resolvable UUIDs](https://github.com/WorldResolvable/ruuid-draft). Provides a `ruuid` CLI with
`generate`, `resolve`, `parse`, `document`, `anchor`, and (experimental) `seal` /
`rotate` / `custody` / `verify` / `sct` subcommands, a Python API, and a demo.

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

> **Running your own issuer host?** See **[docs/DEPLOY.md](docs/DEPLOY.md)**
> and the `deploy/` scripts for the full recipe — DNS (incl. the reverse-DNS
> and `*.rotate.<domain>` wildcard), nginx (incl. the catch-all ACME server),
> `acme.sh`, sealing/rotating, and publishing the custody bundle.

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

The genesis key is an EC (P-256) key that `acme.sh` generates while issuing
the IP cert (we keep it via `--key-file`); the domain cert reuses it, so
both certs share one public key. `seal` mints an RUUID whose `day_count`
falls inside the IP cert's validity window and writes a minimal
Controlled-Identifiers document (`uuid-document.json`) that commits **only
that key**, via a `verificationMethod` (`publicKeyJwk`). The certificate
history is *not* embedded in the document — a document should commit the
key and let CT be the authority for the proof, and its `service` array is
reserved for referent templates (an issuer concern), not cert history. The
proof is instead discoverable from CT via the key's **`spkiSha256`** (the
SHA-256 of the public key): a third party pulls the family of certs with
`crt.sh?spkisha256=<hash>` — used instead of the X.509 Subject Key
Identifier because Let's Encrypt's short-lived profile omits that
extension. The cert coordinates are recorded locally in the `seal.json`
manifest. Everything lands under `~/.ruuid/seals/<uuid>/` (override with
`--out`): `key.pem`, the certs, the domain CSR, `uuid-document.json`, and
`seal.json`.

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

**Pre-rotation (`--pre-rotate`).** For an identity that must survive
*compromise* of its key, `seal --pre-rotate` also generates a successor key
**`K2` cold** (kept offline) and publishes a **commitment** to it in CT: a
certificate *under the genesis key `K1`* whose dNSName encodes `spki(K2)`
(`k<base32>.rotate.<domain>`). Because that cert is signed by `K1` and lives
in append-only, backdate-proof CT, it **pins the successor before `K1` is
ever exposed** — so a later thief of `K1` cannot choose a different
successor (theirs won't match the committed hash, and the genuine
commitment, published at genesis, always wins on earliest-SCT ordering).
A future `ruuid rotate` reveals `K2`. This needs a wildcard DNS record
`*.rotate.<domain>` (override with `--commit-host`) pointing at the host, and
`next-key.pem` must be **backed up offline and kept cold** — it is your
pinned successor.

> **Experimental.** This command prototypes the genesis-proof profile from
> the Verifiable Custody Chains design notes ahead of its `-01` write-up;
> the UUID-document proof shape in particular is expected to evolve.

### Rotating the key (experimental)

`ruuid rotate <state-dir>` moves an RUUID's authority to the successor that
`seal --pre-rotate` pinned. `state-dir` is the previous generation's
directory (the seal, or an earlier rotate) holding the cold `next-key.pem`
and its record. Rotation:

- **activates the pinned successor `K2`** (checking it matches the recorded
  commitment) — this needs *no access to the old key*, so it works even when
  the old key is **compromised**;
- generates a fresh cold `K3` and publishes `K2`'s commitment to it (a cert
  under `K2` whose dNSName encodes `spki(K3)`), making `K2` live in CT and
  pinning the next successor;
- writes a new `uuid-document.json` committing `K2`, plus a `rotation.json`
  generation record.

```
$ ruuid rotate ~/.ruuid/seals/<uuid> --webroot /var/www/html
rotated:      <uuid>  (generation 1)
prev key:     <K1 SPKI>
active key:   <K2 SPKI>
next key:     <K3 SPKI>  (cold)
committed as: k<base32>.rotate.<domain>
```

Publish the new document (it commits `K2`); back up the new `next-key.pem`
(`K3`) offline. A verifier walks the chain in CT — genesis `K1` → its
committed `K2` → `K2`'s committed `K3` … to the tip the document commits —
with earliest-SCT-wins to defeat a compromised-key fork. Rotate again from
the new generation's directory to advance to `K3`, and so on.

### Checking day coverage (experimental)

A genesis certificate never needs *renewing* for liveness — the proof is
historical, frozen in CT. You only need a fresh `seal` to mint an RUUID on a
`day_count` that no existing certificate's validity window covers. **`custody
--summary <ip>`** reports the issue-days an IP already has provable genesis
certificates for (merged from those certs' validity windows), and (with
`--day`) checks a specific date — exiting non-zero when it isn't covered, so
it drives a "seal only when needed" script:

```
$ ruuid custody 100.57.12.254 --summary                  # from CT (anyone)
covered issue-days for 100.57.12.254:
  2026-07-07 .. 2026-07-14   day_count 552..559   (1 cert(s))

$ ruuid custody 100.57.12.254 --summary --day 2026-07-10
2026-07-10 (day_count 555): COVERED — window 2026-07-07..2026-07-14

$ ruuid custody 100.57.12.254 --summary --day 2026-08-01 || \
      ruuid seal 100.57.12.254 uuid.zone --production     # seal only if uncovered
```

Since it's part of `custody`, it works either from **CT** (anyone) or, with
`--seals`, from the issuer's own records (`custody --summary --seals <ip>`) —
the fast, crt.sh-free path on the issuer's box.

### Verifying a genesis proof (experimental)

`verify` is the third-party side of `seal`. The trust root is Certificate
Transparency, keyed by the **IP** — `crt.sh` indexes the `iPAddress` SAN, so
from the RUUID alone (which encodes the IP and the day) it recovers the key
that controlled the anchor on that day, independent of any document:

```
$ ruuid verify 002299ac-52e1-8200-8002-64390cfe0000        # no document
ruuid:        002299ac-52e1-8200-8002-64390cfe0000
anchor:       100.57.12.254  on 2026-07-08 (day_count 553)
genesis key(s) in CT: 96D1B942…293CF7E7
verdict:      VERIFIED — 100.57.12.254 on 2026-07-08 is controlled by key 96D1B942…293CF7E7 (CT cert serial 05F98891…)
anchoring timeline (from CT):
  2026-07-07..2026-07-14  100.57.12.254  (crt.sh#27768999966)  <= genesis
  2026-07-07..2026-10-05  uuid.zone      (crt.sh#27769001291)
```

It queries `crt.sh?q=<IP>` for every certificate ever carrying the RUUID's
IP, keeps those whose validity window covers the RUUID's day, and takes
their public key as the **genesis key** — only the party who held the IP on
that day could hold such a certificate, and CT is backdate-proof. Give it a
document too and it additionally confirms the document commits that key:

```
$ ruuid verify 002299ac-… uuid-document.json
verdict:  VERIFIED — document commits the genesis key controlling 100.57.12.254 on 2026-07-08 (…)
```

Because the key comes from CT and not from the document, an impostor
document (e.g. served by a party who later acquired the released IP) is not
just rejected — `verify` **names the genuine key**, turning a denial into a
recovery. It exits non-zero when not verified.

Verification is a **permanent, historical** check, not a current-validity one:
it asks whether CT shows a certificate carrying the IP with a window covering
the RUUID's day — "who controlled this IP on day D?" — so an RUUID stays
verifiable long after its certificates **expire** and after the issuer loses
the IP prefix, its reverse zone, and its domain. Only *discovery* (finding
where the current document is served) depends on the present; the verdict
itself is a backdate-proof fact that nothing about today can revoke.

**Key rotation is handled too.** If the document commits a key that isn't the
genesis key, `verify` walks the **custody chain** in CT — from the genesis
key, following each generation's pre-rotation commitment (see
`seal --pre-rotate` and `rotate`) to the next — and verifies iff it reaches
the document's key. At each hop the *earliest* commitment wins, so a thief of
some generation's key can't fork the succession (the genuine,
pre-exposure commitment is always earlier). A verified rotated document
reports the chain:

```
custody chain (1 rotation): 96D1B942…  ->  DBF082FE…
verdict:      VERIFIED — document commits DBF082FE… — generation 1 in the custody chain from genesis 96D1B942… (…)
```

A single, un-rotated key is just the length-1 case; re-anchoring the *same*
key to other IPs/domains shows in the timeline and needs no chain.

The CT lookups are slow and crt.sh is flaky, so the evidence is a separable,
cacheable bundle. **`custody <ruuid>`** emits it as `custody.json` (the
genesis certificates plus the key's forward timeline, shaped
`chain: [generation, …]`) needing only the RUUID; **`verify`** then runs
**offline and deterministically** against that bundle, or builds one live
from CT if none is given:

```
$ ruuid custody 002299ac-… > custody.json                             # do the CT lookups once
$ ruuid verify 002299ac-… uuid-document.json --custody custody.json   # offline replay
```

#### Published bundles: verifying without crt.sh

**`ruuid custody <ip>`** builds a `uuid-custody.json` from CT — runnable by
anyone. An issuer, though, already holds its own genesis/commitment
certificates on disk (from `seal`/`rotate`), and those *are* the CT-logged
certs. So **`custody --seals`** builds the **same bundle** from those local
records instead of querying CT — an issuer optimization that's immediate (no
waiting for CT to index a just-issued cert), offline, and crt.sh-free (only
`*-cert.pem` files are read; private keys never leave the box):

```
$ ruuid custody --seals > uuid-custody.json        # from ~/.ruuid/seals (issuer)
$ ruuid custody 100.57.12.254 > uuid-custody.json  # from CT (anyone)
# serve at https://<domain>/.well-known/uuid-custody.json
```

Same output either way — `--seals` is just the issuer's fast, CT-free path to
producing it, which is what keeps crt.sh off the critical path for publishing.
The bundle records a `"source"` field (`"crt.sh"` or `"seals"`) as **advisory
metadata** — "how was this made" for a reader — never a trust input: a bundle
you didn't make yourself is trusted by SCT-verifying its certificates
(`--verify-scts`), which is provenance-independent, not by believing a `source`
label that a forger could set to anything.

A resolver pre-downloads the `uuid-custody.json` files for the domains it
regularly serves into a directory, and points `verify` / `resolve --verify`
at it with **`--bundles DIR`** — verification then runs **entirely off the
local bundles, no crt.sh**:

```
$ ruuid verify 002299ac-… uuid-document.json --bundles ./bundles/
$ ruuid resolve 002299ac-… --verify --bundles ./bundles/
```

This turns crt.sh from a hard dependency into an optional independent-audit
fallback: the bundles supply the evidence, and each certificate remains
independently checkable against CT via its embedded SCTs.

#### Discovery cascade: `--fetch-bundles`

A public or decentralized service takes in RUUIDs it has *never seen*, issued
by parties it doesn't know. `--fetch-bundles` turns discovery into an
automatic cascade — **local bundles → the issuer's published bundle → crt.sh**:

```
$ ruuid verify <ruuid> uuid-document.json --fetch-bundles
$ ruuid resolve <ruuid> --verify --fetch-bundles
```

On a local miss it resolves the RUUID's IP to a domain (PTR) and fetches
`https://<domain>/.well-known/uuid-custody.json`; that self-authenticating
bundle is cached (default `~/.ruuid/bundles/`, override with `--bundles DIR`),
so an unknown issuer becomes locally known for every sibling RUUID thereafter.
crt.sh is the final, cooperation-free fallback for issuers who publish nothing.

Every layer is **discovery only** — verification still checks the fetched
certificates against *this* RUUID's CT genesis and commitment chain — so a
stale PTR or a hostile domain serving a bogus bundle can only fail to help,
never mislead: a wrong bundle simply won't contain a genesis chain to the
document's key, and the cascade falls through. Over time the three
intake cases converge: self-issued and cooperating issuers are already local,
and the long tail of novel issuers is fetched once and cached.

#### Making bundles trustless: SCT verification (`sct`)

A published or fetched bundle raises a question: if you no longer ask crt.sh,
what stops a malicious issuer from putting **fabricated** certificates in its
bundle? The answer is the **embedded SCTs** every Let's Encrypt certificate
carries — a CT log's unforgeable, signed proof that *this exact certificate*
was logged (and therefore issued by a real CA after real validation). Checking
them needs only the logs' public keys — bundled in `ct_logs.json`, no network —
so it's the step that lets you trust a bundle from an untrusted source:

```
$ pip install 'ruuid[sct]'                 # SCT verification needs `cryptography`
$ ruuid sct fullchain.pem
  [verified] Sectigo 'Elephant2026h2'       @ 2026-07-08T00:16:57+00:00
  [verified] IPng Networks 'Halloumi2026h2a' @ 2026-07-08T00:16:56+00:00
verified 2/2 SCT(s) from 2 independent operator(s)
verdict: OK (require >= 2 from trusted logs)
```

Trust doesn't vanish — it **moves to the CT log operators**, where CT intends
it: requiring valid SCTs from two or more independent logs means forgery needs
multiple operators to collude, not just a lying issuer. A fabricated cert that
never went through CT simply carries no verifiable SCTs.

**Gating verification on SCTs (`--verify-scts`).** Published bundles carry each
certificate's full-chain PEM, so a resolver can check the SCTs *itself* at
ingest rather than trusting the publisher. Add `--verify-scts` to `verify` /
`resolve --verify` (with `--bundles` or `--fetch-bundles`): a bundle cert then
counts toward a genesis or a chain hop **only if its embedded SCTs verify**
against trusted logs, and each is stamped with its real SCT timestamp (which
also drives the earliest-commitment-wins ordering, replacing the `notBefore`
approximation). A fabricated cert is dropped, so it can't establish anything —
turning an untrusted bundle trustless. crt.sh, the trusted index, is
unaffected. Requires `pip install 'ruuid[sct]'`.

```
$ ruuid verify <uuid> uuid-document.json --bundles ./bundles/ --verify-scts
```

#### Signed documents: binding content to the key

Committing a key isn't enough on its own — a public key is *public*, so an
attacker could wrap the genuine key around a malicious document (a hostile
referent template). So `seal` and `rotate` **sign** the document with the key
it commits (a W3C Data-Integrity `proof`, ECDSA-P256 over the canonicalized
document), making it **self-authenticating**: its content is bound to the key,
independent of how it was fetched. The policy:

- **`resolve --verify` requires a signed document** — the proof must be present
  and valid (in addition to the CT/chain check on the committed key).
- **Plain `resolve` accepts an unsigned document** (it does not authenticate) —
  *but* if a document carries a proof that is **invalid**, `resolve` refuses
  when resolution would use a **document-supplied (non-default) referent
  template**, since that tampered content can't be trusted. The spec-default
  template (derived from the RUUID + domain, not the document) is unaffected.

Verifying the proof reconstructs the committed key from the document's own
`verificationMethod` and checks the signature with openssl — no CT lookup and
no `cryptography` dependency. (Documents sealed before this feature carry no
proof, so `resolve --verify` will report them unsigned until re-sealed.)

#### Commandeering-safe resolution: `resolve --verify`

Plain `resolve` follows the PTR to whatever document the current IP holder
serves — fast, but it trusts that holder. `resolve --verify` folds the CT
check into resolution: it fetches the candidate document via PTR, requires a
valid document **proof** (above), then confirms its committed key is the
CT-established genesis key (or a chain successor) for the RUUID's IP and day. A
document whose key isn't authorized — or whose content isn't signed by it — is
rejected (exit non-zero), so a party who acquired the released IP can't hijack
an old RUUID.

```
$ ruuid resolve --verify 002299ac-52e1-8200-8002-64390cfe0000
resolved:     uuid.zone  (https://uuid.zone/.well-known/uuid-document.json)
…
verdict:      VERIFIED — document commits the genesis key controlling 100.57.12.254 on 2026-07-08 (…)
```

A document may assert a **minting day-range** it is responsible for, as a
cooperative triage hint:

```json
"mintingDayRange": { "from": "2026-07-07", "to": "2026-07-14" }
```

When a resolved RUUID's day falls outside that range, the current controller
is disowning it (e.g. an honest successor after an IP transfer), and
`resolve --verify` flags that — routing you to the genuine controller (the
key CT names) rather than treating it as an impostor. It is a routing hint
only, never a positive verdict: an in-range claim still has to pass the CT
check, and a dishonest party gains nothing by lying about the range.

#### The per-IP cache: green-light a batch locally

Genesis verification is a function of `(IP, day)` — the sequence is
irrelevant — and CT is append-only and backdate-proof, so "key K held IP on
day D" is an **immutable historical fact**. `verify` and `resolve --verify`
therefore keep a **permanent per-IP cache** (`~/.ruuid/ct-cache/`, override
with `--cache-dir`, disable with `--no-cache`): the first RUUID for an IP
does the CT fetch, and every subsequent RUUID for that IP — any day the
cached certificates cover (a single short-lived cert spans ~7 days), any
sequence — is green-lit **locally, with no network**. Cache entries never
expire; a day no cached cert covers (e.g. a newly sealed one) simply falls
through to CT and merges back in. This rewards issuers who seal a day and
mint a batch against it rather than churning days: fewer distinct `(IP, day)`
pairs means near-100% resolver cache hits.

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
