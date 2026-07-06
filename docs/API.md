# ruuid Python API

Everything in `ruuid.__all__` is public. Anything else (names beginning
with `_`, the CLI module, internal registry builders) is implementation
detail.

```python
from ruuid import RUUID, new_ruuid, resolve_ruuid, Resolver
```

## API at a glance

**Classes**

| object | one-liner |
|:-------|:----------|
| [`RUUID`](#ruuid) | the decoded UUID type — fields, properties, constructors |
| [`Resolver`](#resolver) | runs the registry phase; owns the RUUID protocol, driven by a `Transport` |
| [`Transport`](#transport) | the RUUID-free (pseudo-)DNS query seam a `Resolver` runs over |
| [`DnsTransport`](#dnstransport) | a `Transport` over UDP/TCP DNS |
| [`DohTransport`](#dohtransport) | a `Transport` over DNS-over-HTTPS (RFC 8484) |
| [`ResolveError`](#resolveerror) | raised when a registry-phase step fails |
| [`IdentifierScheme`](#identifierscheme) | name-tags for a UUID document's `identifier_scheme.type` |

**Entry-point functions**

| function | one-liner |
|:---------|:----------|
| [`new_ruuid`](#new_ruuid) | generate a fresh RUUID from an IP anchor |
| [`resolve_ruuid`](#resolve_ruuid) | run the full pipeline end to end (the main entrypoint) |

**Lower-level functions**

| function | one-liner |
|:---------|:----------|
| [`fetch_url_body`](#fetch_url_body) | GET a URI, return body bytes or `None` |
| [`fetch_document`](#fetch_document) | GET a UUID document and parse it as JSON |
| [`resolve_referent_uri`](#resolve_referent_uri) | build the referent URI from a UUID document |
| [`substitute_template`](#substitute_template) | expand `<identifier>`/`<type>`/… placeholders in one template |
| [`synthesise_ruuid_document`](#synthesise_ruuid_document) | wrap the referent URI in a `did:uuid` DID document |
| [`reverse_dns_name`](#reverse_dns_name) | reverse-DNS name for an RUUID's network anchor |
| [`identifier_label`](#identifier_label) | 12-hex form of the 48-bit identifier |
| [`to_ip`](#to_ip) | resolve a host to an IP literal |
| [`default_uuid_document_uri`](#default_uuid_document_uri) | well-known UUID-document URI for a domain |

**Constants**

| name | value |
|:-----|:------|
| [`VERSION`](#constants) | `8` — RFC 9562 experimental UUID version |
| [`VARIANT_RFC4122`](#constants) | `0b10` — standard 2-bit UUID variant |
| [`SIXTOFOUR_PREFIX`](#constants) | `0x2002` — marks a 6to4-encoded IPv4 anchor |
| [`TXT_PREFIX`](#constants) | `"v=ruuid1 "` — prefix of a doc URI carried in a TXT record |
| [`DEFAULT_REFERENT_URI_TEMPLATE`](#constants) | `"https://<domain>/<type>/<identifier>"` |
| [`DEFAULT_UUID_DOCUMENT_URI_TEMPLATE`](#constants) | `"https://<domain>/.well-known/uuid-document.json"` |

### How the pieces fit

Resolution runs in two phases. The **registry phase** turns an RUUID's
network prefix into the issuer domain and the URI of that domain's UUID
document. One `Resolver` owns that protocol; it runs over a `Transport`
(`DnsTransport`, `DohTransport`, or your own) that does the raw queries
and knows nothing about RUUIDs. The **document/referent phase** fetches
that document and applies the matching service entry's template to build
the referent URI, and lives above the resolver. [`resolve_ruuid`](#resolve_ruuid)
does both phases in one call.

---

## `RUUID`

A frozen dataclass holding the decoded fields of a resolvable UUID.

| field        | type  | meaning                                                    |
|:-------------|:------|:-----------------------------------------------------------|
| `identifier` | `int` | 48-bit value naming the referent within the network prefix |
| `network`    | `int` | 64-bit network prefix (the issuer's namespace anchor)      |
| `type_id`    | `int` | 10-bit type selecting a service entry (`#<type_id>`)       |
| `version`    | `int` | UUID version; defaults to `8` (`VERSION`)                  |
| `variant`    | `int` | UUID variant; defaults to `0b10` (`VARIANT_RFC4122`)       |

Constructing `RUUID(...)` directly takes the raw 64-bit `network` slot;
most callers use `RUUID.from_anchor`, `RUUID.from_str`, or `new_ruuid`
instead. The constructor raises `ValueError` if any field is out of range.

**Properties**

| property         | type                         | description                                                |
|:-----------------|:-----------------------------|:-----------------------------------------------------------|
| `address_family` | `int`                        | `4` if the network field is a 6to4-encoded IPv4 anchor, else `6` |
| `prefix_bits`    | `int`                        | reverse-DNS prefix length: `32` (IPv4) or `64` (IPv6)      |
| `ip_network`     | `IPv4Network \| IPv6Network` | the IP network identified by the network field             |
| `int`            | `int`                        | the full 128-bit integer value                             |

`str(ruuid)` returns the canonical 36-character UUID text.

**Class methods**

```python
RUUID.from_int(n: int) -> RUUID
RUUID.from_str(s: str) -> RUUID
RUUID.from_anchor(anchor: IPv4Address | IPv6Address | str, *,
                  identifier: int, type_id: int = 0) -> RUUID
```

- `from_int` / `from_str` decode a 128-bit value or its text; raise
  `ValueError` on out-of-range / malformed input.
- `from_anchor` builds from a single IP address. IPv4 anchors are
  6to4-encoded (resolve via `in-addr.arpa` at /32); IPv6 anchors take the
  high 64 bits (resolve via `ip6.arpa` at /64). Raises `TypeError` for a
  non-address argument.

```python
ru = RUUID.from_anchor("192.0.2.42", identifier=1, type_id=42)
str(ru)            # '00000000-0001-8200-82a2-c000022a0000'
ru.address_family  # 4
ru.ip_network      # IPv4Network('192.0.2.42/32')
RUUID.from_str("00000000-0001-8200-82a2-c000022a0000") == ru   # True
```

---

## `new_ruuid`

```python
new_ruuid(anchor: IPv4Address | IPv6Address | str, *,
          type_id: int = 0, identifier: int | None = None,
          opaque: bool = False, day: datetime | None = None) -> RUUID
```

Create a fresh RUUID anchored to an IP address whose reverse-DNS
delegation you control. A hostname is accepted and resolved via the
system resolver (IPv4 preferred).

When `identifier` is given it is used as-is (`opaque` and `day` ignored).
When `identifier` is `None`, a 48-bit identifier is generated:

- `opaque=False` (default) — the structured form from spec §7.3: a 20-bit
  `day_count` (days since 2025-01-01 UTC) plus a 28-bit random `sequence`.
  `day` selects the tenure day to encode (default: current UTC day).
- `opaque=True` — a plain 48-bit random value (local-scope form).
  Incompatible with `day`.

**Raises** `ValueError` if `anchor` is unresolvable, `identifier` exceeds
48 bits, or both `opaque` and `day` are given.

```python
ru = new_ruuid("192.0.2.42", type_id=5)                          # structured, random
ru = new_ruuid("192.0.2.42", type_id=5, identifier=(123<<28)|7)  # deterministic
str(ru)   # '0007b000-0007-8200-8052-c000022a0000'
ru = new_ruuid("2001:db8:abcd:1234::1", opaque=True)             # local-scope
```

---

## Registry phase

One `Resolver` owns the registry-phase protocol and runs it over a
`Transport`. The resolver's `resolve` returns:

```python
resolver.resolve(ruuid: RUUID, trace: list | None = None) -> dict
# {"reverse_name": str, "domain": str, "uuid_document_uri": str}
```

`uuid_document_uri` is always a URI: with no record at `_uuid.<domain>`
the resolver falls back to the well-known default. See
[Tracing](#tracing) for `trace`.

### `Resolver`

```python
Resolver(transport: Transport | None = None, *,
         nameservers: Iterable[str] | None = None,
         port: int = 53, lifetime: float = 5.0)
```

The single RUUID resolver. It owns the protocol — reverse-zone naming,
the PTR lookup, the `_uuid.<domain>` URI/TXT lookup, the `v=ruuid1 `
prefix, and the well-known default — and delegates the raw queries to a
`Transport`. Pass any `Transport`; or omit it and the DNS keyword
arguments build a `DnsTransport` for you (`nameservers=None` uses the
system resolver config; pass a list and `port` to target a specific
server; `lifetime` is the total per-query timeout in seconds).

Methods: `resolve(ruuid, trace=None) -> dict` (PTR then URI/TXT),
`resolve_domain(ruuid, trace=None) -> str` (PTR only; raises
`ResolveError` on no record), `resolve_uuid_document(ruuid) -> str`,
`reverse_dns_name(ruuid) -> str`.

```python
# System DNS (default transport):
Resolver().resolve(ru)
# {'reverse_name': '42.2.0.192.in-addr.arpa',
#  'domain': 'example.com',
#  'uuid_document_uri': 'https://example.com/.well-known/uuid-document.json'}

# A specific DNS server, or DoH:
Resolver(nameservers=["192.0.2.53"]).resolve(ru)
Resolver(DohTransport("https://doh.example/dns-query")).resolve(ru)
```

### `Transport`

```python
class Transport(Protocol):
    def query(self, name: str, rrtype: str) -> list: ...
```

The RUUID-free seam a `Resolver` runs over. `query(name, rrtype)`
performs one lookup and returns the records as plain Python values — it
knows nothing about RUUIDs, the `_uuid.` name, or the `v=ruuid1`
convention:

| `rrtype` | returns |
|:---------|:--------|
| `"PTR"`  | `list[str]` — target names (trailing dot stripped) |
| `"URI"`  | `list[tuple[int, int, str]]` — (priority, weight, target) |
| `"TXT"`  | `list[str]` — each record's joined text |

It returns an empty list when the name has no records of that type
(NODATA / NXDOMAIN), and raises `dns.exception.DNSException` on a
transport-level failure (timeout, refused) so the caller can fail over.
`Transport` is a runtime-checkable `Protocol`: **any object with a
matching `query` method is a transport** — including a test double, which
is how you exercise all of `Resolver` with no network.

```python
class FakeTransport:
    def query(self, name, rrtype):
        return {
            ("42.2.0.192.in-addr.arpa", "PTR"): ["example.com"],
            ("_uuid.example.com", "URI"): [(10, 1, "https://example.com/doc.json")],
        }.get((name, rrtype), [])

Resolver(FakeTransport()).resolve(ru)["uuid_document_uri"]
# 'https://example.com/doc.json'
```

### `DnsTransport`

```python
DnsTransport(*, nameservers: Iterable[str] | None = None,
             port: int = 53, lifetime: float = 5.0)
```

A `Transport` over UDP/TCP DNS (dnspython). `nameservers=None` uses the
system resolver config; pass a list and `port` for a specific server.
`Resolver()` builds one of these by default.

### `DohTransport`

```python
DohTransport(url: str, *, verify: bool | str = True, timeout: float = 5.0)
```

A `Transport` over DNS-over-HTTPS (RFC 8484): the same queries carried as
wire-format DNS messages in an HTTPS POST to `url`. `verify` is `True`
(system trust store), `False` (none), or a CA-file path.

```python
Resolver(DohTransport("https://doh.example/dns-query")).resolve(ru)
```

### `ResolveError`

Raised by `Resolver` when a registry-phase step fails in a way that
should propagate (no PTR record). The document-phase fetchers do **not**
raise it — they return `None`.

---

## Document / referent phase

### `fetch_url_body`

```python
fetch_url_body(uri: str, *, nameserver: str | None = None,
               timeout: float = 5.0, headers: dict | None = None,
               trace: list | None = None) -> bytes | None
```

Best-effort GET of `uri`; returns body bytes or `None` on any failure.
Schemes are whatever `urllib.request` handles (http, https, ftp, file,
data) plus the installed `did:` handlers. When `nameserver` is set and the
scheme is http/https, the hostname is resolved via that DNS server and the
request goes to the resolved IP with the original `Host` header (a few
redirects followed).

### `fetch_document`

```python
fetch_document(uri: str, *, nameserver: str | None = None,
               timeout: float = 5.0) -> dict | None
```

`fetch_url_body` plus JSON parse. Returns the parsed object, or `None` on
fetch failure, non-JSON body, or non-object top level.

### `resolve_referent_uri`

```python
resolve_referent_uri(ruuid: RUUID, *, domain: str,
                     document: dict | None = None,
                     document_uri: str | None = None) -> str
```

Build the referent URI. Selects the service entry whose `id` fragment
matches `ruuid.type_id` (any URI ending in `#<type_id>`, or a bare
`#<type_id>`), falling back to the `#0` entry and then the spec-wide
default template. `document_uri` is the base for relative
`serviceEndpoint` references.

```python
doc = {"service": [
    {"id": "#42", "type": "CowTag",
     "serviceEndpoint": "https://example.com/cowtag/<identifier>"}]}
resolve_referent_uri(ru, domain="example.com", document=doc)
# 'https://example.com/cowtag/000000000001'
resolve_referent_uri(ru, domain="example.com", document=None)
# 'https://example.com/42/000000000001'   (spec default template)
```

### `substitute_template`

```python
substitute_template(template: str, ruuid: RUUID, *,
                    domain: str = "", document_uri: str | None = None) -> str
```

Expand placeholders in one template:

| placeholder    | expands to                                                                            |
|:---------------|:--------------------------------------------------------------------------------------|
| `<identifier>` | 12-hex full identifier — or the 7-hex 28-bit sequence when `<day>` is in the template |
| `<day>`        | `YYYY-MM-DD` for the top-20-bit `day_count` (2025-01-01 + days, UTC)                   |
| `<type>`       | `ruuid.type_id` as a decimal string                                                   |
| `<network>`    | 16-hex form of `ruuid.network`                                                        |
| `<uuid>`       | the canonical 36-char RUUID text                                                      |
| `<domain>`     | the `domain` argument                                                                 |

If the result has no scheme and `document_uri` is given, it is resolved
against `document_uri` (RFC 3986).

```python
substitute_template("https://<domain>/<day>/<type>/<identifier>", rs, domain="ex.com")
# 'https://ex.com/2025-05-04/5/0000007'
```

### `synthesise_ruuid_document`

```python
synthesise_ruuid_document(ruuid: RUUID, document: dict | None, *,
                          domain: str, document_uri: str | None = None) -> dict
```

Wrap the Phase-2 referent URI in a per-RUUID DID document for the
`did:uuid` method. Returns a dict with `@context` (DID-Core), `id`
(`did:uuid:<ruuid>`), `controller` (`did:uuid:` of the RUUID with
identifier and type zeroed), and an `alsoKnownAs` array holding the
referent URI — the referent denotes the same subject as the DID, which
is the DID-Core meaning of `alsoKnownAs`. With `document` `None`/empty,
the default template is used.

---

## `resolve_ruuid`

```python
resolve_ruuid(ruuid: str | RUUID, *, registry: str | None = None,
              follow: str | None = None,
              registry_trace: list | None = None,
              fetch_trace: list | None = None) -> dict
```

Run the whole pipeline. `ruuid` may be an `RUUID` or its canonical text.

**`registry`** selects the registry-phase transport by URL scheme:

| `registry` value           | resolver / transport                 |
|:---------------------------|:-------------------------------------|
| `None`                     | system DNS (`DnsTransport`)          |
| `dns://[host[:port]]`      | DNS via the given host/port (`DnsTransport`) |
| `doh://host[:port][/path]` | RFC 8484 DoH (`DohTransport`)        |

It governs only the registry phase; document and referent fetches always
use the system resolver. (The keyword is `registry=` for continuity; it
selects the resolver's transport.)

**`follow`** controls how deep the pipeline walks, and which keys the
result carries:

| `follow`           | keys added (beyond the always-present set)           |
|:-------------------|:-----------------------------------------------------|
| `None`             | —                                                    |
| `"document"`       | `document` (`bytes \| None`)                         |
| `"ruuid_document"` | `document`, `ruuid_document` (`dict`)                |
| `"referent_uri"`   | `document`, `ruuid_document`, `referent_uri` (`str`) |
| `"referent"`       | the above plus `referent` (`bytes \| None`)          |

Always present: `network` (`IPv4Network`/`IPv6Network`), `reverse_name`,
`domain`, `uuid_document_uri`.

**Raises** `ValueError` (malformed RUUID/registry URL, or bad `follow`)
and `ResolveError` (registry-phase failure).

```python
out = resolve_ruuid(ru, registry="dns://127.0.0.1:53")          # registry only
out = resolve_ruuid(ru, follow="referent")                       # walk to the body
out["referent_uri"], out["referent"]
```

---

## Helpers

### `reverse_dns_name`

`reverse_dns_name(ruuid: RUUID) -> str` — reverse-DNS name for the network
anchor (`*.in-addr.arpa` or `*.ip6.arpa`). E.g. `'42.2.0.192.in-addr.arpa'`.

### `identifier_label`

`identifier_label(ruuid: RUUID) -> str` — 12-char lowercase hex of the
48-bit identifier. E.g. `'000000000001'`.

### `to_ip`

`to_ip(host: str) -> str` — IP literal for `host` (returned unchanged if
already an IP); resolves a hostname via the system resolver. Raises
`ValueError` when unresolvable.

### `default_uuid_document_uri`

`default_uuid_document_uri(domain: str) -> str` — the well-known
UUID-document URI for `domain`
(`https://<domain>/.well-known/uuid-document.json`).

### `IdentifierScheme`

Name-tags for a UUID document's `identifier_scheme.type` (not part of the
wire format):

- `IdentifierScheme.OPAQUE` = `"opaque"`
- `IdentifierScheme.MONOTONIC` = `"monotonic"`
- `IdentifierScheme.TIMESTAMP` = `"timestamp"`
- `IdentifierScheme.ALL` — frozenset of all three
- `IdentifierScheme.SORTABLE` — `{MONOTONIC, TIMESTAMP}` (the schemes
  making a sortability claim)

---

## Constants

| name                                  | value                                                  |
|:--------------------------------------|:-------------------------------------------------------|
| `VERSION`                             | `8` — RFC 9562 experimental UUID version               |
| `VARIANT_RFC4122`                     | `0b10` — standard 2-bit UUID variant                   |
| `SIXTOFOUR_PREFIX`                    | `0x2002` — top 16 bits marking a 6to4-encoded IPv4 anchor |
| `TXT_PREFIX`                          | `"v=ruuid1 "` — prefix of a doc URI carried in a TXT record |
| `DEFAULT_REFERENT_URI_TEMPLATE`       | `"https://<domain>/<type>/<identifier>"`               |
| `DEFAULT_UUID_DOCUMENT_URI_TEMPLATE`  | `"https://<domain>/.well-known/uuid-document.json"`    |

---

## Tracing

Every `resolve` method and the document/referent fetchers accept an
optional `trace` list (`registry_trace` / `fetch_trace` on
`resolve_ruuid`). When supplied, each step appends one dict describing the
hop — useful for diagnostics and for reproducing the CLI's `--verbose`
output:

```python
trace = []
Resolver().resolve(ru, trace=trace)
# [{'qtype': 'PTR', 'name': '42.2.0.192.in-addr.arpa', 'answer': 'example.com'},
#  {'qtype': 'URI', 'name': '_uuid.example.com', 'uri': 'https://.../uuid-document.json'}]
```

A failed step appends an `{..., "error": "..."}` entry instead of an
answer; the transports never raise on a per-hop miss (they fall back or
return `None`), so the trace is where you see what each hop did.
