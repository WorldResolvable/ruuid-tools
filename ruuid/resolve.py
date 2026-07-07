"""RUUID resolution pipeline.

End-to-end the spec's resolution pipeline runs in two phases:

  Registry phase (PTR + URI/TXT, or an HTTP/DoH equivalent):
    1. determine the IP network from the 64-bit network slot. If the
       top 16 bits are 0x2002, the next 32 bits are the IPv4 /32
       anchor (in-addr.arpa). Otherwise the full 64 bits form an
       IPv6 /64 (ip6.arpa).
    2. PTR-lookup the reverse-DNS name to obtain a domain.
    3. Query `_uuid.<domain>` for the URI of the issuer's UUID
       document.

  Document/referent phase (HTTP/HTTPS):
    4. Fetch the UUID document URI; parse JSON.
    5. Substitute placeholders in the class's referent_uri_template
       to obtain the referent URI; fetch its body if desired.

The DNS step issues two separate queries: `URI` first (RFC 7553),
then `TXT` if no usable URI record was returned. A TXT record
carrying a URI is recognised by the `v=ruuid1 ` prefix. The two
queries replace an earlier ANY-based design: RFC 8482 lets
recursive resolvers return minimal answers to ANY meta-queries
(Cloudflare and others synthesise a single HINFO), so ANY isn't
reliable on the public Internet.

Registry-phase pluggability: `Resolver` runs the registry protocol
over a `Transport` — `DnsTransport` (DNS over UDP/TCP) or
`DohTransport` (DNS over HTTPS per RFC 8484), or any caller-supplied
`Transport`. `_build_resolver(url)` parses a CLI-style URL and returns
a `Resolver` wired to the right transport, with system-DNS failover.

Document/referent phase: `fetch_url_body` and `fetch_document` are
the HTTP fetchers used by the CLI; both honour a `--nameserver`
override by routing hostname resolution through a specific DNS
server while otherwise preserving normal URL semantics
(Host header, redirects, TLS cert validation).
"""

from __future__ import annotations

import dataclasses
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from functools import partial
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver

from ruuid.core import RUUID
import ruuid.did  # noqa: F401 — side effect: installs the did:web urllib handler


TXT_PREFIX = "v=ruuid1 "

DEFAULT_REFERENT_URI_TEMPLATE = "https://<domain>/<type>/<identifier>"
"""Default template used when no class-specific template is available."""

DEFAULT_UUID_DOCUMENT_URI_TEMPLATE = "https://<domain>/.well-known/uuid-document.json"
"""Default UUID-document URI when no `_uuid.<domain>` record is published."""


def default_uuid_document_uri(domain: str) -> str:
    """Return the canonical well-known UUID-document URI for `domain`."""
    return DEFAULT_UUID_DOCUMENT_URI_TEMPLATE.replace("<domain>", domain)


class ResolveError(Exception):
    """A DNS resolution step failed in a way that should propagate."""


def reverse_name_for_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str,
) -> str:
    """Reverse-DNS name for an IP anchor, at the prefix RUUID resolves under.

    IPv4 addresses are reversed at the full /32 under in-addr.arpa. IPv6
    addresses are reversed at the /64 prefix (the high 16 nibbles) under
    ip6.arpa — the same prefix `reverse_dns_name` uses for an RUUID's
    IPv6 anchor, so a raw /128 address collapses to its /64 reverse name.
    """
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv4Address):
        return ".".join(str(b) for b in reversed(ip.packed)) + ".in-addr.arpa"
    hex_chars = ip.packed.hex()[:16]
    return ".".join(reversed(hex_chars)) + ".ip6.arpa"


def reverse_dns_name(ruuid: RUUID) -> str:
    """Construct the reverse-DNS name for an RUUID's network anchor.

    For 6to4-encoded IPv4 networks (top 16 bits = 0x2002), the IPv4 /32
    is reversed under in-addr.arpa. Otherwise, the full 64-bit network
    is reversed under ip6.arpa at /64.
    """
    if ruuid.address_family == 4:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address(
            (ruuid.network >> 16) & 0xFFFFFFFF
        )
    else:
        ip = ipaddress.IPv6Address(ruuid.network << 64)
    return reverse_name_for_ip(ip)


def identifier_label(ruuid: RUUID) -> str:
    """12-char lowercase hex form of the identifier.

    This is the value substituted for `<identifier>` in a
    `referent_uri_template` when `<day>` is not present in the
    template; when `<day>` IS present, `<identifier>` expands to
    just the 28-bit sequence — see `substitute_template`.
    """
    return f"{ruuid.identifier:012x}"


def substitute_template(
    template: str,
    ruuid: RUUID,
    *,
    domain: str = "",
    document_uri: str | None = None,
) -> str:
    """Apply `referent_uri_template` substitution for one RUUID.

    Recognised placeholders:

    - `<identifier>` → 12-char lowercase hex form of the full 48-bit
      identifier when `<day>` is absent from the template; or the
      28-bit `sequence` as 7 lowercase hex digits when `<day>` is
      present (the §7.3 split).
    - `<day>`        → top 20 bits of the identifier interpreted as
      §7.3 `day_count`, rendered as `YYYY-MM-DD`
      (2025-01-01 + `day_count` days, UTC).
    - `<type>`       → `ruuid.type_id` as a decimal integer string
    - `<network>`    → 16-char lowercase hex form of `ruuid.network`
    - `<uuid>`       → canonical 36-char textual form of the RUUID
    - `<domain>`     → `domain` argument (the domain returned by PTR)

    `domain` defaults to the empty string for callers that know their
    template doesn't reference it; pass the resolved domain when using
    the default template or any document-supplied template that may.

    If the substituted result is a relative reference (no scheme) and
    `document_uri` is supplied, it is resolved against `document_uri`
    per RFC 3986. This is the CID/DID-Core convention: serviceEndpoints
    can be absolute-path references like `/docs/<identifier>` and the
    consumer transplants the scheme+authority from the document URI.
    The UUID document can therefore be moved between hosts (S3
    buckets, file paths, did:web bases) without editing every
    serviceEndpoint.
    """
    from datetime import timedelta
    from ruuid.generate import (
        SEQUENCE_BITS,
        STRUCTURED_IDENTIFIER_EPOCH,
    )

    if "<day>" in template:
        # §7.3 split: <identifier> is just the 28-bit sequence; <day>
        # is the 20-bit day_count rendered as a calendar date.
        day_count = ruuid.identifier >> SEQUENCE_BITS
        sequence = ruuid.identifier & ((1 << SEQUENCE_BITS) - 1)
        identifier_str = f"{sequence:07x}"
        day_str = (
            STRUCTURED_IDENTIFIER_EPOCH + timedelta(days=day_count)
        ).date().isoformat()
    else:
        identifier_str = identifier_label(ruuid)
        day_str = ""  # never substituted; placeholder absent
    substituted = (
        template
        .replace("<day>", day_str)
        .replace("<identifier>", identifier_str)
        .replace("<type>", str(ruuid.type_id))
        .replace("<network>", f"{ruuid.network:016x}")
        .replace("<uuid>", str(ruuid))
        .replace("<domain>", domain)
    )
    if document_uri and not urllib.parse.urlparse(substituted).scheme:
        return urllib.parse.urljoin(document_uri, substituted)
    return substituted


def _service_type_fragment(svc_id: object) -> int | None:
    """Return the numeric type fragment of a service `id`, or None.

    A service `id` may be a bare fragment (`"#42"`) or any URI ending
    in one (`"https://example.com/svc#42"`); per RFC 3986 the fragment
    is the text after the first `#`. An `id` that is absent, carries no
    fragment, has a non-numeric fragment, or one outside 0..1023 is not
    selectable and yields None.
    """
    if not isinstance(svc_id, str) or "#" not in svc_id:
        return None
    fragment = urllib.parse.urldefrag(svc_id).fragment
    if not (fragment.isascii() and fragment.isdigit()):
        return None
    value = int(fragment)
    return value if 0 <= value <= 1023 else None


def _select_service_entry(
    document: dict | None,
    type_id: int,
) -> tuple[dict | None, str]:
    """Pick the service entry whose template applies to `type_id`.

    Returns `(entry, template)`. Selection order:

    1. The entry whose `id` fragment is `<type>`.
    2. The entry whose `id` fragment is `0` — the issuer-wide default.
    3. None, with `DEFAULT_REFERENT_URI_TEMPLATE` — the spec-wide
       default, used when neither is available (including the
       no-document case).

    Entries without a string `serviceEndpoint`, or whose `id` lacks a
    numeric fragment in 0..1023, are skipped at every level. When two
    entries share a fragment the first in document order wins.
    """
    services = (document or {}).get("service")
    if not isinstance(services, list):
        return None, DEFAULT_REFERENT_URI_TEMPLATE
    by_type: dict[int, dict] = {}
    for svc in services:
        if not isinstance(svc, dict):
            continue
        if not isinstance(svc.get("serviceEndpoint"), str):
            continue
        fragment = _service_type_fragment(svc.get("id"))
        if fragment is not None:
            by_type.setdefault(fragment, svc)
    for key in (type_id, 0):
        entry = by_type.get(key)
        if entry is not None:
            return entry, entry["serviceEndpoint"]
    return None, DEFAULT_REFERENT_URI_TEMPLATE


def resolve_referent_uri(
    ruuid: RUUID,
    *,
    domain: str,
    document: dict | None = None,
    document_uri: str | None = None,
) -> str:
    """Construct the referent URI for an RUUID per the spec.

    The UUID document is a W3C CID document. Per-class referent
    templates live in `service` entries: the entry's `id` carries a
    numeric fragment `<class-id>` (e.g. `"#1"`, or any URI ending in
    `"#1"`), and its `serviceEndpoint` carries the template. The
    entry's `type` (a required CID-service property) is not used by the
    resolver — only the `id` fragment and `serviceEndpoint`. Template
    selection follows `_select_service_entry`.

    `document_uri` (the URI the document was fetched from) is the base
    for resolving relative serviceEndpoints; see `substitute_template`.
    """
    _entry, template = _select_service_entry(document, ruuid.type_id)
    return substitute_template(
        template, ruuid, domain=domain, document_uri=document_uri,
    )


DID_CORE_CONTEXT = "https://www.w3.org/ns/did/v1"


def synthesise_ruuid_document(
    ruuid: RUUID,
    document: dict | None,
    *,
    domain: str,
    document_uri: str | None = None,
) -> dict:
    """Synthesise the per-RUUID DID document for a `did:uuid:` consumer.

    The RUUID resolution pipeline's normative output is a referent
    URI (Phase 2). The `did:uuid` method (a CID consumer that
    profiles CID for the `did:` URI scheme) synthesises a DID
    document *on top of* that URI so it can satisfy DID-Core §3.1.

    Construction:

    - `id` = `did:uuid:<resolved RUUID>`.
    - `controller` = `did:uuid:<controller-RUUID>` (the resolved
      RUUID with class and identifier zeroed, derived deterministically
      from the RUUID's bits).
    - `alsoKnownAs` = `[<referent URI>]`, the substituted Phase 2
      referent URI. The referent denotes the same subject as the DID,
      which is exactly the DID-Core meaning of `alsoKnownAs`; unlike a
      typical unverified alias, this one is DNS/anchor-bound by the
      RUUID resolution itself. The class label lives in the source
      UUID document's `service` template store and in the RUUID's own
      bits, so it is not repeated here.
    - `@context` = the DID-Core context.

    (Earlier revisions wrapped the referent in a `service` entry with
    an unregistered `type` of "Referent"; `alsoKnownAs` is the
    idiomatic DID-Core home for a same-subject identifier.)

    When `document` is None or empty, the default-template fallback
    is used for the referent URI.
    """
    resolved_did = f"did:uuid:{ruuid}"
    document = document if isinstance(document, dict) else {}

    controller_ruuid = dataclasses.replace(ruuid, identifier=0, type_id=0)
    controller_did = f"did:uuid:{controller_ruuid}"

    _entry, template = _select_service_entry(document, ruuid.type_id)
    referent_uri = substitute_template(
        template, ruuid, domain=domain, document_uri=document_uri,
    )

    return {
        "@context": DID_CORE_CONTEXT,
        "id": resolved_did,
        "controller": controller_did,
        "alsoKnownAs": [referent_uri],
    }


@runtime_checkable
class Transport(Protocol):
    """RUUID-free (pseudo-)DNS query plumbing used by `Resolver`.

    A transport performs one lookup and returns the records as
    normalized Python values. It carries no knowledge of RUUIDs, the
    `_uuid.<domain>` name, or the `v=ruuid1 ` convention — that all
    lives in `Resolver`. `query(name, rrtype)` returns:

      - "PTR" -> list[str]                  target names (trailing dot stripped)
      - "URI" -> list[tuple[int, int, str]] (priority, weight, target)
      - "TXT" -> list[str]                  each record's joined text

    It returns an empty list when the name has no records of that type
    (NODATA / NXDOMAIN), and raises `dns.exception.DNSException` on a
    transport-level failure (timeout, refused, SERVFAIL) so the caller
    can fail over. Any object with this method — including a test
    double — is a usable transport.
    """

    def query(self, name: str, rrtype: str) -> list: ...


def _normalize_records(rrtype: str, rdatas) -> list:
    """Turn dnspython rdata into the transport-neutral form (see `Transport`)."""
    out: list = []
    for r in rdatas:
        if rrtype == "PTR":
            out.append(str(r.target).rstrip("."))
        elif rrtype == "URI":
            target = r.target
            out.append((
                r.priority, r.weight,
                target.decode() if isinstance(target, bytes) else str(target),
            ))
        elif rrtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        else:
            out.append(r)
    return out


class DnsTransport:
    """`Transport` over UDP/TCP DNS, via dnspython.

    `nameservers=None` uses the system resolver configuration; pass an
    explicit list (and `port`) to target a specific server. `lifetime`
    is the total per-query timeout in seconds.
    """

    def __init__(
        self,
        *,
        nameservers: Iterable[str] | None = None,
        port: int = 53,
        lifetime: float = 5.0,
    ) -> None:
        self._r = dns.resolver.Resolver(configure=(nameservers is None))
        if nameservers is not None:
            self._r.nameservers = list(nameservers)
            self._r.port = port
        self._r.lifetime = lifetime

    def query(self, name: str, rrtype: str) -> list:
        try:
            answer = self._r.resolve(name, rrtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        return _normalize_records(rrtype, answer)


class DohTransport:
    """`Transport` over DNS-over-HTTPS (RFC 8484).

    Same queries as `DnsTransport`, carried as wire-format DNS messages
    over an HTTPS POST to the DoH endpoint `url`. `verify` is True
    (system trust store), False (no verification), or a path to a CA
    file. Implemented on stdlib `urllib` rather than `dns.query.https`
    so the `verify` knob can be threaded through without pulling in
    httpx / aioquic; the demo anchor presents a self-signed cert.
    """

    def __init__(
        self,
        url: str,
        *,
        verify: bool | str = True,
        timeout: float = 5.0,
    ) -> None:
        self.url = url
        self._verify = verify
        self._timeout = timeout

    def query(self, name: str, rrtype: str) -> list:
        resp = self._doh_query(name, rrtype)
        want = dns.rdatatype.from_text(rrtype)
        rdatas: list = []
        for rrset in resp.answer:
            if rrset.rdtype == want:
                rdatas.extend(rrset)
        return _normalize_records(rrtype, rdatas)

    def _doh_query(self, qname: str, rdtype: str):
        import ssl as _ssl
        import urllib.request as _ur
        q = dns.message.make_query(qname, rdtype)
        body = q.to_wire()
        if self._verify is False:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
        elif isinstance(self._verify, str):
            ctx = _ssl.create_default_context(cafile=self._verify)
        else:
            ctx = _ssl.create_default_context()
        req = _ur.Request(
            self.url, data=body,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
        )
        with _ur.urlopen(req, timeout=self._timeout, context=ctx) as resp:
            wire = resp.read()
        return dns.message.from_wire(wire)


class Resolver:
    """RUUID resolver: anchor → domain → UUID-document URI.

    Owns the registry-phase protocol — reverse-zone naming, the PTR
    lookup, the `_uuid.<domain>` URI/TXT lookup, the `v=ruuid1 ` prefix,
    and the well-known default — and delegates the actual queries to a
    `Transport`. Pass any `Transport` (`DnsTransport`, `DohTransport`,
    or your own). For convenience, the DNS keyword arguments build a
    `DnsTransport` when no `transport` is given. Fetching the UUID
    document and applying its templates are the caller's job (see
    `resolve_referent_uri` / `resolve_ruuid`).
    """

    def __init__(
        self,
        transport: "Transport | None" = None,
        *,
        nameservers: Iterable[str] | None = None,
        port: int = 53,
        lifetime: float = 5.0,
    ) -> None:
        if transport is None:
            transport = DnsTransport(
                nameservers=nameservers, port=port, lifetime=lifetime,
            )
        self._transport = transport

    # --- Individual resolution steps -------------------------------------

    def reverse_dns_name(self, ruuid: RUUID) -> str:
        return reverse_dns_name(ruuid)

    def resolve_domain(self, ruuid: RUUID,
                       trace: list | None = None) -> str:
        name = reverse_dns_name(ruuid)
        domains = self._transport.query(name, "PTR")
        if not domains:
            if trace is not None:
                trace.append({"qtype": "PTR", "name": name, "error": "no record"})
            raise ResolveError(f"no PTR record at {name}")
        domain = domains[0]
        if trace is not None:
            trace.append({"qtype": "PTR", "name": name, "answer": domain})
        return domain

    def resolve_uuid_document(self, ruuid: RUUID) -> str:
        """Return the UUID-document URI for `ruuid`.

        Falls back to the well-known default when no usable record is
        published at `_uuid.<domain>`; the return value is therefore
        always a URI string. Whether the URI actually points at a
        fetchable document is a separate question for the HTTP layer.
        """
        domain = self.resolve_domain(ruuid)
        return (
            self._query_for_uri(f"_uuid.{domain}")
            or default_uuid_document_uri(domain)
        )

    def resolve(self, ruuid: RUUID, trace: list | None = None) -> dict:
        """Run the registry phase (PTR + URI/TXT at _uuid.<domain>).

        If `trace` is supplied, each hop appends a dict to it:
          - PTR:     {"qtype": "PTR", "name": ..., "answer": domain}
          - URI:     {"qtype": "URI", "name": ..., "uri": doc_uri}
          - TXT:     {"qtype": "TXT", "name": ..., "uri": doc_uri}
          - default: {"qtype": "default", "name": ..., "uri": doc_uri}
          - failure: {"qtype": ..., "name": ..., "error": ...}
        """
        reverse = reverse_dns_name(ruuid)
        domain = self.resolve_domain(ruuid, trace=trace)
        doc_name = f"_uuid.{domain}"
        doc_uri = self._query_for_uri(doc_name, trace=trace)
        if doc_uri is None:
            doc_uri = default_uuid_document_uri(domain)
            if trace is not None:
                trace.append({
                    "qtype": "default", "name": doc_name,
                    "uri": doc_uri,
                })
        return {
            "reverse_name": reverse,
            "domain": domain,
            "uuid_document_uri": doc_uri,
        }

    # --- Internal --------------------------------------------------------

    def _query_for_uri(self, name: str,
                       trace: list | None = None) -> str | None:
        """Find the UUID-document URI at `name`: URI record first, then TXT.

        Two separate, type-specific queries — `URI` (RFC 7553) followed
        by `TXT` (with the `v=ruuid1 ` prefix) if URI returned nothing.
        This avoids `ANY`: RFC 8482 permits recursive resolvers to
        return minimal answers to `ANY` meta-queries, which would
        silently lose published records and force the resolver to the
        default doc URI. Type-specific queries are honoured normally.
        """
        # 1. URI records.
        try:
            uris = self._transport.query(name, "URI")
        except dns.exception.DNSException as e:
            if trace is not None:
                trace.append({"qtype": "URI", "name": name,
                              "error": str(e) or type(e).__name__})
            uris = []
        if uris:
            priority, weight, target = min(uris, key=lambda r: (r[0], -r[1]))
            if trace is not None:
                trace.append({"qtype": "URI", "name": name, "uri": target})
            return target

        # 2. TXT records with the v=ruuid1 prefix.
        try:
            txts = self._transport.query(name, "TXT")
        except dns.exception.DNSException as e:
            if trace is not None:
                trace.append({"qtype": "TXT", "name": name,
                              "error": str(e) or type(e).__name__})
            return None
        for data in txts:
            if data.startswith(TXT_PREFIX):
                uri = data[len(TXT_PREFIX):].strip()
                if trace is not None:
                    trace.append({"qtype": "TXT", "name": name, "uri": uri})
                return uri

        # TXT response existed but no record carried the prefix.
        if trace is not None:
            trace.append({"qtype": "TXT", "name": name,
                          "error": "no v=ruuid1 record"})
        return None


# --- Hostname-to-IP helper ------------------------------------------------

def to_ip(host: str) -> str:
    """Return an IP literal for `host`.

    If `host` is already an IPv4/IPv6 literal it is returned unchanged.
    Otherwise it is resolved via the system resolver (which honours
    `/etc/hosts` as well as DNS), preferring an IPv4 result. Raises
    ValueError when no address is found.
    """
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    last_err: Exception | None = None
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            infos = socket.getaddrinfo(host, None, family=family)
        except socket.gaierror as e:
            last_err = e
            continue
        if infos:
            return infos[0][4][0]
    raise ValueError(f"cannot resolve hostname {host!r}: {last_err}")


# --- TLS / cert plumbing for the dev anchor -------------------------------

_CERT_PATHS = (Path("/etc/ruuid/anchor-cert.pem"), Path("anchor-cert.pem"))


def _find_cert() -> Path | None:
    """Return the first existing path in `_CERT_PATHS`, else None.

    Search order: global install location first, then a repo-local
    file for in-tree development. The same search is used by the
    anchor to decide whether to wrap its socket in TLS.
    """
    for p in _CERT_PATHS:
        if p.is_file():
            return p
    return None


def _demo_ssl_context() -> ssl.SSLContext | None:
    """If a demo anchor cert is reachable, return an SSLContext trusting it.

    Hostname checking stays enabled (the default) so the CLI behaves
    the way curl does: a cert that lacks a SAN entry for the URL
    hostname is rejected. We connect to the resolved IP for the TCP
    layer but pass the URL hostname as the TLS `server_hostname` (see
    `fetch_url_body`), so the cert is validated against the same
    hostname a normal HTTPS client would check. The demo cert (when
    present) is loaded *in addition* to the system CAs, so real
    public-CA hosts (e.g. an S3 bucket) validate exactly as in
    production.
    """
    cert = _find_cert()
    if cert is None:
        return None
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile=str(cert))
    return ctx


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a specific IP but TLS-validate against a URL hostname.

    Equivalent to `curl --resolve hostname:port:ip`: the TCP
    connection goes to `ip`, but the TLS handshake uses `hostname`
    for SNI and cert hostname verification. Needed when
    `--nameserver` has resolved a URL hostname to a private IP (e.g.
    127.0.0.1) and we still want the cert to be validated against
    the hostname the holder of the URL would type.
    """

    def __init__(self, ip: str, hostname: str, port: int, *,
                 timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._ip, self.port), self.timeout, self.source_address,
        )
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = self._context.wrap_socket(
            sock, server_hostname=self.host,
        )


# --- Hostname resolution via specific nameserver --------------------------

def _resolve_host(host: str, nameserver: str | None,
                  timeout: float) -> str | None:
    """Resolve `host` to an IP using `nameserver` if given, else None.

    IP literals are returned as-is. If `nameserver` is None, returns
    None (callers should use stock urllib in that case).
    """
    try:
        ipaddress.ip_address(host)
        return host                              # already an IP
    except ValueError:
        pass
    if nameserver is None:
        return None
    ns_host, _, ns_port_str = nameserver.partition(":")
    try:
        ns_port = int(ns_port_str) if ns_port_str else 53
    except ValueError:
        return None
    try:
        ns_host = to_ip(ns_host)
    except ValueError:
        return None
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ns_host]
    resolver.port = ns_port
    resolver.lifetime = timeout
    for qtype in ("A", "AAAA"):
        try:
            return str(resolver.resolve(host, qtype)[0])
        except dns.exception.DNSException:
            continue
    return None


# --- HTTP fetchers --------------------------------------------------------

def fetch_url_body(uri: str, *, nameserver: str | None = None,
                   timeout: float = 5.0, _redirects: int = 5,
                   headers: dict | None = None,
                   trace: list | None = None) -> bytes | None:
    """Best-effort GET of `uri`. Returns body bytes or None on failure.

    The set of supported schemes is whatever `urllib.request` can
    handle in the calling environment — http, https, ftp, file, and
    data out of the box, plus any custom handlers installed via
    `urllib.request.install_opener`. An unsupported scheme makes
    urllib raise URLError; we catch and return None like any other
    fetch failure.

    If `nameserver` is given and the scheme is http/https, the
    hostname in `uri` is resolved via that DNS server and the request
    is sent to the resolved IP with the original Host header. For
    other schemes `nameserver` is irrelevant (there's no host to
    resolve) and stock urllib is used. Follows up to a few redirects
    on the nameserver-aware path. Optional `headers` are merged into
    the request (Host is set automatically and overrides any
    caller-provided value).

    If `trace` is supplied, each hop appends a dict to it: either
    `{"url": ..., "status": int, "location": str | None}` on a server
    response, or `{"url": ..., "error": str}` on a local failure
    (DNS, connection, etc.). Only the nameserver-aware path populates
    the trace.
    """
    parsed = urllib.parse.urlparse(uri)
    scheme = parsed.scheme.lower()
    extra_headers = dict(headers or {})
    if nameserver is None or scheme not in ("http", "https"):
        ssl_ctx = _demo_ssl_context() if scheme == "https" else None
        try:
            request = urllib.request.Request(uri, headers=extra_headers)
            with urllib.request.urlopen(
                request, timeout=timeout, context=ssl_ctx
            ) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            # An HTTPError is itself a response object backed by a temp
            # file; dropping it unclosed leaks that file (a ResourceWarning
            # "Implicitly cleaning up <HTTPError ...>" under -W error).
            # Plain URLErrors have no body and no close().
            close = getattr(e, "close", None)
            if callable(close):
                close()
            return None
    ssl_ctx = _demo_ssl_context() if scheme == "https" else None

    if _redirects <= 0:
        if trace is not None:
            trace.append({"url": uri, "error": "too many redirects"})
        return None

    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    ip = _resolve_host(host, nameserver, timeout)
    if ip is None:
        if trace is not None:
            trace.append({"url": uri, "error": f"DNS: {host} unresolvable"})
        return None

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if (scheme == "http" and port != 80) or \
       (scheme == "https" and port != 443):
        host_header = f"{host}:{port}"
    else:
        host_header = host

    request_headers = dict(extra_headers)
    request_headers["Host"] = host_header
    conn = None
    try:
        if scheme == "https":
            conn = _PinnedHTTPSConnection(
                ip, host, port, timeout=timeout, context=ssl_ctx,
            )
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers=request_headers)
        resp = conn.getresponse()
        if 300 <= resp.status < 400:
            location = resp.getheader("Location")
            conn.close()
            if trace is not None:
                trace.append({
                    "url": uri, "status": resp.status,
                    "location": location,
                })
            if not location:
                return None
            return fetch_url_body(
                urllib.parse.urljoin(uri, location),
                nameserver=nameserver,
                timeout=timeout,
                _redirects=_redirects - 1,
                headers=headers,
                trace=trace,
            )
        if trace is not None:
            trace.append({"url": uri, "status": resp.status})
        if resp.status >= 400:
            conn.close()
            return None
        body = resp.read()
        conn.close()
        return body
    except (OSError, http.client.HTTPException, TimeoutError) as e:
        if conn is not None:
            conn.close()
        if trace is not None:
            trace.append({"url": uri, "error": str(e) or type(e).__name__})
        return None


def fetch_document(uri: str, *, nameserver: str | None = None,
                   timeout: float = 5.0) -> dict | None:
    """Fetch the UUID document and return it parsed as JSON, or None.

    Honors `nameserver` for hostname resolution by way of
    `fetch_url_body`. Returns None on fetch failure, non-JSON body,
    or non-object top-level.
    """
    return _parse_doc(
        fetch_url_body(uri, nameserver=nameserver, timeout=timeout)
    )


# --- End-to-end pipeline (top-level API) ----------------------------------

# `follow` values for `resolve_ruuid`. Each represents a depth into the
# resolution pipeline:
#   None             — registry phase only (PTR + URI/TXT or equivalent).
#   "document"       — also fetch the UUID document body (raw bytes).
#   "ruuid_document" — also synthesise the per-RUUID DID document on
#                      top of the Phase 2 referent URI (the did:uuid
#                      method's wrapper; see `synthesise_ruuid_document`).
#   "referent_uri"   — also derive the referent URI from the document.
#   "referent"       — also fetch the referent body.
_FOLLOW_DEPTHS = (
    None, "document", "ruuid_document", "referent_uri", "referent",
)


def resolve_ruuid(
    ruuid: "str | RUUID",
    *,
    registry: str | None = None,
    follow: str | None = None,
    registry_trace: list | None = None,
    fetch_trace: list | None = None,
) -> dict:
    """Resolve an RUUID via the spec's pipeline.

    Builds the right registry transport from `registry` and runs the
    registry-phase lookup. Optionally walks further into the document
    and referent fetches.

    Parameters:
        ruuid: An RUUID instance or its canonical text form.
        registry: Registry endpoint URL or None. Schemes:
            None                       system DNS resolver
            dns://[host[:port]]        DNS-protocol via host/port
            doh://host[:port][/path]   RFC 8484 DoH endpoint
            The registry value only governs the registry-phase
            lookup. HTTP fetches of the UUID document and referent
            URI always use the system DNS resolver — the system is
            assumed to know how to reach the hostnames the registry
            puts in front of it (via real DNS, /etc/hosts, etc.).
        follow: How deep to walk after the registry phase. One of
            None, "document", "referent_uri", "referent".
        registry_trace: If supplied, the registry transport appends a
            dict to this list for each hop (PTR / URI / TXT / REGISTRY
            / HTTP, depending on transport).
        fetch_trace: If supplied and `follow == "referent"`, the
            referent fetch appends a dict per HTTP hop.

    Returns a dict with keys:
        network, reverse_name, domain, uuid_document_uri     — always
        document (bytes | None)                              — at "document"
        ruuid_document (dict)                                — at "ruuid_document"
        referent_uri (str)                                   — at "referent_uri"
        referent_uri (str), referent (bytes | None)          — at "referent"

    Raises:
        ValueError: ruuid string is malformed, registry URL is
            malformed, or `follow` is not one of the accepted values.
        ResolveError: registry-phase lookup failed (e.g. PTR not found).
    """
    if isinstance(ruuid, str):
        try:
            ruuid = RUUID.from_str(ruuid)
        except (ValueError, TypeError) as e:
            raise ValueError(f"invalid UUID: {e}") from e
    if follow not in _FOLLOW_DEPTHS:
        raise ValueError(
            f"follow must be one of {_FOLLOW_DEPTHS}; got {follow!r}"
        )

    # A nested resolve_ruuid call (e.g. the did:uuid handler running
    # under our urllib opener, dispatched from a fetch_url_body the
    # outer call made) inherits the outer call's registry. Without
    # this, the outer's choice of DNS server / DoH endpoint would be
    # lost the moment a URI record value pointed at did:uuid:..., and
    # the inner resolve would always default to system DNS.
    if registry is None:
        registry = getattr(_resolve_context, "registry", None)

    prev_registry = getattr(_resolve_context, "registry", None)
    _resolve_context.registry = registry
    try:
        registry_obj = _build_resolver(registry)
        result = registry_obj.resolve(ruuid, trace=registry_trace)
        result["network"] = ruuid.ip_network

        if follow is None:
            return result

        doc_body = fetch_url_body(result["uuid_document_uri"])
        result["document"] = doc_body

        if follow == "document":
            return result

        document = _parse_doc(doc_body)
        result["ruuid_document"] = synthesise_ruuid_document(
            ruuid, document,
            domain=result["domain"],
            document_uri=result["uuid_document_uri"],
        )

        if follow == "ruuid_document":
            return result

        result["referent_uri"] = resolve_referent_uri(
            ruuid,
            domain=result["domain"],
            document=document,
            document_uri=result["uuid_document_uri"],
        )

        if follow == "referent_uri":
            return result

        # follow == "referent"
        result["referent"] = fetch_url_body(
            result["referent_uri"], trace=fetch_trace,
        )
        return result
    finally:
        _resolve_context.registry = prev_registry


# Thread-local state for propagating the resolve context across the
# urllib boundary. See the `registry` handling in `resolve_ruuid` and
# `ruuid.did._open_did_uuid`.
_resolve_context = threading.local()


def _parse_doc(body: bytes | None) -> dict | None:
    """Parse a UUID-document body. Returns None on any decode failure."""
    if body is None:
        return None
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


# --- Registry construction (internal) -------------------------------------

class FailoverResolver:
    """Try one resolver; fall back to a second if the first fails.

    Wraps a `primary` and a `fallback` resolver (anything with a
    `resolve(ruuid, trace=None)` method). The primary is tried first;
    on any resolution failure (ResolveError, DNS-layer errors like
    timeouts and `NoNameservers`, or socket-level `OSError`s such as
    connection refused), the fallback is tried. The primary's failure
    is recorded in the trace as a `failover` entry so verbose output
    shows what happened.

    This is the wrapper that makes `ruuid resolve UUID` work in the
    `ruuid anchor`-then-`ruuid resolve` workflow: the primary points at
    the loopback anchor, the fallback at the system resolver, and if
    the anchor isn't running (or doesn't know the prefix) the system
    resolver answers.
    """

    def __init__(self, primary, fallback) -> None:
        self._primary = primary
        self._fallback = fallback

    def resolve(self, ruuid: RUUID, trace: list | None = None) -> dict:
        try:
            return self._primary.resolve(ruuid, trace=trace)
        except (ResolveError, dns.exception.DNSException, OSError) as e:
            if trace is not None:
                trace.append({
                    "step": "failover",
                    "reason": str(e) or type(e).__name__,
                })
            try:
                return self._fallback.resolve(ruuid, trace=trace)
            except (dns.exception.DNSException, OSError) as e2:
                # Normalise: callers catching `ResolveError` already
                # cover the "no PTR / no record" inner cases; wrap the
                # transport-level final failure so they don't need a
                # second except clause.
                raise ResolveError(
                    f"both primary and fallback failed; fallback: {e2}"
                ) from e2


def _build_primary_resolver(url: str):
    """Parse a registry URL into a single `Resolver` (no failover wrap).

    Supported schemes: `dns://HOST[:PORT]` (a `DnsTransport`) and
    `doh://HOST[:PORT][/PATH]` (a `DohTransport`). Raises ValueError on
    unparseable input or unsupported scheme.
    """
    if url.startswith("dns:"):
        netloc = url[6:] if url.startswith("dns://") else ""
        if not netloc:
            return Resolver()
        host, _, port_str = netloc.partition(":")
        try:
            port = int(port_str) if port_str else 53
        except ValueError:
            raise ValueError(f"invalid port: {port_str!r}")
        host = to_ip(host)
        return Resolver(nameservers=[host], port=port, lifetime=2.0)

    if url.startswith("doh://") or url.startswith("doh+https://"):
        # DoH per RFC 8484: translate doh:// to https://. Default path
        # is /dns-query (the RFC 8484 convention). Use the demo cert
        # as the trust anchor if it's locally available, since the
        # demo anchor presents a self-signed cert; fall back to system
        # CAs otherwise.
        tail = url.split("://", 1)[1]
        https_url = "https://" + tail
        parsed = urllib.parse.urlparse(https_url)
        if not parsed.path:
            parsed = parsed._replace(path="/dns-query")
            https_url = parsed.geturl()
        cert = _find_cert()
        verify: bool | str = str(cert) if cert is not None else True
        return Resolver(DohTransport(https_url, verify=verify, timeout=2.0))

    raise ValueError(
        f"unsupported scheme in {url!r}; "
        "use dns:// or doh://"
    )


def _build_resolver(url: str | None):
    """Build the registry resolver for a registry URL.

    `url is None` — the default — resolves against the system DNS
    resolver directly: the system resolver *is* the registry, so no
    failover wrapper is needed (and there is no loopback DNS server to
    probe, which is what made the old loopback-primary default pay a
    multi-second timeout on machines with no `ruuid anchor` running).

    An explicit `url` (`dns://HOST[:PORT]` or `doh://...`, e.g. a local
    `ruuid anchor` on `dns://127.0.0.1:53`) is used as the *primary*,
    with the system resolver as a fallback, so resolution still
    succeeds for prefixes the chosen endpoint doesn't know about.
    """
    if url is None:
        return Resolver()
    primary = _build_primary_resolver(url)
    fallback = Resolver()
    return FailoverResolver(primary, fallback)
