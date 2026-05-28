"""DNS + HTTP daemon for RUUID issuance scenarios.

A *zone file* (JSON) describes one or more anchored domains. For each
issuer, the daemon serves:

  - The reverse-DNS PTR record mapping the IP anchor's reverse name
    to the issuer's domain.
  - A URI or TXT record at `_uuid.<domain>` whose value is the URL of
    the issuer's UUID document, rooted at this daemon's HTTP server.
  - The UUID document itself, JSON, served over HTTP. The per-class
    `referent_uri_template` entries are synthesised from the zone's
    `path` strings, also rooted here.
  - Stub referents: GETs at the templated paths return a JSON object
    naming the issuer domain, the class, and the identifier.

The same zone drives both DNS and HTTP responses, so a single edit
keeps the two layers consistent.
"""

from __future__ import annotations

import ipaddress
import json
import re
import ssl
import struct
import sys
import threading
import time
import urllib.parse as urllib_parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import IO
import dnslib
from dnslib import QTYPE, RCODE, RD, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from ruuid.core import RUUID
from ruuid.resolve import to_ip

# --- URI rdata class (dnslib 0.9.x doesn't ship one) ---------------------
class _URI(RD):
    """RFC 7553 URI record."""

    def __init__(self, priority: int, weight: int, target):
        self.priority = int(priority)
        self.weight = int(weight)
        self.target = target.encode() if isinstance(target, str) else target

    @classmethod
    def parse(cls, buffer, length):
        prio, weight = struct.unpack("!HH", buffer.get(4))
        target = buffer.get(length - 4)
        return cls(prio, weight, target)

    def pack(self, buffer):
        buffer.append(struct.pack("!HH", self.priority, self.weight))
        buffer.append(self.target)

    def __repr__(self):
        return f'{self.priority} {self.weight} "{self.target.decode()}"'

def _register_uri_once() -> None:
    if "URI" not in dnslib.RDMAP:
        dnslib.RDMAP["URI"] = _URI
    try:
        dnslib.QTYPE["URI"]
    except dnslib.dns.DNSError:
        dnslib.QTYPE.forward["URI"] = 256


# --- Zone model ----------------------------------------------------------
#
# The zone file is structured around *domains*, not anchors. Each domain
# entry carries the content that will appear in the UUID document for
# that domain (a CID `service` array, or alternatively a
# `uuid_document_uri` pointing at an externally-hosted document), plus
# the list of anchor IP addresses that share the domain. Internally we
# still flatten to per-anchor `_Issuer` records — every anchor produces
# its own PTR record, and the daemon's HTTP routing is per-anchor — but
# all siblings under one domain reference the *same* service array (so
# the "one UUID document per domain" property is structural, not a
# tooling inference).

@dataclass
class _Issuer:
    domain: str
    anchor: str                        # IPv4 or IPv6 string; the
                                       # namespace-anchor address.
    ptr_name: str
    service: list[dict] | None         # CID service entries, the
                                       # same list reference for every
                                       # _Issuer sharing this domain.
                                       # None when uuid_document_uri is
                                       # set (the external-doc case).
    uuid_document_uri: str | None = None  # literal URI to publish at
                                       # _uuid.<domain>. When set, the
                                       # anchor doesn't build a UUID
                                       # document or serve referent paths
                                       # — the URI is fetched directly by
                                       # the resolver. Useful for `data:`
                                       # (inline JSON), `file://` (local
                                       # filesystem), `did:web:`,
                                       # `did:plc:`, `did:uuid:`, etc.

    @property
    def network(self) -> int:
        """The 64-bit network slot encoded from `anchor`.

        IPv4 anchors are 6to4-encoded (top 16 bits = 0x2002); IPv6
        anchors take the high 64 bits of the /128. This is the same
        encoding `RUUID.from_anchor` uses, so it's the value `<network>`
        substitutes to in templates anchored at this issuer.
        """
        return RUUID.from_anchor(self.anchor, identifier=0).network


def _reverse_ptr_name(anchor: str) -> str:
    """Derive the reverse-DNS name for an IPv4 /32 or IPv6 /64 anchor."""
    addr = ipaddress.ip_address(anchor)
    if isinstance(addr, ipaddress.IPv4Address):
        return ".".join(str(b) for b in reversed(addr.packed)) + ".in-addr.arpa"
    hex_chars = addr.packed.hex()[:16]
    return ".".join(reversed(hex_chars)) + ".ip6.arpa"


def _resolve_uuid_document_uri(
    raw_uri: str | None,
    *,
    domain: str,
    zone_dir: Path,
) -> str | None:
    """Resolve a possibly-relative `uuid_document_uri` to its absolute form.

    Accepted shorthands:

    - `"/.well-known/uuid-document.json"` (no scheme, absolute path) →
      `https://<domain>/.well-known/uuid-document.json`.
    - `"http:/.well-known/uuid-document.json"` (scheme + path, no `//`) →
      `http://<domain>/.well-known/uuid-document.json`. Same for `https:`.
    - `"file:foo/uuid-document.json"` (file scheme, relative path) →
      `file://<absolute-zone-file-dir>/foo/uuid-document.json`.

    Opaque schemes (`data:`, `did:web:`, `did:plc:`, `did:uuid:`, etc.)
    and already-absolute http(s)/file URIs pass through unchanged.

    The implementation is one `urljoin` call against a base picked from
    the URI's scheme — RFC 3986 §5.3 handles the rest.
    """
    if not raw_uri:
        return None
    parsed = urllib_parse.urlparse(raw_uri)
    scheme = parsed.scheme.lower()
    if scheme == "file":
        base = f"file://{zone_dir}/"
    elif scheme in ("http", "https"):
        base = f"{scheme}://{domain}/"
    elif scheme == "":
        base = f"https://{domain}/"
    else:
        # data:, did:web:, did:plc:, did:uuid:, gopher:, ftp:, ... —
        # opaque schemes the zone has to give in absolute form.
        return raw_uri
    return urllib_parse.urljoin(base, raw_uri)


def _load_zone(zone_path: Path) -> list[_Issuer]:
    """Read a zone file and flatten its domain entries to per-anchor records.

    The zone file's top level is `{"domains": [<domain entry>, ...]}`.
    Each domain entry carries the UUID-document content (a CID
    `service` array, OR a `uuid_document_uri` for externally-hosted
    documents) plus the list of `anchors` that share the domain. Every
    anchor in a domain becomes its own `_Issuer` record; all siblings
    under one domain reference the *same* `service` list (or the same
    `uuid_document_uri`), so that the "one UUID document per domain"
    property is preserved structurally rather than via a tool-side
    heuristic.

    `uuid_document_uri` may be a shorthand (path-only, scheme+path with
    no authority, or relative `file:` path) — see
    `_resolve_uuid_document_uri` for the resolution rules. The loader
    expands shorthands to absolute URIs before constructing _Issuer
    records, so downstream code always sees an absolute form.
    """
    zone_path = Path(zone_path).resolve()
    zone_dir = zone_path.parent
    raw = json.loads(zone_path.read_text())
    issuers: list[_Issuer] = []
    for entry in raw.get("domains", []):
        domain = entry["domain"]
        anchors = entry.get("anchors") or []
        uuid_document_uri = _resolve_uuid_document_uri(
            entry.get("uuid_document_uri"), domain=domain, zone_dir=zone_dir,
        )
        service = entry.get("service")
        # `service` and `uuid_document_uri` can coexist: the issuer
        # publishes the document at a specific URL (often a non-default
        # host:port or scheme) AND describes what the document
        # contains. External-doc cases (data:, file:, did:web:, did:plc:,
        # did:uuid:) typically set only `uuid_document_uri`.
        for anchor in anchors:
            issuers.append(_Issuer(
                domain=domain,
                anchor=anchor,
                ptr_name=_reverse_ptr_name(anchor),
                service=service,
                uuid_document_uri=uuid_document_uri,
            ))
    return issuers

# --- DNS access logger --------------------------------------------------
class _AccessLogger(DNSLogger):
    """One-line, webserver-style access log for the DNS server.

    Emits a single line per query/reply pair on `sys.stderr`,
    formatted to match `BaseHTTPRequestHandler`'s default HTTP access
    log so DNS and HTTP entries read uniformly in the same stream:

        127.0.0.1 - - [16/May/2026 14:23:45] "PTR 42.2.0.192.in-addr.arpa" NOERROR

    The base `DNSLogger` emits multi-line dumps from `log_recv` /
    `log_send` / `log_request` / `log_reply` / `log_data`; we suppress
    those and emit our own line in `log_reply`, after the resolver
    has produced an rcode.
    """

    def __init__(self) -> None:
        super().__init__(log="", prefix=False)

    # Silence the verbose defaults.
    def log_recv(self, *args, **kw) -> None: pass
    def log_send(self, *args, **kw) -> None: pass
    def log_request(self, *args, **kw) -> None: pass
    def log_data(self, *args, **kw) -> None: pass
    def log_truncated(self, *args, **kw) -> None: pass

    def log_reply(self, handler, reply) -> None:
        addr = getattr(handler, "client_address", None)
        client = addr[0] if addr else "?"
        q = reply.q
        qtype = QTYPE.get(q.qtype, str(q.qtype))
        rcode_name = RCODE.get(reply.header.rcode, str(reply.header.rcode))
        ts = time.strftime("%d/%b/%Y %H:%M:%S")
        sys.stderr.write(
            f'{client} - - [{ts}] "{qtype} {q.qname}" {rcode_name}\n'
        )
        sys.stderr.flush()

    def log_error(self, handler, e) -> None:
        addr = getattr(handler, "client_address", None)
        client = addr[0] if addr else "?"
        ts = time.strftime("%d/%b/%Y %H:%M:%S")
        sys.stderr.write(f'{client} - - [{ts}] error: {e}\n')
        sys.stderr.flush()


# --- HTTP server with quieter teardown logging --------------------------
class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that silences benign client-side teardown errors.

    A client that closes the connection before/during the request line --
    a probe, a redirect follower that disconnects after seeing 302, a
    curl run that bails on cert mismatch -- triggers BrokenPipeError or
    ssl.SSLEOFError on the server's next read. These are client-side
    events, not server bugs, so they shouldn't print stack traces to
    stderr and clutter the demo output.
    """

    _silent_excs = (
        BrokenPipeError,
        ConnectionResetError,
        ConnectionAbortedError,
        ssl.SSLEOFError,
    )

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, self._silent_excs):
            return
        super().handle_error(request, client_address)


# --- The combined DNS+HTTP daemon ---------------------------------------
@dataclass
class _ReferentRoute:
    pattern: re.Pattern
    domain: str
    network: int                       # issuer's 64-bit network slot, for
                                       # <network>/<uuid> alias_to expansion
    type_id: str
    type_name: str
    alias_to: str | None = None


class Anchor:
    """Combined DNS + HTTP daemon driven by one zone file."""

    def __init__(
        self,
        issuers: list[_Issuer],
        *,
        bind: str = "127.0.0.1",
        dns_port: int = 53,
        http_port: int = 80,
        https_port: int = 443,
        rrtype: str = "both",
        serve_https: bool | None = None,
    ) -> None:
        if rrtype not in ("both", "URI", "TXT"):
            raise ValueError(
                f"rrtype must be 'both', 'URI', or 'TXT'; got {rrtype!r}"
            )
        self.issuers = issuers
        self.bind = bind
        self.dns_port = dns_port
        self.http_port = http_port
        self.https_port = https_port
        self.rrtype = rrtype

        # The daemon listens on HTTP (http_port) unconditionally and on
        # HTTPS (https_port) whenever a usable cert is found. HTTPS auto-
        # detects /etc/ruuid/anchor-cert.pem (preferred) or
        # ./anchor-cert.pem (repo-local fallback); pass serve_https=False
        # to force plain HTTP only (e.g. tests on ephemeral ports).
        self._cert_path: Path | None = None
        if serve_https is not False:
            for p in (Path("/etc/ruuid/anchor-cert.pem"),
                      Path("anchor-cert.pem")):
                if p.is_file():
                    self._cert_path = p
                    break

        self._dns_records = self._build_dns_records()
        self._documents = self._build_documents()
        self._referent_routes = self._build_referent_routes()
        self._host_to_issuer = self._build_host_to_issuer()

        self._dns_server: DNSServer | None = None
        self._dns_tcp_server: DNSServer | None = None
        self._http_server: ThreadingHTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._https_server: ThreadingHTTPServer | None = None
        self._https_thread: threading.Thread | None = None

    # --- URL helpers -----------------------------------------------------

    def _doc_path(self, domain: str) -> str:
        """Internal canonical path used for HTTP routing."""
        return f"/{domain}/uuid-document.json"

    def _doc_url(self, iss: _Issuer) -> str:
        """The doc URL advertised in DNS records.

        Returns `iss.uuid_document_uri` when set (the literal external
        URI — `data:`, `file://`, `did:web:`, `did:plc:`, `did:uuid:`,
        any HTTP(S) URL the issuer chose), otherwise the well-known
        default `https://<domain>/.well-known/uuid-document.json`.
        """
        if iss.uuid_document_uri:
            return iss.uuid_document_uri
        return f"https://{iss.domain}/.well-known/uuid-document.json"

    def _referent_path(self, domain: str, path: str) -> str:
        """Internal canonical path used for HTTP routing."""
        return f"/{domain}{path}"

    def _hosts_for(self, iss: _Issuer) -> set[str]:
        """Return every public-facing host this issuer is reachable at.

        That's `iss.domain` (always), the hosts of any `service[].serviceEndpoint`
        URL with an http/https scheme, and the host of
        `iss.uuid_document_uri` when it is http(s). These are the
        hostnames the daemon synthesises A/AAAA records for so a
        client using the daemon as its DNS resolver can reach every
        advertised URL.
        """
        hosts: set[str] = {iss.domain}
        for entry in (iss.service or []):
            ep = entry.get("serviceEndpoint")
            if not isinstance(ep, str):
                continue
            parsed = urllib_parse.urlparse(ep)
            if parsed.scheme in ("http", "https") and parsed.hostname:
                hosts.add(parsed.hostname)
        if iss.uuid_document_uri:
            parsed = urllib_parse.urlparse(iss.uuid_document_uri)
            if parsed.scheme in ("http", "https") and parsed.hostname:
                hosts.add(parsed.hostname)
        return hosts

    def _build_host_to_issuer(self) -> dict[str, _Issuer]:
        """Map every issuer-facing host to its issuer for HTTP dispatch.

        Always includes `iss.domain` plus any host derived from a
        `serviceEndpoint` URL or from `uuid_document_uri`. When several
        anchors share a domain (the sibling-anchor case), the daemon
        prefers a service-bearing entry so the host resolves to one
        whose referent paths the daemon actually serves; the
        setdefault-after-sort cements the first-seen entry, leaving
        PTR-only siblings as fallbacks.
        """
        result: dict[str, _Issuer] = {}
        for iss in sorted(self.issuers, key=lambda i: 0 if i.service else 1):
            for host in self._hosts_for(iss):
                result.setdefault(host, iss)
        return result

    # --- Zone → DNS / HTTP -----------------------------------------------
    def _build_dns_records(self) -> dict[tuple[str, str], list[RD]]:
        records: dict[tuple[str, str], list[RD]] = {}

        def add(name: str, qtype: str, rdata: RD) -> None:
            # Dedup identical rdata for the same (name, qtype) — multiple
            # issuer entries sharing a domain would otherwise emit
            # duplicate A records pointing at the same bind IP.
            existing = records.setdefault((_canon(name), qtype), [])
            if any(str(r) == str(rdata) for r in existing):
                return
            existing.append(rdata)

        # If the anchor binds on a literal IP, publish A/AAAA records
        # for each issuer's hostname pointing at it. This is the
        # dev-fixture path: integration tests use it to make hostnames
        # like `branch.example` reach the test anchor without touching
        # /etc/hosts. The bundled demo doesn't rely on it — its
        # demo.example.com is mapped to 127.0.0.1 in /etc/hosts by the
        # install step — but the synthetic A is harmless there too.
        try:
            bind_ip = ipaddress.ip_address(self.bind)
        except ValueError:
            bind_ip = None

        for iss in self.issuers:
            add(iss.ptr_name, "PTR", dnslib.PTR(iss.domain + "."))
            # An issuer that publishes a UUID document gets URI and/or
            # TXT records at _uuid.<domain>. Default is both; --rrtype
            # restricts to one so the demo can exercise the resolver's
            # URI-preferred / TXT-fallback paths separately. Zero-
            # config issuers (no service and no literal
            # uuid_document_uri) publish neither.
            if iss.service or iss.uuid_document_uri:
                doc_url = self._doc_url(iss)
                if self.rrtype in ("both", "URI"):
                    add(f"_uuid.{iss.domain}", "URI",
                        _URI(10, 1, doc_url))
                if self.rrtype in ("both", "TXT"):
                    # RFC 1035: each TXT character-string is <=255 bytes;
                    # a TXT record can carry multiple strings that the
                    # resolver concatenates. Long values (e.g. inline
                    # data: URIs) need chunking. The TXT_PREFIX check on
                    # the resolver side already runs against the joined
                    # bytes.
                    payload = f"v=ruuid1 {doc_url}".encode()
                    chunks = [payload[i:i + 255]
                              for i in range(0, len(payload), 255)] or [b""]
                    add(f"_uuid.{iss.domain}", "TXT", dnslib.TXT(chunks))

            if bind_ip is not None:
                for hostname in self._hosts_for(iss):
                    if isinstance(bind_ip, ipaddress.IPv4Address):
                        add(hostname, "A", dnslib.A(self.bind))
                    else:
                        add(hostname, "AAAA", dnslib.AAAA(self.bind))
        return records

    def _build_documents(self) -> dict[str, bytes]:
        """Build the UUID document for each domain with a `service` array.

        Delegates the document structure to `ruuid.issue.build_uuid_documents`
        (so the live anchor and the standalone `ruuid document` CLI
        produce identical output).
        """
        from ruuid.issue import build_uuid_documents

        documents: dict[str, bytes] = {}
        for domain, doc in build_uuid_documents(
            self.issuers,
            doc_url_for=self._doc_url,
        ):
            documents[self._doc_path(domain)] = json.dumps(
                doc, indent=2
            ).encode("utf-8")
        return documents

    def _build_referent_routes(self) -> list[_ReferentRoute]:
        """Build HTTP-routing patterns from each domain's `service` entries.

        The serviceEndpoint may be an absolute URL (http/https) or a
        relative reference (e.g. `/tag/<identifier>` — see RUUID §6.9
        Placeholder substitution). For routing we want only the path
        portion of the URL: an absolute-URL entry contributes its
        `parsed.path`; a relative-reference entry contributes its raw
        string (urlparse leaves the leading `/` in `path` for those).
        Service entries with no `serviceEndpoint`, with an absolute
        non-http(s) scheme (`data:`, `file:`, `did:`), or without a
        `#<type>` fragment are skipped — the daemon doesn't route
        those.

        Placeholders we know at route-build time (`<type>`,
        `<network>`, `<domain>`) are substituted into the path;
        `<identifier>` is left as the regex capture group.
        """
        routes: list[_ReferentRoute] = []
        seen_iss: set[id] = set()  # iss.service is shared across siblings
        for iss in self.issuers:
            if iss.service is None:
                continue
            sig = (iss.domain, id(iss.service))
            if sig in seen_iss:
                continue
            seen_iss.add(sig)
            for entry in iss.service:
                ep = entry.get("serviceEndpoint")
                if not isinstance(ep, str):
                    continue
                sid = entry.get("id", "")
                if not (isinstance(sid, str) and sid.startswith("#")):
                    continue
                type_id = sid[1:]
                if not type_id:
                    continue
                parsed = urllib_parse.urlparse(ep)
                if parsed.scheme and parsed.scheme not in ("http", "https"):
                    # absolute URL on a non-http(s) scheme — not ours to route
                    continue
                path_template = parsed.path
                if not path_template.startswith("/"):
                    # path-relative reference — not supported for routing;
                    # the resolver would urljoin it against the document URI
                    # but the daemon has no good way to route it.
                    continue
                path_template = (
                    path_template
                    .replace("<type>", type_id)
                    .replace("<network>", f"{iss.network:016x}")
                    .replace("<domain>", iss.domain)
                )
                full = self._referent_path(iss.domain, path_template)
                pattern = re.escape(full).replace(
                    re.escape("<identifier>"),
                    r"(?P<identifier>[^/]+)",
                )
                routes.append(_ReferentRoute(
                    pattern=re.compile(f"^{pattern}$"),
                    domain=iss.domain,
                    network=iss.network,
                    type_id=type_id,
                    type_name=entry.get("type", ""),
                    alias_to=entry.get("alias_to"),
                ))
        return routes

    @staticmethod
    def _expand_alias(template: str, route: "_ReferentRoute",
                      identifier: str) -> str:
        """Substitute placeholders in an `alias_to` template.

        Recognises the same five placeholders as
        `ruuid.resolve.substitute_template`:
        `<identifier>`, `<type>`, `<network>`, `<uuid>`, `<domain>`.

        `<identifier>` is replaced with the literal value matched out
        of the request URL (which the regex does not constrain to the
        canonical 12-hex form), so the alias mirrors what the client
        supplied. `<network>` is derived from the issuer's anchor.
        `<uuid>` additionally requires `<identifier>` to parse as a
        hexadecimal integer within the 48-bit RUUID range; if it
        doesn't, the `<uuid>` placeholder is left in the result so
        the malformed input is visible rather than silently dropped.
        """
        result = (
            template
            .replace("<identifier>", identifier)
            .replace("<type>", route.type_id)
            .replace("<network>", f"{route.network:016x}")
            .replace("<domain>", route.domain)
        )
        if "<uuid>" in result:
            try:
                ru = RUUID(
                    identifier=int(identifier, 16),
                    network=route.network,
                    type_id=int(route.type_id),
                )
            except ValueError:
                return result
            result = result.replace("<uuid>", str(ru))
        return result

    def _match_referent(self, path: str):
        for route in self._referent_routes:
            m = route.pattern.match(path)
            if m:
                return route, m.group("identifier")
        return None, None

    # --- Lifecycle -------------------------------------------------------
    def start(self) -> None:
        _register_uri_once()
        resolver = _ZoneResolver(self._dns_records)
        # One-line-per-query DNS access log on stderr, matching
        # BaseHTTPRequestHandler's default HTTP log format so both
        # streams read uniformly when interleaved.
        logger = _AccessLogger()
        self._dns_server = DNSServer(
            resolver, port=self.dns_port, address=self.bind, logger=logger,
        )
        self._dns_server.start_thread()
        # TCP is required by RFC 7766 and is what `dig` reaches for on
        # ANY queries; bind both transports on the same port.
        self._dns_tcp_server = DNSServer(
            resolver, port=self.dns_port, address=self.bind, logger=logger,
            tcp=True,
        )
        self._dns_tcp_server.start_thread()

        handler_cls = self._make_http_handler()

        # HTTP is always served.
        self._http_server = _QuietThreadingHTTPServer(
            (self.bind, self.http_port), handler_cls,
        )
        self._http_thread = threading.Thread(
            target=self._http_server.serve_forever, daemon=True
        )
        self._http_thread.start()

        # HTTPS is served whenever a cert is available (detected in
        # __init__). The handler is the same; the difference is just the
        # TLS-wrapped socket on a separate port.
        self._serves_https = self._cert_path is not None
        if self._cert_path is not None:
            self._https_server = _QuietThreadingHTTPServer(
                (self.bind, self.https_port), handler_cls,
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(self._cert_path))
            self._https_server.socket = ctx.wrap_socket(
                self._https_server.socket, server_side=True,
            )
            self._https_thread = threading.Thread(
                target=self._https_server.serve_forever, daemon=True,
            )
            self._https_thread.start()

    def stop(self) -> None:
        # shutdown() stops the serve_forever loop; server_close() releases
        # the listening socket. dnslib's DNSServer.stop() only does the
        # former, so close its underlying socketserver explicitly. Without
        # the server_close() calls the sockets leak (ResourceWarning under
        # -W error).
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server.server_close()
        if self._https_server is not None:
            self._https_server.shutdown()
            self._https_server.server_close()
        if self._dns_server is not None:
            self._dns_server.stop()
            self._dns_server.server.server_close()
        if self._dns_tcp_server is not None:
            self._dns_tcp_server.stop()
            self._dns_tcp_server.server.server_close()

    def serve_forever(self, banner: IO[str] | None = sys.stderr) -> None:
        self.start()
        if banner is not None:
            print(
                f"ruuid anchor DNS   on {self.bind}:{self.dns_port}/udp+tcp",
                file=banner,
            )
            print(
                f"ruuid anchor HTTP  on {self.bind}:{self.http_port}/tcp",
                file=banner,
            )
            if self._serves_https:
                print(
                    f"ruuid anchor HTTPS on {self.bind}:{self.https_port}/tcp",
                    file=banner,
                )
            print(
                f"serving {len(self.issuers)} issuer(s); Ctrl-C to stop",
                file=banner,
            )
            banner.flush()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # --- HTTP handler factory --------------------------------------------
    def _make_http_handler(self):
        anchor = self

        class _Handler(BaseHTTPRequestHandler):
            # RFC 8484 DoH endpoint. The path is conventionally
            # /dns-query but any path the operator chose is fine -- the
            # resolver targets the URL they configured. We accept the
            # conventional path here.
            _DOH_PATH = "/dns-query"

            def _serve_doh(self, dns_wire: bytes) -> None:
                """Proxy a DoH-encoded DNS message to the anchor's own UDP
                DNS server and return the response.

                Reusing the DNS-over-UDP layer means parsing, resolution
                and serialisation are not duplicated -- the DoH handler
                is just transport glue.
                """
                import socket as _sock
                s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                s.settimeout(2.0)
                try:
                    s.sendto(dns_wire, (anchor.bind, anchor.dns_port))
                    reply, _ = s.recvfrom(65535)
                except (_sock.timeout, OSError) as e:
                    self.send_error(502, f"DNS upstream error: {e}")
                    return
                finally:
                    s.close()
                self._respond(
                    200, "application/dns-message", reply,
                )

            def do_POST(self) -> None:  # noqa: N802
                # DoH POST: body is the wire-format DNS message.
                path, _, _ = self.path.partition("?")
                if path == self._DOH_PATH:
                    ct = self.headers.get("Content-Type", "")
                    if ct.split(";")[0].strip() != "application/dns-message":
                        self.send_error(415, "Unsupported Media Type")
                        return
                    length = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(length) if length else b""
                    if not body:
                        self.send_error(400, "Empty DoH body")
                        return
                    self._serve_doh(body)
                    return
                self.send_error(405, "Method Not Allowed")

            def do_GET(self) -> None:  # noqa: N802
                # DoH GET: ?dns=<base64url-encoded-message>
                path, _, query = self.path.partition("?")
                if path == self._DOH_PATH:
                    params = urllib_parse.parse_qs(query)
                    dns_b64 = (params.get("dns") or [""])[0]
                    if not dns_b64:
                        self.send_error(400, "Missing ?dns parameter")
                        return
                    import base64
                    # base64url decode; padding is optional per RFC 8484
                    pad = "=" * (-len(dns_b64) % 4)
                    try:
                        body = base64.urlsafe_b64decode(dns_b64 + pad)
                    except (ValueError, Exception):
                        self.send_error(400, "Invalid ?dns encoding")
                        return
                    self._serve_doh(body)
                    return

                # If Host: matches any host the issuer is reachable at
                # (its domain, or any serviceEndpoint URL host), route
                # the request as if its path had the issuer's domain
                # prepended (the canonical internal form). This lets
                # the anchor advertise public-looking URLs like
                # https://demo.example.com/things/<id> while still
                # serving them on its own bind+port.
                host = self.headers.get("Host", "")
                lookup_path = self.path
                host_iss = anchor._host_to_issuer.get(host)
                if host_iss is None and ":" in host:
                    host_iss = anchor._host_to_issuer.get(host.split(":", 1)[0])
                if host_iss is not None:
                    # Translate /.well-known/uuid-document.json → canonical
                    if self.path == "/.well-known/uuid-document.json":
                        lookup_path = anchor._doc_path(host_iss.domain)
                    else:
                        lookup_path = anchor._referent_path(
                            host_iss.domain, self.path
                        )

                # UUID-document path?
                body = anchor._documents.get(lookup_path)
                if body is not None:
                    self._respond(200, "application/json", body)
                    return
                # Referent path?
                route, identifier = anchor._match_referent(lookup_path)
                if route is not None:
                    if route.alias_to:
                        target = anchor._expand_alias(
                            route.alias_to, route, identifier,
                        )
                        self.send_response(302)
                        self.send_header("Location", target)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    stub = {
                        "domain": route.domain,
                        "type_id": route.type_id,
                        "type_name": route.type_name,
                        "identifier": identifier,
                    }
                    self._respond(
                        200, "application/json",
                        json.dumps(stub, indent=2).encode("utf-8"),
                    )
                    return
                # Default-template fallback: a request to /<type>/
                # <identifier> on a known issuer's host gets a generic
                # stub. This is the URL the resolver derives via the
                # spec's default template, so it must dereference even
                # when the issuer publishes no UUID document (zero-
                # config) or no entry for this specific type.
                if host_iss is not None:
                    m = re.match(r"^/(\d+)/([^/]+)$", self.path)
                    if m:
                        type_id, identifier = m.group(1), m.group(2)
                        type_name = ""
                        for entry in (host_iss.service or []):
                            if entry.get("id") == f"#{type_id}":
                                type_name = entry.get("type", "")
                                break
                        stub = {
                            "domain": host_iss.domain,
                            "type_id": type_id,
                            "type_name": type_name,
                            "identifier": identifier,
                            "via": "default-template",
                        }
                        self._respond(
                            200, "application/json",
                            json.dumps(stub, indent=2).encode("utf-8"),
                        )
                        return
                self.send_error(404, "Not Found")

            def _respond(self, status: int, content_type: str, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            # log_message inherited from BaseHTTPRequestHandler: emits
            # one line per request to stderr in apache-combined-style
            # format. Pairs with _AccessLogger for the DNS side.

        return _Handler


def _canon(name: str) -> str:
    return name.lower().rstrip(".")


# --- DNS resolver glue ---------------------------------------------------
class _ZoneResolver(BaseResolver):
    def __init__(self, records: dict[tuple[str, str], list[RD]]) -> None:
        self._records = records
        self._known_names = {name for (name, _) in records.keys()}

    def resolve(self, request, handler):  # noqa: D401
        reply = request.reply()
        qname = request.q.qname
        canon = _canon(str(qname))
        qtype_int = request.q.qtype
        qtype_str = QTYPE[qtype_int]

        # QTYPE=ANY: return every record we hold for this name. The
        # RUUID I-D recommends ANY as the single query for resolving
        # _uuid.<domain>, since a publisher may use URI, TXT, or both.
        if qtype_str == "ANY":
            for (name, t), rdatas in self._records.items():
                if name != canon:
                    continue
                rr_type = 256 if t == "URI" else dnslib.QTYPE.reverse[t]
                for rdata in rdatas:
                    reply.add_answer(RR(qname, rr_type, ttl=60, rdata=rdata))
            if not reply.rr and canon not in self._known_names:
                reply.header.rcode = RCODE.NXDOMAIN
            return reply

        matches = self._records.get((canon, qtype_str), [])
        if matches:
            for rdata in matches:
                rr_type = (256 if qtype_str == "URI"
                           else dnslib.QTYPE.forward.get(qtype_str, qtype_int))
                reply.add_answer(RR(qname, rr_type, ttl=60, rdata=rdata))
        elif canon not in self._known_names:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply


# --- Module entry point --------------------------------------------------
def run(
    zone_path: Path,
    *,
    bind: str = "127.0.0.1",
    dns_port: int = 53,
    http_port: int = 80,
    https_port: int = 443,
    rrtype: str = "both",
) -> int:
    """Load a zone file and run the daemon until interrupted.

    `bind` may be an IP literal or a hostname; hostnames are resolved
    via the system resolver. Raises ValueError on an unresolvable
    hostname, FileNotFoundError on a missing zone, and json/key/value
    errors on a malformed zone file.
    """
    bind = to_ip(bind)
    issuers = _load_zone(zone_path)
    Anchor(
        issuers,
        bind=bind,
        dns_port=dns_port,
        http_port=http_port,
        https_port=https_port,
        rrtype=rrtype,
    ).serve_forever()
    return 0
