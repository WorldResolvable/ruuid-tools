"""DIF Universal Resolver driver for the `did:uuid` method.

This is a thin HTTP service that adapts RUUID's `did:uuid` resolution
to the [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver)
driver contract: a container that answers

    GET /1.0/identifiers/<did>

with either a DID document or a DID Resolution Result. The Universal
Resolver's `uni-resolver-web` front end routes every `did:uuid:...`
request to this driver (matched on the `^(did:uuid:.+)$` pattern) and
wraps whatever the driver returns into the client-facing response.

The driver carries no issuer infrastructure of its own — no `ruuid
anchor`, no zone files. It resolves against whatever DNS the container
is configured to use (the system resolver by default, or a `dns://` /
`doh://` endpoint via `--registry` / `RUUID_DRIVER_REGISTRY`). The
anchor in this package is a development/demo tool for *publishing* RUUID
records; a deployed driver only *consumes* them, over real DNS.

Resolution itself is entirely `ruuid.resolve.resolve_ruuid(...,
follow="ruuid_document")`: PTR → `_uuid.<domain>` → fetch the UUID
document → synthesise the per-RUUID DID document. `resolve_did_uuid`
adds only the method-level validation (version 8, variant RFC 4122)
and the mapping from RUUID resolution outcomes to DID-resolution
errors and HTTP status codes.

Run it directly:

    python -m ruuid.driver --port 8080
    ruuid-did-uuid-driver --registry doh://dns.example/dns-query
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ruuid.core import RUUID, VERSION, VARIANT_RFC4122
from ruuid.resolve import ResolveError, resolve_ruuid


# Content types from the W3C DID Resolution spec / Universal Resolver.
DID_LD_JSON = "application/did+ld+json"
RESOLUTION_RESULT_CT = (
    'application/ld+json;profile="https://w3id.org/did-resolution"'
)
DID_RESOLUTION_CONTEXT = "https://w3id.org/did-resolution/v1"

# Default port the Universal Resolver expects a driver to listen on
# inside its container.
DEFAULT_PORT = 8080

# Default registry endpoint for the driver. "dns://" (empty netloc)
# means "the system resolver", with no wasted probe of the loopback
# anchor that `resolve_ruuid`'s own None-default would make first.
# Override with --registry / RUUID_DRIVER_REGISTRY to target a specific
# DNS or DoH server.
DEFAULT_REGISTRY = "dns://"


@dataclass(frozen=True)
class DidResolution:
    """The outcome of resolving one DID, independent of HTTP encoding.

    `did_document` is the synthesised per-RUUID DID document on success,
    or None on any error. `resolution_metadata` carries `contentType`
    on success or `error` (+ `errorMessage`) on failure, mirroring the
    `didResolutionMetadata` of a DID Resolution Result. `http_status`
    is the status the driver returns for this outcome.
    """

    http_status: int
    did_document: dict | None
    resolution_metadata: dict
    document_metadata: dict = field(default_factory=dict)

    def resolution_result(self) -> dict:
        """Wrap this outcome as a W3C DID Resolution Result object."""
        return {
            "@context": DID_RESOLUTION_CONTEXT,
            "didDocument": self.did_document,
            "didResolutionMetadata": self.resolution_metadata,
            "didDocumentMetadata": self.document_metadata,
        }


def _ok(document: dict) -> DidResolution:
    return DidResolution(200, document, {"contentType": DID_LD_JSON})


def _error(http_status: int, error: str, message: str) -> DidResolution:
    return DidResolution(
        http_status,
        None,
        {"error": error, "errorMessage": message},
    )


def resolve_did_uuid(did: str, *, registry: str | None = None) -> DidResolution:
    """Resolve a `did:uuid:` DID to a `DidResolution`.

    Validates that `did` is a `did:uuid` DID whose method-specific id is
    a canonical RUUID of version 8 and variant RFC 4122, then runs the
    two-phase RUUID pipeline and synthesises the per-RUUID DID document.

    Outcome → error / status mapping (the `error` value is the
    DID-resolution error registered for that case):

      - not a DID / malformed UUID / wrong version / wrong variant
                                              → 400 invalidDid
      - DID method other than `uuid`         → 501 methodNotSupported
      - no PTR / registry lookup failed      → 404 notFound
      - any other resolution failure         → 500 internalError

    `registry` is forwarded to `resolve_ruuid` (None inherits its
    default; pass a `dns://`/`doh://` URL to target a specific server).
    Never raises — every failure is returned as a `DidResolution`.
    """
    if not isinstance(did, str) or not did.startswith("did:"):
        return _error(400, "invalidDid", f"not a DID: {did!r}")

    method, _, msid = did.removeprefix("did:").partition(":")
    if method != "uuid":
        return _error(
            501, "methodNotSupported",
            f"this driver resolves did:uuid, not did:{method}",
        )
    if not msid:
        return _error(400, "invalidDid", "missing method-specific identifier")

    # A DID URL may carry a path, query, or fragment after the DID; the
    # method-specific id of did:uuid is just the bare RUUID, so trim
    # anything past it before parsing.
    msid = msid.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]

    try:
        ru = RUUID.from_str(msid)
    except (ValueError, TypeError) as e:
        return _error(400, "invalidDid", f"malformed UUID {msid!r}: {e}")
    if ru.version != VERSION:
        return _error(
            400, "invalidDid",
            f"version {ru.version}, expected {VERSION}",
        )
    if ru.variant != VARIANT_RFC4122:
        return _error(
            400, "invalidDid",
            f"variant 0b{ru.variant:02b}, expected RFC 4122 (0b10)",
        )

    try:
        result = resolve_ruuid(ru, follow="ruuid_document", registry=registry)
    except ResolveError as e:
        return _error(404, "notFound", str(e) or "resolution failed")
    except ValueError as e:
        # Malformed registry URL or UUID surfaced late.
        return _error(400, "invalidDid", str(e))
    except Exception as e:  # noqa: BLE001 — transport/IO failures become 500s
        return _error(500, "internalError", str(e) or type(e).__name__)

    document = result.get("ruuid_document")
    if document is None:
        return _error(
            404, "notFound",
            "no Phase 2 referent URI available for this RUUID",
        )
    return _ok(document)


# --- HTTP layer -----------------------------------------------------------

def _wants_resolution_result(accept: str) -> bool:
    """True if the `Accept` header asks for a DID Resolution Result.

    The trigger is the resolution profile in the media-type parameters
    (`profile="https://w3id.org/did-resolution"`). A plain
    `application/ld+json` or `application/did+ld+json` (what
    `uni-resolver-web` sends) gets the bare DID document.
    """
    return "https://w3id.org/did-resolution" in accept


def _make_handler(registry: str):
    """Build a `BaseHTTPRequestHandler` subclass bound to `registry`."""

    class _DriverHandler(BaseHTTPRequestHandler):
        server_version = "ruuid-did-uuid-driver"
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            path = urllib.parse.urlparse(self.path).path
            if path in ("/", "/health"):
                self._text(200, "ruuid did:uuid Universal Resolver driver\n")
                return
            if path == "/1.0/methods":
                self._json(200, ["did:uuid"])
                return
            if path == "/1.0/properties":
                self._json(200, {})
                return
            prefix = "/1.0/identifiers/"
            if path.startswith(prefix):
                # The DID sits in a single path segment; it may arrive
                # with its colons percent-encoded (did%3Auuid%3A...) or
                # literally. unquote handles both.
                did = urllib.parse.unquote(path[len(prefix):])
                self._resolve(did)
                return
            self.send_error(404, "Not Found")

        def _resolve(self, did: str) -> None:
            res = resolve_did_uuid(did, registry=registry)
            accept = self.headers.get("Accept", "")
            if res.did_document is not None and not _wants_resolution_result(accept):
                body = _encode(res.did_document)
                self._respond(res.http_status, DID_LD_JSON, body)
            else:
                # Errors (no document) and explicit resolution-result
                # requests both get the full DID Resolution Result.
                body = _encode(res.resolution_result())
                self._respond(res.http_status, RESOLUTION_RESULT_CT, body)

        def _respond(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj) -> None:
            self._respond(status, "application/json", _encode(obj))

        def _text(self, status: int, text: str) -> None:
            self._respond(status, "text/plain; charset=utf-8", text.encode("utf-8"))

    return _DriverHandler


def _encode(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


class _DriverServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    *,
    registry: str = DEFAULT_REGISTRY,
) -> ThreadingHTTPServer:
    """Build (but do not start) the driver HTTP server."""
    return _DriverServer((host, port), _make_handler(registry))


def run(
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    *,
    registry: str = DEFAULT_REGISTRY,
    banner=sys.stderr,
) -> int:
    """Serve the driver until interrupted. Returns a process exit code."""
    httpd = make_server(host, port, registry=registry)
    bound_host, bound_port = httpd.server_address[:2]
    if banner is not None:
        print(
            f"ruuid did:uuid driver on http://{bound_host}:{bound_port}"
            f"  (registry: {registry or 'system DNS'})",
            file=banner,
        )
        print(
            f"resolve endpoint: GET /1.0/identifiers/<did:uuid:...>; "
            f"Ctrl-C to stop",
            file=banner,
        )
        banner.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    default_registry = os.environ.get("RUUID_DRIVER_REGISTRY") or DEFAULT_REGISTRY
    p = argparse.ArgumentParser(
        prog="ruuid-did-uuid-driver",
        description=(
            "DIF Universal Resolver driver for did:uuid. Serves "
            "GET /1.0/identifiers/<did> over HTTP, resolving each "
            "did:uuid via the RUUID pipeline against the configured "
            "DNS registry."
        ),
    )
    p.add_argument(
        "--host",
        default=os.environ.get("RUUID_DRIVER_HOST", "0.0.0.0"),
        help="address to bind (default: 0.0.0.0; env RUUID_DRIVER_HOST)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("RUUID_DRIVER_PORT", str(DEFAULT_PORT))),
        help=f"TCP port to bind (default: {DEFAULT_PORT}; env RUUID_DRIVER_PORT)",
    )
    p.add_argument(
        "--registry",
        default=default_registry,
        metavar="URL",
        help=(
            "registry endpoint for the PTR + _uuid.<domain> lookups: "
            "'dns://' (system resolver, the default), 'dns://HOST[:PORT]', "
            "or 'doh://HOST[:PORT][/PATH]'. The UUID-document and referent "
            "HTTP fetches always use the system resolver. "
            "Env RUUID_DRIVER_REGISTRY."
        ),
    )
    args = p.parse_args(argv)
    try:
        return run(args.host, args.port, registry=args.registry)
    except OSError as e:
        print(f"ruuid-did-uuid-driver: cannot bind {args.host}:{args.port}: {e}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
