"""Custom urllib handler for `did:` URIs.

This module adds the `did` scheme to `urllib.request`. Importing it
installs the handler in urllib's default opener, so any subsequent
call to `urllib.request.urlopen("did:...")` is dispatched to the
handler. RUUID's `fetch_url_body` goes through `urlopen` under the
hood, so any RUUID whose URI record carries a supported `did:` URI
resolves transparently.

Supported methods:

  did:web   The DID URI maps deterministically to an HTTPS URL
            serving a DID document (per
            https://w3c-ccg.github.io/did-method-web/). RUUID's UUID
            documents are W3C Controlled Identifiers documents whose
            field set is a strict subset of DID-Core's, so a did:web
            URL points at one directly with no extension fields
            required.

              did:web:example.com               → https://example.com/.well-known/did.json
              did:web:example.com:user:alice    → https://example.com/user/alice/did.json
              did:web:example.com%3A8080        → https://example.com:8080/.well-known/did.json
                                                   (host portion percent-decoded)

  did:uuid  The method-specific id is a canonical RUUID textual form
            (must be variant 1 — RFC 4122 — and version 8). The
            handler verifies the version/variant, then runs the
            two-phase RUUID resolution pipeline against the RUUID to
            obtain a Phase 2 referent URI, and synthesises a per-RUUID
            DID document that carries the URI as an `alsoKnownAs`
            alias (see `ruuid.resolve.synthesise_ruuid_document`). The returned
            bytes are the synthesised document encoded as JSON.

              did:uuid:00000000-0000-8200-8002-c000022a0000
                                                → run PTR + URI/TXT
                                                  + HTTP-fetch for
                                                  that RUUID,
                                                  synthesise the
                                                  per-RUUID document,
                                                  return JSON bytes.

Other DID methods raise URLError on open. Adding more (did:key,
did:jwk, did:peer, ...) would just be more `did:X` branches in
`DidHandler.did_open`.
"""

from __future__ import annotations

import email
import io
import json
import urllib.error
import urllib.parse
import urllib.request
import urllib.response


class DidHandler(urllib.request.BaseHandler):
    """Dispatch `did:` opens by DID method.

    Registered against the `did` scheme via the method-naming
    convention urllib uses to look up handlers (`<scheme>_open`).
    """

    def did_open(self, req: urllib.request.Request):
        uri = req.full_url
        method, _, msid = uri.removeprefix("did:").partition(":")
        if method == "web":
            return self._open_did_web(req, msid)
        if method == "uuid":
            return self._open_did_uuid(req, msid)
        raise urllib.error.URLError(
            f"unsupported DID method {method!r} in {uri!r}"
        )

    def _open_did_web(self, req: urllib.request.Request, msid: str):
        https_url = _did_web_msid_to_https(msid)
        new_req = urllib.request.Request(https_url, headers=dict(req.headers))
        return self.parent.open(new_req, timeout=req.timeout)

    def _open_did_uuid(self, req: urllib.request.Request, msid: str):
        # Lazy imports: `ruuid.resolve` imports this module at load
        # time to install the handler, so taking `resolve_ruuid` at
        # module scope would create an import cycle. The cycle is
        # broken because by the time anyone open()s a did:uuid URI,
        # `ruuid.resolve` is fully loaded.
        from ruuid.core import RUUID, VERSION, VARIANT_RFC4122
        from ruuid.resolve import resolve_ruuid

        try:
            ru = RUUID.from_str(msid)
        except (ValueError, TypeError) as e:
            raise urllib.error.URLError(
                f"did:uuid: malformed UUID {msid!r}: {e}"
            )
        if ru.version != VERSION:
            raise urllib.error.URLError(
                f"did:uuid: {msid} has version {ru.version}, "
                f"expected {VERSION}"
            )
        if ru.variant != VARIANT_RFC4122:
            raise urllib.error.URLError(
                f"did:uuid: {msid} has variant {ru.variant}, "
                f"expected RFC 4122 (0b10)"
            )

        try:
            result = resolve_ruuid(ru, follow="ruuid_document")
        except Exception as e:
            raise urllib.error.URLError(
                f"did:uuid: resolve failed for {ru}: {e}"
            )

        doc = result.get("ruuid_document")
        if doc is None:
            raise urllib.error.URLError(
                f"did:uuid: could not synthesise DID document for "
                f"{ru} (no Phase 2 referent URI available)"
            )

        body = json.dumps(doc, separators=(",", ":")).encode("utf-8")
        headers = email.message_from_string("Content-Type: application/json\n")
        return urllib.response.addinfourl(
            io.BytesIO(body), headers, req.full_url, code=200,
        )


def _did_web_msid_to_https(msid: str) -> str:
    """Translate a `did:web` method-specific id to its HTTPS URL.

    Per the did:web spec: split on `:`, percent-decode the host (the
    first segment), join the rest as the URL path with `/`. If no
    path was supplied, the document lives at /.well-known/.
    """
    parts = msid.split(":")
    host = urllib.parse.unquote(parts[0])
    rest = parts[1:]
    if not rest:
        return f"https://{host}/.well-known/did.json"
    return f"https://{host}/{'/'.join(rest)}/did.json"


def install() -> None:
    """Install `DidHandler` in urllib's default opener (idempotent).

    Calling this more than once is harmless; the second call notices
    the handler already on the opener and returns without rebuilding.
    """
    existing = urllib.request._opener
    if existing is not None and any(
        isinstance(h, DidHandler) for h in existing.handlers
    ):
        return
    urllib.request.install_opener(
        urllib.request.build_opener(DidHandler())
    )


install()
