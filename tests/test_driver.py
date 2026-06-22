"""Tests for ruuid.driver — the DIF Universal Resolver did:uuid driver.

Two layers are covered:

  - `resolve_did_uuid`: method validation and the mapping from RUUID
    resolution outcomes to DID-resolution errors / HTTP status codes.
    The error paths need no network; one success path runs the real
    pipeline against the in-process `test_ns` fake DNS server.
  - The HTTP server: routing, content negotiation, and status codes.
    These monkeypatch `resolve_did_uuid` so the HTTP contract is tested
    in isolation from DNS.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from ruuid import RUUID
import ruuid.driver as driver
from ruuid.driver import (
    DID_LD_JSON,
    RESOLUTION_RESULT_CT,
    DidResolution,
    make_server,
    resolve_did_uuid,
)


# --- resolve_did_uuid: validation / error classification -----------------

@pytest.mark.parametrize("did,error", [
    ("not-a-did", "invalidDid"),
    ("urn:uuid:00000000-0000-8200-8002-c000022a0000", "invalidDid"),
    ("did:uuid:", "invalidDid"),
    ("did:uuid:not-a-uuid", "invalidDid"),
    # Valid UUID text, but wrong version (4) for did:uuid (needs 8).
    ("did:uuid:00000000-0000-4200-8002-c000022a0000", "invalidDid"),
    # Version 8 but wrong variant (0b11 / Microsoft) — needs RFC 4122.
    ("did:uuid:00000000-0000-8200-c002-c000022a0000", "invalidDid"),
])
def test_resolve_rejects_bad_did_as_invalid(did, error):
    res = resolve_did_uuid(did)
    assert res.http_status == 400
    assert res.did_document is None
    assert res.resolution_metadata["error"] == error


def test_resolve_rejects_other_method_as_method_not_supported():
    res = resolve_did_uuid("did:web:example.com")
    assert res.http_status == 501
    assert res.resolution_metadata["error"] == "methodNotSupported"


def test_resolve_maps_no_ptr_to_not_found(test_ns):
    """A version-8 RUUID whose prefix has no PTR record resolves to a
    notFound / 404 (the registry phase raises ResolveError)."""
    ru = RUUID.from_anchor("192.0.2.99", identifier=1, type_id=0)
    # test_ns has no records at all → NXDOMAIN on the PTR lookup.
    res = resolve_did_uuid(ru_did(ru), registry=f"dns://127.0.0.1:{test_ns.port}")
    assert res.http_status == 404
    assert res.resolution_metadata["error"] == "notFound"


def test_resolve_success_synthesises_did_document(test_ns):
    """A resolvable RUUID yields a 200 with the per-RUUID DID document.

    No UUID document is published (the doc fetch fails against the
    unresolvable .invalid host), so synthesis falls back to the
    spec-default referent template — the document is still well-formed.
    """
    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "issuer.invalid")
    res = resolve_did_uuid(ru_did(ru), registry=f"dns://127.0.0.1:{test_ns.port}")
    assert res.http_status == 200
    assert res.resolution_metadata == {"contentType": DID_LD_JSON}
    doc = res.did_document
    assert doc["id"] == f"did:uuid:{ru}"
    assert doc["@context"] == "https://www.w3.org/ns/did/v1"
    assert doc["service"][0]["serviceEndpoint"] == (
        "https://issuer.invalid/0/00000000002a"
    )


def test_resolution_result_wraps_outcome():
    """`DidResolution.resolution_result()` produces the DID Resolution
    Result envelope with all four members."""
    res = DidResolution(200, {"id": "did:uuid:x"}, {"contentType": DID_LD_JSON})
    rr = res.resolution_result()
    assert rr["@context"] == "https://w3id.org/did-resolution/v1"
    assert rr["didDocument"] == {"id": "did:uuid:x"}
    assert rr["didResolutionMetadata"] == {"contentType": DID_LD_JSON}
    assert rr["didDocumentMetadata"] == {}


# --- HTTP server ---------------------------------------------------------

_SAMPLE_DID = "did:uuid:00000000-0000-8200-8002-c000022a0000"
_SAMPLE_DOC = {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": _SAMPLE_DID,
    "service": [{"id": f"{_SAMPLE_DID}#0", "type": "Referent",
                 "serviceEndpoint": "https://example.com/0/00000000002a"}],
}


@contextmanager
def _running_driver():
    httpd = make_server("127.0.0.1", 0, registry="dns://")
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _get(port, path, *, accept=None):
    """GET path; return (status, content_type, body_bytes). Reads error
    bodies too (and closes them — -W error would flag a leaked HTTPError)."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    if accept is not None:
        req.add_header("Accept", accept)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.headers.get("Content-Type"), resp.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.headers.get("Content-Type"), e.read()
        finally:
            e.close()


def test_http_resolve_returns_did_document(monkeypatch):
    monkeypatch.setattr(
        driver, "resolve_did_uuid",
        lambda did, registry=None: driver._ok(_SAMPLE_DOC),
    )
    with _running_driver() as port:
        status, ct, body = _get(port, f"/1.0/identifiers/{_SAMPLE_DID}")
    assert status == 200
    assert ct == DID_LD_JSON
    assert json.loads(body) == _SAMPLE_DOC


def test_http_resolve_honours_resolution_result_accept(monkeypatch):
    monkeypatch.setattr(
        driver, "resolve_did_uuid",
        lambda did, registry=None: driver._ok(_SAMPLE_DOC),
    )
    with _running_driver() as port:
        status, ct, body = _get(
            port, f"/1.0/identifiers/{_SAMPLE_DID}",
            accept='application/ld+json;profile="https://w3id.org/did-resolution"',
        )
    assert status == 200
    assert ct == RESOLUTION_RESULT_CT
    result = json.loads(body)
    assert result["@context"] == "https://w3id.org/did-resolution/v1"
    assert result["didDocument"] == _SAMPLE_DOC
    assert result["didResolutionMetadata"] == {"contentType": DID_LD_JSON}


def test_http_resolve_percent_encoded_did_is_decoded(monkeypatch):
    seen = {}

    def fake(did, registry=None):
        seen["did"] = did
        return driver._ok(_SAMPLE_DOC)

    monkeypatch.setattr(driver, "resolve_did_uuid", fake)
    encoded = "did%3Auuid%3A00000000-0000-8200-8002-c000022a0000"
    with _running_driver() as port:
        status, _, _ = _get(port, f"/1.0/identifiers/{encoded}")
    assert status == 200
    assert seen["did"] == _SAMPLE_DID


def test_http_resolve_error_uses_status_and_resolution_result(monkeypatch):
    monkeypatch.setattr(
        driver, "resolve_did_uuid",
        lambda did, registry=None: driver._error(404, "notFound", "no PTR"),
    )
    with _running_driver() as port:
        status, ct, body = _get(port, f"/1.0/identifiers/{_SAMPLE_DID}")
    assert status == 404
    assert ct == RESOLUTION_RESULT_CT
    result = json.loads(body)
    assert result["didDocument"] is None
    assert result["didResolutionMetadata"]["error"] == "notFound"


def test_http_invalid_did_returns_400(monkeypatch):
    monkeypatch.setattr(
        driver, "resolve_did_uuid",
        lambda did, registry=None: driver._error(400, "invalidDid", "bad"),
    )
    with _running_driver() as port:
        status, _, body = _get(port, "/1.0/identifiers/did:uuid:nope")
    assert status == 400
    assert json.loads(body)["didResolutionMetadata"]["error"] == "invalidDid"


def test_http_methods_endpoint():
    with _running_driver() as port:
        status, ct, body = _get(port, "/1.0/methods")
    assert status == 200
    assert json.loads(body) == ["did:uuid"]


def test_http_health_endpoint():
    with _running_driver() as port:
        status, ct, body = _get(port, "/")
    assert status == 200
    assert ct.startswith("text/plain")
    assert b"did:uuid" in body


def test_http_unknown_path_returns_404():
    with _running_driver() as port:
        status, _, _ = _get(port, "/nope")
    assert status == 404


def ru_did(ru: RUUID) -> str:
    return f"did:uuid:{ru}"
