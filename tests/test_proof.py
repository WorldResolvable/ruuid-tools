"""Tests for UUID-document proofs (ruuid.proof) and the resolve policy:

- vanilla `resolve` accepts an unsigned document, and a valid-proof document;
- but refuses when a document has an INVALID proof and resolution would use a
  document-supplied (non-default) referent template;
- `resolve --verify` requires a validly-signed document.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest

import ruuid.resolve as R
from ruuid.proof import sign_document, verify_document_proof
from ruuid.resolve import ResolveError

RU = "5300cafe-beef-8000-8002-000c0a800200"     # a resolvable RUUID (type 0)


def _make_key(tmp: Path, name: str = "k"):
    key = tmp / f"{name}.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "EC",
         "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)],
        check=True, capture_output=True,
    )
    der = subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
        capture_output=True,
    ).stdout
    pt = der[-65:]                                # 0x04 || X || Y
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(pt[1:33]), "y": b64u(pt[33:65])}
    return key, jwk


def _doc(jwk, *, service: bool):
    did = f"did:uuid:{RU}"
    d = {"@context": ["https://www.w3.org/ns/cid/v1"], "id": did,
         "verificationMethod": [{"id": f"{did}#genesis-key", "type": "JsonWebKey",
                                 "controller": did, "publicKeyJwk": jwk}]}
    if service:                                   # a document-supplied template
        d["service"] = [{"id": "#0", "type": "RUUIDReferent",
                         "serviceEndpoint": "https://ex.example/<identifier>"}]
    return d


# --- proof primitive ------------------------------------------------------

def test_sign_and_verify_roundtrip(tmp_path):
    key, jwk = _make_key(tmp_path)
    signed = sign_document(_doc(jwk, service=True), key, created="2026-07-09T00:00:00Z")
    assert signed["proof"]["type"] == "DataIntegrityProof"
    assert verify_document_proof(signed) is True


def test_tampered_content_fails(tmp_path):
    key, jwk = _make_key(tmp_path)
    signed = sign_document(_doc(jwk, service=True), key, created="2026-07-09T00:00:00Z")
    signed["service"][0]["serviceEndpoint"] = "https://evil.example/<identifier>"
    assert verify_document_proof(signed) is False


def test_unsigned_document_is_none(tmp_path):
    _, jwk = _make_key(tmp_path)
    assert verify_document_proof(_doc(jwk, service=True)) is None


def test_wrong_key_fails(tmp_path):
    key, _ = _make_key(tmp_path, "a")
    _, other_jwk = _make_key(tmp_path, "b")
    # sign with `key` but commit a DIFFERENT key -> proof can't verify
    signed = sign_document(_doc(other_jwk, service=False), key,
                           created="2026-07-09T00:00:00Z")
    assert verify_document_proof(signed) is False


# --- resolve policy -------------------------------------------------------

def _patch(monkeypatch, document):
    class FakeReg:
        def resolve(self, ru, trace=None):
            return {"domain": "example.com",
                    "uuid_document_uri":
                        "https://example.com/.well-known/uuid-document.json"}

    monkeypatch.setattr(R, "_build_resolver", lambda reg: FakeReg())
    monkeypatch.setattr(
        R, "fetch_url_body",
        lambda uri, **kw: (json.dumps(document).encode()
                           if "uuid-document" in uri else b"referent"),
    )


def test_resolve_refuses_invalid_proof_with_nondefault_template(tmp_path, monkeypatch):
    key, jwk = _make_key(tmp_path)
    doc = sign_document(_doc(jwk, service=True), key, created="2026-07-09T00:00:00Z")
    doc["service"][0]["serviceEndpoint"] = "https://evil.example/<identifier>"  # tamper
    _patch(monkeypatch, doc)
    with pytest.raises(ResolveError, match="proof is invalid"):
        R.resolve_ruuid(RU, follow="referent_uri")


def test_resolve_allows_invalid_proof_when_default_template(tmp_path, monkeypatch):
    key, jwk = _make_key(tmp_path)
    doc = sign_document(_doc(jwk, service=False), key, created="2026-07-09T00:00:00Z")
    doc["id"] = "did:uuid:tampered"              # tamper -> proof invalid
    _patch(monkeypatch, doc)
    out = R.resolve_ruuid(RU, follow="referent_uri")   # no document template used
    assert out["referent_uri"].startswith("https://example.com/")


def test_resolve_allows_unsigned_document_with_nondefault_template(tmp_path, monkeypatch):
    _, jwk = _make_key(tmp_path)
    _patch(monkeypatch, _doc(jwk, service=True))   # no proof at all
    out = R.resolve_ruuid(RU, follow="referent_uri")
    assert out["referent_uri"] == "https://ex.example/5300cafebeef"


def test_resolve_allows_valid_proof_with_nondefault_template(tmp_path, monkeypatch):
    key, jwk = _make_key(tmp_path)
    doc = sign_document(_doc(jwk, service=True), key, created="2026-07-09T00:00:00Z")
    _patch(monkeypatch, doc)
    out = R.resolve_ruuid(RU, follow="referent_uri")
    assert out["referent_uri"] == "https://ex.example/5300cafebeef"
