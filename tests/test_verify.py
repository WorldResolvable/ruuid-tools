"""Tests for `ruuid verify` / `ruuid custody` (CT genesis verification).

Offline: the CT source is a fake keyed by IP and SPKI, so the genesis
lookup and verification logic run without touching crt.sh.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json

import pytest

from ruuid.core import RUUID
from ruuid.cli import main
from ruuid.verify import (
    CtCert,
    anchor_ip,
    gather_custody,
    spki_sha256_from_jwk,
    verify,
    verify_ruuid,
)


# The real uuid.zone production RUUID + its genesis key (P-256).
RU_STR = "002299ac-52e1-8200-8002-64390cfe0000"
IP = "100.57.12.254"
JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "qM6pdisyyMUQnUsm_wwcvKPcLXBQ-MOIHJHa0Pe6OmI",
    "y": "XoevPX2HU8sYj-QOCFE6udZ1GHunw2tzMn0J17x4ocE",
}
SPKI = "96D1B94232374BF4F6F85FE1D0846925347D75B1D52D19FA91AF7525293CF7E7"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


IMPOSTOR_JWK = {"kty": "EC", "crv": "P-256",
                "x": _b64u(b"\x11" * 32), "y": _b64u(b"\x22" * 32)}
IMPOSTOR_SPKI = spki_sha256_from_jwk(IMPOSTOR_JWK)


def _document(jwk=JWK, ruuid=RU_STR):
    did = f"did:uuid:{ruuid}"
    return {
        "@context": ["https://www.w3.org/ns/cid/v1"],
        "id": did,
        "verificationMethod": [
            {"id": f"{did}#genesis-key", "type": "JsonWebKey",
             "controller": did, "publicKeyJwk": jwk}
        ],
    }


def _cert(ip_sans=(), dns_sans=(), *, nb, na, serial="s", cid=1, spki=SPKI):
    return CtCert(
        crtsh_id=cid, serial=serial, spki_sha256=spki,
        not_before=_dt.datetime.fromisoformat(nb),
        not_after=_dt.datetime.fromisoformat(na),
        ip_sans=tuple(ip_sans), dns_sans=tuple(dns_sans),
    )


class FakeCt:
    """Fake CT source keyed by both IP-SAN and SPKI (filters one cert list)."""

    def __init__(self, certs):
        self._certs = list(certs)

    def certs_for_ip(self, ip):
        return [c for c in self._certs if ip in c.ip_sans]

    def certs_for_spki(self, spki):
        return [c for c in self._certs if c.spki_sha256 == spki]


# day_count 553 == 2026-07-08; a 7-day IP cert covering it, under our key:
GENESIS_CERT = _cert(
    ip_sans=(IP,), nb="2026-07-07T23:15:18+00:00",
    na="2026-07-14T23:15:17+00:00", serial="genesis", cid=101, spki=SPKI,
)


# --- spki ----------------------------------------------------------------

def test_spki_from_jwk_matches_openssl_value():
    assert spki_sha256_from_jwk(JWK) == SPKI


def test_anchor_ip_and_daycount():
    ru = RUUID.from_str(RU_STR)
    assert anchor_ip(ru) == IP
    assert ru.identifier >> 28 == 553


# --- verify with a document ----------------------------------------------

def test_verify_success_document_commits_genesis_key():
    ru = RUUID.from_str(RU_STR)
    result, custody = verify_ruuid(ru, _document(), ct_source=FakeCt([GENESIS_CERT]))
    assert result.verified
    assert result.genuine_keys == (SPKI,)       # recovered from CT by IP
    assert result.document_key == SPKI
    assert result.genesis.serial == "genesis"


def test_verify_rejects_impostor_document_and_names_genuine_key():
    # Impostor serves a document with their key; genesis (from CT by IP) is ours.
    ru = RUUID.from_str(RU_STR)
    result, _ = verify_ruuid(
        ru, _document(jwk=IMPOSTOR_JWK), ct_source=FakeCt([GENESIS_CERT])
    )
    assert not result.verified
    assert result.document_key == IMPOSTOR_SPKI
    assert result.genuine_keys == (SPKI,)       # points to the real key
    assert SPKI in result.reason


def test_verify_no_genesis_in_ct():
    ru = RUUID.from_str(RU_STR)
    late = _cert(ip_sans=(IP,), nb="2026-08-01T00:00:00+00:00",
                 na="2026-08-08T00:00:00+00:00", serial="late")
    result, _ = verify_ruuid(ru, _document(), ct_source=FakeCt([late]))
    assert not result.verified
    assert "no genesis" in result.reason


# --- verify WITHOUT a document (recover the key from CT) ------------------

def test_verify_no_document_reports_genuine_key():
    ru = RUUID.from_str(RU_STR)
    result, _ = verify_ruuid(ru, None, ct_source=FakeCt([GENESIS_CERT]))
    assert result.verified
    assert result.genuine_keys == (SPKI,)
    assert result.document_key is None
    assert SPKI in result.reason


# --- the EIP-move / commandeering scenario -------------------------------

def test_old_ruuid_after_move_and_commandeering():
    # Our genesis IP cert (covers Jul 8). We move to a new IP (same key), and
    # a commandeering party later acquires IP_old and gets a real IP cert dated
    # to their tenure under THEIR key. Recovery must still resolve to our key.
    ru = RUUID.from_str(RU_STR)
    moved = _cert(ip_sans=("203.0.113.9",), nb="2026-09-01T00:00:00+00:00",
                  na="2026-09-08T00:00:00+00:00", serial="new-eip", cid=102,
                  spki=SPKI)
    commandeer = _cert(ip_sans=(IP,), nb="2026-09-01T00:00:00+00:00",
                       na="2026-09-08T00:00:00+00:00", serial="commandeer",
                       cid=103, spki=IMPOSTOR_SPKI)
    ct = FakeCt([GENESIS_CERT, moved, commandeer])

    # No document: from IP + day alone we recover OUR key (the commandeering
    # cert covers Sept, not Jul 8, so it doesn't qualify).
    result, _ = verify_ruuid(ru, None, ct_source=ct)
    assert result.verified
    assert result.genuine_keys == (SPKI,)

    # Impostor's document is rejected; ours verifies.
    assert not verify_ruuid(ru, _document(jwk=IMPOSTOR_JWK), ct_source=ct)[0].verified
    ok, _ = verify_ruuid(ru, _document(), ct_source=ct)
    assert ok.verified
    # The forward move shows in the timeline (following our key's SPKI).
    assert {a.serial for a in ok.timeline} >= {"genesis", "new-eip"}


# --- custody bundle ------------------------------------------------------

def test_gather_custody_shape_ip_based():
    ru = RUUID.from_str(RU_STR)
    domain = _cert(dns_sans=("uuid.zone",), nb="2026-07-07T00:00:00+00:00",
                   na="2026-10-05T00:00:00+00:00", serial="dom", cid=104,
                   spki=SPKI)
    custody = gather_custody(ru, FakeCt([GENESIS_CERT, domain]))
    assert custody["ruuid"] == RU_STR
    assert custody["anchorIp"] == IP
    assert custody["dayCount"] == 553
    certs = custody["chain"][0]["certificates"]
    serials = {c["serial"] for c in certs}
    assert "genesis" in serials and "dom" in serials   # genesis + forward timeline
    assert all("spkiSha256" in c for c in certs)


def test_verify_roundtrips_through_json_custody():
    ru = RUUID.from_str(RU_STR)
    custody = gather_custody(ru, FakeCt([GENESIS_CERT]))
    reloaded = json.loads(json.dumps(custody))
    result = verify(ru, _document(), reloaded)
    assert result.verified


def test_document_without_key_raises():
    ru = RUUID.from_str(RU_STR)
    custody = gather_custody(ru, FakeCt([GENESIS_CERT]))
    with pytest.raises(ValueError, match="verificationMethod"):
        verify(ru, {"id": "did:uuid:x"}, custody)


# --- CLI -----------------------------------------------------------------

def test_cli_verify_with_prebuilt_custody(tmp_path, capsys):
    ru = RUUID.from_str(RU_STR)
    doc_path = tmp_path / "doc.json"
    doc_path.write_text(json.dumps(_document()))
    custody = gather_custody(ru, FakeCt([GENESIS_CERT]))
    cust_path = tmp_path / "custody.json"
    cust_path.write_text(json.dumps(custody))

    rc = main(["verify", RU_STR, str(doc_path), "--custody", str(cust_path)])
    assert rc == 0
    assert "VERIFIED" in capsys.readouterr().out

    # impostor document -> non-zero, names the genuine key
    doc_path.write_text(json.dumps(_document(jwk=IMPOSTOR_JWK)))
    rc = main(["verify", RU_STR, str(doc_path), "--custody", str(cust_path)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "NOT VERIFIED" in out and SPKI in out


def test_cli_verify_no_document(tmp_path, capsys):
    ru = RUUID.from_str(RU_STR)
    custody = gather_custody(ru, FakeCt([GENESIS_CERT]))
    cust_path = tmp_path / "custody.json"
    cust_path.write_text(json.dumps(custody))
    rc = main(["verify", RU_STR, "--custody", str(cust_path)])
    assert rc == 0
    assert SPKI in capsys.readouterr().out
