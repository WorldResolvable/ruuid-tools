"""Tests for `ruuid verify` / `ruuid custody` (CT genesis verification).

Offline: the CT source is a fake returning canned certificates, so the
verification logic runs without touching crt.sh.
"""

from __future__ import annotations

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


def _document(jwk=JWK, ruuid=RU_STR):
    did = f"did:uuid:{ruuid}"
    return {
        "@context": ["https://www.w3.org/ns/cid/v1"],
        "id": did,
        "verificationMethod": [
            {"id": f"{did}#genesis-key", "type": "JsonWebKey",
             "controller": did, "publicKeyJwk": jwk}
        ],
        "authentication": [f"{did}#genesis-key"],
        "assertionMethod": [f"{did}#genesis-key"],
    }


def _cert(ip_sans=(), dns_sans=(), *, nb, na, serial="s", cid=1):
    return CtCert(
        crtsh_id=cid, serial=serial,
        not_before=_dt.datetime.fromisoformat(nb),
        not_after=_dt.datetime.fromisoformat(na),
        ip_sans=tuple(ip_sans), dns_sans=tuple(dns_sans),
    )


class FakeCt:
    def __init__(self, certs):
        self._certs = certs
        self.queried = None

    def certs_for_spki(self, spki):
        self.queried = spki
        return list(self._certs)


# day_count 553 == 2026-07-08; a 7-day IP cert covering it:
GENESIS_CERT = _cert(
    ip_sans=(IP,), nb="2026-07-07T23:15:18+00:00",
    na="2026-07-14T23:15:17+00:00", serial="genesis", cid=101,
)


# --- spki ----------------------------------------------------------------

def test_spki_from_jwk_matches_openssl_value():
    assert spki_sha256_from_jwk(JWK) == SPKI


def test_anchor_ip_and_daycount():
    ru = RUUID.from_str(RU_STR)
    assert anchor_ip(ru) == IP
    assert ru.identifier >> 28 == 553  # day_count for 2026-07-08


# --- verify --------------------------------------------------------------

def test_verify_success():
    ru = RUUID.from_str(RU_STR)
    result, custody = verify_ruuid(ru, _document(), ct_source=FakeCt([GENESIS_CERT]))
    assert result.verified
    assert result.genesis is not None
    assert result.genesis.serial == "genesis"
    assert result.spki_sha256 == SPKI
    assert custody["chain"][0]["spkiSha256"] == SPKI


def test_verify_fails_when_window_misses_the_day():
    ru = RUUID.from_str(RU_STR)
    late = _cert(ip_sans=(IP,), nb="2026-08-01T00:00:00+00:00",
                 na="2026-08-08T00:00:00+00:00", serial="late")
    result, _ = verify_ruuid(ru, _document(), ct_source=FakeCt([late]))
    assert not result.verified
    assert "covering" in result.reason
    # the cert still shows in the timeline, just not flagged genesis
    assert result.timeline and not result.timeline[0].is_genesis


def test_verify_fails_on_wrong_ip():
    ru = RUUID.from_str(RU_STR)
    other = _cert(ip_sans=("198.51.100.7",), nb="2026-07-07T00:00:00+00:00",
                  na="2026-07-14T00:00:00+00:00", serial="other")
    result, _ = verify_ruuid(ru, _document(), ct_source=FakeCt([other]))
    assert not result.verified


def test_verify_fails_when_custody_is_for_a_different_key():
    ru = RUUID.from_str(RU_STR)
    custody = gather_custody(ru, _document(), FakeCt([GENESIS_CERT]))
    custody["chain"][0]["spkiSha256"] = "DEADBEEF" * 8   # tamper
    result = verify(ru, _document(), custody)
    assert not result.verified
    assert "different key" in result.reason


def test_verify_through_ip_and_domain_changes_single_key():
    # Same key, later re-anchored to a new IP and a domain — still verified,
    # timeline shows all three, only the genesis cert is flagged.
    ru = RUUID.from_str(RU_STR)
    later_ip = _cert(ip_sans=("203.0.113.9",), nb="2026-08-01T00:00:00+00:00",
                     na="2026-08-08T00:00:00+00:00", serial="moved", cid=102)
    domain = _cert(dns_sans=("uuid.zone",), nb="2026-07-07T00:00:00+00:00",
                   na="2026-10-05T00:00:00+00:00", serial="dom", cid=103)
    result, _ = verify_ruuid(
        ru, _document(), ct_source=FakeCt([GENESIS_CERT, later_ip, domain])
    )
    assert result.verified
    assert len(result.timeline) == 3
    assert sum(a.is_genesis for a in result.timeline) == 1
    assert result.genesis.serial == "genesis"


def test_verify_roundtrips_through_json_custody():
    ru = RUUID.from_str(RU_STR)
    custody = gather_custody(ru, _document(), FakeCt([GENESIS_CERT]))
    reloaded = json.loads(json.dumps(custody))       # serialize/deserialize
    result = verify(ru, _document(), reloaded)
    assert result.verified


def test_document_without_key_raises():
    ru = RUUID.from_str(RU_STR)
    with pytest.raises(ValueError, match="verificationMethod"):
        verify_ruuid(ru, {"id": "did:uuid:x"}, ct_source=FakeCt([]))


# --- custody bundle shape ------------------------------------------------

def test_gather_custody_shape():
    ru = RUUID.from_str(RU_STR)
    ct = FakeCt([GENESIS_CERT])
    custody = gather_custody(ru, _document(), ct)
    assert ct.queried == SPKI               # queried CT by the doc's key
    assert custody["ruuid"] == RU_STR
    assert custody["anchorIp"] == IP
    assert custody["dayCount"] == 553
    gen = custody["chain"][0]
    assert gen["generation"] == 0 and gen["role"] == "genesis"
    assert gen["spkiSha256"] == SPKI
    assert gen["certificates"][0]["ipSans"] == [IP]


# --- CLI -----------------------------------------------------------------

def test_cli_verify_with_prebuilt_custody(tmp_path, capsys):
    ru = RUUID.from_str(RU_STR)
    doc_path = tmp_path / "doc.json"
    doc_path.write_text(json.dumps(_document()))
    custody = gather_custody(ru, _document(), FakeCt([GENESIS_CERT]))
    cust_path = tmp_path / "custody.json"
    cust_path.write_text(json.dumps(custody))

    rc = main(["verify", RU_STR, str(doc_path), "--custody", str(cust_path)])
    assert rc == 0
    assert "VERIFIED" in capsys.readouterr().out

    # tamper the window so it no longer covers the day -> non-zero exit
    custody["chain"][0]["certificates"][0]["notBefore"] = "2026-08-01T00:00:00+00:00"
    custody["chain"][0]["certificates"][0]["notAfter"] = "2026-08-08T00:00:00+00:00"
    cust_path.write_text(json.dumps(custody))
    rc = main(["verify", RU_STR, str(doc_path), "--custody", str(cust_path)])
    assert rc == 1
    assert "NOT VERIFIED" in capsys.readouterr().out
