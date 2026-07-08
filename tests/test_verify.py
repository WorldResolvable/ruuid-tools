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
from ruuid.generate import new_ruuid
from ruuid.verify import (
    CtCert,
    IpCertCache,
    anchor_ip,
    document_disclaims,
    gather_custody,
    minting_day_range,
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


# --- key rotation: the custody chain-walk --------------------------------

from ruuid.seal import commitment_label   # noqa: E402

def _key(seed):
    jwk = {"kty": "EC", "crv": "P-256",
           "x": _b64u(bytes([seed]) * 32), "y": _b64u(bytes([seed + 1]) * 32)}
    return jwk, spki_sha256_from_jwk(jwk)


K2_JWK, K2_SPKI = _key(0x33)
K3_JWK, K3_SPKI = _key(0x55)
K4_JWK, K4_SPKI = _key(0x77)


def _commit_cert(under, nxt, *, nb, na, serial, cid):
    """A commitment cert under `under` pinning `nxt` (both hex SPKIs)."""
    label = commitment_label(bytes.fromhex(nxt))
    return _cert(dns_sans=(f"{label}.rotate.uuid.zone",),
                 nb=nb, na=na, serial=serial, cid=cid, spki=under)


# A realistic gen1 chain: genesis K1 (IP cert) commits K2; K2 has rotated in
# and so has published its own commitment to a cold K3.
K1_TO_K2 = _commit_cert(SPKI, K2_SPKI, nb="2026-07-08T00:00:00+00:00",
                        na="2026-10-06T00:00:00+00:00", serial="c1", cid=201)
K2_TO_K3 = _commit_cert(K2_SPKI, K3_SPKI, nb="2026-07-09T00:00:00+00:00",
                        na="2026-10-07T00:00:00+00:00", serial="c2", cid=202)
K3_TO_K4 = _commit_cert(K3_SPKI, K4_SPKI, nb="2026-07-10T00:00:00+00:00",
                        na="2026-10-08T00:00:00+00:00", serial="c3", cid=203)


def test_verify_walks_chain_to_rotated_key():
    ru = RUUID.from_str(RU_STR)
    result, _ = verify_ruuid(ru, _document(jwk=K2_JWK),
                             ct_source=FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3]))
    assert result.verified
    assert result.chain == (SPKI, K2_SPKI)       # genesis -> rotated key
    assert result.document_key == K2_SPKI


def test_verify_walks_two_hop_chain():
    ru = RUUID.from_str(RU_STR)
    result, _ = verify_ruuid(
        ru, _document(jwk=K3_JWK),
        ct_source=FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3, K3_TO_K4]))
    assert result.verified
    assert result.chain == (SPKI, K2_SPKI, K3_SPKI)


def test_verify_rejects_pinned_but_unactivated_key():
    # K2 is committed by K1 but has not itself acted in CT (still cold).
    ru = RUUID.from_str(RU_STR)
    result, _ = verify_ruuid(ru, _document(jwk=K2_JWK),
                             ct_source=FakeCt([GENESIS_CERT, K1_TO_K2]))
    assert not result.verified
    assert "not been activated" in result.reason


def test_verify_rejects_unendorsed_key():
    ru = RUUID.from_str(RU_STR)
    # Document commits an impostor key that no one in the chain committed to.
    result, _ = verify_ruuid(ru, _document(jwk=IMPOSTOR_JWK),
                             ct_source=FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3]))
    assert not result.verified
    assert "successor" in result.reason


def test_verify_chain_fork_earliest_commitment_wins():
    # Two commitments under the genesis key: the genuine one (early) pins K2;
    # a later fork (a thief) pins the impostor. Earliest-SCT-wins picks K2.
    ru = RUUID.from_str(RU_STR)
    fork = _commit_cert(SPKI, IMPOSTOR_SPKI, nb="2026-07-20T00:00:00+00:00",
                        na="2026-10-18T00:00:00+00:00", serial="fork", cid=299)
    ct = FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3, fork])
    ok, _ = verify_ruuid(ru, _document(jwk=K2_JWK), ct_source=ct)
    assert ok.verified and ok.chain == (SPKI, K2_SPKI)
    bad, _ = verify_ruuid(ru, _document(jwk=IMPOSTOR_JWK), ct_source=ct)
    assert not bad.verified                       # the fork target loses


def test_custody_bundle_follows_chain_forward():
    ru = RUUID.from_str(RU_STR)
    bundle = gather_custody(ru, FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3]))
    serials = {c["serial"] for c in bundle["chain"][0]["certificates"]}
    assert {"genesis", "c1", "c2"} <= serials     # whole chain gathered from CT


def test_verify_no_document_reports_activated_tip():
    ru = RUUID.from_str(RU_STR)
    result, _ = verify_ruuid(
        ru, None, ct_source=FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3]))
    assert result.verified
    assert result.chain == (SPKI, K2_SPKI)        # tip is the activated K2, not K3
    assert K2_SPKI in result.reason


def test_verify_no_document_only_pinned_reports_genesis():
    # Genesis committed K2 but has not rotated: current key is still genesis.
    ru = RUUID.from_str(RU_STR)
    result, _ = verify_ruuid(ru, None, ct_source=FakeCt([GENESIS_CERT, K1_TO_K2]))
    assert result.verified
    assert result.chain == (SPKI,)                # K2 is only pinned, trimmed


# --- published custody bundles (offline, crt.sh-free) --------------------

def test_local_bundle_source_offline_verify(tmp_path):
    from ruuid.verify import LocalBundleSource
    ru = RUUID.from_str(RU_STR)
    bundle = gather_custody(ru, FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3]))
    d = tmp_path / "bundles"
    d.mkdir()
    (d / "uuid-custody.json").write_text(json.dumps(bundle))
    # Verify the rotated document off the local bundle dir — no CT source.
    result, _ = verify_ruuid(ru, _document(jwk=K2_JWK),
                             ct_source=LocalBundleSource(d))
    assert result.verified
    assert result.chain == (SPKI, K2_SPKI)


def test_local_bundle_source_flat_shape(tmp_path):
    from ruuid.verify import LocalBundleSource
    ru = RUUID.from_str(RU_STR)
    flat = {"kind": "uuid-custody",
            "certificates": [GENESIS_CERT.as_dict(), K1_TO_K2.as_dict(),
                             K2_TO_K3.as_dict()]}
    p = tmp_path / "flat.json"
    p.write_text(json.dumps(flat))
    result, _ = verify_ruuid(ru, _document(jwk=K2_JWK),
                             ct_source=LocalBundleSource([p]))
    assert result.verified


def test_build_published_custody_excludes_private_keys(tmp_path):
    import subprocess
    from ruuid.verify import build_published_custody
    seal_dir = tmp_path / "seals" / "ruuidX"
    seal_dir.mkdir(parents=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", str(seal_dir / "key.pem"),      # a PRIVATE KEY, must be skipped
         "-out", str(seal_dir / "ip-cert.pem"), "-days", "7", "-subj", "/",
         "-addext", "subjectAltName=IP:100.57.12.254"],
        check=True, capture_output=True,
    )
    bundle = build_published_custody(tmp_path / "seals")
    assert bundle["kind"] == "uuid-custody"
    assert len(bundle["certificates"]) == 1           # only the -cert.pem
    assert "100.57.12.254" in bundle["certificates"][0]["ipSans"]
    blob = json.dumps(bundle)
    assert "PRIVATE KEY" not in blob                  # no key material leaked


def test_cli_verify_off_bundles(tmp_path, capsys):
    ru = RUUID.from_str(RU_STR)
    bundle = gather_custody(ru, FakeCt([GENESIS_CERT, K1_TO_K2, K2_TO_K3]))
    d = tmp_path / "bundles"
    d.mkdir()
    (d / "uuid-custody.json").write_text(json.dumps(bundle))
    doc = tmp_path / "doc.json"
    doc.write_text(json.dumps(_document(jwk=K2_JWK)))
    rc = main(["verify", RU_STR, str(doc), "--bundles", str(d)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERIFIED" in out and "custody chain" in out


# --- per-IP cache / local green-lighting ---------------------------------

class CountingCt(FakeCt):
    def __init__(self, certs):
        super().__init__(certs)
        self.ip_calls = 0

    def certs_for_ip(self, ip):
        self.ip_calls += 1
        return super().certs_for_ip(ip)


def test_ctcert_dict_roundtrip():
    assert CtCert.from_dict(GENESIS_CERT.as_dict()) == GENESIS_CERT


def test_cache_green_lights_further_ruuids_same_ip(tmp_path):
    cache = IpCertCache(tmp_path)
    ct = CountingCt([GENESIS_CERT])

    # 1st RUUID for the IP: cache miss -> one CT fetch, cached.
    ru1 = RUUID.from_str(RU_STR)
    r1, _ = verify_ruuid(ru1, _document(), ct_source=ct, cache=cache)
    assert r1.verified and ct.ip_calls == 1

    # 2nd RUUID: same IP + same day, fresh random sequence, its own document
    # committing the genesis key -> cache HIT, NO further CT fetch.
    import datetime as dt
    ru2 = new_ruuid(IP, day=dt.datetime(2026, 7, 8, tzinfo=dt.timezone.utc))
    assert str(ru2) != RU_STR and anchor_ip(ru2) == IP
    r2, _ = verify_ruuid(ru2, _document(ruuid=str(ru2)), ct_source=ct, cache=cache)
    assert r2.verified
    assert ct.ip_calls == 1                       # green-lit locally

    # A fresh cache instance (new process) reads the persisted certs.
    r3, _ = verify_ruuid(ru1, _document(), ct_source=ct, cache=IpCertCache(tmp_path))
    assert r3.verified and ct.ip_calls == 1


def test_cache_miss_for_uncovered_day_refetches(tmp_path):
    cache = IpCertCache(tmp_path)
    ct = CountingCt([GENESIS_CERT])
    ru1 = RUUID.from_str(RU_STR)
    verify_ruuid(ru1, _document(), ct_source=ct, cache=cache)   # caches
    assert ct.ip_calls == 1
    # An RUUID for the same IP but a day the cached cert does NOT cover
    # (e.g. a later, not-yet-cached day) must fall through to CT.
    import datetime as dt
    ru_late = new_ruuid(IP, day=dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc))
    verify_ruuid(ru_late, _document(ruuid=str(ru_late)), ct_source=ct, cache=cache)
    assert ct.ip_calls == 2                        # re-fetched


# --- minting day-range (resolver triage) ---------------------------------

def test_minting_day_range_and_disclaim():
    # day_count 553 == 2026-07-08
    doc = _document()
    doc["mintingDayRange"] = {"from": "2026-07-07", "to": "2026-07-14"}
    assert minting_day_range(doc) == (552, 559)
    assert not document_disclaims(doc, 553)     # in range -> not disclaimed
    assert document_disclaims(doc, 600)         # after range -> disclaimed
    assert document_disclaims(doc, 400)         # before range -> disclaimed


def test_disclaim_absent_or_malformed_range():
    assert minting_day_range(_document()) is None          # no field
    assert not document_disclaims(_document(), 553)
    bad = _document()
    bad["mintingDayRange"] = {"from": "nonsense"}
    assert minting_day_range(bad) is None
    assert not document_disclaims(bad, 553)


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
