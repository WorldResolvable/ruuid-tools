"""Tests for embedded SCT verification (ruuid.sct), RFC 6962 §3.2.

The positive fixture is a real Let's Encrypt *production* certificate (the IP
genesis cert of 002299ac) with genuine embedded SCTs, plus its issuer chain —
so the precertificate reconstruction and signature checks run against real CT
evidence, offline, against the bundled log list.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ruuid.sct import load_log_list, verify_cert_scts

FIXTURE = Path(__file__).parent / "fixtures" / "le-prod-ip-cert.pem"


def test_real_le_cert_scts_verify():
    r = verify_cert_scts(FIXTURE.read_bytes())
    assert r.verified_count == 2                 # LE embeds >= 2 SCTs
    assert r.ok(min_scts=2)
    assert len(r.verified_operators) == 2        # from two independent operators
    assert r.earliest_verified_ms and r.earliest_verified_ms > 0


def test_unknown_logs_are_not_trusted():
    # No trusted logs -> the SCTs are parsed but none verify.
    r = verify_cert_scts(FIXTURE.read_bytes(), log_list={})
    assert len(r.scts) == 2
    assert r.verified_count == 0 and not r.ok(1)
    assert all(s.log_description is None for s in r.scts)


def test_signature_is_actually_checked():
    # Right log id, WRONG key -> signatures must fail (proves we verify, not
    # merely match ids / presence).
    real = verify_cert_scts(FIXTURE.read_bytes())
    used = {s.log_id_b64 for s in real.scts}
    logs = load_log_list()
    other_key = next(v["key"] for k, v in logs.items() if k not in used)
    tampered = {k: dict(v) for k, v in logs.items()}
    for lid in used:
        tampered[lid]["key"] = other_key
    r = verify_cert_scts(FIXTURE.read_bytes(), log_list=tampered)
    assert r.verified_count == 0


def test_fabricated_cert_has_no_verifiable_scts(tmp_path):
    # A cert minted outside CT (self-run CA, no LE, no logging) carries no SCTs,
    # so it can never satisfy ok() — a forged custody bundle can't fake this.
    def run(*a):
        subprocess.run(a, check=True, capture_output=True)

    ca_key, ca = tmp_path / "ca.key", tmp_path / "ca.pem"
    lf_key, lf, csr = tmp_path / "l.key", tmp_path / "l.pem", tmp_path / "l.csr"
    run("openssl", "genpkey", "-algorithm", "EC",
        "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(ca_key))
    run("openssl", "req", "-x509", "-new", "-key", str(ca_key),
        "-subj", "/CN=Fake CA", "-days", "1", "-out", str(ca))
    run("openssl", "genpkey", "-algorithm", "EC",
        "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(lf_key))
    run("openssl", "req", "-new", "-key", str(lf_key),
        "-subj", "/CN=fake.example", "-out", str(csr))
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
        "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-out", str(lf))
    fullchain = lf.read_bytes() + ca.read_bytes()

    r = verify_cert_scts(fullchain)
    assert r.scts == ()                          # no SCT extension at all
    assert not r.ok(1)


def test_leaf_without_issuer_chain_raises():
    leaf_only = (FIXTURE.read_text().split("-----END CERTIFICATE-----")[0]
                 + "-----END CERTIFICATE-----\n")
    with pytest.raises(ValueError, match="issuer"):
        verify_cert_scts(leaf_only)


def test_bundled_log_list_loads():
    logs = load_log_list()
    assert len(logs) > 20
    any_log = next(iter(logs.values()))
    assert "key" in any_log and "description" in any_log
