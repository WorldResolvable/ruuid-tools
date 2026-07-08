"""Tests for `ruuid seal` (CT-anchored genesis proof).

Fully offline: PTR resolution is served by the in-process `FakeNS`
fixture, and the ACME/Let's Encrypt round-trip is replaced by a fake
runner that self-signs the supplied CSR with openssl — sharing the real
generated key and honouring a controllable validity window. Everything
else (openssl key/CSR generation, certificate parsing, SKI extraction,
anchor-day selection, RUUID minting, and document/manifest emission) runs
for real.
"""

from __future__ import annotations

import datetime as _dt
import json
import subprocess

import pytest

import ruuid.seal as seal_mod
from ruuid import RUUID
from ruuid.cli import main
from ruuid.generate import SEQUENCE_BITS, days_since_epoch
from ruuid.resolve import reverse_name_for_ip
from ruuid.seal import AcmeRequest, seal


IP = "203.0.113.99"
DOMAIN = "example.com"


# --- fake ACME runner ----------------------------------------------------

def _self_sign(req: AcmeRequest) -> None:
    """Stand in for acme.sh: produce a self-signed cert for `req`.

    In "issue" mode, generate an EC (P-256) key at `req.key_path` (as
    acme.sh would) and self-sign; in "signcsr" mode, self-sign the supplied
    CSR with the shared key. A hash-based Subject Key Identifier is added
    (matching how a real CA derives the SKI from the public key), so the
    parsing/SKI/JWK code exercises a genuine certificate. IP certs get a
    ~7-day window (like LE's short-lived profile); domain certs 90 days.
    """
    san = f"IP:{req.identifier}" if req.is_ip else f"DNS:{req.identifier}"
    work = req.cert_out.parent
    if req.mode == "issue":
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "EC",
             "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(req.key_path)],
            check=True, capture_output=True,
        )
        csr = work / f"{req.cert_out.stem}-fake.csr"
        subprocess.run(
            ["openssl", "req", "-new", "-key", str(req.key_path), "-subj", "/",
             "-addext", f"subjectAltName={san}", "-out", str(csr)],
            check=True, capture_output=True,
        )
    else:
        csr = req.csr_path
    ext = work / f"{req.cert_out.stem}-ext.cnf"
    ext.write_text(f"subjectKeyIdentifier=hash\nsubjectAltName={san}\n")
    days = "7" if req.is_ip else "90"
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(csr),
            "-signkey", str(req.key_path), "-days", days,
            "-extfile", str(ext), "-out", str(req.cert_out),
        ],
        check=True, capture_output=True,
    )


class FakeAcme:
    """Recording fake ACME runner."""

    def __init__(self) -> None:
        self.requests: list[AcmeRequest] = []

    def __call__(self, req: AcmeRequest) -> None:
        self.requests.append(req)
        _self_sign(req)


@pytest.fixture
def ptr_ns(test_ns):
    """FakeNS with the IP's reverse name pointing at DOMAIN."""
    test_ns.add_ptr(reverse_name_for_ip(IP), DOMAIN)
    return test_ns


def _ns_arg(ns) -> str:
    return f"127.0.0.1:{ns.port}"


# --- happy path ----------------------------------------------------------

def test_seal_happy_path(ptr_ns, tmp_path):
    acme = FakeAcme()
    result = seal(
        IP, DOMAIN,
        out_dir=tmp_path / "seal",
        nameserver=_ns_arg(ptr_ns),
        acme_runner=acme,
        challenge="http-01",
    )

    # Minted RUUID reflects the anchor and the day.
    assert result.address_family == 4
    assert result.ip == IP
    assert result.domain == DOMAIN
    today = _dt.datetime.now(_dt.timezone.utc).date()
    assert result.anchor_day == today
    assert result.day_count == days_since_epoch(
        _dt.datetime(today.year, today.month, today.day, tzinfo=_dt.timezone.utc)
    )
    ru = result.ruuid
    assert isinstance(ru, RUUID)
    assert ru.identifier >> SEQUENCE_BITS == result.day_count
    # The minted RUUID's anchor IP is the sealed IP.
    assert str(ru.ip_network.network_address) == IP

    # SPKI hash present and identical across both same-key certs.
    assert result.spki_sha256
    assert result.domain_cert is not None
    assert result.ip_cert.spki_sha256 == result.domain_cert.spki_sha256
    assert result.spki_sha256 == result.ip_cert.spki_sha256

    # Artifacts on disk.
    out = tmp_path / "seal"
    for name in (
        "key.pem", "ip-cert.pem", "domain.csr", "domain-cert.pem",
        "uuid-document.json", "seal.json",
    ):
        assert (out / name).exists(), name

    # The genesis private key must be owner-only.
    assert (out / "key.pem").stat().st_mode & 0o077 == 0


def test_seal_two_certs_issued_with_right_profiles(ptr_ns, tmp_path):
    acme = FakeAcme()
    seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=acme, challenge="http-01",
    )
    assert len(acme.requests) == 2
    ip_req = next(r for r in acme.requests if r.is_ip)
    dom_req = next(r for r in acme.requests if not r.is_ip)
    assert ip_req.profile == seal_mod.SHORTLIVED_PROFILE
    assert dom_req.profile is None
    assert ip_req.identifier == IP
    assert dom_req.identifier == DOMAIN


def test_seal_document_commits_only_the_key(ptr_ns, tmp_path):
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=FakeAcme(), challenge="http-01",
    )
    doc = result.document
    assert doc["id"] == f"did:uuid:{result.ruuid}"

    # Commits the genesis key via verificationMethod.
    vm = doc["verificationMethod"][0]
    assert vm["type"] == "JsonWebKey"
    jwk = vm["publicKeyJwk"]
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert jwk["x"] and jwk["y"]    # public point present
    assert jwk["kid"] == result.spki_sha256
    assert doc["authentication"] == [f"did:uuid:{result.ruuid}#genesis-key"]

    # A clean CID document: NO cert history and NO `service` entries —
    # `service` is for referent templates (issuer's concern), and the proof
    # lives in CT / seal.json, not the document.
    assert "service" not in doc
    assert "CTAnchoredGenesisProof" not in json.dumps(doc)
    assert "ipCertificate" not in json.dumps(doc)

    # The written document matches the returned one.
    on_disk = json.loads((tmp_path / "s" / "uuid-document.json").read_text())
    assert on_disk == doc


def test_seal_manifest_wellformed(ptr_ns, tmp_path):
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=FakeAcme(), challenge="http-01",
    )
    manifest = json.loads((tmp_path / "s" / "seal.json").read_text())
    assert manifest["ruuid"] == str(result.ruuid)
    assert manifest["ip"] == IP
    assert manifest["domain"] == DOMAIN
    assert manifest["staging"] is True
    assert manifest["acmeServer"] == seal_mod.ACME_SERVER_STAGING
    assert manifest["spkiSha256"] == result.spki_sha256
    assert manifest["ipCertificate"]["kind"] == "ip"
    assert manifest["domainCertificate"]["kind"] == "domain"
    # The operator-local manifest DOES record the on-disk cert paths.
    assert manifest["ipCertificate"]["path"].endswith("ip-cert.pem")
    assert manifest["artifacts"]["key"].endswith("key.pem")


# --- staging vs production ----------------------------------------------

def test_seal_defaults_to_staging(ptr_ns, tmp_path):
    acme = FakeAcme()
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=acme, challenge="http-01",
    )
    assert result.staging is True
    assert all(r.staging for r in acme.requests)


def test_seal_production_flag(ptr_ns, tmp_path):
    acme = FakeAcme()
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=acme, challenge="http-01", production=True,
    )
    assert result.staging is False
    assert all(not r.staging for r in acme.requests)


# --- --no-domain-cert ----------------------------------------------------

def test_seal_no_domain_cert(ptr_ns, tmp_path):
    acme = FakeAcme()
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=acme, challenge="http-01", domain_cert=False,
    )
    assert result.domain_cert is None
    assert len(acme.requests) == 1
    assert acme.requests[0].is_ip
    assert not (tmp_path / "s" / "domain-cert.pem").exists()
    manifest = json.loads((tmp_path / "s" / "seal.json").read_text())
    assert manifest["domainCertificate"] is None
    # Document commits only the key regardless of the domain cert.
    assert "service" not in result.document
    assert result.document["verificationMethod"][0]["publicKeyJwk"]["kid"] \
        == result.spki_sha256


# --- PTR failures --------------------------------------------------------

def test_seal_ptr_mismatch(test_ns, tmp_path):
    test_ns.add_ptr(reverse_name_for_ip(IP), "attacker.example")
    with pytest.raises(ValueError, match="not example.com"):
        seal(
            IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(test_ns),
            acme_runner=FakeAcme(), challenge="http-01",
        )


def test_seal_no_ptr(test_ns, tmp_path):
    with pytest.raises(ValueError, match="no PTR record"):
        seal(
            IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(test_ns),
            acme_runner=FakeAcme(), challenge="http-01",
        )


def test_seal_ptr_trailing_dot_and_case_insensitive(test_ns, tmp_path):
    test_ns.add_ptr(reverse_name_for_ip(IP), "Example.COM")
    # Should match DOMAIN case-insensitively (and PTR targets carry a dot).
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(test_ns),
        acme_runner=FakeAcme(), challenge="http-01",
    )
    assert result.domain == DOMAIN


# --- anchor-day selection ------------------------------------------------

def test_seal_day_outside_window(ptr_ns, tmp_path):
    past = _dt.datetime(2025, 1, 2, tzinfo=_dt.timezone.utc)  # before cert window
    with pytest.raises(ValueError, match="outside the certificate window"):
        seal(
            IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
            acme_runner=FakeAcme(), challenge="http-01", day=past,
        )


def test_seal_future_day_rejected(ptr_ns, tmp_path):
    tomorrow = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1)
    with pytest.raises(ValueError, match="in the future"):
        seal(
            IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
            acme_runner=FakeAcme(), challenge="http-01", day=tomorrow,
        )


def test_seal_explicit_day_in_window(ptr_ns, tmp_path):
    today = _dt.datetime.now(_dt.timezone.utc)
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=FakeAcme(), challenge="http-01", day=today,
    )
    assert result.anchor_day == today.date()


# --- CLI -----------------------------------------------------------------

def test_cli_seal_happy(ptr_ns, tmp_path, monkeypatch, capsys):
    # Route the default runner through the offline self-signer.
    monkeypatch.setattr(seal_mod, "_resolve_acme", lambda p: "acme.sh")
    monkeypatch.setattr(
        seal_mod, "_run_acme_sh",
        lambda req, *, acme_path: _self_sign(req),
    )
    out = tmp_path / "cli-seal"
    rc = main([
        "seal", IP, DOMAIN,
        "--nameserver", _ns_arg(ptr_ns),
        "--out", str(out),
        "--challenge", "http-01",
    ])
    assert rc == 0
    report = capsys.readouterr().out
    assert "sealed:" in report
    assert "STAGING" in report
    assert (out / "uuid-document.json").exists()


# --- pre-rotation (genesis commitment to a cold successor) ---------------

def test_seal_pre_rotate_commits_cold_successor(ptr_ns, tmp_path):
    from ruuid.seal import spki_from_commitment_label
    acme = FakeAcme()
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=acme, challenge="http-01", pre_rotate=True,
    )
    nk = result.next_key
    assert nk is not None
    assert nk["spkiSha256"] and nk["spkiSha256"] != result.spki_sha256  # K2 != K1
    # commitment name is a subdomain of rotate.<domain>, its label decodes to K2
    assert nk["commitmentName"].endswith(f".rotate.{DOMAIN}")
    label = nk["commitmentName"].split(".")[0]
    assert spki_from_commitment_label(label) == nk["spkiSha256"]

    out = tmp_path / "s"
    assert (out / "next-key.pem").exists()
    assert (out / "next-key.pem").stat().st_mode & 0o077 == 0   # cold key owner-only
    assert (out / "commitment-cert.pem").exists()

    # An extra acme request (the commitment cert) beyond IP + domain,
    # signed under the genesis key (its CSR uses the genesis key).
    assert len(acme.requests) == 3
    commit_req = next(r for r in acme.requests if not r.is_ip
                      and "rotate" in r.identifier)
    assert commit_req.mode == "signcsr"

    manifest = json.loads((out / "seal.json").read_text())
    assert manifest["nextKey"]["spkiSha256"] == nk["spkiSha256"]
    # the commitment cert is under the genesis key (same SPKI)
    assert manifest["nextKey"]["commitmentCertificate"]["spkiSha256"] \
        == result.spki_sha256


def test_seal_without_pre_rotate_has_no_next_key(ptr_ns, tmp_path):
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=FakeAcme(), challenge="http-01",
    )
    assert result.next_key is None
    assert not (tmp_path / "s" / "next-key.pem").exists()


# --- webroot mode --------------------------------------------------------

def test_seal_webroot_threads_through(ptr_ns, tmp_path):
    acme = FakeAcme()
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=acme, webroot="/var/www/acme",
    )
    assert result.webroot == "/var/www/acme"
    assert result.challenge == "http-01"     # webroot always uses HTTP-01
    assert all(r.webroot == "/var/www/acme" for r in acme.requests)
    manifest = json.loads((tmp_path / "s" / "seal.json").read_text())
    assert manifest["webroot"] == "/var/www/acme"
    assert manifest["challenge"] == "http-01"


def test_seal_webroot_overrides_challenge(ptr_ns, tmp_path):
    # --challenge is ignored when a webroot is given.
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=FakeAcme(), webroot="/wr", challenge="tls-alpn-01",
    )
    assert result.challenge == "http-01"


def _capture_acme_argv(tmp_path, monkeypatch):
    captured = {}

    def fake_run(argv, *, input_bytes=None):
        captured["argv"] = argv
        # satisfy the post-run existence checks (cert always; key in issue mode)
        (tmp_path / "cert.pem").write_text("stub")
        (tmp_path / "key.pem").write_text("stub")
        return b""

    monkeypatch.setattr(seal_mod, "_run", fake_run)
    return captured


def test_run_acme_sh_argv_issue_webroot(tmp_path, monkeypatch):
    # IP cert: issue mode + webroot + shortlived profile.
    captured = _capture_acme_argv(tmp_path, monkeypatch)
    req = AcmeRequest(
        mode="issue", key_path=tmp_path / "key.pem",
        cert_out=tmp_path / "cert.pem", identifier=IP, is_ip=True,
        challenge="http-01", staging=True, profile=seal_mod.SHORTLIVED_PROFILE,
        webroot="/var/www/acme",
    )
    seal_mod._run_acme_sh(req, acme_path="acme.sh")
    argv = captured["argv"]
    assert "--issue" in argv and "-d" in argv and IP in argv
    assert "--key-file" in argv and "--fullchain-file" in argv
    assert "-w" in argv and "/var/www/acme" in argv
    assert "--standalone" not in argv and "--alpn" not in argv
    assert "--signcsr" not in argv
    assert "letsencrypt_test" in argv                # staging server
    assert "--cert-profile" in argv and "shortlived" in argv
    assert "--force" in argv


def test_run_acme_sh_argv_signcsr_standalone_modes(tmp_path, monkeypatch):
    # Domain cert: signcsr, TLS-ALPN-01, production, no profile.
    captured = _capture_acme_argv(tmp_path, monkeypatch)
    req = AcmeRequest(
        mode="signcsr", key_path=tmp_path / "key.pem",
        csr_path=tmp_path / "d.csr", cert_out=tmp_path / "cert.pem",
        identifier=DOMAIN, is_ip=False, challenge="tls-alpn-01",
        staging=False, profile=None, webroot=None,
    )
    seal_mod._run_acme_sh(req, acme_path="acme.sh")
    argv = captured["argv"]
    assert "--signcsr" in argv and "--csr" in argv
    assert "--issue" not in argv
    assert "--force" in argv
    assert "--alpn" in argv and "-w" not in argv and "--standalone" not in argv
    assert "letsencrypt" in argv and "letsencrypt_test" not in argv

    # HTTP-01 standalone.
    req2 = AcmeRequest(
        mode="signcsr", key_path=tmp_path / "key.pem",
        csr_path=tmp_path / "d.csr", cert_out=tmp_path / "cert.pem",
        identifier=DOMAIN, is_ip=False, challenge="http-01",
        staging=True, profile=None, webroot=None,
    )
    seal_mod._run_acme_sh(req2, acme_path="acme.sh")
    assert "--standalone" in captured["argv"] and "-w" not in captured["argv"]


def test_cli_seal_webroot(ptr_ns, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(seal_mod, "_resolve_acme", lambda p: "acme.sh")
    monkeypatch.setattr(
        seal_mod, "_run_acme_sh",
        lambda req, *, acme_path: _self_sign(req),
    )
    out = tmp_path / "cli-wr"
    rc = main([
        "seal", IP, DOMAIN,
        "--nameserver", _ns_arg(ptr_ns),
        "--out", str(out),
        "--webroot", "/var/www/acme",
    ])
    assert rc == 0
    assert "webroot /var/www/acme" in capsys.readouterr().out


# --- coverage ------------------------------------------------------------

def _write_seal(seals_dir, ruuid_str, ip, not_before, not_after, staging=False):
    d = seals_dir / ruuid_str
    d.mkdir(parents=True)
    (d / "seal.json").write_text(json.dumps({
        "ruuid": ruuid_str,
        "staging": staging,
        "ipCertificate": {
            "identifier": ip,
            "notBefore": not_before,
            "notAfter": not_after,
        },
    }))


def test_ip_coverage_single_window(tmp_path):
    from ruuid.seal import ip_coverage
    _write_seal(tmp_path, "aaa", IP,
                "2026-07-07T23:15:18+00:00", "2026-07-14T23:15:17+00:00")
    ranges = ip_coverage(IP, seals_dir=tmp_path)
    assert len(ranges) == 1
    assert ranges[0].start_date.isoformat() == "2026-07-07"
    assert ranges[0].end_date.isoformat() == "2026-07-14"
    assert ranges[0].covers(days_since_epoch(
        _dt.datetime(2026, 7, 10, tzinfo=_dt.timezone.utc)))
    assert not ranges[0].covers(days_since_epoch(
        _dt.datetime(2026, 8, 1, tzinfo=_dt.timezone.utc)))


def test_ip_coverage_merges_adjacent_and_filters_ip(tmp_path):
    from ruuid.seal import ip_coverage
    # two adjacent windows for IP -> one merged span
    _write_seal(tmp_path, "aaa", IP,
                "2026-07-07T00:00:00+00:00", "2026-07-14T00:00:00+00:00")
    _write_seal(tmp_path, "bbb", IP,
                "2026-07-15T00:00:00+00:00", "2026-07-22T00:00:00+00:00")
    # a window for a DIFFERENT ip must be ignored
    _write_seal(tmp_path, "ccc", "198.51.100.7",
                "2026-07-07T00:00:00+00:00", "2026-07-14T00:00:00+00:00")
    ranges = ip_coverage(IP, seals_dir=tmp_path)
    assert len(ranges) == 1
    assert ranges[0].start_date.isoformat() == "2026-07-07"
    assert ranges[0].end_date.isoformat() == "2026-07-22"
    assert set(ranges[0].seals) == {"aaa", "bbb"}


def test_ip_coverage_disjoint_windows_stay_separate(tmp_path):
    from ruuid.seal import find_coverage, ip_coverage
    _write_seal(tmp_path, "aaa", IP,
                "2026-07-07T00:00:00+00:00", "2026-07-14T00:00:00+00:00")
    _write_seal(tmp_path, "bbb", IP,
                "2026-09-01T00:00:00+00:00", "2026-09-08T00:00:00+00:00")
    ranges = ip_coverage(IP, seals_dir=tmp_path)
    assert len(ranges) == 2
    gap_day = days_since_epoch(_dt.datetime(2026, 8, 1, tzinfo=_dt.timezone.utc))
    assert find_coverage(ranges, gap_day) is None


def test_ip_coverage_excludes_staging_by_default(tmp_path):
    from ruuid.seal import ip_coverage
    _write_seal(tmp_path, "prod", IP,
                "2026-07-07T00:00:00+00:00", "2026-07-14T00:00:00+00:00",
                staging=False)
    _write_seal(tmp_path, "stg", IP,
                "2026-09-01T00:00:00+00:00", "2026-09-08T00:00:00+00:00",
                staging=True)
    prod_only = ip_coverage(IP, seals_dir=tmp_path)
    assert len(prod_only) == 1
    assert prod_only[0].seals == ("prod",)
    with_staging = ip_coverage(IP, seals_dir=tmp_path, production_only=False)
    assert len(with_staging) == 2


def test_cli_coverage_exit_codes(tmp_path, capsys):
    _write_seal(tmp_path, "aaa", IP,
                "2026-07-07T00:00:00+00:00", "2026-07-14T00:00:00+00:00")
    assert main(["coverage", IP, "--seals", str(tmp_path),
                 "--day", "2026-07-10"]) == 0
    assert "COVERED" in capsys.readouterr().out
    assert main(["coverage", IP, "--seals", str(tmp_path),
                 "--day", "2026-08-01"]) == 1
    assert "NOT COVERED" in capsys.readouterr().err


def test_cli_coverage_empty(tmp_path, capsys):
    assert main(["coverage", IP, "--seals", str(tmp_path)]) == 0
    assert "no sealed coverage" in capsys.readouterr().out


def test_cli_seal_ptr_mismatch(test_ns, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(seal_mod, "_resolve_acme", lambda p: "acme.sh")
    monkeypatch.setattr(
        seal_mod, "_run_acme_sh",
        lambda req, *, acme_path: _self_sign(req),
    )
    test_ns.add_ptr(reverse_name_for_ip(IP), "attacker.example")
    rc = main([
        "seal", IP, DOMAIN,
        "--nameserver", _ns_arg(test_ns),
        "--out", str(tmp_path / "s"),
        "--challenge", "http-01",
    ])
    assert rc == 1
    assert "ruuid seal:" in capsys.readouterr().err
