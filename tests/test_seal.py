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
    """Self-sign `req`'s CSR into `req.cert_out`, standing in for LE.

    Copies the CSR's SAN and adds a hash-based Subject Key Identifier
    (matching how a real CA derives the SKI from the public key), so the
    parsing/SKI code exercises a genuine certificate. IP certs get a
    ~7-day window (like LE's short-lived profile); domain certs 90 days.
    """
    san = f"IP:{req.identifier}" if req.is_ip else f"DNS:{req.identifier}"
    ext = req.cert_out.parent / f"{req.cert_out.stem}-ext.cnf"
    ext.write_text(f"subjectKeyIdentifier=hash\nsubjectAltName={san}\n")
    days = "7" if req.is_ip else "90"
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(req.csr_path),
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

    # SKI present and identical across both same-key certs.
    assert result.subject_key_identifier
    assert result.domain_cert is not None
    assert (
        result.ip_cert.subject_key_identifier
        == result.domain_cert.subject_key_identifier
    )

    # Artifacts on disk.
    out = tmp_path / "seal"
    for name in (
        "key.pem", "ip.csr", "ip-cert.pem", "domain.csr", "domain-cert.pem",
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


def test_seal_document_commits_key_and_proof(ptr_ns, tmp_path):
    result = seal(
        IP, DOMAIN, out_dir=tmp_path / "s", nameserver=_ns_arg(ptr_ns),
        acme_runner=FakeAcme(), challenge="http-01",
    )
    doc = result.document
    assert doc["id"] == f"did:uuid:{result.ruuid}"

    vm = doc["verificationMethod"][0]
    assert vm["type"] == "JsonWebKey"
    jwk = vm["publicKeyJwk"]
    assert jwk["kty"] == "RSA"
    assert jwk["e"] == "AQAB"       # exponent 65537
    assert jwk["n"]                 # modulus present
    assert jwk["kid"] == result.subject_key_identifier

    svc = doc["service"][0]
    assert svc["type"] == "CTAnchoredGenesisProof"
    ep = svc["serviceEndpoint"]
    assert ep["ipAddress"] == IP
    assert ep["domain"] == DOMAIN
    assert ep["subjectKeyIdentifier"] == result.subject_key_identifier
    assert ep["dayCount"] == result.day_count
    assert ep["ptr"]["name"] == reverse_name_for_ip(IP)
    assert DOMAIN in ep["ptr"]["targets"]

    # The published document must NOT leak local filesystem paths — a
    # verifier finds the cert in CT by serial/fingerprint/SKI.
    assert "path" not in ep["ipCertificate"]
    assert "path" not in ep["domainCertificate"]
    assert ep["ipCertificate"]["serial"]
    assert ep["ipCertificate"]["fingerprintSha256"]

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
    assert manifest["subjectKeyIdentifier"] == result.subject_key_identifier
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
    assert result.document["service"][0]["serviceEndpoint"]["domainCertificate"] \
        is None


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
        (tmp_path / "cert.pem").write_text("stub")   # satisfy existence check
        return b""

    monkeypatch.setattr(seal_mod, "_run", fake_run)
    return captured


def test_run_acme_sh_argv_webroot(tmp_path, monkeypatch):
    captured = _capture_acme_argv(tmp_path, monkeypatch)
    req = AcmeRequest(
        csr_path=tmp_path / "ip.csr", key_path=tmp_path / "key.pem",
        cert_out=tmp_path / "cert.pem", identifier=IP, is_ip=True,
        challenge="http-01", staging=True, profile=seal_mod.SHORTLIVED_PROFILE,
        webroot="/var/www/acme",
    )
    seal_mod._run_acme_sh(req, acme_path="acme.sh")
    argv = captured["argv"]
    assert "-w" in argv and "/var/www/acme" in argv
    assert "--standalone" not in argv and "--alpn" not in argv
    assert "--signcsr" in argv
    assert "letsencrypt_test" in argv                # staging server
    assert "--cert-profile" in argv and "shortlived" in argv


def test_run_acme_sh_argv_standalone_modes(tmp_path, monkeypatch):
    # TLS-ALPN-01, production, no profile.
    captured = _capture_acme_argv(tmp_path, monkeypatch)
    req = AcmeRequest(
        csr_path=tmp_path / "d.csr", key_path=tmp_path / "key.pem",
        cert_out=tmp_path / "cert.pem", identifier=DOMAIN, is_ip=False,
        challenge="tls-alpn-01", staging=False, profile=None, webroot=None,
    )
    seal_mod._run_acme_sh(req, acme_path="acme.sh")
    argv = captured["argv"]
    assert "--alpn" in argv and "-w" not in argv and "--standalone" not in argv
    assert "letsencrypt" in argv and "letsencrypt_test" not in argv

    # HTTP-01 standalone.
    req2 = AcmeRequest(
        csr_path=tmp_path / "d.csr", key_path=tmp_path / "key.pem",
        cert_out=tmp_path / "cert.pem", identifier=DOMAIN, is_ip=False,
        challenge="http-01", staging=True, profile=None, webroot=None,
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
