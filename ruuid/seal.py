"""Experimental `ruuid seal`: CT-anchored genesis proof for an RUUID.

RUUID resolution roots in mutable infrastructure — an IP prefix, its
reverse-DNS delegation, and the domain its PTR maps to. The
*commandeering* problem is that a later holder of a transferred prefix or
domain can serve an authentic-looking but unauthorized resolution; DNS
authenticates the *current* operator and carries no continuity of
identity across a transfer.

`seal` establishes the RUUID-v0-native answer worked out in the custody
design notes — the **CT-anchored genesis proof**. It binds the issuer's
key to the IP (and domain) at a specific day inside Certificate
Transparency, using the RUUID's own immutable `day_count` field as the
time anchor. CT is append-only / backdate-proof, so a party who acquires
the prefix later can get a valid certificate, but never one dated back to
the anchor day. A third party can later find the certificate in CT and
confirm control on the day of issuance.

Concretely, `seal(address, domain)`:

  1. Verifies the PTR — that `reverse-name(address)` maps to `domain`
     right now — recording the reverse-zone → domain mapping as of the
     day of issuance. (Let's Encrypt offers no DNS-01 challenge over
     in-addr.arpa / ip6.arpa, so this leg is attested by observation,
     not by a certificate.)
  2. Has `acme.sh` issue an IP-SAN short-lived cert (routing control of the
     IP, validated by HTTP-01 / TLS-ALPN-01). acme.sh generates the EC
     (P-256) genesis key as part of this and hands it back — the only path
     that yields a Boulder-valid IP cert (an IP literal in the CSR's Common
     Name is rejected, and acme.sh's `--signcsr` cannot read an empty CN).
  3. Issues an optional same-key 90-day `dNSName` cert for the domain
     (control of the domain) by building a CSR with that same key and
     submitting it via `acme.sh --signcsr`. One key gives both certs the
     same Subject Key Identifier (SKI), linking them in CT.
  4. Mints an RUUID whose `day_count` falls inside the IP cert's validity
     window, and emits a UUID document that commits to the SKI and the
     public key.

The proof is *historical, not live*: the certs are frozen in CT with
permanent SCTs, so a verifier years later only checks whether a logged
cert's window covered the RUUID's anchor day. One short-lived cert
therefore anchors an unbounded minting batch — there is no renewal
treadmill.

This is **experimental** tooling prototyping the profile ahead of the
`draft-motters-custody-01` write-up; the UUID-document genesis-proof shape
in particular is expected to evolve.
"""

from __future__ import annotations

import base64
import datetime as _dt
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import dns.exception

from ruuid.core import RUUID
from ruuid.generate import SEQUENCE_BITS, new_ruuid
from ruuid.resolve import DnsTransport, reverse_name_for_ip, to_ip


# --- LE endpoints -------------------------------------------------------

# acme.sh CA aliases. Staging (the default) exercises the identical ACME
# flow from an untrusted root and test CT logs; production hits real LE
# and real, third-party-discoverable Certificate Transparency.
ACME_SERVER_STAGING = "letsencrypt_test"
ACME_SERVER_PRODUCTION = "letsencrypt"

# LE issues IP-address certificates only under the short-lived profile
# (~6.67-day validity). The domain cert takes the default (~90-day)
# profile.
SHORTLIVED_PROFILE = "shortlived"

CHALLENGE_HTTP01 = "http-01"
CHALLENGE_TLS_ALPN01 = "tls-alpn-01"


# --- data types ---------------------------------------------------------

@dataclass(frozen=True)
class CertInfo:
    """Parsed fields of an issued certificate."""

    kind: str                 # "ip" or "domain"
    identifier: str           # the IP or domain SAN value
    path: Path
    subject_key_identifier: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    serial: str
    fingerprint_sha256: str
    scts: list[dict] = field(default_factory=list)

    def as_dict(self, *, include_path: bool = False) -> dict:
        """Serialise for JSON.

        `include_path` adds the local filesystem path — appropriate for the
        operator-local `seal.json` manifest, but NOT for the published UUID
        document (a verifier discovers the cert in CT by serial / fingerprint
        / SKI, and a local path would only leak filesystem structure).
        """
        d = {
            "kind": self.kind,
            "identifier": self.identifier,
            "subjectKeyIdentifier": self.subject_key_identifier,
            "notBefore": self.not_before.isoformat(),
            "notAfter": self.not_after.isoformat(),
            "serial": self.serial,
            "fingerprintSha256": self.fingerprint_sha256,
            "signedCertificateTimestamps": self.scts,
        }
        if include_path:
            d["path"] = str(self.path)
        return d


@dataclass(frozen=True)
class AcmeRequest:
    """One certificate request handed to the ACME runner.

    Two modes:

      - "issue": acme.sh generates the (EC P-256) key and CSR itself and is
        told to write the key to `key_path` (--key-file) and the chain to
        `cert_out` (--fullchain-file). Used for the IP cert — acme.sh only
        builds a Boulder-valid IP CSR (IP in the SAN, not the Common Name)
        in its own issue path; `--signcsr` cannot (an IP literal in the CN
        is rejected, and an empty CN is unreadable by acme.sh).
      - "signcsr": we supply `csr_path`, built with the *same* key the issue
        step produced, so both certs share one Subject Key Identifier and
        link in CT. Used for the domain cert.

    `key_path` is where the private key lives: acme.sh writes it in issue
    mode; in signcsr mode it already exists (the shared genesis key) and the
    real runner ignores it (the injected test runner self-signs with it).
    The default runner (`_run_acme_sh`) turns this into acme.sh flags; a
    runner MUST write a PEM certificate chain to `cert_out`.
    """

    mode: str                 # "issue" | "signcsr"
    key_path: Path
    cert_out: Path
    identifier: str           # the IP or domain being certified
    is_ip: bool
    challenge: str            # CHALLENGE_HTTP01 | CHALLENGE_TLS_ALPN01
    staging: bool
    profile: str | None       # SHORTLIVED_PROFILE for the IP cert, else None
    webroot: str | None = None  # if set, HTTP-01 via this webroot (no standalone)
    csr_path: Path | None = None  # signcsr mode only


AcmeRunner = Callable[[AcmeRequest], None]


@dataclass(frozen=True)
class SealResult:
    ruuid: RUUID
    ip: str
    domain: str
    address_family: int
    staging: bool
    challenge: str
    webroot: str | None
    anchor_day: _dt.date
    day_count: int
    subject_key_identifier: str
    ptr_name: str
    ptr_targets: list[str]
    ip_cert: CertInfo
    domain_cert: CertInfo | None
    out_dir: Path
    document: dict
    manifest: dict


# --- openssl plumbing ---------------------------------------------------

def _run(argv: list[str], *, input_bytes: bytes | None = None) -> bytes:
    """Run a subprocess, returning stdout; raise RuntimeError on failure."""
    try:
        proc = subprocess.run(argv, input=input_bytes, capture_output=True)
    except FileNotFoundError as e:
        raise RuntimeError(f"{argv[0]}: command not found") from e
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"{argv[0]} failed: {err or 'unknown error'}")
    return proc.stdout


def _require(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise RuntimeError(f"{tool} is required but was not found on PATH")
    return path


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _openssl_csr(
    openssl: str, key_path: Path, csr_path: Path, *, san: str, cn: str | None = None
) -> None:
    """Write a CSR for `key_path` carrying a single SAN (`IP:...`/`DNS:...`).

    `cn=None` yields an empty subject. This is required for IP-address
    certs: CAs (Boulder/Let's Encrypt) reject a CSR with an IP literal in
    the Common Name (`badCSR`), so the IP must live only in the SAN.
    """
    subject = f"/CN={cn}" if cn else "/"
    _run([
        openssl, "req", "-new",
        "-key", str(key_path),
        "-subj", subject,
        "-addext", f"subjectAltName={san}",
        "-out", str(csr_path),
    ])


# openssl "NIST CURVE" name -> (JWK crv, coordinate byte length)
_EC_CURVES = {
    "P-256": ("P-256", 32),
    "P-384": ("P-384", 48),
    "P-521": ("P-521", 66),
}


def _ec_public_jwk(openssl: str, key_path: Path, *, kid: str) -> dict:
    """Build an RFC 7517 EC public JWK from a private key via openssl.

    acme.sh issues EC (P-256) keys by default, and that is the only key
    type that survives its IP-cert CSR path, so the genesis key is EC.
    """
    text = _run([openssl, "pkey", "-in", str(key_path), "-noout", "-text"]).decode()

    curve_match = re.search(r"NIST CURVE:\s*(\S+)", text)
    if not curve_match or curve_match.group(1) not in _EC_CURVES:
        raise RuntimeError(
            f"unsupported or unreadable EC curve in key {key_path}"
        )
    crv, coord_len = _EC_CURVES[curve_match.group(1)]

    # The public point is printed as a colon-separated hex block between
    # "pub:" and the "ASN1 OID:" line; it is 0x04 || X || Y (uncompressed).
    pub_match = re.search(r"pub:\s*(.*?)\n\s*ASN1 OID", text, re.S)
    if not pub_match:
        raise RuntimeError(f"could not read EC public point from key {key_path}")
    point = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", pub_match.group(1)))
    if len(point) != 1 + 2 * coord_len or point[0] != 0x04:
        raise RuntimeError(
            f"unexpected EC public point ({len(point)} bytes) in key {key_path}"
        )
    x = point[1:1 + coord_len]
    y = point[1 + coord_len:]

    return {
        "kty": "EC",
        "crv": crv,
        "x": _b64u(x),
        "y": _b64u(y),
        "kid": kid,
    }


def _parse_openssl_time(value: str) -> _dt.datetime:
    """Parse an openssl `notBefore=`/`notAfter=` value into aware UTC."""
    s = value.split("=", 1)[-1].strip()
    if s.endswith(" GMT"):
        s = s[:-4]
    s = " ".join(s.split())
    dt = _dt.datetime.strptime(s, "%b %d %H:%M:%S %Y")
    return dt.replace(tzinfo=_dt.timezone.utc)


def _parse_scts(text: str) -> list[dict]:
    """Best-effort extraction of embedded SCT (log id, timestamp) pairs."""
    scts: list[dict] = []
    # The -text block lists each SCT with "Log ID" (over two lines) and
    # a "Timestamp". Capture them pairwise, tolerating formatting drift.
    blocks = re.split(r"Signed Certificate Timestamp:", text)[1:]
    for block in blocks:
        log = re.search(r"Log ID\s*:\s*([0-9A-Fa-f:\s]+?)\n\s*Timestamp", block)
        ts = re.search(r"Timestamp\s*:\s*(.+)", block)
        entry: dict = {}
        if log:
            entry["logId"] = re.sub(r"\s+", "", log.group(1))
        if ts:
            entry["timestamp"] = ts.group(1).strip()
        if entry:
            scts.append(entry)
    return scts


def _cert_info(openssl: str, cert_path: Path, *, kind: str, identifier: str) -> CertInfo:
    fields = _run([
        openssl, "x509", "-in", str(cert_path), "-noout",
        "-serial", "-startdate", "-enddate", "-fingerprint", "-sha256",
    ]).decode()
    values: dict[str, str] = {}
    for line in fields.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip()
    # The fingerprint key varies by openssl version/casing
    # ("sha256 Fingerprint" on 3.x); match it loosely.
    fingerprint = next(
        (v for k, v in values.items() if k.lower().endswith("fingerprint")),
        "",
    )

    ski_out = _run([
        openssl, "x509", "-in", str(cert_path), "-noout",
        "-ext", "subjectKeyIdentifier",
    ]).decode()
    ski = ""
    for line in ski_out.splitlines():
        line = line.strip()
        if re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+", line):
            ski = line.upper()
            break

    text = _run([openssl, "x509", "-in", str(cert_path), "-noout", "-text"]).decode()

    return CertInfo(
        kind=kind,
        identifier=identifier,
        path=cert_path,
        subject_key_identifier=ski,
        not_before=_parse_openssl_time(values.get("notBefore", "")),
        not_after=_parse_openssl_time(values.get("notAfter", "")),
        serial=values.get("serial", ""),
        fingerprint_sha256=fingerprint.replace(":", ""),
        scts=_parse_scts(text),
    )


# --- acme.sh runner -----------------------------------------------------

def _resolve_acme(acme_path: str | None) -> str:
    """Locate the acme.sh binary (explicit path, PATH, or ~/.acme.sh)."""
    if acme_path:
        if not Path(acme_path).exists():
            raise RuntimeError(f"acme.sh not found at {acme_path}")
        return acme_path
    found = shutil.which("acme.sh")
    if found:
        return found
    default = Path.home() / ".acme.sh" / "acme.sh"
    if default.exists():
        return str(default)
    raise RuntimeError(
        "acme.sh is required but was not found. Install it from "
        "https://github.com/acmesh-official/acme.sh, or pass --acme PATH."
    )


def _run_acme_sh(req: AcmeRequest, *, acme_path: str) -> None:
    """Default ACME runner: drive acme.sh against Let's Encrypt.

    In "issue" mode acme.sh generates the key and CSR (the only path that
    yields a Boulder-valid IP cert) and writes both to our paths; in
    "signcsr" mode it submits our pre-built CSR. The exact flags for IP-SAN
    issuance and the LE short-lived profile are still stabilising in
    acme.sh, so they are confined to this one function for easy tuning
    without touching the rest of the pipeline.
    """
    server = ACME_SERVER_STAGING if req.staging else ACME_SERVER_PRODUCTION
    if req.mode == "issue":
        argv = [
            acme_path, "--issue",
            "-d", req.identifier,
            "--key-file", str(req.key_path),
            "--fullchain-file", str(req.cert_out),
            "--server", server,
            "--force",
        ]
    else:
        argv = [
            acme_path, "--signcsr",
            "--csr", str(req.csr_path),
            "--fullchain-file", str(req.cert_out),
            "--server", server,
        ]
    if req.webroot:
        # Webroot HTTP-01: acme.sh drops the challenge token under
        # <webroot>/.well-known/acme-challenge/ and the already-running
        # web server serves it — no port takeover, no downtime.
        argv += ["-w", req.webroot]
    elif req.challenge == CHALLENGE_TLS_ALPN01:
        argv.append("--alpn")
    else:
        argv.append("--standalone")
    if req.profile:
        # acme.sh spells this --cert-profile (aka --certificate-profile);
        # LE requires the "shortlived" profile for IP-address certs.
        argv += ["--cert-profile", req.profile]
    _run(argv)
    if not req.cert_out.exists():
        raise RuntimeError(
            f"acme.sh completed but no certificate was written to {req.cert_out}"
        )
    if req.mode == "issue" and not req.key_path.exists():
        raise RuntimeError(
            f"acme.sh completed but no key was written to {req.key_path}"
        )


# --- challenge selection ------------------------------------------------

def _has_listener(port: int) -> bool:
    """True if something is already accepting TCP on localhost:`port`."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _select_challenge(requested: str) -> str:
    """Resolve `--challenge`. `auto` prefers TLS-ALPN-01 (no port-80 takeover).

    DNS-01 is intentionally never selected — it is invalid for IP
    identifiers (RFC 8738) and this command certifies an IP.
    """
    if requested in (CHALLENGE_HTTP01, CHALLENGE_TLS_ALPN01):
        return requested
    if requested != "auto":
        raise ValueError(f"unknown challenge {requested!r}")
    # Standalone challenges need to *be* the listener on their port; pick
    # the one whose port is free. Prefer 443/TLS-ALPN-01.
    if not _has_listener(443):
        return CHALLENGE_TLS_ALPN01
    if not _has_listener(80):
        return CHALLENGE_HTTP01
    return CHALLENGE_TLS_ALPN01


# --- PTR verification ---------------------------------------------------

def _verify_ptr(
    ip: str, domain: str, *, nameserver: str | None
) -> tuple[str, list[str]]:
    """Confirm the reverse zone maps `ip` to `domain`; return (name, targets).

    Raises ValueError if no PTR is published or none of the targets match
    `domain` (case- and trailing-dot-insensitive).
    """
    name = reverse_name_for_ip(ip)
    if nameserver:
        host, _, port_str = nameserver.partition(":")
        port = int(port_str) if port_str else 53
        transport = DnsTransport(nameservers=[host], port=port)
    else:
        transport = DnsTransport()
    try:
        targets = transport.query(name, "PTR")
    except dns.exception.DNSException as e:
        where = nameserver or "the system resolver"
        raise RuntimeError(
            f"PTR lookup for {name} via {where} failed: {e}"
        ) from e

    def norm(s: str) -> str:
        return s.rstrip(".").lower()

    if not targets:
        raise ValueError(f"no PTR record at {name}")
    if norm(domain) not in {norm(t) for t in targets}:
        joined = ", ".join(targets)
        raise ValueError(
            f"PTR at {name} is {joined}, not {domain}; the reverse zone does "
            f"not map this address to the domain"
        )
    return name, targets


# --- anchor-day selection -----------------------------------------------

def _pick_anchor_day(
    not_before: _dt.datetime,
    not_after: _dt.datetime,
    requested: _dt.datetime | None,
) -> _dt.date:
    """Choose an anchor day inside [not_before, not_after] that is not future.

    Per the spec, `day_count` may be *any* day the issuer held the prefix,
    not necessarily the issuance day — so a short-lived cert window is a
    perfectly good anchor. We pick today when it falls in the window,
    else clamp to the window while refusing a future day.
    """
    today = _dt.datetime.now(_dt.timezone.utc)
    start, end = not_before.date(), not_after.date()
    if requested is not None:
        d = requested.date()
        if not start <= d <= end:
            raise ValueError(
                f"--day {d.isoformat()} is outside the certificate window "
                f"{start.isoformat()}..{end.isoformat()}"
            )
        if requested.date() > today.date():
            raise ValueError(f"--day {d.isoformat()} is in the future")
        return d
    chosen = min(today, not_after).date()
    if chosen < start:
        raise ValueError(
            f"certificate window {start.isoformat()}..{end.isoformat()} "
            f"contains no non-future day to anchor to"
        )
    return chosen


# --- UUID document ------------------------------------------------------

def _build_document(
    ru: RUUID,
    *,
    ip: str,
    domain: str,
    anchor_day: _dt.date,
    day_count: int,
    ski: str,
    jwk: dict,
    ptr_name: str,
    ptr_targets: list[str],
    verified_at: str,
    ip_cert: CertInfo,
    domain_cert: CertInfo | None,
) -> dict:
    """Build the CID UUID document committing to the genesis key + proof."""
    did = f"did:uuid:{ru}"
    proof_endpoint = {
        "profile": "CTAnchoredGenesisProof",
        "ipAddress": ip,
        "domain": domain,
        "anchorDay": anchor_day.isoformat(),
        "dayCount": day_count,
        "subjectKeyIdentifier": ski,
        "ptr": {
            "name": ptr_name,
            "targets": ptr_targets,
            "verifiedAt": verified_at,
        },
        "ipCertificate": ip_cert.as_dict(),
        "domainCertificate": domain_cert.as_dict() if domain_cert else None,
    }
    return {
        "@context": [
            "https://www.w3.org/ns/cid/v1",
            "https://www.w3.org/ns/did/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#genesis-key",
                "type": "JsonWebKey",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [f"{did}#genesis-key"],
        "assertionMethod": [f"{did}#genesis-key"],
        "service": [
            {
                "id": f"{did}#ct-genesis-proof",
                "type": "CTAnchoredGenesisProof",
                "serviceEndpoint": proof_endpoint,
            }
        ],
    }


# --- the command --------------------------------------------------------

def seal(
    address: str,
    domain: str,
    *,
    type_id: int = 0,
    day: _dt.datetime | None = None,
    out_dir: Path | str | None = None,
    production: bool = False,
    challenge: str = "auto",
    webroot: str | None = None,
    domain_cert: bool = True,
    nameserver: str | None = None,
    acme_path: str | None = None,
    acme_runner: AcmeRunner | None = None,
) -> SealResult:
    """Establish a CT-anchored genesis proof for an RUUID; see module docstring.

    Verifies the PTR, has acme.sh issue the IP-SAN cert (which also
    generates the EC genesis key), issues an optional same-key dNSName cert
    for the domain, mints an RUUID whose `day_count` falls inside the IP
    cert's window, and writes the key, certs, a committing UUID document,
    and a `seal.json` manifest into `out_dir` (default
    `~/.ruuid/seals/<uuid>/`).

    Raises:
        ValueError: the address is unresolvable, the PTR does not map the
            address to `domain`, or `--day` falls outside the cert window.
        RuntimeError: a required tool (openssl / acme.sh) is missing, or a
            tool invocation failed.
    """
    openssl = _require("openssl")
    ip = to_ip(address)
    family = ipaddress.ip_address(ip).version
    staging = not production
    # Webroot always uses HTTP-01 (the running web server serves the token);
    # it takes precedence over --challenge and skips the standalone port probe.
    chosen_challenge = CHALLENGE_HTTP01 if webroot else _select_challenge(challenge)

    # 1. PTR — reverse zone maps the IP to the domain, right now.
    ptr_name, ptr_targets = _verify_ptr(ip, domain, nameserver=nameserver)
    verified_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

    # Resolve the ACME runner (skip the acme.sh lookup when one is injected).
    if acme_runner is None:
        resolved = _resolve_acme(acme_path)
        acme_runner = lambda req: _run_acme_sh(req, acme_path=resolved)  # noqa: E731

    # 2-3. Certificates — worked in a temp dir, then copied into the final
    # out_dir once the RUUID (and thus the default path) is known. The IP
    # cert is issued by acme.sh, which also generates the EC genesis key and
    # writes it to key_path; the domain cert then reuses that key via a CSR
    # so both certs share one SKI.
    with tempfile.TemporaryDirectory(prefix="ruuid-seal-") as tmp:
        tmpd = Path(tmp)
        key_path = tmpd / "key.pem"

        ip_cert_path = tmpd / "ip-cert.pem"
        acme_runner(AcmeRequest(
            mode="issue", key_path=key_path, cert_out=ip_cert_path,
            identifier=ip, is_ip=True, challenge=chosen_challenge,
            staging=staging, profile=SHORTLIVED_PROFILE, webroot=webroot,
        ))
        ip_info = _cert_info(openssl, ip_cert_path, kind="ip", identifier=ip)

        domain_info: CertInfo | None = None
        domain_csr: Path | None = None
        domain_cert_path: Path | None = None
        if domain_cert:
            domain_csr = tmpd / "domain.csr"
            _openssl_csr(
                openssl, key_path, domain_csr, san=f"DNS:{domain}", cn=domain
            )
            domain_cert_path = tmpd / "domain-cert.pem"
            acme_runner(AcmeRequest(
                mode="signcsr", key_path=key_path, csr_path=domain_csr,
                cert_out=domain_cert_path, identifier=domain, is_ip=False,
                challenge=chosen_challenge, staging=staging, profile=None,
                webroot=webroot,
            ))
            domain_info = _cert_info(
                openssl, domain_cert_path, kind="domain", identifier=domain
            )

        # 4. Anchor day inside the IP cert window; mint the RUUID.
        anchor_day = _pick_anchor_day(
            ip_info.not_before, ip_info.not_after, day
        )
        anchor_dt = _dt.datetime(
            anchor_day.year, anchor_day.month, anchor_day.day,
            tzinfo=_dt.timezone.utc,
        )
        ru = new_ruuid(ip, type_id=type_id, day=anchor_dt)
        day_count = ru.identifier >> SEQUENCE_BITS

        jwk = _ec_public_jwk(
            openssl, key_path, kid=ip_info.subject_key_identifier
        )
        document = _build_document(
            ru, ip=ip, domain=domain, anchor_day=anchor_day,
            day_count=day_count, ski=ip_info.subject_key_identifier, jwk=jwk,
            ptr_name=ptr_name, ptr_targets=ptr_targets, verified_at=verified_at,
            ip_cert=ip_info, domain_cert=domain_info,
        )

        # 5-6. Persist everything into the final directory.
        if out_dir is None:
            final = Path.home() / ".ruuid" / "seals" / str(ru)
        else:
            final = Path(out_dir)
        final.mkdir(parents=True, exist_ok=True)
        # The genesis private key is the root of authority — keep it and its
        # directory owner-only.
        try:
            final.chmod(0o700)
        except OSError:
            pass

        key_dst = final / "key.pem"
        shutil.copy(key_path, key_dst)
        try:
            key_dst.chmod(0o600)
        except OSError:
            pass
        shutil.copy(ip_cert_path, final / "ip-cert.pem")
        ip_info = _replace_path(ip_info, final / "ip-cert.pem")
        if domain_info is not None and domain_csr and domain_cert_path:
            shutil.copy(domain_csr, final / "domain.csr")
            shutil.copy(domain_cert_path, final / "domain-cert.pem")
            domain_info = _replace_path(domain_info, final / "domain-cert.pem")

    manifest = {
        "ruuid": str(ru),
        "did": f"did:uuid:{ru}",
        "ip": ip,
        "domain": domain,
        "addressFamily": family,
        "createdAt": verified_at,
        "staging": staging,
        "acmeServer": ACME_SERVER_STAGING if staging else ACME_SERVER_PRODUCTION,
        "challenge": chosen_challenge,
        "webroot": webroot,
        "anchorDay": anchor_day.isoformat(),
        "dayCount": day_count,
        "typeId": type_id,
        "subjectKeyIdentifier": ip_info.subject_key_identifier,
        "ptr": {"name": ptr_name, "targets": ptr_targets},
        "ipCertificate": ip_info.as_dict(include_path=True),
        "domainCertificate": (
            domain_info.as_dict(include_path=True) if domain_info else None
        ),
        "artifacts": {
            "key": str(final / "key.pem"),
            "ipCert": str(final / "ip-cert.pem"),
            "domainCsr": str(final / "domain.csr") if domain_info else None,
            "domainCert": str(final / "domain-cert.pem") if domain_info else None,
            "document": str(final / "uuid-document.json"),
        },
    }

    (final / "uuid-document.json").write_text(json.dumps(document, indent=2) + "\n")
    (final / "seal.json").write_text(json.dumps(manifest, indent=2) + "\n")

    return SealResult(
        ruuid=ru, ip=ip, domain=domain, address_family=family, staging=staging,
        challenge=chosen_challenge, webroot=webroot,
        anchor_day=anchor_day, day_count=day_count,
        subject_key_identifier=ip_info.subject_key_identifier, ptr_name=ptr_name,
        ptr_targets=ptr_targets, ip_cert=ip_info, domain_cert=domain_info,
        out_dir=final, document=document, manifest=manifest,
    )


def _replace_path(info: CertInfo, path: Path) -> CertInfo:
    return CertInfo(
        kind=info.kind, identifier=info.identifier, path=path,
        subject_key_identifier=info.subject_key_identifier,
        not_before=info.not_before, not_after=info.not_after,
        serial=info.serial, fingerprint_sha256=info.fingerprint_sha256,
        scts=info.scts,
    )


# --- reporting ----------------------------------------------------------

def render_report(result: SealResult) -> str:
    """Human-readable summary of a seal, for the CLI."""
    lines = []
    env = "STAGING (untrusted; real CT logging requires --production)" \
        if result.staging else "PRODUCTION (real Let's Encrypt + CT)"
    lines.append(f"sealed:            {result.ruuid}")
    lines.append(f"did:               did:uuid:{result.ruuid}")
    lines.append(f"environment:       {env}")
    lines.append(f"ip:                {result.ip}")
    lines.append(f"domain:            {result.domain}")
    lines.append(
        f"ptr:               {result.ptr_name} -> "
        f"{', '.join(result.ptr_targets)}  (verified)"
    )
    challenge_line = result.challenge
    if result.webroot:
        challenge_line += f" (webroot {result.webroot})"
    lines.append(f"challenge:         {challenge_line}")
    lines.append(
        f"anchor day:        {result.anchor_day.isoformat()} "
        f"(day_count={result.day_count})"
    )
    lines.append(f"subject key id:    {result.subject_key_identifier}")
    ic = result.ip_cert
    lines.append(
        f"ip cert:           {ic.not_before.date().isoformat()}.."
        f"{ic.not_after.date().isoformat()}  serial {ic.serial}"
    )
    if result.domain_cert:
        dc = result.domain_cert
        lines.append(
            f"domain cert:       {dc.not_before.date().isoformat()}.."
            f"{dc.not_after.date().isoformat()}  serial {dc.serial}"
        )
    else:
        lines.append("domain cert:       (skipped)")
    lines.append(f"artifacts:         {result.out_dir}")
    return "\n".join(lines)
