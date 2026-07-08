"""Certificate Transparency SCT verification (RFC 6962).

Verifies the embedded Signed Certificate Timestamps in a certificate against a
bundled list of trusted CT-log public keys. A valid SCT is a log's unforgeable,
signed promise that *this exact certificate* was logged — so it proves the cert
really went through Certificate Transparency (and thus a real CA's validation),
**without trusting whoever handed you the certificate**. This is what lets a
resolver accept a custody bundle from an untrusted issuer: the certs become
self-authenticating, and crt.sh / the issuer drop out of the trust base (trust
moves to the CT log operators, where CT intends it).

The check is fully offline — it needs only the logs' public keys (bundled in
`ct_logs.json`), never a network call.

Requires the `cryptography` package (optional extra: ``pip install 'ruuid[sct]'``).
The heavy lifting — reconstructing the precertificate `tbsCertificate` the log
actually signed (RFC 6962 §3.2) — is done by `Certificate.tbs_precertificate_bytes`.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_LOG_LIST_PATH = Path(__file__).with_name("ct_logs.json")


class SctUnavailable(RuntimeError):
    """Raised when SCT verification can't run (the `cryptography` extra is absent)."""


def _require_cryptography():
    try:
        import cryptography  # noqa: F401
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise SctUnavailable(
            "SCT verification requires the 'cryptography' package; "
            "install it with:  pip install 'ruuid[sct]'"
        ) from e


@dataclass(frozen=True)
class SctResult:
    log_id_b64: str
    log_description: str | None    # None if the log isn't in the trusted list
    timestamp_ms: int
    verified: bool


@dataclass(frozen=True)
class CertSctVerification:
    """The per-SCT outcomes for one certificate."""

    scts: tuple[SctResult, ...]

    @property
    def verified_count(self) -> int:
        return sum(1 for s in self.scts if s.verified)

    @property
    def verified_operators(self) -> set[str]:
        return {s.log_description for s in self.scts
                if s.verified and s.log_description}

    @property
    def earliest_verified_ms(self) -> int | None:
        """Earliest verified SCT time — the backdate-proof log timestamp."""
        times = [s.timestamp_ms for s in self.scts if s.verified]
        return min(times) if times else None

    def ok(self, min_scts: int = 2) -> bool:
        """True if at least `min_scts` SCTs verify against trusted logs."""
        return self.verified_count >= min_scts


def load_log_list(path: Path | str | None = None) -> dict:
    """The trusted CT logs, keyed by base64 log id -> {description, operator, key}."""
    p = Path(path) if path is not None else _LOG_LIST_PATH
    return json.loads(p.read_text())["logs"]


def _timestamp_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    d = dt - _EPOCH
    return d.days * 86_400_000 + d.seconds * 1000 + d.microseconds // 1000


def _signed_data(sct, tbs_precert: bytes, issuer_key_hash: bytes) -> bytes:
    """The exact bytes the log signed, per RFC 6962 §3.2 (precert entry)."""
    exts = sct.extension_bytes or b""
    return (
        b"\x00"                                   # SCT version: v1
        b"\x00"                                   # signature_type: certificate_timestamp
        + _timestamp_ms(sct.timestamp).to_bytes(8, "big")
        + b"\x00\x01"                             # entry_type: precert_entry
        + issuer_key_hash                         # PreCert.issuer_key_hash (32 bytes)
        + len(tbs_precert).to_bytes(3, "big") + tbs_precert   # opaque tbs<uint24>
        + len(exts).to_bytes(2, "big") + exts     # CtExtensions<uint16>
    )


def verify_cert_scts(pem: bytes | str, *, log_list: dict | None = None) -> CertSctVerification:
    """Verify the embedded SCTs of the leaf certificate in `pem`.

    `pem` must be a full chain (leaf first, then the issuer) — the issuer's
    public key is needed to reconstruct what the log signed. Each SCT is checked
    against the bundled trusted logs; unknown logs count as unverified.
    """
    _require_cryptography()
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    logs = load_log_list() if log_list is None else log_list
    if isinstance(pem, str):
        pem = pem.encode()
    certs = x509.load_pem_x509_certificates(pem)
    if not certs:
        raise ValueError("no certificate found in PEM")
    leaf = certs[0]

    # No SCT extension -> no CT evidence at all (e.g. a fabricated cert). Bail
    # before touching tbs_precertificate_bytes, which requires the extension.
    try:
        sct_list = leaf.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        ).value
    except x509.ExtensionNotFound:
        return CertSctVerification(scts=())

    issuer = next((c for c in certs[1:] if c.subject == leaf.issuer), None)
    if issuer is None:
        raise ValueError(
            "issuer certificate not present in the chain — supply a full chain "
            "(leaf + issuer) so the precertificate can be reconstructed"
        )
    spki = issuer.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    issuer_key_hash = hashlib.sha256(spki).digest()
    tbs = leaf.tbs_precertificate_bytes

    results: list[SctResult] = []
    for sct in sct_list:
        log_id_b64 = base64.b64encode(sct.log_id).decode()
        log = logs.get(log_id_b64)
        verified = False
        if log is not None:
            pub = serialization.load_der_public_key(base64.b64decode(log["key"]))
            data = _signed_data(sct, tbs, issuer_key_hash)
            try:
                if isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(sct.signature, data, ec.ECDSA(hashes.SHA256()))
                elif isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(sct.signature, data, padding.PKCS1v15(), hashes.SHA256())
                else:  # pragma: no cover - CT logs are EC/RSA only
                    raise InvalidSignature("unsupported log key type")
                verified = True
            except InvalidSignature:
                verified = False
        results.append(SctResult(
            log_id_b64=log_id_b64,
            log_description=(log or {}).get("description"),
            timestamp_ms=_timestamp_ms(sct.timestamp),
            verified=verified,
        ))
    return CertSctVerification(scts=tuple(results))
