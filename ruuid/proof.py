"""Self-authenticating UUID documents: a `proof` signed by the committed key.

A UUID document commits a key (its `verificationMethod`); a `proof` binds the
document's *content* to that key, so an attacker can't wrap the genuine public
key around malicious content. Verification is then: the committed key is
CT-authorised (genesis/chain), AND the document's proof is a valid signature by
it. This makes the document self-authenticating and transport-independent, like
the custody bundle.

Simplified W3C Data-Integrity profile: the proof value is an ECDSA-P256/SHA-256
signature over the JCS-canonicalised document with the `proof` field removed.
(For the string-valued CID documents here, sorted compact JSON == JCS.) Uses
openssl — no `cryptography` dependency — so the check runs in the core resolver.
"""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
from pathlib import Path

# SubjectPublicKeyInfo prefix for an uncompressed P-256 point (same constant the
# spki computation uses): the DER up to the 0x04 || X || Y public point.
_P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
)

PROOF_TYPE = "DataIntegrityProof"
PROOF_CRYPTOSUITE = "ecdsa-jcs-2019"


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def canonicalize(document: dict) -> bytes:
    """Canonical bytes of the document with any `proof` removed (JCS profile)."""
    body = {k: v for k, v in document.items() if k != "proof"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _jwk_public_pem(jwk: dict) -> str:
    x = _b64u_decode(jwk["x"])
    y = _b64u_decode(jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("committed key is not a P-256 public point")
    der = _P256_SPKI_PREFIX + x + y
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n"


def _committed_jwk(document: dict, vm_id: str | None) -> dict | None:
    vms = document.get("verificationMethod")
    if not isinstance(vms, list) or not vms:
        return None
    chosen = None
    if vm_id is not None:
        chosen = next((m for m in vms if isinstance(m, dict) and m.get("id") == vm_id), None)
    if chosen is None:
        chosen = vms[0]
    jwk = chosen.get("publicKeyJwk") if isinstance(chosen, dict) else None
    return jwk if isinstance(jwk, dict) else None


def document_verification_method_id(document: dict) -> str | None:
    vms = document.get("verificationMethod")
    if isinstance(vms, list) and vms and isinstance(vms[0], dict):
        return vms[0].get("id")
    return None


def sign_document(
    document: dict,
    key_path: "Path | str",
    *,
    created: str,
    openssl: str = "openssl",
) -> dict:
    """Return `document` with a `proof` signed by `key_path` (an EC P-256 key).

    The proof's `verificationMethod` is the document's first
    `verificationMethod` id — i.e. the document is signed by the key it commits.
    """
    vm_id = document_verification_method_id(document)
    doc = {k: v for k, v in document.items() if k != "proof"}
    sig = subprocess.run(
        [openssl, "dgst", "-sha256", "-sign", str(key_path)],
        input=canonicalize(doc), capture_output=True, check=True,
    ).stdout
    doc["proof"] = {
        "type": PROOF_TYPE,
        "cryptosuite": PROOF_CRYPTOSUITE,
        "created": created,
        "verificationMethod": vm_id,
        "proofPurpose": "assertionMethod",
        "proofValue": _b64u_encode(sig),
    }
    return doc


def verify_document_proof(document: dict, *, openssl: str = "openssl") -> bool | None:
    """Verify a document's `proof` against its committed key.

    Returns None if the document carries no `proof` (unsigned), True if the
    proof is a valid signature by the committed key, False otherwise (present
    but invalid, malformed, or unverifiable).
    """
    proof = document.get("proof")
    if not isinstance(proof, dict) or "proofValue" not in proof:
        return None
    jwk = _committed_jwk(document, proof.get("verificationMethod"))
    if jwk is None:
        return False
    try:
        pem = _jwk_public_pem(jwk)
        sig = _b64u_decode(proof["proofValue"])
    except (ValueError, KeyError, TypeError):
        return False
    data = canonicalize(document)
    with tempfile.TemporaryDirectory(prefix="ruuid-proof-") as tmp:
        pub = Path(tmp) / "pub.pem"
        sigf = Path(tmp) / "sig.der"
        pub.write_text(pem)
        sigf.write_bytes(sig)
        proc = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(pub), "-signature", str(sigf)],
            input=data, capture_output=True,
        )
    return proc.returncode == 0
