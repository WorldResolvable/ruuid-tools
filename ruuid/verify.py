"""Experimental `ruuid verify` / `ruuid custody`: CT-based genesis verification.

Given an RUUID, recover from Certificate Transparency the key that controlled
the RUUID's network anchor on the day the RUUID encodes — the genesis proof
established by `ruuid seal` — and (optionally) confirm that a UUID document
commits that key.

The trust root is CT, keyed by the IP, not the document. crt.sh indexes the
`iPAddress` SAN, so:

    RUUID -> IP, day D
      -> crt.sh?q=IP                 every cert that has ever carried this IP
      -> keep those whose window covers D
      -> their public key IS the genesis key   (only the party who held the IP
                                                 on day D could hold such a cert;
                                                 CT is backdate-proof)

So `verify <ruuid>` alone reports the genuine controlling key and anchoring
timeline straight from CT; `verify <ruuid> <document>` additionally checks
that the document commits that key (rejecting an impostor document and
naming the genuine key).

Two artifacts, one core:

  - `gather_custody(ruuid, ct_source)` builds a **custody bundle** (JSON): the
    anchor/day and the CT certificates involved — the certs that carry the IP
    (which establish the genesis key) plus that key's forward timeline. This
    is what `custody` emits and freezes as `custody.json` — portable, cacheable
    evidence, so verification need not re-query a flaky live log.
  - `verify(ruuid, document, custody)` is a **pure function** over that bundle:
    recompute which certs establish the genesis key, then judge the document
    (or report the key when no document is given).

This is the **stage-1 (single-key)** verifier: one key from genesis to now,
which may have been re-anchored to other IPs/domains (they appear in the
timeline). Key rotation (a custody chain of endorsed generations) is a later
layer; the bundle already carries a `chain: [generation, ...]` array with a
single generation here, so that layer extends it without a schema break.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import ipaddress
import json
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ruuid.core import RUUID
from ruuid.generate import (
    SEQUENCE_BITS,
    STRUCTURED_IDENTIFIER_EPOCH,
    days_since_epoch,
)
from ruuid.seal import _run


# --- key identity -------------------------------------------------------

# DER SubjectPublicKeyInfo prefix for an EC P-256 public key, up to and
# including the 0x04 uncompressed-point marker; the 64 bytes of X||Y follow.
_P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
)


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def spki_sha256_from_jwk(jwk: dict) -> str:
    """SHA-256 of the SubjectPublicKeyInfo for an EC P-256 public JWK.

    Computed from the key's own coordinates, so it does not trust the JWK's
    `kid`.
    """
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 verification keys are supported")
    x = _b64u_decode(jwk["x"])
    y = _b64u_decode(jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("malformed P-256 public-key coordinates")
    der = _P256_SPKI_PREFIX + x + y
    return hashlib.sha256(der).hexdigest().upper()


def document_key(document: dict) -> dict:
    """Return the committed genesis public JWK from a UUID document."""
    vms = document.get("verificationMethod") or []
    if not vms or "publicKeyJwk" not in vms[0]:
        raise ValueError("document has no verificationMethod publicKeyJwk")
    return vms[0]["publicKeyJwk"]


# --- CT source ----------------------------------------------------------

@dataclass(frozen=True)
class CtCert:
    """A CT-logged certificate: its key, anchors (SANs), and validity window."""

    crtsh_id: int
    serial: str
    spki_sha256: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    ip_sans: tuple[str, ...]
    dns_sans: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "crtshId": self.crtsh_id,
            "serial": self.serial,
            "spkiSha256": self.spki_sha256,
            "notBefore": self.not_before.isoformat(),
            "notAfter": self.not_after.isoformat(),
            "ipSans": list(self.ip_sans),
            "dnsSans": list(self.dns_sans),
        }


@runtime_checkable
class CtSource(Protocol):
    """CT lookups: by IP-address SAN (the genesis root) and by key (SPKI)."""

    def certs_for_ip(self, ip: str) -> list[CtCert]: ...
    def certs_for_spki(self, spki_sha256: str) -> list[CtCert]: ...


class CrtShSource:
    """`CtSource` backed by crt.sh.

    crt.sh indexes both the `iPAddress` SAN (`?q=<ip>`) and the key's SPKI
    hash (`?spkisha256=`); neither response includes the full SAN set, so we
    fetch each certificate (`?d=<id>`) and parse it with openssl. crt.sh is
    flaky (intermittent non-JSON error pages), so every request is retried.
    """

    _IP_URL = "https://crt.sh/?q={ip}&output=json"
    _SPKI_URL = "https://crt.sh/?spkisha256={spki}&output=json"
    _PEM_URL = "https://crt.sh/?d={crtsh_id}"

    def __init__(
        self,
        *,
        retries: int = 6,
        timeout: float = 30.0,
        sleep: float = 4.0,
        openssl: str = "openssl",
    ) -> None:
        self._retries = retries
        self._timeout = timeout
        self._sleep = sleep
        self._openssl = openssl

    def _get(self, url: str, *, as_json: bool = False):
        last = None
        for attempt in range(self._retries):
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "ruuid-verify"}
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    body = resp.read()
                return json.loads(body) if as_json else body
            except Exception as e:  # network flake or non-JSON body
                last = e
                if attempt + 1 < self._retries:
                    time.sleep(self._sleep)
        raise RuntimeError(
            f"crt.sh request failed after {self._retries} tries ({url}): {last}"
        )

    def certs_for_ip(self, ip: str) -> list[CtCert]:
        return self._certs(self._get(self._IP_URL.format(ip=ip), as_json=True))

    def certs_for_spki(self, spki_sha256: str) -> list[CtCert]:
        return self._certs(
            self._get(self._SPKI_URL.format(spki=spki_sha256), as_json=True)
        )

    def _certs(self, entries) -> list[CtCert]:
        # crt.sh lists precertificate + final cert separately with the same
        # serial; fetch one per serial.
        by_serial: dict[str, int] = {}
        for e in entries:
            serial = (e.get("serial_number") or "").lower()
            if serial and serial not in by_serial:
                by_serial[serial] = e["id"]
        certs = [
            self._parse_cert(self._get(self._PEM_URL.format(crtsh_id=cid)), cid)
            for cid in by_serial.values()
        ]
        certs.sort(key=lambda c: c.not_before)
        return certs

    def _parse_cert(self, pem: bytes, crtsh_id: int) -> CtCert:
        import re
        fields = _run(
            [self._openssl, "x509", "-noout", "-serial", "-startdate", "-enddate"],
            input_bytes=pem,
        ).decode()
        vals: dict[str, str] = {}
        for line in fields.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                vals[k.strip()] = v.strip()
        san = _run(
            [self._openssl, "x509", "-noout", "-ext", "subjectAltName"],
            input_bytes=pem,
        ).decode()
        ip_sans = tuple(re.findall(r"IP Address:([0-9A-Fa-f:.]+)", san))
        dns_sans = tuple(re.findall(r"DNS:([^\s,]+)", san))
        pub = _run(
            [self._openssl, "x509", "-noout", "-pubkey"], input_bytes=pem
        )
        der = _run(
            [self._openssl, "pkey", "-pubin", "-outform", "DER"], input_bytes=pub
        )
        return CtCert(
            crtsh_id=crtsh_id,
            serial=vals.get("serial", ""),
            spki_sha256=hashlib.sha256(der).hexdigest().upper(),
            not_before=_parse_time(vals.get("notBefore", "")),
            not_after=_parse_time(vals.get("notAfter", "")),
            ip_sans=ip_sans,
            dns_sans=dns_sans,
        )


def _parse_time(value: str) -> _dt.datetime:
    s = value.split("=", 1)[-1].strip()
    if s.endswith(" GMT"):
        s = s[:-4]
    s = " ".join(s.split())
    return _dt.datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(
        tzinfo=_dt.timezone.utc
    )


# --- custody bundle -----------------------------------------------------

def anchor_ip(ru: RUUID) -> str:
    """The RUUID's network anchor as an IP string (the /32 host, or /64 base)."""
    return str(ru.ip_network.network_address)


def _day_count(ru: RUUID) -> int:
    return ru.identifier >> SEQUENCE_BITS


def _day_to_date(day_count: int) -> _dt.date:
    return (STRUCTURED_IDENTIFIER_EPOCH + _dt.timedelta(days=day_count)).date()


def _cert_is_genesis(cert: CtCert, ru: RUUID, day_count: int) -> bool:
    """True if `cert` carries the RUUID's IP with a window covering its day."""
    net = ru.ip_network
    if not any(_ip_in_network(s, net) for s in cert.ip_sans):
        return False
    start = days_since_epoch(cert.not_before)
    end = days_since_epoch(cert.not_after)
    return start <= day_count <= end


def gather_custody(ru: RUUID, ct_source: CtSource) -> dict:
    """Build the custody bundle for `ru` from CT — genesis by IP, plus timeline.

    Enumerates certs carrying the RUUID's IP (the genesis root), then follows
    each genesis key's SPHI for its full anchoring timeline (IP moves, domain
    certs). No document required.
    """
    ip = anchor_ip(ru)
    day_count = _day_count(ru)

    ip_certs = ct_source.certs_for_ip(ip)
    genesis_keys = sorted(
        {c.spki_sha256 for c in ip_certs if _cert_is_genesis(c, ru, day_count)}
    )
    by_serial = {c.serial: c for c in ip_certs}
    for spki in genesis_keys:
        for c in ct_source.certs_for_spki(spki):
            by_serial.setdefault(c.serial, c)
    certs = sorted(by_serial.values(), key=lambda c: c.not_before)

    return {
        "ruuid": str(ru),
        "network": str(ru.ip_network),
        "anchorIp": ip,
        "dayCount": day_count,
        "anchorDate": _day_to_date(day_count).isoformat(),
        "source": "crt.sh",
        "chain": [
            {
                "generation": 0,
                "role": "genesis",
                "endorsedBy": None,
                "certificates": [c.as_dict() for c in certs],
            }
        ],
    }


# --- verification -------------------------------------------------------

@dataclass(frozen=True)
class Anchoring:
    serial: str
    crtsh_id: int
    spki_sha256: str
    not_before: _dt.date
    not_after: _dt.date
    ip_sans: tuple[str, ...]
    dns_sans: tuple[str, ...]
    is_genesis: bool


@dataclass(frozen=True)
class VerifyResult:
    ruuid: str
    verified: bool
    reason: str
    anchor_ip: str
    anchor_date: _dt.date
    day_count: int
    genuine_keys: tuple[str, ...]        # keys that held the IP on day D (from CT)
    document_key: str | None             # SPKI committed by the document, if any
    genesis: Anchoring | None
    timeline: tuple[Anchoring, ...] = field(default_factory=tuple)


def verify(ru: RUUID, document: dict | None, custody: dict) -> VerifyResult:
    """Judge the RUUID's genesis against a custody bundle (pure).

    Recomputes, from the bundle's raw certificate data, which certs establish
    the genesis key (carry the RUUID's IP, window covers its day). Then:

      - with a document: VERIFIED iff the document commits one of those genesis
        keys (else it names the genuine key and rejects the document);
      - without a document: VERIFIED iff exactly one genesis key exists, which
        it reports (the "who controls this RUUID" answer straight from CT).
    """
    ip = anchor_ip(ru)
    day_count = _day_count(ru)
    anchor_date = _day_to_date(day_count)

    timeline: list[Anchoring] = []
    genesis_keys: list[str] = []
    genesis_by_key: dict[str, Anchoring] = {}
    for cert in (custody.get("chain") or [{}])[0].get("certificates") or []:
        try:
            nb = _dt.datetime.fromisoformat(cert["notBefore"])
            na = _dt.datetime.fromisoformat(cert["notAfter"])
        except (KeyError, ValueError):
            continue
        ip_sans = tuple(cert.get("ipSans") or [])
        spki = cert.get("spkiSha256", "")
        c = CtCert(
            crtsh_id=cert.get("crtshId", 0), serial=cert.get("serial", ""),
            spki_sha256=spki, not_before=nb, not_after=na,
            ip_sans=ip_sans, dns_sans=tuple(cert.get("dnsSans") or []),
        )
        is_gen = _cert_is_genesis(c, ru, day_count)
        anchoring = Anchoring(
            serial=c.serial, crtsh_id=c.crtsh_id, spki_sha256=spki,
            not_before=nb.date(), not_after=na.date(),
            ip_sans=ip_sans, dns_sans=c.dns_sans, is_genesis=is_gen,
        )
        timeline.append(anchoring)
        if is_gen and spki not in genesis_by_key:
            genesis_keys.append(spki)
            genesis_by_key[spki] = anchoring

    doc_key = None
    if document is not None:
        doc_key = spki_sha256_from_jwk(document_key(document))

    def make(verified, reason, genesis):
        return VerifyResult(
            ruuid=str(ru), verified=verified, reason=reason, anchor_ip=ip,
            anchor_date=anchor_date, day_count=day_count,
            genuine_keys=tuple(genesis_keys), document_key=doc_key,
            genesis=genesis, timeline=tuple(timeline),
        )

    if not genesis_keys:
        return make(
            False,
            f"no CT-logged certificate carries {ip} with a window covering "
            f"{anchor_date.isoformat()} (day_count {day_count}) — no genesis",
            None,
        )

    if document is not None:
        if doc_key in genesis_by_key:
            g = genesis_by_key[doc_key]
            return make(
                True,
                f"document commits the genesis key controlling {ip} on "
                f"{anchor_date.isoformat()} (CT cert serial {g.serial})",
                g,
            )
        return make(
            False,
            f"document commits {doc_key}, but the genesis key for {ip} on "
            f"{anchor_date.isoformat()} is {', '.join(genesis_keys)} "
            f"(CT cert serial {genesis_by_key[genesis_keys[0]].serial}) — "
            f"wrong or impostor document",
            None,
        )

    # No document: report the genuine key from CT.
    if len(genesis_keys) == 1:
        g = genesis_by_key[genesis_keys[0]]
        return make(
            True,
            f"{ip} on {anchor_date.isoformat()} is controlled by key "
            f"{genesis_keys[0]} (CT cert serial {g.serial})",
            g,
        )
    return make(
        False,
        f"ambiguous: multiple keys held {ip} on {anchor_date.isoformat()} "
        f"({', '.join(genesis_keys)}); supply the document to disambiguate",
        None,
    )


def _ip_in_network(ip_str: str, network) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


def verify_ruuid(
    ru: RUUID,
    document: dict | None = None,
    *,
    custody: dict | None = None,
    ct_source: CtSource | None = None,
) -> tuple[VerifyResult, dict]:
    """Verify, building the custody bundle from CT when one isn't supplied."""
    if custody is None:
        if ct_source is None:
            ct_source = CrtShSource()
        custody = gather_custody(ru, ct_source)
    return verify(ru, document, custody), custody


# --- reporting ----------------------------------------------------------

def render(result: VerifyResult) -> str:
    lines = []
    verdict = "VERIFIED" if result.verified else "NOT VERIFIED"
    lines.append(f"ruuid:        {result.ruuid}")
    lines.append(
        f"anchor:       {result.anchor_ip}  on {result.anchor_date.isoformat()} "
        f"(day_count {result.day_count})"
    )
    if result.genuine_keys:
        lines.append(f"genesis key(s) in CT: {', '.join(result.genuine_keys)}")
    if result.document_key is not None:
        lines.append(f"document commits key: {result.document_key}")
    lines.append(f"verdict:      {verdict} — {result.reason}")
    if result.timeline:
        lines.append("anchoring timeline (from CT):")
        for a in result.timeline:
            sans = ", ".join(list(a.ip_sans) + list(a.dns_sans))
            mark = "  <= genesis" if a.is_genesis else ""
            lines.append(
                f"  {a.not_before.isoformat()}..{a.not_after.isoformat()}  "
                f"{sans}  (crt.sh#{a.crtsh_id}){mark}"
            )
    return "\n".join(lines)
