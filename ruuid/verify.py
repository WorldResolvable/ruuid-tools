"""Experimental `ruuid verify` / `ruuid custody`: CT-based genesis verification.

Given an RUUID and its committed key (from the UUID document), confirm in
Certificate Transparency that the key controlled the RUUID's network anchor
on the day the RUUID encodes — i.e. that the CT-anchored genesis proof
established by `ruuid seal` holds.

Two artifacts, one core:

  - `gather_custody(ruuid, document, ct_source)` builds a **custody bundle**
    (a JSON dict): the RUUID's anchor/day, the committed key, and every
    CT-logged certificate that key has (its full anchoring timeline). This
    is what the `custody` command emits and freezes as `custody.json` — the
    portable, cacheable evidence, so verification need not re-query a flaky
    live log.
  - `verify(ruuid, document, custody)` is a **pure function** over that
    bundle: check the custody is for the document's key, then find a
    CT-logged certificate carrying the RUUID's IP whose validity window
    covers the RUUID's day. `verify` builds the bundle from CT if none is
    supplied.

This is the **stage-1 (single-key)** verifier: it assumes one key from
genesis to now — no key rotation, though the key may have been re-anchored
to new IPs/domains over time (all provable from CT under the one key). Key
rotation (a custody *chain* of endorsed generations) is a later layer; the
bundle already carries a `chain: [generation, ...]` array with a single
generation here, so that layer extends it without a schema break.

The known trust boundary: the key is taken from the document's claim (crt.sh
cannot be queried by IP, only by the key's SPKI hash), so `verify` confirms
"the document's key controlled the anchor on day D," not "this is the only
possible key." The bundle records exactly which certificates were used, so
the judgement is auditable.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import ipaddress
import json
import re
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
from ruuid.seal import _parse_openssl_time, _require, _run


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

    This is the CT discovery handle (crt.sh `?spkisha256=`). Computed from
    the key's own coordinates, so it does not trust the JWK's `kid`.
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
    """A CT-logged certificate for a key: its anchors (SANs) and window."""

    crtsh_id: int
    serial: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    ip_sans: tuple[str, ...]
    dns_sans: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "crtshId": self.crtsh_id,
            "serial": self.serial,
            "notBefore": self.not_before.isoformat(),
            "notAfter": self.not_after.isoformat(),
            "ipSans": list(self.ip_sans),
            "dnsSans": list(self.dns_sans),
        }


@runtime_checkable
class CtSource(Protocol):
    """Returns every CT-logged certificate carrying a given public key."""

    def certs_for_spki(self, spki_sha256: str) -> list[CtCert]: ...


class CrtShSource:
    """`CtSource` backed by crt.sh.

    crt.sh cannot be searched by IP SAN, only by the key's SPKI hash
    (`?spkisha256=`), and that response does not include the SANs — so we
    fetch each certificate (`?d=<id>`) and parse its SANs/window with
    openssl. crt.sh is flaky, so JSON reads are retried.
    """

    _JSON_URL = "https://crt.sh/?spkisha256={spki}&output=json"
    _PEM_URL = "https://crt.sh/?d={crtsh_id}"

    def __init__(
        self,
        *,
        retries: int = 5,
        timeout: float = 30.0,
        sleep: float = 4.0,
        openssl: str | None = None,
    ) -> None:
        self._retries = retries
        self._timeout = timeout
        self._sleep = sleep
        self._openssl = openssl or _require("openssl")

    def _get(self, url: str, *, as_json: bool = False):
        """Fetch `url`, retrying — crt.sh is flaky and may 200 an HTML error."""
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

    def certs_for_spki(self, spki_sha256: str) -> list[CtCert]:
        entries = self._get(self._JSON_URL.format(spki=spki_sha256), as_json=True)
        # crt.sh lists the precertificate and the final cert separately with
        # the same serial; keep one crt.sh id per serial.
        by_serial: dict[str, int] = {}
        for e in entries:
            serial = (e.get("serial_number") or "").lower()
            if serial and serial not in by_serial:
                by_serial[serial] = e["id"]

        certs: list[CtCert] = []
        for serial, crtsh_id in by_serial.items():
            pem = self._get(self._PEM_URL.format(crtsh_id=crtsh_id))
            certs.append(self._parse_cert(pem, crtsh_id))  # pem is bytes
        certs.sort(key=lambda c: c.not_before)
        return certs

    def _parse_cert(self, pem: bytes, crtsh_id: int) -> CtCert:
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
        return CtCert(
            crtsh_id=crtsh_id,
            serial=vals.get("serial", ""),
            not_before=_parse_openssl_time(vals.get("notBefore", "")),
            not_after=_parse_openssl_time(vals.get("notAfter", "")),
            ip_sans=ip_sans,
            dns_sans=dns_sans,
        )


# --- custody bundle -----------------------------------------------------

def anchor_ip(ru: RUUID) -> str:
    """The RUUID's network anchor as an IP string (the /32 host, or /64 base)."""
    return str(ru.ip_network.network_address)


def gather_custody(ru: RUUID, document: dict, ct_source: CtSource) -> dict:
    """Build the custody bundle for `ru` from CT via the document's key.

    Stage 1: a single generation (the one committed key) whose
    `certificates` are the key's full CT anchoring timeline.
    """
    jwk = document_key(document)
    spki = spki_sha256_from_jwk(jwk)
    certs = ct_source.certs_for_spki(spki)
    day_count = days_since_epoch(_anchor_datetime(ru))
    return {
        "ruuid": str(ru),
        "network": str(ru.ip_network),
        "anchorIp": anchor_ip(ru),
        "dayCount": day_count,
        "anchorDate": _day_to_date(day_count).isoformat(),
        "source": "crt.sh",
        "chain": [
            {
                "generation": 0,
                "role": "genesis",
                "spkiSha256": spki,
                "publicKeyJwk": jwk,
                "endorsedBy": None,
                "certificates": [c.as_dict() for c in certs],
            }
        ],
    }


def _anchor_datetime(ru: RUUID) -> _dt.datetime:
    day_count = ru.identifier >> SEQUENCE_BITS
    return STRUCTURED_IDENTIFIER_EPOCH + _dt.timedelta(days=day_count)


def _day_to_date(day_count: int) -> _dt.date:
    return (STRUCTURED_IDENTIFIER_EPOCH + _dt.timedelta(days=day_count)).date()


# --- verification -------------------------------------------------------

@dataclass(frozen=True)
class Anchoring:
    """One certificate in the key's timeline, as seen by the verifier."""

    serial: str
    crtsh_id: int
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
    spki_sha256: str
    genesis: Anchoring | None
    timeline: tuple[Anchoring, ...] = field(default_factory=tuple)


def verify(ru: RUUID, document: dict, custody: dict) -> VerifyResult:
    """Check the RUUID's genesis proof against a custody bundle (pure).

    Stage 1 (single key): confirm the bundle is for the document's committed
    key, then find a certificate in the (single) generation carrying the
    RUUID's IP whose validity window covers the RUUID's day. The key may
    have been re-anchored to other IPs/domains — those appear in the
    timeline but are not required for the verdict.
    """
    jwk = document_key(document)
    spki = spki_sha256_from_jwk(jwk)
    ip = anchor_ip(ru)
    network = ru.ip_network
    day_count = ru.identifier >> SEQUENCE_BITS
    anchor_date = _day_to_date(day_count)

    def result(verified: bool, reason: str,
               genesis: Anchoring | None, timeline: tuple[Anchoring, ...]):
        return VerifyResult(
            ruuid=str(ru), verified=verified, reason=reason, anchor_ip=ip,
            anchor_date=anchor_date, day_count=day_count, spki_sha256=spki,
            genesis=genesis, timeline=timeline,
        )

    chain = custody.get("chain") or []
    if not chain:
        return result(False, "custody bundle has no chain", None, ())
    gen0 = chain[0]
    if gen0.get("spkiSha256") != spki:
        return result(
            False,
            "custody bundle is for a different key than the document commits "
            f"({gen0.get('spkiSha256')} vs {spki})",
            None, (),
        )

    timeline: list[Anchoring] = []
    genesis: Anchoring | None = None
    for cert in gen0.get("certificates") or []:
        try:
            nb = _dt.datetime.fromisoformat(cert["notBefore"])
            na = _dt.datetime.fromisoformat(cert["notAfter"])
        except (KeyError, ValueError):
            continue
        ip_sans = tuple(cert.get("ipSans") or [])
        covers_ip = any(
            _ip_in_network(s, network) for s in ip_sans
        )
        start = days_since_epoch(nb)
        end = days_since_epoch(na)
        covers_day = start <= day_count <= end
        is_genesis = covers_ip and covers_day
        anchoring = Anchoring(
            serial=cert.get("serial", ""),
            crtsh_id=cert.get("crtshId", 0),
            not_before=nb.date(),
            not_after=na.date(),
            ip_sans=ip_sans,
            dns_sans=tuple(cert.get("dnsSans") or []),
            is_genesis=is_genesis,
        )
        timeline.append(anchoring)
        if is_genesis and genesis is None:
            genesis = anchoring

    if genesis is None:
        return result(
            False,
            f"no CT-logged certificate for the committed key carries {ip} "
            f"with a validity window covering {anchor_date.isoformat()} "
            f"(day_count {day_count})",
            None, tuple(timeline),
        )
    return result(
        True,
        f"key controlled {ip} on {anchor_date.isoformat()} "
        f"(CT cert serial {genesis.serial})",
        genesis, tuple(timeline),
    )


def _ip_in_network(ip_str: str, network) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


def verify_ruuid(
    ru: RUUID,
    document: dict,
    *,
    custody: dict | None = None,
    ct_source: CtSource | None = None,
) -> tuple[VerifyResult, dict]:
    """Verify, building the custody bundle from CT when one isn't supplied.

    Returns `(result, custody)` so callers can persist the gathered bundle.
    """
    if custody is None:
        if ct_source is None:
            ct_source = CrtShSource()
        custody = gather_custody(ru, document, ct_source)
    return verify(ru, document, custody), custody


# --- reporting ----------------------------------------------------------

def render(result: VerifyResult) -> str:
    lines = []
    verdict = "VERIFIED" if result.verified else "NOT VERIFIED"
    lines.append(f"ruuid:        {result.ruuid}")
    lines.append(f"anchor:       {result.anchor_ip}  on {result.anchor_date.isoformat()} "
                 f"(day_count {result.day_count})")
    lines.append(f"committed key: {result.spki_sha256}")
    lines.append(f"verdict:      {verdict} — {result.reason}")
    if result.timeline:
        lines.append("key anchoring timeline (from CT, one key):")
        for a in result.timeline:
            sans = ", ".join(list(a.ip_sans) + list(a.dns_sans))
            mark = "  <= genesis" if a.is_genesis else ""
            lines.append(
                f"  {a.not_before.isoformat()}..{a.not_after.isoformat()}  "
                f"{sans}  (crt.sh#{a.crtsh_id}){mark}"
            )
    return "\n".join(lines)
