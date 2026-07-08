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
from pathlib import Path
from typing import Protocol, runtime_checkable

from ruuid.core import RUUID
from ruuid.generate import (
    SEQUENCE_BITS,
    STRUCTURED_IDENTIFIER_EPOCH,
    days_since_epoch,
)
from ruuid.seal import _run, spki_from_commitment_label


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
    # Full-chain PEM (leaf + issuer), carried in published bundles so a resolver
    # can verify the cert's SCTs itself rather than trusting the publisher.
    pem: str | None = None
    # Earliest verified SCT time (ms since epoch), set once SCTs are checked at
    # ingest; the backdate-proof anchor and the ordering key for earliest-wins.
    sct_timestamp_ms: int | None = None

    def as_dict(self) -> dict:
        d = {
            "crtshId": self.crtsh_id,
            "serial": self.serial,
            "spkiSha256": self.spki_sha256,
            "notBefore": self.not_before.isoformat(),
            "notAfter": self.not_after.isoformat(),
            "ipSans": list(self.ip_sans),
            "dnsSans": list(self.dns_sans),
        }
        if self.pem is not None:
            d["pem"] = self.pem
        if self.sct_timestamp_ms is not None:
            d["sctTimestampMs"] = self.sct_timestamp_ms
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CtCert":
        return cls(
            crtsh_id=d.get("crtshId", 0),
            serial=d.get("serial", ""),
            spki_sha256=d.get("spkiSha256", ""),
            not_before=_dt.datetime.fromisoformat(d["notBefore"]),
            not_after=_dt.datetime.fromisoformat(d["notAfter"]),
            ip_sans=tuple(d.get("ipSans") or []),
            dns_sans=tuple(d.get("dnsSans") or []),
            pem=d.get("pem"),
            sct_timestamp_ms=d.get("sctTimestampMs"),
        )

    def ordering_ms(self) -> int:
        """Earliest-wins key: the verified SCT time if known, else notBefore."""
        if self.sct_timestamp_ms is not None:
            return self.sct_timestamp_ms
        return int(self.not_before.timestamp() * 1000)


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
        return parse_cert_pem(pem, crtsh_id, openssl=self._openssl)


def parse_cert_pem(pem: bytes, crtsh_id: int = 0, *, openssl: str = "openssl") -> CtCert:
    """Parse a PEM certificate into a `CtCert` (serial, SPKI, window, SANs)."""
    import re
    fields = _run(
        [openssl, "x509", "-noout", "-serial", "-startdate", "-enddate"],
        input_bytes=pem,
    ).decode()
    vals: dict[str, str] = {}
    for line in fields.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip()
    san = _run(
        [openssl, "x509", "-noout", "-ext", "subjectAltName"], input_bytes=pem,
    ).decode()
    ip_sans = tuple(re.findall(r"IP Address:([0-9A-Fa-f:.]+)", san))
    dns_sans = tuple(re.findall(r"DNS:([^\s,]+)", san))
    pub = _run([openssl, "x509", "-noout", "-pubkey"], input_bytes=pem)
    der = _run([openssl, "pkey", "-pubin", "-outform", "DER"], input_bytes=pub)
    return CtCert(
        crtsh_id=crtsh_id,
        serial=vals.get("serial", ""),
        spki_sha256=hashlib.sha256(der).hexdigest().upper(),
        not_before=_parse_time(vals.get("notBefore", "")),
        not_after=_parse_time(vals.get("notAfter", "")),
        ip_sans=ip_sans,
        dns_sans=dns_sans,
    )


def _bundle_certs(obj: dict) -> list[CtCert]:
    """Extract CtCerts from a custody bundle, tolerating both the per-RUUID
    shape (`chain[*].certificates`) and a flat published shape
    (`certificates`)."""
    raw = list(obj.get("certificates") or [])
    for gen in obj.get("chain") or []:
        raw.extend(gen.get("certificates") or [])
    out = []
    for c in raw:
        try:
            out.append(CtCert.from_dict(c))
        except Exception:
            continue
    return out


class LocalBundleSource:
    """`CtSource` served from pre-downloaded custody bundles — no crt.sh.

    Point it at a directory of `*.json` custody bundles (e.g. a resolver's
    cache of issuers' published `uuid-custody.json` files), or a list of bundle
    files/dicts. It unions their certificates and answers `certs_for_ip` /
    `certs_for_spki` locally, so `verify` and `resolve --verify` run
    deterministically and offline against published evidence instead of the
    (flaky) live CT index.
    """

    def __init__(
        self, source: "Path | str | list", *,
        verify_scts: bool = False, min_scts: int = 2,
    ) -> None:
        self._certs_list: list[CtCert] = []
        paths: list[Path] = []
        if isinstance(source, (str, Path)):
            p = Path(source)
            paths = sorted(p.glob("*.json")) if p.is_dir() else [p]
        else:
            for item in source:
                if isinstance(item, dict):
                    self._certs_list.extend(_bundle_certs(item))
                else:
                    paths.append(Path(item))
        by_serial: dict[str, CtCert] = {}
        for path in paths:
            try:
                obj = json.loads(Path(path).read_text())
            except (OSError, ValueError):
                continue
            for c in _bundle_certs(obj):
                by_serial.setdefault(c.serial, c)
        for c in self._certs_list:
            by_serial.setdefault(c.serial, c)
        certs = list(by_serial.values())
        # SCT gate at ingest: an untrusted bundle's certs count only if their
        # embedded SCTs verify against trusted CT logs.
        self._certs_list = sct_gate(certs, min_scts=min_scts) if verify_scts else certs

    def all_certs(self) -> list[CtCert]:
        return list(self._certs_list)

    def certs_for_ip(self, ip: str) -> list[CtCert]:
        return [c for c in self._certs_list if ip in c.ip_sans]

    def certs_for_spki(self, spki_sha256: str) -> list[CtCert]:
        return [c for c in self._certs_list if c.spki_sha256 == spki_sha256]


def sct_gate(certs: list[CtCert], *, min_scts: int = 2, log_list=None) -> list[CtCert]:
    """Keep only certs whose embedded SCTs verify, stamping the SCT timestamp.

    Each kept cert must carry a full-chain PEM and have >= `min_scts` SCTs that
    verify against trusted CT logs; it is returned stamped with its earliest
    verified SCT time. Certs without a PEM, or that fail verification, are
    dropped — so a fabricated cert in an untrusted bundle can't establish a
    genesis or a chain hop. Requires the `cryptography` extra (raises
    SctUnavailable otherwise).
    """
    import dataclasses

    from ruuid.sct import verify_cert_scts

    kept: list[CtCert] = []
    for c in certs:
        if not c.pem:
            continue
        try:
            v = verify_cert_scts(c.pem, log_list=log_list)
        except ValueError:
            continue
        if v.ok(min_scts):
            kept.append(dataclasses.replace(c, sct_timestamp_ms=v.earliest_verified_ms))
    return kept


def _safe_name(s: str) -> str:
    return "".join(ch if (ch.isalnum() or ch in ".-_") else "_" for ch in s)


class CascadingSource:
    """A discovery cascade `CtSource`: local bundles -> the issuer's published
    bundle -> crt.sh.

    For public/decentralized intake, where you receive RUUIDs you have never
    seen and don't know who issued. On a local miss, it resolves the IP's
    domain (PTR) and GETs `https://<domain>/.well-known/uuid-custody.json`;
    that (self-authenticating) bundle is added to the pool and persisted, so
    an unknown issuer becomes locally known for every sibling RUUID
    thereafter. crt.sh is the final, cooperation-free fallback.

    Every layer is DISCOVERY only — verification still checks the certificates
    against the RUUID's own CT genesis and commitment chain — so a wrong or
    hostile issuer domain can only fail to help, never mislead. (Like the
    per-IP cache, a persisted bundle green-lights the genesis facts, which are
    immutable; a document committing a *newly* rotated key not yet in a
    persisted bundle re-fetches / falls through to crt.sh only if the local
    pool doesn't already reach it — force a refresh by clearing the dir.)
    """

    _WELL_KNOWN = "https://{domain}/.well-known/uuid-custody.json"

    def __init__(
        self,
        *,
        bundles_dir: "Path | str | None" = None,
        use_crtsh: bool = True,
        crtsh_source: "CtSource | None" = None,
        persist: bool = True,
        nameserver: str | None = None,
        timeout: float = 15.0,
        verify_scts: bool = False,
        min_scts: int = 2,
        resolve_domains=None,
        fetch=None,
    ) -> None:
        self._dir = (
            Path(bundles_dir) if bundles_dir is not None
            else Path.home() / ".ruuid" / "bundles"
        )
        self._verify_scts = verify_scts
        self._min_scts = min_scts
        self._pool: dict[str, CtCert] = {}
        if self._dir.exists():
            for c in self._gate(LocalBundleSource(self._dir).all_certs()):
                self._pool.setdefault(c.serial, c)
        self._crtsh = (
            crtsh_source if crtsh_source is not None
            else (CrtShSource() if use_crtsh else None)
        )
        self._persist = persist
        self._nameserver = nameserver
        self._timeout = timeout
        self._resolve_domains = resolve_domains or self._ptr_domains
        self._fetch = fetch or self._http_fetch
        self._tried_ips: set[str] = set()
        # Set once certs_for_ip is answered from a (complete) published bundle:
        # then a key absent from the pool is genuinely cold, not a crt.sh miss,
        # so we must NOT fall through to crt.sh for it (which would be a slow,
        # pointless lookup of a pinned successor that has no certs of its own).
        self._authoritative = False

    def _gate(self, certs: list[CtCert]) -> list[CtCert]:
        """SCT-gate bundle-sourced certs when verify_scts is on (crt.sh, the
        trusted index, is never gated — its results aren't pooled)."""
        return sct_gate(certs, min_scts=self._min_scts) if self._verify_scts else certs

    def _add(self, certs: list[CtCert]) -> None:
        for c in certs:
            self._pool.setdefault(c.serial, c)

    # The pool holds only whole published bundles (complete per key), so a
    # pool hit is authoritative. crt.sh is delegated live — it returns the
    # complete result per query — and is NOT merged into the pool, so a
    # partial crt.sh result can never short-circuit a later chain hop.
    def certs_for_ip(self, ip: str) -> list[CtCert]:
        got = [c for c in self._pool.values() if ip in c.ip_sans]  # 1. local
        if got:
            self._authoritative = True
            return got
        if ip not in self._tried_ips:                 # 2. the issuer's bundle
            self._tried_ips.add(ip)
            if self._fetch_issuer(ip):
                got = [c for c in self._pool.values() if ip in c.ip_sans]
                if got:
                    self._authoritative = True
                    return got
        self._authoritative = False
        if self._crtsh is not None:                   # 3. crt.sh (live)
            return self._crtsh.certs_for_ip(ip)
        return got

    def certs_for_spki(self, spki_sha256: str) -> list[CtCert]:
        got = [c for c in self._pool.values() if c.spki_sha256 == spki_sha256]
        if got:
            return got
        # A published bundle is complete for its chain: a key not in it is
        # genuinely cold, so don't chase it through crt.sh.
        if self._authoritative or self._crtsh is None:
            return got
        return self._crtsh.certs_for_spki(spki_sha256)

    def _fetch_issuer(self, ip: str) -> bool:
        for domain in self._resolve_domains(ip):
            body = self._fetch(self._WELL_KNOWN.format(domain=domain))
            if not body:
                continue
            try:
                obj = json.loads(body)
            except (ValueError, TypeError):
                continue
            certs = self._gate(_bundle_certs(obj))   # SCT-gate untrusted fetch
            if certs:
                self._add(certs)
                if self._persist:
                    self._save(_safe_name(domain), obj)
                return True
        return False

    def _ptr_domains(self, ip: str) -> list[str]:
        from ruuid.resolve import DnsTransport, reverse_name_for_ip
        ns, port = None, 53
        if self._nameserver:
            host, _, p = self._nameserver.partition(":")
            ns, port = [host], (int(p) if p else 53)
        try:
            answers = DnsTransport(nameservers=ns, port=port).query(
                reverse_name_for_ip(ip), "PTR"
            )
        except Exception:
            return []
        return [str(a).rstrip(".") for a in answers]

    def _http_fetch(self, uri: str):
        from ruuid.resolve import fetch_url_body
        try:
            return fetch_url_body(
                uri, nameserver=self._nameserver, timeout=self._timeout
            )
        except Exception:
            return None

    def _save(self, name: str, payload) -> None:
        if isinstance(payload, dict):
            obj = payload
        else:
            if not payload:
                return
            obj = {"kind": "uuid-custody",
                   "certificates": [c.as_dict() for c in payload]}
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            (self._dir / f"{name}.json").write_text(json.dumps(obj, indent=2) + "\n")
        except OSError:
            pass


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


# A custody chain is bounded, to stop a runaway / cyclic walk.
_MAX_GENERATIONS = 64


def _commitment_successor(cert: CtCert) -> str | None:
    """If `cert` is a pre-rotation commitment, the SPKI it pins, else None.

    A commitment certificate carries a dNSName whose leftmost label is a
    `commitment_label` (`k<base32>`) that decodes to a 32-byte SPKI.
    """
    for name in cert.dns_sans:
        spki = spki_from_commitment_label(name.split(".", 1)[0])
        if spki:
            return spki
    return None


def _earliest_successor(key: str, certs: list[CtCert]) -> str | None:
    """The successor `key` commits to, resolving forks by earliest cert.

    Among the certificates *under* `key`, the earliest commitment (by
    notBefore ≈ issuance/SCT time) wins — so a later fork published by a
    thief of `key` cannot override the genuine, pre-exposure commitment.
    """
    commits = []
    for c in certs:
        if c.spki_sha256 != key:
            continue
        succ = _commitment_successor(c)
        if succ:
            commits.append((c.ordering_ms(), succ))   # verified SCT time if known
    if not commits:
        return None
    commits.sort(key=lambda t: t[0])
    return commits[0][1]


def _activated(key: str, certs: list[CtCert]) -> bool:
    """True if `key` has acted in CT — i.e. some certificate is under it.

    A genesis key holds its IP cert; a rotated-in key publishes its own
    successor commitment (via `rotate`). A key that is only the *target* of a
    commitment (a pinned, still-cold successor) has no cert of its own and is
    not yet the current key.
    """
    return any(c.spki_sha256 == key for c in certs)


def _walk_chain(
    start: str, target: str | None, certs: list[CtCert]
) -> list[str] | None:
    """Follow the commitment chain from `start`.

    With a `target`, return the chain reaching it, or None. With
    `target=None`, walk to the chain's current tip and return the full chain.
    """
    chain = [start]
    seen = {start}
    cur = start
    for _ in range(_MAX_GENERATIONS):
        if target is not None and cur == target:
            return chain
        succ = _earliest_successor(cur, certs)
        if not succ or succ in seen:
            break
        chain.append(succ)
        seen.add(succ)
        cur = succ
    if target is None:
        return chain
    return chain if cur == target else None


def _fetch_certs(ru: RUUID, ct_source: CtSource) -> list[CtCert]:
    """Certs carrying the RUUID's IP (the genesis root), plus the forward
    custody chain — each key's certs, following its pre-rotation commitment
    to the next generation. Deduped by serial."""
    ip = anchor_ip(ru)
    day_count = _day_count(ru)
    ip_certs = ct_source.certs_for_ip(ip)
    by_serial = {c.serial: c for c in ip_certs}

    visited: set[str] = set()
    frontier = [c.spki_sha256 for c in ip_certs if _cert_is_genesis(c, ru, day_count)]
    while frontier and len(visited) < _MAX_GENERATIONS:
        key = frontier.pop()
        if key in visited:
            continue
        visited.add(key)
        key_certs = ct_source.certs_for_spki(key)
        for c in key_certs:
            by_serial.setdefault(c.serial, c)
        succ = _earliest_successor(key, key_certs)
        if succ and succ not in visited:
            frontier.append(succ)
    return sorted(by_serial.values(), key=lambda c: c.not_before)


def _merge_certs(a: list[CtCert], b: list[CtCert]) -> list[CtCert]:
    by_serial = {c.serial: c for c in a}
    for c in b:
        by_serial.setdefault(c.serial, c)
    return sorted(by_serial.values(), key=lambda c: c.not_before)


def _custody_bundle(ru: RUUID, certs: list[CtCert]) -> dict:
    day_count = _day_count(ru)
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
                "endorsedBy": None,
                "certificates": [c.as_dict() for c in certs],
            }
        ],
    }


def build_published_custody(seals_dir: Path | str) -> dict:
    """Aggregate an issuer's own on-disk certificates into a custody bundle.

    Walks `seals_dir` (default `~/.ruuid/seals`) for certificate files
    (`*-cert.pem` — never the `key.pem`/`next-key.pem` private keys) left by
    `seal`/`rotate`, and emits a flat, self-contained `uuid-custody.json`:

        { "kind": "uuid-custody", "generatedAt": ...,
          "domains": [...], "networks": [...], "certificates": [ ... ] }

    Publish it at e.g. `https://<domain>/.well-known/uuid-custody.json`. It
    needs no CT query — these certs are the CT-logged ones (they carry their
    own SCTs) — so an issuer serves its own evidence and resolvers verify off
    it, with crt.sh reduced to an independent-audit fallback.
    """
    import dataclasses

    root = Path(seals_dir)
    by_serial: dict[str, CtCert] = {}
    for pem in sorted(root.rglob("*-cert.pem")):
        try:
            body = pem.read_bytes()
            cert = parse_cert_pem(body)
        except (OSError, RuntimeError):
            continue
        # Carry the full-chain PEM so a resolver can verify this cert's SCTs
        # itself (trustless) rather than believing the distilled facts.
        cert = dataclasses.replace(cert, pem=body.decode("ascii", "replace"))
        by_serial.setdefault(cert.serial, cert)
    domains, networks = set(), set()
    for meta in list(root.rglob("seal.json")) + list(root.rglob("rotation.json")):
        try:
            d = json.loads(meta.read_text())
        except (OSError, ValueError):
            continue
        if d.get("domain"):
            domains.add(d["domain"])
        if d.get("network"):
            networks.add(d["network"])
    certs = sorted(by_serial.values(), key=lambda c: c.not_before)
    return {
        "kind": "uuid-custody",
        "generatedAt": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "domains": sorted(domains),
        "networks": sorted(networks),
        "certificates": [c.as_dict() for c in certs],
    }


def gather_custody(ru: RUUID, ct_source: CtSource) -> dict:
    """Build the custody bundle for `ru` from CT — genesis by IP, plus timeline.

    Enumerates certs carrying the RUUID's IP (the genesis root), then follows
    each genesis key's SPKI for its full anchoring timeline (IP moves, domain
    certs). No document required.
    """
    return _custody_bundle(ru, _fetch_certs(ru, ct_source))


class IpCertCache:
    """A permanent on-disk cache of the CT certificates for an IP.

    Genesis verification is a function of `(IP, day)`, and CT is append-only
    and backdate-proof, so a cached `(IP -> certs)` entry is an immutable
    historical fact — it never needs invalidation. One CT fetch per IP then
    green-lights every RUUID for that IP (any day the certs cover, any
    sequence) with a purely local check. Cache misses (an IP not seen, or a
    day no cached cert covers — possibly a newly sealed day) fall through to
    CT and merge the fresh certs back in.
    """

    def __init__(self, cache_dir: Path | str | None = None) -> None:
        self.dir = (
            Path(cache_dir) if cache_dir is not None
            else Path.home() / ".ruuid" / "ct-cache"
        )

    def _path(self, ip: str) -> Path:
        safe = ip.replace(":", "_").replace("/", "_")
        return self.dir / f"{safe}.json"

    def load(self, ip: str) -> list[CtCert] | None:
        path = self._path(ip)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return [CtCert.from_dict(c) for c in data.get("certificates", [])]
        except (OSError, ValueError, KeyError):
            return None

    def save(self, ip: str, certs: list[CtCert]) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self._path(ip).write_text(
                json.dumps(
                    {"ip": ip, "certificates": [c.as_dict() for c in certs]},
                    indent=2,
                )
                + "\n"
            )
        except OSError:
            pass


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
    chain: tuple[str, ...] = field(default_factory=tuple)  # genesis..document key


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

    certs: list[CtCert] = []
    timeline: list[Anchoring] = []
    genesis_keys: list[str] = []
    genesis_by_key: dict[str, Anchoring] = {}
    for cert in (custody.get("chain") or [{}])[0].get("certificates") or []:
        try:
            c = CtCert.from_dict(cert)   # carries pem + sctTimestampMs if present
        except (KeyError, ValueError):
            continue
        spki = c.spki_sha256
        certs.append(c)
        is_gen = _cert_is_genesis(c, ru, day_count)
        anchoring = Anchoring(
            serial=c.serial, crtsh_id=c.crtsh_id, spki_sha256=spki,
            not_before=c.not_before.date(), not_after=c.not_after.date(),
            ip_sans=c.ip_sans, dns_sans=c.dns_sans, is_genesis=is_gen,
        )
        timeline.append(anchoring)
        if is_gen and spki not in genesis_by_key:
            genesis_keys.append(spki)
            genesis_by_key[spki] = anchoring

    doc_key = None
    if document is not None:
        doc_key = spki_sha256_from_jwk(document_key(document))

    def make(verified, reason, genesis, chain=()):
        return VerifyResult(
            ruuid=str(ru), verified=verified, reason=reason, anchor_ip=ip,
            anchor_date=anchor_date, day_count=day_count,
            genuine_keys=tuple(genesis_keys), document_key=doc_key,
            genesis=genesis, timeline=tuple(timeline), chain=tuple(chain),
        )

    if not genesis_keys:
        return make(
            False,
            f"no CT-logged certificate carries {ip} with a window covering "
            f"{anchor_date.isoformat()} (day_count {day_count}) — no genesis",
            None,
        )

    if document is not None:
        # Base case: the document commits a genesis key directly.
        if doc_key in genesis_by_key:
            g = genesis_by_key[doc_key]
            return make(
                True,
                f"document commits the genesis key controlling {ip} on "
                f"{anchor_date.isoformat()} (CT cert serial {g.serial})",
                g, chain=(doc_key,),
            )
        # Rotated: the document commits a descendant — walk the custody chain
        # from a genesis key to it (earliest-commitment-wins at each hop).
        for gk in genesis_keys:
            ch = _walk_chain(gk, doc_key, certs)
            if ch is None:
                continue
            if _activated(doc_key, certs):
                return make(
                    True,
                    f"document commits {doc_key} — generation {len(ch) - 1} in "
                    f"the custody chain from genesis {gk} "
                    f"({' -> '.join(ch)})",
                    genesis_by_key[gk], chain=tuple(ch),
                )
            # Endorsed by the chain but still cold — the issuer must `rotate`
            # (which activates it in CT) before committing a document to it.
            return make(
                False,
                f"document commits {doc_key}, the pre-committed successor at "
                f"generation {len(ch) - 1} of genesis {gk}, but it has not been "
                f"activated in CT — run `rotate` to activate it before "
                f"publishing a document that commits it",
                None, chain=tuple(ch),
            )
        return make(
            False,
            f"document commits {doc_key}, which is neither the genesis key for "
            f"{ip} on {anchor_date.isoformat()} ({', '.join(genesis_keys)}) nor "
            f"a pre-committed successor of it in CT — wrong / impostor / "
            f"unendorsed key",
            None,
        )

    # No document: report the genuine key from CT (and, if it has rotated, the
    # current tip of the custody chain).
    if len(genesis_keys) == 1:
        gk = genesis_keys[0]
        g = genesis_by_key[gk]
        ch = _walk_chain(gk, None, certs) or [gk]  # follow the commitments
        # Drop a trailing pinned-but-not-yet-activated successor: the current
        # key is the last one that has actually acted in CT.
        while len(ch) > 1 and not _activated(ch[-1], certs):
            ch.pop()
        tip = ch[-1]
        if tip == gk:
            reason = (f"{ip} on {anchor_date.isoformat()} is controlled by key "
                      f"{gk} (CT cert serial {g.serial})")
        else:
            reason = (f"{ip} on {anchor_date.isoformat()} was genesis-controlled "
                      f"by {gk}; the custody chain's current key is {tip} "
                      f"({' -> '.join(ch)})")
        return make(True, reason, g, chain=tuple(ch))
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


# --- minting day-range (a resolver triage / disclaimer hint) ------------

def minting_day_range(document: dict) -> tuple[int, int] | None:
    """The inclusive `day_count` range a document asserts it mints in.

    Read from an optional top-level
    `"mintingDayRange": {"from": "YYYY-MM-DD", "to": "YYYY-MM-DD"}`. This is a
    controller's cooperative claim — a cached hint of the union of its CT
    certificate windows — used only as a routing/disclaimer signal (a resolved
    RUUID outside the range is disowned by the current controller); it is never
    a positive verdict (CT decides). Returns None when absent or malformed.
    """
    r = document.get("mintingDayRange")
    if not isinstance(r, dict):
        return None
    try:
        start = _dt.date.fromisoformat(r["from"])
        end = _dt.date.fromisoformat(r["to"])
    except (KeyError, ValueError, TypeError):
        return None
    epoch = STRUCTURED_IDENTIFIER_EPOCH.date()
    return ((start - epoch).days, (end - epoch).days)


def document_disclaims(document: dict, day_count: int) -> bool:
    """True if the document asserts a minting range that excludes `day_count`.

    A disclaim means the current controller says "this RUUID is not mine"
    (e.g. an honest successor after an IP transfer) — route to CT for the
    genuine controller.
    """
    rng = minting_day_range(document)
    return rng is not None and not (rng[0] <= day_count <= rng[1])


def verify_ruuid(
    ru: RUUID,
    document: dict | None = None,
    *,
    custody: dict | None = None,
    ct_source: CtSource | None = None,
    cache: "IpCertCache | None" = None,
) -> tuple[VerifyResult, dict]:
    """Verify, building the custody bundle when one isn't supplied.

    With a `cache`, an IP whose cached certs already establish this RUUID's
    genesis is verified locally (no CT); otherwise CT is queried and the
    fresh certs merged back into the cache.
    """
    if custody is not None:
        return verify(ru, document, custody), custody

    ip = anchor_ip(ru)
    day_count = _day_count(ru)
    cached = cache.load(ip) if cache is not None else None
    if cached is not None and any(
        _cert_is_genesis(c, ru, day_count) for c in cached
    ):
        certs = cached                      # local green-light, no CT
    else:
        if ct_source is None:
            ct_source = CrtShSource()
        certs = _merge_certs(cached or [], _fetch_certs(ru, ct_source))
        if cache is not None:
            cache.save(ip, certs)
    custody = _custody_bundle(ru, certs)
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
    if len(result.chain) > 1:
        lines.append(
            f"custody chain ({len(result.chain) - 1} rotation"
            f"{'s' if len(result.chain) > 2 else ''}): "
            + " -> ".join(result.chain)
        )
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
