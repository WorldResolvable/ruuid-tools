#!/usr/bin/env python3
"""Verify the live riverscape.info did:uuid deployment.

Run after publishing the DNS records and hosting the contents of
`site/`. It walks the resolution pipeline step by step against real
public DNS and HTTP, so a failure points at the exact hop that is not
yet live (PTR, _uuid record, UUID document, referent, or the
synthesised DID document).

    python examples/riverscape.info/verify.py
    python examples/riverscape.info/verify.py --driver-url http://localhost:8080

With --driver-url it additionally GETs
`<driver-url>/1.0/identifiers/<did>` and checks the driver's HTTP
response matches the library resolution — point it at a running
container or a deployed driver.

Exit status is 0 only if every required check passes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# Prefer this repository's source over any installed `ruuid` copy, so
# the script verifies the code in this tree (and runs without a prior
# `pip install`). Repo root is two directories up from this file.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ruuid import RUUID
from ruuid.resolve import Resolver, ResolveError, fetch_url_body
from ruuid.driver import DID_LD_JSON, resolve_did_uuid

# The live anchor and its expected, fully-hosted resolution.
ANCHOR = "52.22.50.16"
DOMAIN = "riverscape.info"
DID = "did:uuid:00000000-0001-8200-8002-341632100000"
DOC_URL = "https://riverscape.info/.well-known/uuid-document.json"
REFERENT_URL = "https://riverscape.info/things/000000000001"
# The serviceEndpoint the spec-default template produces when the UUID
# document is NOT hosted — used to give a precise "doc not hosted yet"
# diagnosis rather than a bare mismatch.
DEFAULT_TEMPLATE_ENDPOINT = "https://riverscape.info/0/000000000001"


class Checks:
    """Accumulates pass/fail results and prints them as it goes."""

    def __init__(self) -> None:
        self.failed = 0
        self.passed = 0
        self._color = sys.stdout.isatty()

    def _tag(self, code: str, word: str) -> str:
        return f"\033[{code}m{word}\033[0m" if self._color else word

    def ok(self, label: str, detail: str = "") -> None:
        self.passed += 1
        print(f"  {self._tag('32', 'PASS')} {label}" + (f" — {detail}" if detail else ""))

    def fail(self, label: str, detail: str = "") -> None:
        self.failed += 1
        print(f"  {self._tag('31', 'FAIL')} {label}" + (f" — {detail}" if detail else ""))

    def warn(self, label: str, detail: str = "") -> None:
        print(f"  {self._tag('33', 'WARN')} {label}" + (f" — {detail}" if detail else ""))


def check_dns(c: Checks) -> None:
    print("DNS (system resolver):")
    ru = RUUID.from_str(DID.removeprefix("did:uuid:"))
    trace: list = []
    try:
        reg = Resolver().resolve(ru, trace=trace)
    except ResolveError as e:
        c.fail("PTR lookup", str(e))
        return
    if reg["domain"] == DOMAIN:
        c.ok("PTR", f"{reg['reverse_name']} → {reg['domain']}")
    else:
        c.fail("PTR", f"expected {DOMAIN}, got {reg['domain']}")

    # Did a real _uuid.<domain> record answer, or did we fall back to
    # the well-known default? The last registry trace hop tells us.
    uuid_hop = next(
        (h for h in reversed(trace)
         if str(h.get("name", "")).startswith("_uuid.")), None
    )
    if uuid_hop and uuid_hop.get("qtype") in ("URI", "TXT") and "uri" in uuid_hop:
        c.ok("_uuid record", f"{uuid_hop['qtype']} → {uuid_hop['uri']}")
    else:
        c.warn(
            "_uuid record",
            "no _uuid.riverscape.info record; using well-known default "
            "(this is fine — the document is at the default path)",
        )


def check_http(c: Checks) -> None:
    print("HTTP (hosted files):")
    body = fetch_url_body(DOC_URL)
    if body is None:
        c.fail("UUID document", f"could not fetch {DOC_URL}")
    else:
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            c.fail("UUID document", f"not JSON: {e}")
            doc = None
        if isinstance(doc, dict):
            svc = (doc.get("service") or [{}])[0]
            if svc.get("serviceEndpoint") == "/things/<identifier>":
                c.ok("UUID document", f"{DOC_URL} serves the expected template")
            else:
                c.fail(
                    "UUID document",
                    f"unexpected service endpoint template: "
                    f"{svc.get('serviceEndpoint')!r}",
                )

    ref = fetch_url_body(REFERENT_URL)
    if ref is None:
        c.fail("referent", f"could not fetch {REFERENT_URL}")
    else:
        c.ok("referent", f"{REFERENT_URL} reachable ({len(ref)} bytes)")


def check_resolution(c: Checks) -> dict | None:
    """The real driver code path: resolve_did_uuid against live DNS+HTTP."""
    print("Driver resolution (resolve_did_uuid):")
    res = resolve_did_uuid(DID)
    if res.http_status != 200 or res.did_document is None:
        err = res.resolution_metadata.get("error")
        c.fail("resolve", f"status {res.http_status} ({err})")
        return None
    doc = res.did_document
    if doc.get("id") != DID:
        c.fail("DID document id", f"expected {DID}, got {doc.get('id')}")
    else:
        c.ok("DID document id", DID)

    endpoint = (doc.get("alsoKnownAs") or [None])[0]
    if endpoint == REFERENT_URL:
        c.ok("alsoKnownAs", f"{endpoint} (hosted document in use)")
    elif endpoint == DEFAULT_TEMPLATE_ENDPOINT:
        c.fail(
            "alsoKnownAs",
            f"got the default-template endpoint {endpoint} — the UUID "
            f"document is not being fetched (not hosted, or unreachable)",
        )
    else:
        c.fail("alsoKnownAs", f"unexpected: {endpoint}")
    return doc


def check_driver_http(c: Checks, driver_url: str, expected_doc: dict | None) -> None:
    print(f"Driver HTTP endpoint ({driver_url}):")
    url = f"{driver_url.rstrip('/')}/1.0/identifiers/{DID}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            status = resp.status
            ctype = resp.headers.get("Content-Type")
            body = resp.read()
    except urllib.error.HTTPError as e:
        body = e.read()
        e.close()
        c.fail("driver GET", f"HTTP {e.code}: {body[:200]!r}")
        return
    except urllib.error.URLError as e:
        c.fail("driver GET", f"unreachable: {e}")
        return
    if status != 200:
        c.fail("driver GET", f"HTTP {status}")
        return
    if ctype != DID_LD_JSON:
        c.warn("driver Content-Type", f"expected {DID_LD_JSON}, got {ctype}")
    try:
        got = json.loads(body)
    except (json.JSONDecodeError, ValueError) as e:
        c.fail("driver body", f"not JSON: {e}")
        return
    if expected_doc is not None and got == expected_doc:
        c.ok("driver GET", "200, body matches library resolution")
    elif got.get("id") == DID:
        c.ok("driver GET", f"200, id {DID}")
    else:
        c.fail("driver GET", f"unexpected body id {got.get('id')!r}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--driver-url", metavar="URL", default=None,
        help="also check a running driver's HTTP endpoint, e.g. "
             "http://localhost:8080",
    )
    args = p.parse_args(argv)

    print(f"Verifying {DID}\n  anchor {ANCHOR} → {DOMAIN}\n")
    c = Checks()
    check_dns(c)
    check_http(c)
    doc = check_resolution(c)
    if args.driver_url:
        check_driver_http(c, args.driver_url, doc)

    print(f"\n{c.passed} passed, {c.failed} failed")
    if c.failed:
        print("Deployment is not fully live yet — see the FAIL lines above.")
        return 1
    print("All checks passed — the did:uuid deployment is live.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
