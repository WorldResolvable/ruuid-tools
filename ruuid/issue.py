"""Publishing-side tooling: UUID documents and DNS zone records.

Beyond generating the RUUID itself, two things need to be published: a
UUID document at a well-known location (one per domain) and the DNS
records that point a resolver from the RUUID's network prefix to that
document. The reference anchor daemon in `ruuid.anchor` produces both
at runtime from a JSON zone file, but a production deployment on S3 /
Cloudflare / a self-run DNS provider doesn't run that daemon — it
needs the JSON document and the zone-file records as static output
to upload and paste.

The zone file is *domain-keyed* and the UUID document it generates is
a W3C Controlled Identifiers (CID) document with the same structure:
each domain entry in the zone carries a `service` array of CID
service entries (`id`, `type`, `serviceEndpoint`) that becomes the
document's service array essentially verbatim, along with the list of
anchor IP addresses that map to the domain via reverse DNS. The
document's `id` is the URI at which it is served — either the
explicit `uuid_document_uri` (for `data:`, `file://`, `did:web:`,
`did:plc:`, `did:uuid:`, etc.) or the default well-known URL
`https://<domain>/.well-known/uuid-document.json`.

The tool does not synthesise `alsoKnownAs` entries from the zone
file: the zone is the anchor utility's routing config, not an
identity-assertion document. To publish `alsoKnownAs` entries, edit
the emitted document before publishing.

This module factors out the pure-function core that produces the two
artefacts:

  - `build_uuid_document(group)` builds the per-domain UUID-document
    JSON from a list of `_Issuer` records sharing a domain.
  - `build_zone_records(issuers)` builds the BIND-style (name,
    type, value) tuples that need to go in the authoritative zone
    (PTR per anchor + URI/TXT at `_uuid.<domain>`).

Both functions are also called by `ruuid.anchor` internally, so the
demo daemon and the standalone CLI subcommands stay in sync.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Iterable


# Re-export _Issuer / _load_zone from anchor.py so callers can stay
# import-cycle-free. The leading-underscore originals remain the
# canonical names within anchor.py.
def _import_anchor():
    from ruuid import anchor as _anchor
    return _anchor


def load_zone(zone_path: Path | str) -> list:
    """Parse the issuer zone-file JSON into a list of `_Issuer` records."""
    return _import_anchor()._load_zone(Path(zone_path))


def default_doc_url(issuer) -> str:
    """The UUID-document URL a domain publishes at.

    Returns the explicit `uuid_document_uri` when set, otherwise
    the well-known default
    `https://<domain>/.well-known/uuid-document.json`.
    """
    if issuer.uuid_document_uri:
        return issuer.uuid_document_uri
    return f"https://{issuer.domain}/.well-known/uuid-document.json"


# --- UUID document ------------------------------------------------------

# Fields on a zone-file service entry that are stripped before the entry
# is emitted into the published UUID document. `alias_to` is the demo
# daemon's local routing hint and has no place in a normative CID
# document.
_ZONE_ONLY_SERVICE_FIELDS = frozenset({"alias_to"})


def _service_for_document(entry: dict) -> dict:
    """Return a CID service entry with zone-only fields stripped."""
    return {k: v for k, v in entry.items() if k not in _ZONE_ONLY_SERVICE_FIELDS}


def build_uuid_document(
    group: list,
    *,
    doc_url_for: Callable | None = None,
) -> dict | None:
    """Build the UUID document for a group of zone entries sharing a domain.

    A "group" is one or more `_Issuer` records all naming the same
    `domain`. All siblings reference the same `service` list (set up
    by `_load_zone`); the function reads `service` from any one of
    them. Domains whose service is None and that have no
    `uuid_document_uri` publish no UUID document and the function
    returns None.

    The document is a W3C Controlled Identifiers (CID) document with:

      - `@context`: the CID context (`https://www.w3.org/ns/cid/v1`).
      - `id`: the URI at which the document is served — whatever
        `doc_url_for(issuer)` returns (default: the explicit
        `uuid_document_uri` or
        `https://<domain>/.well-known/uuid-document.json`).
      - `service`: the zone's `service` array verbatim, with any
        zone-only fields (e.g. `alias_to`) stripped.

    `doc_url_for(issuer)` produces the published document URL;
    defaults to `default_doc_url`.
    """
    if doc_url_for is None:
        doc_url_for = default_doc_url

    if not group:
        return None
    iss = group[0]
    if iss.service is None:
        return None

    return {
        "@context": "https://www.w3.org/ns/cid/v1",
        "id": doc_url_for(iss),
        "service": [_service_for_document(e) for e in iss.service],
    }


def build_uuid_documents(
    issuers: Iterable,
    *,
    doc_url_for: Callable | None = None,
) -> list[tuple[str, dict]]:
    """Build UUID documents for every domain represented in `issuers`.

    Returns `[(domain, document), ...]` in domain-first-seen order.
    Domains whose entries carry no `service` array (external-doc cases,
    or empty entries) are skipped.
    """
    siblings: dict[str, list] = {}
    for iss in issuers:
        if iss.service is None:
            continue  # external-doc-only or zero-config domain
        siblings.setdefault(iss.domain, []).append(iss)

    out: list[tuple[str, dict]] = []
    for domain, group in siblings.items():
        doc = build_uuid_document(group, doc_url_for=doc_url_for)
        if doc is not None:
            out.append((domain, doc))
    return out


# --- DNS records --------------------------------------------------------

def build_zone_records(
    issuers: Iterable,
    *,
    doc_url_for: Callable | None = None,
    rrtype: str = "both",
) -> list[tuple[str, str, str]]:
    """Build the BIND-style DNS records an issuer needs to publish.

    Returns a list of `(name, type, value)` tuples, deduplicated.
    `name` is the owner name without trailing dot; `type` is `PTR` /
    `URI` / `TXT`; `value` is the textual rdata in the form BIND zone
    files expect (a quoted hostname for PTR; `<priority> <weight>
    "<target>"` for URI; a quoted string for TXT).

    Per issuer:
      - PTR at `<reverse-DNS name>` → `<domain>.` (always).
      - URI and/or TXT at `_uuid.<domain>` when the domain publishes
        a UUID document (`service` or `uuid_document_uri` set).
        Sibling anchors under the same domain emit the same URI/TXT
        value and the seen-set dedup collapses them to one record.
        `rrtype` controls which records are emitted (`"both"`,
        `"URI"`, `"TXT"`).

    `doc_url_for(issuer)` defaults to `default_doc_url`.
    """
    if doc_url_for is None:
        doc_url_for = default_doc_url
    if rrtype not in ("both", "URI", "TXT"):
        raise ValueError(f"rrtype must be 'both', 'URI', or 'TXT'; got {rrtype!r}")

    records: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(name: str, qtype: str, value: str) -> None:
        key = (name, qtype, value)
        if key in seen:
            return
        seen.add(key)
        records.append(key)

    for iss in issuers:
        add(iss.ptr_name, "PTR", f"{iss.domain}.")
        if iss.service or iss.uuid_document_uri:
            url = doc_url_for(iss)
            if rrtype in ("both", "URI"):
                add(f"_uuid.{iss.domain}", "URI", f'10 1 "{url}"')
            if rrtype in ("both", "TXT"):
                add(f"_uuid.{iss.domain}", "TXT", f'"v=ruuid1 {url}"')
    return records


def format_zone_records(
    records: list[tuple[str, str, str]],
    *,
    ttl: int = 3600,
) -> str:
    """Render `(name, type, value)` records as a BIND-style zone snippet."""
    if not records:
        return ""
    width = max(len(name) for name, _, _ in records)
    lines = [
        f"{name + '.':<{width + 1}} {ttl} IN {qtype:3} {value}"
        for name, qtype, value in records
    ]
    return "\n".join(lines) + "\n"


# --- CLI helpers --------------------------------------------------------

def emit_document(
    zone_path: Path | str,
    *,
    domain: str | None = None,
    indent: int = 2,
) -> str:
    """Return the UUID-document JSON for `domain` (or the only domain that has one).

    Raises ValueError when no domain publishes a UUID document, or
    when multiple do and `--domain` wasn't supplied, or when the
    requested domain isn't in the zone.
    """
    issuers = load_zone(zone_path)
    docs = build_uuid_documents(issuers)
    if not docs:
        raise ValueError(
            "zone has no domain entries with a service array; nothing to publish"
        )
    if domain is None:
        if len(docs) > 1:
            domains = ", ".join(d for d, _ in docs)
            raise ValueError(
                f"zone has multiple document-publishing domains ({domains}); "
                f"use --domain to select one"
            )
        _, doc = docs[0]
    else:
        match = next((d for d, x in docs if d == domain), None)
        if match is None:
            raise ValueError(
                f"no document-publishing domain entry found for {domain!r}"
            )
        _, doc = next((d, x) for d, x in docs if d == domain)
    return json.dumps(doc, indent=indent) + "\n"


def emit_records(
    zone_path: Path | str,
    *,
    domain: str | None = None,
    rrtype: str = "both",
    ttl: int = 3600,
) -> str:
    """Return the BIND zone snippet for the issuer(s) in `zone_path`.

    With `domain`, restrict to records for that domain's anchors (PTR
    for each anchor plus the `_uuid.<domain>` URI/TXT). Without, emit
    records for every issuer.
    """
    issuers = load_zone(zone_path)
    if domain is not None:
        issuers = [i for i in issuers if i.domain == domain]
        if not issuers:
            raise ValueError(f"no anchors found for domain {domain!r}")
    records = build_zone_records(issuers, rrtype=rrtype)
    return format_zone_records(records, ttl=ttl)
