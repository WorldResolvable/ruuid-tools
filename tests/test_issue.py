"""Tests for ruuid.issue: UUID-document and DNS-record generation.

This is the publishing-side counterpart to ruuid.resolve. The Anchor
class delegates here for its document building, so the live demo
daemon and the standalone `ruuid document` / `ruuid records` CLI
emit identical output.
"""

from __future__ import annotations

import json

import pytest

from ruuid.anchor import _Issuer, _load_zone, _reverse_ptr_name
from ruuid.issue import (
    build_uuid_document,
    build_uuid_documents,
    build_zone_records,
    default_doc_url,
    emit_document,
    emit_records,
    format_zone_records,
)


def _issuer(domain="x.example", anchor="192.0.2.1", service=None, **kw):
    """Build a per-anchor _Issuer record for tests.

    `service` is the CID-shaped service array. Pass None for the
    external-doc / zero-config case (combined with `uuid_document_uri`
    in kwargs as needed).
    """
    return _Issuer(
        domain=domain,
        anchor=anchor,
        ptr_name=_reverse_ptr_name(anchor),
        service=service,
        **kw,
    )


def _write_zone(tmp_path, data):
    p = tmp_path / "zone.json"
    p.write_text(json.dumps(data))
    return p


_DEFAULT_SERVICE = [
    {
        "id": "#1",
        "type": "Thing",
        "serviceEndpoint": "https://x.example/things/<identifier>",
    }
]


# --- build_uuid_document ----------------------------------------------

def test_uuid_document_id_is_fetch_url_no_inferred_aka():
    """The tool emits a CID-shaped doc with id = the default fetch URL;
    it does NOT manufacture alsoKnownAs entries from the zone file."""
    iss = _issuer(service=_DEFAULT_SERVICE)
    doc = build_uuid_document([iss])
    assert doc["@context"] == "https://www.w3.org/ns/cid/v1"
    assert doc["id"] == "https://x.example/.well-known/uuid-document.json"
    assert "alsoKnownAs" not in doc
    assert "controller" not in doc  # CID defaults controller to id


def test_uuid_document_service_carries_zone_service_array_verbatim():
    """The document's service array is the zone's service array, with
    zone-only fields (alias_to) stripped."""
    iss = _issuer(service=[
        {
            "id": "#1",
            "type": "Thing",
            "serviceEndpoint": "https://x.example/things/<identifier>",
            "alias_to": "https://x.example/<type>/<identifier>",
        }
    ])
    doc = build_uuid_document([iss])
    assert doc["service"] == [{
        "id": "#1",
        "type": "Thing",
        "serviceEndpoint": "https://x.example/things/<identifier>",
    }]


def test_uuid_document_does_not_infer_alsoknownas_from_zone_grouping():
    """Even when the zone file groups multiple anchors under one
    domain, the tool does not synthesise sibling did:uuid: entries in
    alsoKnownAs."""
    a = _issuer(anchor="192.0.2.1", service=_DEFAULT_SERVICE)
    b = _issuer(anchor="192.0.2.2", service=_DEFAULT_SERVICE)
    doc = build_uuid_document([a, b])
    assert "alsoKnownAs" not in doc


def test_uuid_document_returns_none_when_no_service():
    """A domain with neither service nor uuid_document_uri publishes no document."""
    iss = _issuer(service=None)
    assert build_uuid_document([iss]) is None


def test_uuid_document_class_without_endpoint_is_kept_verbatim():
    """A service entry without serviceEndpoint (no per-class template;
    resolver will fall back to the issuer-wide or spec default) is
    emitted as-is."""
    iss = _issuer(service=[
        {"id": "#7", "type": "Other"},
    ])
    doc = build_uuid_document([iss])
    svc = doc["service"][0]
    assert svc == {"id": "#7", "type": "Other"}


# --- build_uuid_documents (multi-domain) ------------------------------

def test_uuid_documents_handles_multiple_domains(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "a.example",
            "anchors": ["192.0.2.1"],
            "service": [{
                "id": "#1", "type": "Thing",
                "serviceEndpoint": "https://a.example/t/<identifier>",
            }],
        },
        {
            "domain": "b.example",
            "anchors": ["198.51.100.1"],
            "service": [{
                "id": "#1", "type": "Thing",
                "serviceEndpoint": "https://b.example/t/<identifier>",
            }],
        },
    ]})
    docs = build_uuid_documents(_load_zone(p))
    domains = [d for d, _ in docs]
    assert domains == ["a.example", "b.example"]


def test_uuid_documents_skips_external_doc_domains(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example", "anchors": ["192.0.2.1"],
            "uuid_document_uri": "data:application/json;base64,e30=",
        },
    ]})
    assert build_uuid_documents(_load_zone(p)) == []


# --- build_zone_records -------------------------------------------------

def test_zone_records_emit_ptr_per_anchor():
    issuers = [
        _issuer(anchor="192.0.2.1", service=_DEFAULT_SERVICE),
        _issuer(anchor="192.0.2.2", service=_DEFAULT_SERVICE),
    ]
    records = build_zone_records(issuers)
    ptrs = [r for r in records if r[1] == "PTR"]
    assert len(ptrs) == 2
    assert all(value == "x.example." for _, _, value in ptrs)


def test_zone_records_emit_uri_and_txt_at_underscore_uuid():
    iss = _issuer(service=_DEFAULT_SERVICE)
    records = build_zone_records([iss])
    types = {qtype for _, qtype, _ in records}
    assert types == {"PTR", "URI", "TXT"}
    uri = next(r for r in records if r[1] == "URI")
    txt = next(r for r in records if r[1] == "TXT")
    assert uri == (
        "_uuid.x.example", "URI",
        '10 1 "https://x.example/.well-known/uuid-document.json"',
    )
    assert "v=ruuid1 https://x.example/.well-known/uuid-document.json" in txt[2]


def test_zone_records_rrtype_uri_skips_txt():
    iss = _issuer(service=_DEFAULT_SERVICE)
    records = build_zone_records([iss], rrtype="URI")
    types = {qtype for _, qtype, _ in records}
    assert types == {"PTR", "URI"}


def test_zone_records_skip_uuid_records_for_zero_config_issuer():
    """A PTR-only domain (no service, no uuid_document_uri) gets only PTR."""
    iss = _issuer(service=None)
    records = build_zone_records([iss])
    types = {qtype for _, qtype, _ in records}
    assert types == {"PTR"}


def test_zone_records_use_literal_uuid_document_uri_when_set():
    iss = _issuer(
        service=None,
        uuid_document_uri="data:application/json;base64,e30=",
    )
    records = build_zone_records([iss])
    uri = next(r for r in records if r[1] == "URI")
    assert uri[2] == '10 1 "data:application/json;base64,e30="'


def test_zone_records_dedup_identical_entries():
    """Sibling anchors sharing a domain emit the same URI/TXT and dedup."""
    a = _issuer(anchor="192.0.2.1", service=_DEFAULT_SERVICE)
    b = _issuer(anchor="192.0.2.2", service=_DEFAULT_SERVICE)
    records = build_zone_records([a, b])
    uri_records = [r for r in records if r[1] == "URI"]
    assert len(uri_records) == 1


# --- format_zone_records ------------------------------------------------

def test_format_zone_records_produces_bind_like_lines():
    records = [
        ("1.2.0.192.in-addr.arpa", "PTR", "x.example."),
        ("_uuid.x.example", "URI", '10 1 "https://x.example/u"'),
    ]
    text = format_zone_records(records, ttl=300)
    lines = text.strip().split("\n")
    assert len(lines) == 2
    # Each line starts with the trailing-dot owner name.
    assert lines[0].startswith("1.2.0.192.in-addr.arpa.")
    # TTL and class appear.
    assert " 300 IN " in lines[0]


# --- default URL builders -----------------------------------------------

def test_default_doc_url_uses_well_known_default():
    """With no uuid_document_uri set, the doc URL is the well-known URL."""
    iss = _issuer()
    assert (
        default_doc_url(iss)
        == "https://x.example/.well-known/uuid-document.json"
    )


def test_default_doc_url_prefers_literal_uuid_document_uri():
    iss = _issuer(uuid_document_uri="data:application/json;base64,e30=")
    assert default_doc_url(iss) == "data:application/json;base64,e30="


# --- emit_document (CLI helper) -----------------------------------------

def test_emit_document_returns_pretty_json(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example",
            "anchors": ["192.0.2.1"],
            "service": [{
                "id": "#1", "type": "Thing",
                "serviceEndpoint": "https://x.example/t/<identifier>",
            }],
        },
    ]})
    text = emit_document(p)
    doc = json.loads(text)
    assert doc["id"] == "https://x.example/.well-known/uuid-document.json"
    # default indent=2 makes the output multi-line
    assert "\n  " in text


def test_emit_document_requires_domain_when_multiple_publishing(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "a.example", "anchors": ["192.0.2.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://a.example/t/<identifier>"}],
        },
        {
            "domain": "b.example", "anchors": ["198.51.100.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://b.example/t/<identifier>"}],
        },
    ]})
    with pytest.raises(ValueError, match="multiple"):
        emit_document(p)


def test_emit_document_selects_by_domain(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "a.example", "anchors": ["192.0.2.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://a.example/t/<identifier>"}],
        },
        {
            "domain": "b.example", "anchors": ["198.51.100.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://b.example/t/<identifier>"}],
        },
    ]})
    doc = json.loads(emit_document(p, domain="b.example"))
    assert doc["service"][0]["serviceEndpoint"].startswith("https://b.example/")


def test_emit_document_basic_for_domain_not_in_zone(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "a.example", "anchors": ["192.0.2.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://a.example/t/<identifier>"}],
        },
    ]})
    doc = json.loads(emit_document(p, domain="missing.example"))
    assert doc == {
        "@context": "https://www.w3.org/ns/cid/v1",
        "id": "https://missing.example/.well-known/uuid-document.json",
    }
    assert "service" not in doc


def test_emit_document_basic_without_a_zone():
    doc = json.loads(emit_document(domain="fresh.example"))
    assert doc == {
        "@context": "https://www.w3.org/ns/cid/v1",
        "id": "https://fresh.example/.well-known/uuid-document.json",
    }


def test_emit_document_domain_in_zone_without_service_is_basic(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {"domain": "x.example", "anchors": ["192.0.2.1"]},   # no service array
    ]})
    doc = json.loads(emit_document(p, domain="x.example"))
    assert doc["id"] == "https://x.example/.well-known/uuid-document.json"
    assert "service" not in doc


def test_emit_document_needs_domain_when_none_inferable(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {"domain": "x.example", "anchors": ["192.0.2.1"]},   # nothing publishes
    ]})
    with pytest.raises(ValueError, match="specify a domain"):
        emit_document(p)
    with pytest.raises(ValueError, match="specify a domain"):
        emit_document()                                      # no zone, no domain


# --- emit_records (CLI helper) ------------------------------------------

def test_emit_records_renders_full_zone_snippet(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example", "anchors": ["192.0.2.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://x.example/t/<identifier>"}],
        },
    ]})
    text = emit_records(p)
    # PTR + URI + TXT, one line each, trailing dots and TTL present.
    assert "1.2.0.192.in-addr.arpa. " in text
    assert "x.example." in text
    assert "_uuid.x.example. " in text
    assert "URI" in text and "TXT" in text


def test_emit_records_filters_by_domain(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "a.example", "anchors": ["192.0.2.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://a.example/t/<identifier>"}],
        },
        {
            "domain": "b.example", "anchors": ["198.51.100.1"],
            "service": [{"id": "#1", "type": "T", "serviceEndpoint": "https://b.example/t/<identifier>"}],
        },
    ]})
    text = emit_records(p, domain="b.example")
    assert "b.example" in text
    assert "a.example" not in text


def test_emit_records_rejects_unknown_domain(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {"domain": "x.example", "anchors": ["192.0.2.1"]},
    ]})
    with pytest.raises(ValueError, match="no anchors found"):
        emit_records(p, domain="missing.example")
