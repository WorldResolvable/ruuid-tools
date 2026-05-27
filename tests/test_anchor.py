"""Tests for ruuid.anchor — zone loading and URL synthesis.

The full daemon (binding sockets, serving DNS/HTTP) is exercised by
the demo.sh integration; here we cover the in-process logic that
turns a zone file into DNS records, documents, and referent routes.
"""

from __future__ import annotations

import json

import pytest

from ruuid import RUUID
from ruuid.anchor import (
    Anchor,
    _Issuer,
    _load_zone,
    _reverse_ptr_name,
)


def test_reverse_ptr_name_ipv4():
    assert _reverse_ptr_name("192.0.2.42") == "42.2.0.192.in-addr.arpa"


def test_reverse_ptr_name_ipv6():
    assert (
        _reverse_ptr_name("2001:db8:abcd:1234::1")
        == "4.3.2.1.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa"
    )


def _write_zone(tmp_path, data):
    p = tmp_path / "zone.json"
    p.write_text(json.dumps(data))
    return p


# --- _load_zone ----------------------------------------------------------

def test_load_zone_minimal(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {"domain": "x.example", "anchors": ["192.0.2.1"]},
    ]})
    issuers = _load_zone(p)
    assert len(issuers) == 1
    assert issuers[0].domain == "x.example"
    assert issuers[0].anchor == "192.0.2.1"
    assert issuers[0].ptr_name == "1.2.0.192.in-addr.arpa"
    assert issuers[0].service is None
    assert issuers[0].uuid_document_uri is None


def test_load_zone_with_service(tmp_path):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example",
            "anchors": ["192.0.2.1"],
            "service": [{
                "id": "#0", "type": "Thing",
                "serviceEndpoint": "https://x.example/things/<identifier>",
            }],
        },
    ]})
    issuers = _load_zone(p)
    assert issuers[0].service == [{
        "id": "#0", "type": "Thing",
        "serviceEndpoint": "https://x.example/things/<identifier>",
    }]


def test_load_zone_flattens_anchors_to_per_anchor_records(tmp_path):
    """A domain with N anchors produces N _Issuer records, all sharing
    the same service list reference."""
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example",
            "anchors": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
            "service": [{
                "id": "#0", "type": "T",
                "serviceEndpoint": "https://x.example/r/<identifier>",
            }],
        },
    ]})
    issuers = _load_zone(p)
    assert [i.anchor for i in issuers] == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert all(i.domain == "x.example" for i in issuers)
    # Same service list object — not just equal-by-value.
    assert all(i.service is issuers[0].service for i in issuers)


def test_load_zone_accepts_service_with_uuid_document_uri_override(tmp_path):
    """When the zone wants to advertise a non-default doc URL (e.g.
    http://example.com:8080/.well-known/uuid-document.json) but still
    have the daemon build the document, both fields are set."""
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example",
            "anchors": ["192.0.2.1"],
            "service": [{"id": "#0", "type": "T",
                         "serviceEndpoint": "https://x.example/r/<identifier>"}],
            "uuid_document_uri": "http://x.example:8080/.well-known/uuid-document.json",
        },
    ]})
    issuers = _load_zone(p)
    assert issuers[0].service is not None
    assert issuers[0].uuid_document_uri == "http://x.example:8080/.well-known/uuid-document.json"


# --- _load_zone: uuid_document_uri shorthands ----------------------------

def test_load_zone_path_only_uri_resolves_to_https_on_domain(tmp_path):
    """Path-only uuid_document_uri picks up scheme+host from the domain
    (defaulting scheme to https)."""
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example",
            "anchors": ["192.0.2.1"],
            "uuid_document_uri": "/uuids/document.json",
        },
    ]})
    assert _load_zone(p)[0].uuid_document_uri == "https://x.example/uuids/document.json"


def test_load_zone_http_scheme_path_shorthand_picks_up_domain(tmp_path):
    """`http:/path` (scheme + absolute path, no authority) means
    `http://<domain>/path` — handy when the issuer serves on the same
    host as their domain field but wants http rather than https
    (e.g., an S3 static-website bucket)."""
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "bucket.s3.example",
            "anchors": ["203.0.113.99"],
            "uuid_document_uri": "http:/.well-known/uuid-document.json",
        },
    ]})
    assert _load_zone(p)[0].uuid_document_uri == (
        "http://bucket.s3.example/.well-known/uuid-document.json"
    )


def test_load_zone_relative_file_uri_resolves_against_zone_dir(tmp_path):
    """`file:path` (no `//`) resolves against the zone file's directory,
    so the issuer can avoid hard-coding their absolute filesystem path."""
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "doc.json").write_text("{}")
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example",
            "anchors": ["192.0.2.1"],
            "uuid_document_uri": "file:subdir/doc.json",
        },
    ]})
    resolved = _load_zone(p)[0].uuid_document_uri
    assert resolved == f"file://{tmp_path}/subdir/doc.json"


def test_load_zone_opaque_scheme_uri_passes_through(tmp_path):
    """data:, did:web:, did:plc:, did:uuid: URIs are opaque — the
    loader passes them through unchanged."""
    cases = [
        "data:application/json;base64,e30=",
        "did:web:other.example",
        "did:plc:abc123",
        "did:uuid:00000000-0000-8200-8002-c000020100",
    ]
    for uri in cases:
        p = _write_zone(tmp_path, {"domains": [
            {
                "domain": "x.example",
                "anchors": ["192.0.2.1"],
                "uuid_document_uri": uri,
            },
        ]})
        assert _load_zone(p)[0].uuid_document_uri == uri


def test_load_zone_absolute_https_uri_passes_through(tmp_path):
    """Already-absolute https URIs are untouched — issuer wanted them
    that way (e.g., pointing at a different host than the domain)."""
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example",
            "anchors": ["192.0.2.1"],
            "uuid_document_uri": "https://elsewhere.example/document.json",
        },
    ]})
    assert _load_zone(p)[0].uuid_document_uri == (
        "https://elsewhere.example/document.json"
    )


# --- Anchor: URL synthesis -----------------------------------------------

def _anchor(issuers, http_port=8080):
    # serve_https=False so the URL synthesis tests see plain http://
    # regardless of whether /etc/ruuid/anchor-cert.pem exists on the dev box.
    return Anchor(
        issuers, bind="127.0.0.1", dns_port=5353, http_port=http_port,
        serve_https=False,
    )


def _issuer(domain="x.example", anchor="192.0.2.1", service=None, **kw):
    return _Issuer(
        domain=domain,
        anchor=anchor,
        ptr_name=_reverse_ptr_name(anchor),
        service=service,
        **kw,
    )


_DEFAULT_SERVICE = [
    {"id": "#0", "type": "Thing",
     "serviceEndpoint": "https://x.example/things/<identifier>"},
    {"id": "#7", "type": "Other"},  # no serviceEndpoint
]


def test_documents_carry_zone_service_array_verbatim():
    """The emitted UUID document has the zone's service array (alias_to
    stripped) and id = the well-known URL."""
    issuer = _issuer(service=_DEFAULT_SERVICE)
    a = _anchor([issuer])
    body = a._documents["/x.example/uuid-document.json"]
    doc = json.loads(body)
    assert doc["@context"] == "https://www.w3.org/ns/cid/v1"
    assert doc["id"] == "https://x.example/.well-known/uuid-document.json"
    assert "alsoKnownAs" not in doc
    services = {s["id"]: s for s in doc["service"]}
    assert services["#0"]["serviceEndpoint"] == "https://x.example/things/<identifier>"
    assert "serviceEndpoint" not in services["#7"]
    assert services["#7"]["type"] == "Other"


def test_dns_records_publish_both_uri_and_txt_for_service_bearing_domain():
    """Any domain that publishes a UUID document gets both URI and TXT
    records at _uuid.<domain>, so a resolver that picks either works."""
    issuer = _issuer(service=_DEFAULT_SERVICE)
    a = _anchor([issuer])
    assert ("1.2.0.192.in-addr.arpa", "PTR") in a._dns_records
    assert ("_uuid.x.example", "URI") in a._dns_records
    txt_records = a._dns_records[("_uuid.x.example", "TXT")]
    assert len(txt_records) == 1
    # dnslib's TXT __repr__ wraps the value in quotes; check raw bytes.
    rdata_bytes = b"".join(txt_records[0].data)
    assert rdata_bytes.startswith(b"v=ruuid1 ")
    assert b"https://x.example/.well-known/uuid-document.json" in rdata_bytes


def test_dns_resolver_any_query_returns_all_record_types():
    """ANY at _uuid.<domain> returns every record we hold for that name."""
    import dnslib
    from ruuid.anchor import _ZoneResolver

    issuer = _issuer(service=_DEFAULT_SERVICE)
    a = _anchor([issuer])
    # Force-add a TXT alongside the URI so the test exercises mixed-type ANY.
    a._dns_records.setdefault(("_uuid.x.example", "TXT"), []).append(
        dnslib.TXT(b"v=ruuid1 http://example/")
    )
    resolver = _ZoneResolver(a._dns_records)

    q = dnslib.DNSRecord.question("_uuid.x.example", "ANY")
    reply = resolver.resolve(q, handler=None)
    rtypes = {dnslib.QTYPE[rr.rtype] for rr in reply.rr}
    assert "URI" in rtypes
    assert "TXT" in rtypes


def test_rrtype_uri_publishes_only_uri():
    issuer = _issuer(service=_DEFAULT_SERVICE)
    a = Anchor([issuer], bind="127.0.0.1", dns_port=5353,
               http_port=8080, rrtype="URI", serve_https=False)
    assert ("_uuid.x.example", "URI") in a._dns_records
    assert ("_uuid.x.example", "TXT") not in a._dns_records


def test_rrtype_txt_publishes_only_txt():
    issuer = _issuer(service=_DEFAULT_SERVICE)
    a = Anchor([issuer], bind="127.0.0.1", dns_port=5353,
               http_port=8080, rrtype="TXT", serve_https=False)
    assert ("_uuid.x.example", "TXT") in a._dns_records
    assert ("_uuid.x.example", "URI") not in a._dns_records


def test_dns_records_omit_uuid_record_when_zero_config():
    """A PTR-only domain (no service, no uuid_document_uri) publishes
    only PTR, no _uuid records."""
    issuer = _issuer(service=None)
    a = _anchor([issuer])
    assert ("1.2.0.192.in-addr.arpa", "PTR") in a._dns_records
    assert ("_uuid.x.example", "URI") not in a._dns_records
    assert ("_uuid.x.example", "TXT") not in a._dns_records


# --- Anchor: referent routing -------------------------------------------

def test_referent_match_succeeds_for_templated_path():
    issuer = _issuer(service=[{
        "id": "#42", "type": "CowTag",
        "serviceEndpoint": "https://x.example/cowtag/<identifier>",
    }])
    a = _anchor([issuer])
    route, identifier = a._match_referent("/x.example/cowtag/abcdef012345")
    assert route is not None
    assert route.domain == "x.example"
    assert route.type_id == "42"
    assert route.type_name == "CowTag"
    assert identifier == "abcdef012345"


def test_referent_match_fails_for_unknown_path():
    issuer = _issuer(service=[{
        "id": "#0", "type": "Thing",
        "serviceEndpoint": "https://x.example/things/<identifier>",
    }])
    a = _anchor([issuer])
    route, identifier = a._match_referent("/x.example/nope/123")
    assert route is None
    assert identifier is None


# --- alias_to ------------------------------------------------------------

def test_referent_route_carries_alias_template():
    issuer = _issuer(service=[{
        "id": "#7", "type": "Event",
        "serviceEndpoint": "https://x.example/events/<identifier>",
        "alias_to": "https://example.org/e/<identifier>",
    }])
    a = _anchor([issuer])
    route, identifier = a._match_referent("/x.example/events/abc")
    assert route.alias_to == "https://example.org/e/<identifier>"
    assert identifier == "abc"


def _route(*, domain="x.example", anchor_addr="192.0.2.42",
           type_id="42", alias_to=None):
    """Build a _ReferentRoute for _expand_alias tests."""
    from ruuid.anchor import _ReferentRoute
    import re as _re
    network = RUUID.from_anchor(anchor_addr, identifier=0).network
    return _ReferentRoute(
        pattern=_re.compile("^x$"),
        domain=domain,
        network=network,
        type_id=type_id,
        type_name="",
        alias_to=alias_to,
    )


def test_expand_alias_substitutes_identifier_type_id_domain():
    """The three original placeholders still expand to literal values."""
    route = _route()
    out = Anchor._expand_alias(
        "https://up.example/<domain>/<type>/<identifier>",
        route,
        "abcd",
    )
    assert out == "https://up.example/x.example/42/abcd"


def test_expand_alias_substitutes_network_from_issuer_anchor():
    """<network> renders the 16-char hex of the issuer's network slot."""
    route = _route(anchor_addr="192.0.2.42")
    out = Anchor._expand_alias("https://up.example/<network>/x", route, "abcd")
    assert out == "https://up.example/2002c000022a0000/x"


def test_expand_alias_substitutes_network_for_ipv6_anchor():
    route = _route(anchor_addr="2001:db8:abcd:1234::1")
    out = Anchor._expand_alias("https://up.example/<network>", route, "abcd")
    assert out == "https://up.example/20010db8abcd1234"


def test_expand_alias_substitutes_uuid_canonical_form():
    """<uuid> assembles the canonical 36-char form from network+class+identifier."""
    route = _route(anchor_addr="192.0.2.42", type_id="7")
    out = Anchor._expand_alias("https://up.example/u/<uuid>", route, "abc")
    # Identifier "abc" parses as 0xabc; canonical RUUID built from anchor+class.
    expected_ru = RUUID.from_anchor("192.0.2.42", identifier=0xABC, type_id=7)
    assert out == f"https://up.example/u/{expected_ru}"


def test_expand_alias_leaves_uuid_unsubstituted_for_non_hex_identifier():
    """A non-parseable identifier preserves the literal <uuid> placeholder."""
    route = _route()
    out = Anchor._expand_alias("https://up.example/<uuid>", route, "not-hex!")
    assert out == "https://up.example/<uuid>"


def test_expand_alias_substitutes_all_five_placeholders_together():
    route = _route(anchor_addr="192.0.2.42", type_id="7")
    out = Anchor._expand_alias(
        "https://<domain>/n/<network>/c/<type>/i/<identifier>?u=<uuid>",
        route,
        "abc",
    )
    expected_ru = RUUID.from_anchor("192.0.2.42", identifier=0xABC, type_id=7)
    assert out == (
        f"https://x.example/n/2002c000022a0000/c/7/i/abc?u={expected_ru}"
    )


def test_no_alias_to_means_route_serves_stub():
    issuer = _issuer(service=[{
        "id": "#0", "type": "Thing",
        "serviceEndpoint": "https://x.example/things/<identifier>",
    }])
    a = _anchor([issuer])
    route, _ = a._match_referent("/x.example/things/abc")
    assert route.alias_to is None


def test_document_id_uses_well_known_default_regardless_of_http_port():
    """The UUID document's id is always the well-known URL, independent of
    the daemon's bind port — issuers advertise their public hostname,
    not the daemon's bind."""
    issuer = _issuer(service=[{
        "id": "#0", "type": "T",
        "serviceEndpoint": "https://x.example/t/<identifier>",
    }])
    a = _anchor([issuer], http_port=80)
    body = a._documents["/x.example/uuid-document.json"]
    doc = json.loads(body)
    assert doc["id"] == "https://x.example/.well-known/uuid-document.json"


# --- Access logger --------------------------------------------------------

def test_access_logger_emits_one_line_per_dns_reply(capsys):
    """`_AccessLogger.log_reply` writes one stderr line per request,
    in webserver-combined-log format."""
    import dnslib
    from types import SimpleNamespace
    from ruuid.anchor import _AccessLogger

    logger = _AccessLogger()
    # Build a minimal reply: question "_uuid.x.example" type URI, rcode 0.
    request = dnslib.DNSRecord.question("_uuid.x.example", "URI")
    reply = request.reply()
    reply.header.rcode = 0  # NOERROR

    handler = SimpleNamespace(client_address=("203.0.113.7", 54321))
    logger.log_reply(handler, reply)

    err = capsys.readouterr().err
    # One line, with the client IP, the qtype, the qname, and the rcode.
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1
    line = lines[0]
    assert line.startswith("203.0.113.7 - - [")
    assert '"URI _uuid.x.example."' in line
    assert line.rstrip().endswith("NOERROR")
