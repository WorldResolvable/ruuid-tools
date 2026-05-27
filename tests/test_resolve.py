"""Tests for ruuid.resolve: reverse-DNS naming, DNS resolution, templates."""

from __future__ import annotations

import pytest

from ruuid import (
    DEFAULT_REFERENT_URI_TEMPLATE,
    DEFAULT_UUID_DOCUMENT_URI_TEMPLATE,
    RUUID,
    Resolver,
    ResolveError,
    default_uuid_document_uri,
    identifier_label,
    resolve_referent_uri,
    reverse_dns_name,
    substitute_template,
    synthesise_ruuid_document,
)


# --- reverse_dns_name -----------------------------------------------------

def test_reverse_name_ipv4_via_6to4():
    """6to4-encoded IPv4 is reversed under in-addr.arpa."""
    r = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    assert reverse_dns_name(r) == "42.2.0.192.in-addr.arpa"


def test_reverse_name_ipv6():
    """Native IPv6 anchor is reversed under ip6.arpa at /64."""
    r = RUUID.from_anchor("2001:db8:abcd:1234::1", identifier=42, type_id=0)
    assert reverse_dns_name(r) == "4.3.2.1.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa"


# --- identifier_label -----------------------------------------------------

def test_identifier_label_is_12_lowercase_hex():
    r = RUUID.from_anchor("192.0.2.1", identifier=0x123456789ABC, type_id=0)
    assert identifier_label(r) == "123456789abc"


def test_identifier_label_zero_padded():
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=0)
    assert identifier_label(r) == "00000000002a"


# --- substitute_template --------------------------------------------------

def test_template_substitutes_identifier_placeholder():
    r = RUUID.from_anchor("192.0.2.1", identifier=0x123456789ABC, type_id=0)
    assert (
        substitute_template("https://example.com/things/<identifier>", r)
        == "https://example.com/things/123456789abc"
    )


def test_template_substitutes_zero_padded_identifier():
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=0)
    assert (
        substitute_template("https://example.com/cowtag/<identifier>", r)
        == "https://example.com/cowtag/00000000002a"
    )


def test_template_with_no_placeholder_is_returned_verbatim():
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=0)
    assert (
        substitute_template("https://example.com/static", r)
        == "https://example.com/static"
    )


def test_template_substitutes_multiple_occurrences():
    """A class may legitimately repeat the identifier (e.g. path + query)."""
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=0)
    out = substitute_template(
        "https://example.com/cowtag/<identifier>?ref=<identifier>", r
    )
    assert out == "https://example.com/cowtag/00000000002a?ref=00000000002a"


def test_template_substitutes_type_id_as_decimal():
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=7)
    assert (
        substitute_template("https://example.com/<type>/<identifier>", r)
        == "https://example.com/7/00000000002a"
    )


def test_template_substitutes_type_id_max_10_bit():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=1023)
    assert (
        substitute_template("https://example.com/<type>/x", r)
        == "https://example.com/1023/x"
    )


def test_template_substitutes_domain():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=5)
    assert (
        substitute_template(
            "https://<domain>/c/<type>/i/<identifier>", r, domain="example.com"
        )
        == "https://example.com/c/5/i/000000000001"
    )


def test_template_substitutes_network_ipv4_as_6to4_hex():
    """<network> renders the 64-bit network slot as 16 lowercase hex digits.

    For an IPv4 anchor it carries the 6to4 prefix (2002:WXYZ:0000:0000),
    so the high 16 bits are always 0x2002.
    """
    r = RUUID.from_anchor("192.0.2.42", identifier=1, type_id=0)
    assert (
        substitute_template("https://example/<network>/<identifier>", r)
        == "https://example/2002c000022a0000/000000000001"
    )


def test_template_substitutes_network_ipv6_top_64_bits():
    r = RUUID.from_anchor("2001:db8:abcd:1234::1", identifier=1, type_id=0)
    assert (
        substitute_template("https://example/<network>", r)
        == "https://example/20010db8abcd1234"
    )


def test_substitute_resolves_absolute_path_reference_against_document_uri():
    """When the template is an absolute-path reference (`/docs/...`)
    the substituted result is resolved against the document URI, so
    the scheme+host are transplanted from where the UUID document was fetched."""
    r = RUUID.from_anchor("203.0.113.99", identifier=0x5300CAFEBEEF, type_id=1)
    out = substitute_template(
        "/docs/<identifier>", r,
        document_uri="http://ruuid.s3-website-us-east-1.amazonaws.com/.well-known/uuid-document.json",
    )
    assert out == "http://ruuid.s3-website-us-east-1.amazonaws.com/docs/5300cafebeef"


def test_substitute_absolute_template_overrides_document_uri():
    """An already-absolute serviceEndpoint is left alone — the issuer
    can still point referents at a host different from the document's."""
    r = RUUID.from_anchor("203.0.113.99", identifier=0x5300CAFEBEEF, type_id=1)
    out = substitute_template(
        "https://other-host.example/docs/<identifier>", r,
        document_uri="http://ruuid.s3-website-us-east-1.amazonaws.com/.well-known/uuid-document.json",
    )
    assert out == "https://other-host.example/docs/5300cafebeef"


def test_substitute_relative_reference_without_document_uri_returns_unchanged():
    """No document_uri → no urljoin; the substituted template is
    returned as-is (relative reference)."""
    r = RUUID.from_anchor("192.0.2.42", identifier=1, type_id=0)
    assert substitute_template("/docs/<identifier>", r) == "/docs/000000000001"


def test_template_day_placeholder_splits_identifier():
    """When `<day>` appears in the template, `<identifier>` collapses to
    just the 28-bit sequence (7 hex chars) and `<day>` expands to the
    calendar date from the top 20 bits."""
    # day_count = 0 (epoch), sequence = 0x000002a (42)
    r = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=1)
    out = substitute_template(
        "https://example.com/<day>/<identifier>", r,
    )
    assert out == "https://example.com/2025-01-01/000002a"


def test_template_day_placeholder_with_realistic_date():
    """day_count = 511 → 2026-05-27 (epoch + 511 days)."""
    # identifier = (511 << 28) | 0xDEADBEE = 0x1FFDEADBEE
    r = RUUID.from_anchor(
        "192.0.2.42",
        identifier=(511 << 28) | 0xDEADBEE,
        type_id=1,
    )
    out = substitute_template(
        "https://example.com/by-day/<day>/items/<identifier>", r,
    )
    assert out == "https://example.com/by-day/2026-05-27/items/deadbee"


def test_template_without_day_uses_full_48_bit_identifier():
    """When `<day>` is absent, `<identifier>` is the full 12-hex-char
    form regardless of what the top 20 bits decode to. Spec-default
    behaviour preserved."""
    # Same RUUID as the previous test; without <day>, identifier is full.
    r = RUUID.from_anchor(
        "192.0.2.42",
        identifier=(511 << 28) | 0xDEADBEE,
        type_id=1,
    )
    out = substitute_template(
        "https://example.com/<type>/<identifier>", r,
    )
    assert out == "https://example.com/1/001ffdeadbee"


def test_template_day_placeholder_with_implausible_date():
    """An opaque identifier whose top 20 bits decode to a far-future
    date still substitutes mechanically — the resolver doesn't second-
    guess the publisher's template choice."""
    # top 20 bits = 0xFFFFF → day_count 1048575 → year ~4895
    r = RUUID.from_anchor(
        "192.0.2.42",
        identifier=(0xFFFFF << 28) | 0x1234567,
        type_id=1,
    )
    out = substitute_template("https://example.com/<day>/<identifier>", r)
    # Computed: 2025-01-01 + 1048575 days = some far-future date
    assert out.startswith("https://example.com/")
    assert "/1234567" in out  # sequence portion (7 hex chars)
    assert out.endswith("/1234567")


def test_template_day_only_no_identifier():
    """`<day>` can appear without `<identifier>` (rare but legal); the
    bare `<day>` substitutes regardless."""
    r = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=1)
    out = substitute_template("https://example.com/by-day/<day>/", r)
    assert out == "https://example.com/by-day/2025-01-01/"


def test_template_default_unaffected_by_day_semantics():
    """The spec-default template `https://<domain>/<type>/<identifier>`
    contains no `<day>`, so the existing behaviour (full 12-hex
    identifier) is preserved."""
    r = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=7)
    assert (
        substitute_template(
            DEFAULT_REFERENT_URI_TEMPLATE, r, domain="example.com",
        )
        == "https://example.com/7/00000000002a"
    )


def test_template_substitutes_network_zero_padded():
    r = RUUID(identifier=1, network=0xFF, type_id=0)
    assert (
        substitute_template("<network>", r) == "00000000000000ff"
    )


def test_template_substitutes_uuid_full_canonical_form():
    r = RUUID.from_anchor("192.0.2.42", identifier=0x123456789ABC, type_id=7)
    assert (
        substitute_template("https://example/u/<uuid>", r)
        == f"https://example/u/{r}"
    )
    # And the full UUID matches the canonical 8-4-4-4-12 form.
    assert (
        substitute_template("<uuid>", r) == str(r)
    )


def test_template_substitutes_all_placeholders_together():
    r = RUUID.from_anchor("192.0.2.42", identifier=0x123456789ABC, type_id=7)
    out = substitute_template(
        "https://<domain>/n/<network>/c/<type>/i/<identifier>?u=<uuid>",
        r,
        domain="example.com",
    )
    assert out == (
        f"https://example.com/n/2002c000022a0000/c/7/i/123456789abc?u={r}"
    )


def test_template_default_form():
    """The default template constant matches the spec."""
    assert DEFAULT_REFERENT_URI_TEMPLATE == "https://<domain>/<type>/<identifier>"


def test_template_default_substitution_end_to_end():
    r = RUUID.from_anchor("192.0.2.1", identifier=0xABCDEF012345, type_id=42)
    out = substitute_template(
        DEFAULT_REFERENT_URI_TEMPLATE, r, domain="example.com"
    )
    assert out == "https://example.com/42/abcdef012345"


# --- resolve_referent_uri ------------------------------------------------

def _class_svc(type_id, *, template=None, name=None):
    """Build a single class-bearing service entry for a test document.

    The class id is encoded as the entry's `id` fragment (`#<n>`);
    `type` carries the class name when one is set.
    """
    svc = {"id": f"#{type_id}"}
    if name is not None:
        svc["type"] = name
    if template is not None:
        svc["serviceEndpoint"] = template
    return svc


def test_resolve_referent_uri_uses_class_template_when_present():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=42)
    document = {
        "service": [_class_svc("42", template="https://example.com/cowtag/<identifier>")],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/cowtag/000000000001"
    )


def test_resolve_referent_uri_falls_back_to_default_when_class_missing():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=99)
    document = {
        "service": [_class_svc("42", template="https://example.com/cowtag/<identifier>")],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/99/000000000001"
    )


def test_resolve_referent_uri_falls_back_when_class_entry_lacks_template():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=42)
    document = {
        "service": [_class_svc("42", name="CowTag")],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/42/000000000001"
    )


def test_resolve_referent_uri_falls_back_when_service_absent():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=7)
    assert (
        resolve_referent_uri(r, domain="example.com", document={})
        == "https://example.com/7/000000000001"
    )


def test_resolve_referent_uri_falls_back_when_document_is_none():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=7)
    assert (
        resolve_referent_uri(r, domain="example.com", document=None)
        == "https://example.com/7/000000000001"
    )


# --- class-0 (issuer-wide) fallback --------------------------------------

def test_type_zero_template_is_used_when_request_class_missing():
    """Class 0's template applies when the requested class isn't listed."""
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=99)
    document = {
        "service": [_class_svc("0", template="https://example.com/r/<type>/<identifier>")],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/r/99/000000000001"
    )


def test_type_zero_template_is_used_when_request_class_lacks_template():
    """Class entry present but no template → fall to class 0's template."""
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=42)
    document = {
        "service": [
            _class_svc("0", template="https://example.com/r/<type>/<identifier>"),
            _class_svc("42", name="CowTag"),
        ],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/r/42/000000000001"
    )


def test_type_zero_template_applies_to_type_zero_itself():
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=0)
    document = {
        "service": [_class_svc("0", template="https://example.com/r/<identifier>")],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/r/000000000001"
    )


def test_class_specific_template_wins_over_type_zero():
    """A matching type entry's template is preferred to class 0's."""
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=42)
    document = {
        "service": [
            _class_svc("0",  template="https://example.com/default/<identifier>"),
            _class_svc("42", template="https://example.com/cowtag/<identifier>"),
        ],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/cowtag/000000000001"
    )


def test_spec_default_when_type_zero_lacks_template():
    """Class 0 entry exists but has no referent_uri_template → spec default."""
    r = RUUID.from_anchor("192.0.2.1", identifier=1, type_id=7)
    document = {
        "service": [_class_svc("0", name="Default")],
    }
    assert (
        resolve_referent_uri(r, domain="example.com", document=document)
        == "https://example.com/7/000000000001"
    )


# --- synthesise_ruuid_document -------------------------------------------

def _document(controller_did, *, services=None, also_known_as=None):
    """Build a minimal UUID document with `id == controller`."""
    doc = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": controller_did,
        "controller": controller_did,
    }
    if also_known_as is not None:
        doc["alsoKnownAs"] = also_known_as
    if services is not None:
        doc["service"] = services
    return doc


def test_synthesise_sets_id_to_resolved_did_and_controller_to_anchor_did():
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=1)
    document = _document(
        "https://example.com/.well-known/uuid-document.json",
        services=[_class_svc(
            "1", name="Thing",
            template="https://example.com/thing/<identifier>",
        )],
    )
    doc = synthesise_ruuid_document(r, document, domain="example.com")
    anchor_did = (
        f"did:uuid:{RUUID.from_anchor('192.0.2.1', identifier=0, type_id=0)}"
    )
    assert doc["id"] == f"did:uuid:{r}"
    assert doc["controller"] == anchor_did
    assert doc["@context"] == "https://www.w3.org/ns/did/v1"


def test_synthesise_projects_to_single_class_service_entry():
    """The synthesised doc carries only the resolved class's service."""
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=1)
    document = _document(
        "did:uuid:00000000-0000-8200-8002-c000020100000",
        services=[
            _class_svc("1", name="Thing", template="https://example.com/thing/<identifier>"),
            _class_svc("2", name="Other", template="https://example.com/other/<identifier>"),
        ],
    )
    doc = synthesise_ruuid_document(r, document, domain="example.com")
    assert len(doc["service"]) == 1
    assert doc["service"][0]["type"] == "Thing"


def test_synthesise_substitutes_endpoint_template():
    """Template placeholders in the chosen service entry resolve."""
    r = RUUID.from_anchor("192.0.2.1", identifier=0xABCDEF, type_id=1)
    document = _document(
        "did:uuid:00000000-0000-8200-8002-c000020100000",
        services=[_class_svc(
            "1", name="Thing",
            template="https://example.com/thing/<identifier>",
        )],
    )
    doc = synthesise_ruuid_document(r, document, domain="example.com")
    assert (
        doc["service"][0]["serviceEndpoint"]
        == "https://example.com/thing/000000abcdef"
    )


def test_synthesise_service_id_is_fragment_under_resolved_did():
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=3)
    document = _document("did:uuid:00000000-0000-8200-8002-c000020100000")
    doc = synthesise_ruuid_document(r, document, domain="example.com")
    assert doc["service"][0]["id"] == f"did:uuid:{r}#3"


def test_synthesise_uses_did_core_context_regardless_of_document_context():
    """The synthesised DID document carries the DID-Core context, not the
    UUID document's CID context — they're different documents with
    different consumers."""
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=1)
    document = _document("https://example.com/.well-known/uuid-document.json")
    document["@context"] = "https://www.w3.org/ns/cid/v1"
    doc = synthesise_ruuid_document(r, document, domain="example.com")
    assert doc["@context"] == "https://www.w3.org/ns/did/v1"


def test_synthesise_ignores_document_id_when_constructing_controller():
    """Controller is derived deterministically from the RUUID's anchor,
    so it's independent of whatever URI the UUID document happens to be
    served at (HTTPS URL, did:web, did:uuid of the controller, etc.)."""
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=1)
    anchor_did = (
        f"did:uuid:{RUUID.from_anchor('192.0.2.1', identifier=0, type_id=0)}"
    )
    for document_id in (
        "https://example.com/.well-known/uuid-document.json",
        "did:web:example.com",
        anchor_did,
    ):
        document = _document(document_id, services=[_class_svc(
            "1", name="Thing",
            template="https://example.com/thing/<identifier>",
        )])
        doc = synthesise_ruuid_document(r, document, domain="example.com")
        assert doc["controller"] == anchor_did


def test_synthesise_with_no_document_uses_default_template():
    """No document → synthesise with the spec-wide default template.
    Controller is still derivable from the resolved RUUID."""
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=7)
    doc = synthesise_ruuid_document(r, None, domain="example.com")
    anchor_did = (
        f"did:uuid:{RUUID.from_anchor('192.0.2.1', identifier=0, type_id=0)}"
    )
    assert doc["id"] == f"did:uuid:{r}"
    assert doc["controller"] == anchor_did
    assert doc["service"][0]["serviceEndpoint"] == "https://example.com/7/00000000002a"


def test_synthesise_falls_back_to_type_zero_template():
    """Same fallback ladder as resolve_referent_uri: type-specific, then #0."""
    r = RUUID.from_anchor("192.0.2.1", identifier=42, type_id=99)
    document = _document(
        "did:uuid:00000000-0000-8200-8002-c000020100000",
        services=[_class_svc(
            "0", name="Default",
            template="https://example.com/any/<identifier>",
        )],
    )
    doc = synthesise_ruuid_document(r, document, domain="example.com")
    assert (
        doc["service"][0]["serviceEndpoint"]
        == "https://example.com/any/00000000002a"
    )


# --- end-to-end DNS resolution against the test NS -----------------------

def _resolver(test_ns) -> Resolver:
    return Resolver(nameservers=[test_ns.address], port=test_ns.port, lifetime=2.0)


@pytest.fixture
def example_ruuid() -> RUUID:
    return RUUID.from_anchor(
        "192.0.2.42",
        identifier=0x123456789ABC,
        type_id=0,
    )


def test_resolve_domain(test_ns, example_ruuid):
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    r = _resolver(test_ns)
    assert r.resolve_domain(example_ruuid) == "example.com"


def test_resolve_uuid_document_via_uri(test_ns, example_ruuid):
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    test_ns.add_uri(
        "_uuid.example.com",
        "https://example.com/.well-known/uuid-document.json",
    )
    r = _resolver(test_ns)
    assert (
        r.resolve_uuid_document(example_ruuid)
        == "https://example.com/.well-known/uuid-document.json"
    )


def test_resolve_uuid_document_via_txt(test_ns, example_ruuid):
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    test_ns.add_txt(
        "_uuid.example.com",
        "v=ruuid1 https://example.com/.well-known/uuid-document.json",
    )
    r = _resolver(test_ns)
    assert (
        r.resolve_uuid_document(example_ruuid)
        == "https://example.com/.well-known/uuid-document.json"
    )


def test_uri_preferred_over_txt(test_ns, example_ruuid):
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    test_ns.add_uri("_uuid.example.com", "https://example.com/from-uri")
    test_ns.add_txt(
        "_uuid.example.com",
        "v=ruuid1 https://example.com/from-txt",
    )
    r = _resolver(test_ns)
    assert r.resolve_uuid_document(example_ruuid) == "https://example.com/from-uri"


def test_txt_without_prefix_falls_back_to_default(test_ns, example_ruuid):
    """A TXT record at _uuid.<domain> that lacks the RUUID prefix is ignored,
    so the doc URI falls back to the well-known default."""
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    test_ns.add_txt(
        "_uuid.example.com",
        "v=spf1 include:_spf.example.com ~all",
    )
    r = _resolver(test_ns)
    assert (
        r.resolve_uuid_document(example_ruuid)
        == "https://example.com/.well-known/uuid-document.json"
    )


def test_doc_uri_defaults_when_no_uuid_record(test_ns, example_ruuid):
    """No record at _uuid.<domain> → well-known default doc URI."""
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    r = _resolver(test_ns)
    assert (
        r.resolve_uuid_document(example_ruuid)
        == "https://example.com/.well-known/uuid-document.json"
    )


def test_default_uuid_document_uri_helper():
    assert (
        default_uuid_document_uri("example.com")
        == "https://example.com/.well-known/uuid-document.json"
    )
    assert (
        DEFAULT_UUID_DOCUMENT_URI_TEMPLATE
        == "https://<domain>/.well-known/uuid-document.json"
    )


def test_resolve_no_ptr_record(test_ns, example_ruuid):
    r = _resolver(test_ns)
    with pytest.raises(ResolveError):
        r.resolve_domain(example_ruuid)


def test_uri_priority_lowest_wins(test_ns, example_ruuid):
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    test_ns.add_uri(
        "_uuid.example.com",
        "https://low-priority.example.com/",
        priority=50,
    )
    test_ns.add_uri(
        "_uuid.example.com",
        "https://high-priority.example.com/",
        priority=10,
    )
    r = _resolver(test_ns)
    assert (
        r.resolve_uuid_document(example_ruuid)
        == "https://high-priority.example.com/"
    )


def test_full_pipeline_ipv4(test_ns, example_ruuid):
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    test_ns.add_uri(
        "_uuid.example.com",
        "https://example.com/.well-known/uuid-document.json",
    )
    out = _resolver(test_ns).resolve(example_ruuid)
    assert out == {
        "reverse_name": "42.2.0.192.in-addr.arpa",
        "domain": "example.com",
        "uuid_document_uri": "https://example.com/.well-known/uuid-document.json",
    }


def test_full_pipeline_ipv6(test_ns):
    ru = RUUID.from_anchor("2001:db8::1", identifier=0xDEADBEEF, type_id=1)
    test_ns.add_ptr(
        "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        "v6.example.",
    )
    test_ns.add_uri(
        "_uuid.v6.example",
        "https://v6.example/.well-known/uuid-document.json",
    )
    out = _resolver(test_ns).resolve(ru)
    assert out["domain"] == "v6.example"
    assert out["uuid_document_uri"] == "https://v6.example/.well-known/uuid-document.json"


def test_full_pipeline_no_uuid_record_uses_default(test_ns, example_ruuid):
    """Only a PTR is published; the doc URI is the well-known default."""
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    out = _resolver(test_ns).resolve(example_ruuid)
    assert out["domain"] == "example.com"
    assert (
        out["uuid_document_uri"]
        == "https://example.com/.well-known/uuid-document.json"
    )


# --- _build_registry default + failover ----------------------------------

def test_build_registry_default_is_loopback_with_failover():
    """No --registry means: try dns://127.0.0.1:53, fall back to system."""
    from ruuid.resolve import _build_registry, FailoverRegistry, Resolver
    reg = _build_registry(None)
    assert isinstance(reg, FailoverRegistry)
    assert isinstance(reg._primary, Resolver)
    assert reg._primary._r.nameservers == ["127.0.0.1"]
    assert reg._primary._r.port == 53
    # The fallback is a system Resolver (no override).
    assert isinstance(reg._fallback, Resolver)


def test_build_registry_explicit_url_is_still_wrapped_with_failover():
    """`--registry dns://1.2.3.4` keeps the system-DNS fallback."""
    from ruuid.resolve import _build_registry, FailoverRegistry
    reg = _build_registry("dns://1.2.3.4:5353")
    assert isinstance(reg, FailoverRegistry)
    assert reg._primary._r.nameservers == ["1.2.3.4"]
    assert reg._primary._r.port == 5353


def test_failover_primary_success_skips_fallback():
    """When primary succeeds, fallback is never consulted."""
    from ruuid.resolve import FailoverRegistry

    expected = {"reverse_name": "x", "domain": "x", "uuid_document_uri": "x"}

    class _Ok:
        def resolve(self, ruuid, trace=None):
            return expected

    class _Boom:
        def resolve(self, ruuid, trace=None):
            raise AssertionError("fallback must not run")

    reg = FailoverRegistry(_Ok(), _Boom())
    assert reg.resolve(RUUID.from_anchor("192.0.2.1", identifier=1)) == expected


def test_failover_primary_failure_runs_fallback_and_traces_reason():
    """When primary raises ResolveError, fallback runs and the trace
    records a `failover` entry with the primary's failure reason."""
    from ruuid.resolve import FailoverRegistry, ResolveError

    expected = {"reverse_name": "y", "domain": "y", "uuid_document_uri": "y"}

    class _Fail:
        def resolve(self, ruuid, trace=None):
            raise ResolveError("primary boom")

    class _Ok:
        def resolve(self, ruuid, trace=None):
            return expected

    reg = FailoverRegistry(_Fail(), _Ok())
    trace: list = []
    out = reg.resolve(
        RUUID.from_anchor("192.0.2.1", identifier=1), trace=trace,
    )
    assert out == expected
    assert any(
        h.get("step") == "failover" and "primary boom" in h.get("reason", "")
        for h in trace
    )


def test_failover_catches_dns_layer_errors():
    """DNS-layer exceptions (timeout, NoNameservers) also trigger failover,
    not just ResolveError."""
    from ruuid.resolve import FailoverRegistry
    import dns.exception

    class _Timeout:
        def resolve(self, ruuid, trace=None):
            raise dns.exception.Timeout()

    class _Ok:
        def resolve(self, ruuid, trace=None):
            return {"reverse_name": "z", "domain": "z", "uuid_document_uri": "z"}

    reg = FailoverRegistry(_Timeout(), _Ok())
    out = reg.resolve(RUUID.from_anchor("192.0.2.1", identifier=1))
    assert out["domain"] == "z"


def test_failover_catches_os_error():
    """Connection refused etc. (OSError) trigger failover."""
    from ruuid.resolve import FailoverRegistry

    class _Refused:
        def resolve(self, ruuid, trace=None):
            raise ConnectionRefusedError("nope")

    class _Ok:
        def resolve(self, ruuid, trace=None):
            return {"reverse_name": "z", "domain": "z", "uuid_document_uri": "z"}

    reg = FailoverRegistry(_Refused(), _Ok())
    out = reg.resolve(RUUID.from_anchor("192.0.2.1", identifier=1))
    assert out["domain"] == "z"


def test_failover_propagates_fallback_failure():
    """If both primary and fallback fail, the fallback's exception escapes."""
    from ruuid.resolve import FailoverRegistry, ResolveError

    class _Fail:
        def __init__(self, msg): self.msg = msg
        def resolve(self, ruuid, trace=None):
            raise ResolveError(self.msg)

    reg = FailoverRegistry(_Fail("primary"), _Fail("fallback"))
    with pytest.raises(ResolveError, match="fallback"):
        reg.resolve(RUUID.from_anchor("192.0.2.1", identifier=1))
