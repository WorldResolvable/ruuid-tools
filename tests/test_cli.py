"""Tests for the `ruuid` command-line interface."""

from __future__ import annotations

import re

import pytest

from ruuid import RUUID
from ruuid.cli import main


# --- generate -------------------------------------------------------------

def test_generate_with_explicit_identifier(capsys):
    rc = main(["generate", "192.0.2.42", "42"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    ru = RUUID.from_str(out)
    assert ru.identifier == 42
    assert ru.type_id == 0


def test_generate_with_hex_identifier(capsys):
    rc = main(["generate", "192.0.2.42", "0xABCDEF012345"])
    assert rc == 0
    ru = RUUID.from_str(capsys.readouterr().out.strip())
    assert ru.identifier == 0xABCDEF012345


def test_generate_with_class_option(capsys):
    rc = main(["generate", "192.0.2.42", "1", "--type", "42"])
    assert rc == 0
    ru = RUUID.from_str(capsys.readouterr().out.strip())
    assert ru.type_id == 42
    assert ru.identifier == 1


def test_generate_random_identifier_when_omitted(capsys):
    rc = main(["generate", "192.0.2.42"])
    assert rc == 0
    ru = RUUID.from_str(capsys.readouterr().out.strip())
    assert 0 <= ru.identifier < (1 << 48)


def test_generate_ipv6_anchor(capsys):
    rc = main(["generate", "2001:db8::1", "42"])
    assert rc == 0
    ru = RUUID.from_str(capsys.readouterr().out.strip())
    assert ru.address_family == 6


def test_generate_short_identifier_is_zero_padded_in_textual_form(capsys):
    """A small identifier like 42 fills 48 bits with leading zeros."""
    rc = main(["generate", "192.0.2.42", "42"])
    assert rc == 0
    text = capsys.readouterr().out.strip()
    # Group 1 (top 32 bits of identifier) is all zeros for a 42-valued id.
    assert text.startswith("00000000-")
    # And the 13th nibble of the identifier portion is '2', the 14th 'a'.
    assert re.match(r"00000000-002a-", text)


def test_generate_rejects_over_48_bit_identifier(capsys):
    rc = main(["generate", "192.0.2.42", str(1 << 48)])
    err = capsys.readouterr().err
    assert rc != 0
    assert "identifier" in err


def test_generate_rejects_bad_address(capsys):
    rc = main(["generate", "not-an-address"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "ruuid generate" in err


def test_generate_day_iso_date(capsys):
    """--day YYYY-MM-DD sets day_count to days since 2025-01-01 UTC."""
    rc = main(["generate", "192.0.2.42", "--day", "2025-02-10"])
    assert rc == 0
    ru = RUUID.from_str(capsys.readouterr().out.strip())
    # 2025-01-01 → 2025-02-10 is 40 days
    assert ru.identifier >> 28 == 40


def test_generate_day_integer(capsys):
    """--day N (integer) sets day_count directly."""
    rc = main(["generate", "192.0.2.42", "--day", "0"])
    assert rc == 0
    ru = RUUID.from_str(capsys.readouterr().out.strip())
    assert ru.identifier >> 28 == 0  # epoch day


def test_generate_day_rejects_future_date(capsys):
    """--day in the future fails per the spec MUST NOT."""
    rc = main(["generate", "192.0.2.42", "--day", "3000-01-01"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "future" in err


def test_generate_day_and_opaque_conflict(capsys):
    """--day and --opaque together is a user error."""
    rc = main(
        ["generate", "192.0.2.42", "--day", "2025-01-01", "--opaque"]
    )
    err = capsys.readouterr().err
    assert rc != 0
    assert "mutually exclusive" in err


def test_generate_day_rejects_malformed(capsys):
    """Garbage in --day fails at argparse parse time (SystemExit(2))."""
    with pytest.raises(SystemExit) as excinfo:
        main(["generate", "192.0.2.42", "--day", "not-a-date"])
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "--day" in err


# --- resolve --------------------------------------------------------------

def test_resolve_rejects_malformed_uuid(capsys):
    rc = main(["resolve", "not-a-uuid"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "invalid UUID" in err


def test_resolve_default_prints_just_doc_uri(test_ns, capsys):
    """Default output is the UUID-document URI alone — no caption, no extras."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "resolve",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() == "https://example.com/.well-known/uuid-document.json"


def test_resolve_registry_from_env(test_ns, capsys, monkeypatch):
    """RUUID_REGISTRY supplies the registry when --registry is omitted."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    monkeypatch.setenv("RUUID_REGISTRY", f"dns://127.0.0.1:{test_ns.port}")
    rc = main(["resolve", str(ru)])  # no --registry flag
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() == "https://example.com/.well-known/uuid-document.json"


def test_resolve_flag_overrides_env_registry(test_ns, capsys, monkeypatch):
    """An explicit --registry beats RUUID_REGISTRY (flag precedence)."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    # Env points at a dead port; the flag points at the live fake NS.
    monkeypatch.setenv("RUUID_REGISTRY", "dns://127.0.0.1:1")
    rc = main([
        "resolve",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() == "https://example.com/.well-known/uuid-document.json"


def test_resolve_verbose_emits_all_sections(test_ns, capsys):
    """--verbose prints detail block + doc-document section + referent-body section."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "resolve", "--verbose",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    # Detail block:
    assert "domain:            example.com" in out
    assert "uuid_document_uri: https://example.com/.well-known/uuid-document.json" in out
    assert "referent_uri:      https://example.com/0/00000000002a" in out
    # Both content sections are present, both unavailable (no real http
    # server backing example.com):
    assert "--- UUID document ---" in out
    assert "--- referent body ---" in out
    assert out.count("(unavailable)") == 2


# --- parse ----------------------------------------------------------------

def test_parse_emits_detail_block_and_trace(test_ns, capsys):
    """`ruuid parse` prints the detail block + DNS trace, no body sections."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "parse",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    captured = capsys.readouterr()
    out = captured.out
    assert rc == 0
    # Detail block present
    assert "domain:            example.com" in out
    assert "uuid_document_uri: https://example.com/.well-known/uuid-document.json" in out
    assert "referent_uri:      https://example.com/0/00000000002a" in out
    # DNS trace present
    assert "PTR     42.2.0.192.in-addr.arpa → example.com" in out
    # NO body sections
    assert "--- UUID document ---" not in out
    assert "--- did:uuid: Document ---" not in out
    assert "--- referent body ---" not in out


def test_parse_rejects_malformed_uuid(capsys):
    rc = main(["parse", "not-a-uuid"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "invalid UUID" in err


def test_parse_emits_structured_reading_for_low_day_count(test_ns, capsys):
    """Identifier with day_count in [epoch, today] gets a §7.3 reading
    line showing the date and the sequence."""
    from ruuid import RUUID

    # day_count = 0 (epoch), sequence = 0x000002a (42).
    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "parse",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "identifier:        00000000002a" in out
    assert "§7.3: day_count=0 (2025-01-01), sequence=0x000002a" in out
    assert "future" not in out  # day_count=0 is the epoch, not future


def test_parse_flags_future_day_count_as_likely_opaque(capsys):
    """An identifier whose top 20 bits decode to a future date can't be
    a valid §7.3 day_count — flag it so the operator knows."""
    from ruuid import RUUID

    # identifier with top 20 bits = 0xFFFFF → day_count ≈ 1.05M → year ~4895
    ru = RUUID(
        identifier=(0xFFFFF << 28) | 0x1234567,
        network=0x2002_C000_022A_0000,
        type_id=0,
    )
    rc = main(["parse", "--registry", "dns://127.0.0.1:1", str(ru)])
    out = capsys.readouterr().out
    assert rc == 0
    # The structured-reading line still appears, with the "future" flag
    assert "§7.3:" in out
    assert "future" in out
    assert "likely opaque" in out


def test_parse_emits_not_resolved_when_dns_fails(monkeypatch, capsys):
    """When neither primary nor fallback can resolve, parse exits 0 and
    prints `not resolved` for the DNS-derived fields; the UUID's own
    bits still print."""
    from ruuid import RUUID
    from ruuid import resolve as resolve_mod

    # Point the failover fallback at a closed port so resolution
    # ultimately fails (no anchor, no system DNS that can answer).
    real_resolver_cls = resolve_mod.Resolver

    def closed_port_factory(*args, **kwargs):
        if not kwargs and not args:
            return real_resolver_cls(
                nameservers=["127.0.0.1"], port=1, lifetime=0.5,
            )
        return real_resolver_cls(*args, **kwargs)

    monkeypatch.setattr(resolve_mod, "Resolver", closed_port_factory)
    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    rc = main([
        "parse",
        "--registry", "dns://127.0.0.1:1",  # also unreachable
        str(ru),
    ])
    captured = capsys.readouterr()
    out = captured.out
    assert rc == 0
    # Bit-level fields present
    assert "uuid:              " in out
    assert "identifier:        00000000002a" in out
    assert "reverse_name:      42.2.0.192.in-addr.arpa" in out
    # DNS-derived fields show the placeholder
    assert "domain:            not resolved" in out
    assert "uuid_document_uri: not resolved" in out
    assert "referent_uri:      not resolved" in out
    # No timeout noise, no FAILOVR line
    assert "FAILOVR" not in out
    assert "timed out" not in out
    assert "lifetime" not in out


def test_parse_quiet_trace_drops_failover_and_errors(monkeypatch, test_ns, capsys):
    """When the primary fails but fallback succeeds, parse suppresses
    the FAILOVR line and per-hop error entries (verbose would show them)."""
    import dns.resolver
    from ruuid import RUUID
    from ruuid import resolve as resolve_mod

    # Primary: a closed port (forces failover). Fallback: the test NS.
    real_resolver_cls = resolve_mod.Resolver
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")

    def factory(*args, **kwargs):
        if not kwargs and not args:
            return real_resolver_cls(
                nameservers=["127.0.0.1"], port=test_ns.port, lifetime=2.0,
            )
        return real_resolver_cls(*args, **kwargs)

    monkeypatch.setattr(resolve_mod, "Resolver", factory)
    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    rc = main([
        "parse",
        "--registry", "dns://127.0.0.1:1",  # closed → triggers failover
        str(ru),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    # Resolution did succeed (via fallback), so the result is shown
    assert "domain:            example.com" in out
    # But the FAILOVR + error noise is suppressed
    assert "FAILOVR" not in out
    assert "→ no record" not in out


def test_parse_uses_registry_default(monkeypatch, test_ns, capsys):
    """`ruuid parse` with no --registry resolves via the system resolver
    directly (no loopback primary, no failover wrapper). Here we redirect
    the default `Resolver()` at the test NS by monkey-patching its
    constructor, so the test exercises the default code path without
    needing root or port 53."""
    import dns.resolver
    from ruuid import RUUID
    from ruuid import resolve as resolve_mod

    real_resolver_cls = resolve_mod.Resolver
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")

    def system_factory(*args, **kwargs):
        # Default Resolver() (no args) → the system; redirect to test NS.
        if not kwargs and not args:
            return real_resolver_cls(
                nameservers=["127.0.0.1"],
                port=test_ns.port,
                lifetime=2.0,
            )
        return real_resolver_cls(*args, **kwargs)

    monkeypatch.setattr(resolve_mod, "Resolver", system_factory)
    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    rc = main(["parse", str(ru)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "example.com" in out


def test_resolve_follow_reports_unreachable_referent(test_ns, capsys):
    """Bare --follow against an unreachable referent exits non-zero."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "resolve", "--follow",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    captured = capsys.readouterr()
    assert rc != 0
    # The target URL is the default referent template — example.com is not
    # locally served, so the fetch fails.
    assert "could not fetch" in captured.err
    assert "example.com" in captured.err


def test_resolve_follow_document_reports_unreachable_doc(test_ns, capsys):
    """--follow=document against an unreachable doc exits non-zero."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "resolve", "--follow", "document",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    captured = capsys.readouterr()
    assert rc != 0
    # The target URL is the well-known default doc URI; we error on it,
    # not on the referent URI.
    assert "could not fetch" in captured.err
    assert ".well-known/uuid-document.json" in captured.err


def test_resolve_follow_rejects_unknown_value(capsys):
    """--follow with a value not in the documented choices fails."""
    with pytest.raises(SystemExit) as exc:
        main([
            "resolve", "--follow", "junk",
            "00000000-0000-8000-8000-000000000000",
        ])
    assert exc.value.code == 2
    assert "usage:" in capsys.readouterr().err


def test_resolve_follow_ruuid_document_emits_json(test_ns, capsys):
    """--follow ruuid_document prints the synthesised per-RUUID doc as JSON.

    No UUID document is published, so the synthesis falls back to the
    spec-default template. The output should still be a conformant
    JSON document with `id` equal to the resolved DID.
    """
    import json
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "resolve", "--follow", "ruuid_document",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert doc["id"] == f"did:uuid:{ru}"
    assert doc["alsoKnownAs"] == ["https://example.com/0/00000000002a"]


def test_resolve_follow_referent_uri_prints_uri_without_fetching(test_ns, capsys):
    """--follow referent_uri stops at the referent URI string (no HTTP)."""
    from ruuid import RUUID

    ru = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0)
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    rc = main([
        "resolve", "--follow", "referent_uri",
        "--registry", f"dns://127.0.0.1:{test_ns.port}",
        str(ru),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    # No HTTP needed; we get the default referent template.
    assert out.strip() == "https://example.com/0/00000000002a"


def test_resolve_rejects_bad_registry_port(capsys):
    rc = main(["resolve", "00000000-0000-8000-8000-000000000000",
               "--registry", "dns://127.0.0.1:not-a-port"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "--registry" in err
    assert "invalid port" in err


# --- document / records --------------------------------------------------

def _write_zone(tmp_path, data):
    import json
    p = tmp_path / "zone.json"
    p.write_text(json.dumps(data))
    return p


def test_document_emits_json_to_stdout(tmp_path, capsys):
    import json
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
    rc = main(["document", "--zone", str(p)])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["@context"] == "https://www.w3.org/ns/cid/v1"
    assert doc["id"] == "https://x.example/.well-known/uuid-document.json"
    assert doc["service"][0]["serviceEndpoint"] == "https://x.example/t/<identifier>"


def test_document_basic_without_zone(capsys):
    import json
    rc = main(["document", "new.example"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["@context"] == "https://www.w3.org/ns/cid/v1"
    assert doc["id"] == "https://new.example/.well-known/uuid-document.json"
    assert "service" not in doc and "verificationMethod" not in doc


def test_document_needs_domain_without_zone(capsys):
    rc = main(["document"])
    assert rc == 1
    assert "specify a domain" in capsys.readouterr().err


def test_document_fails_without_domain_when_ambiguous(tmp_path, capsys):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "a.example", "anchors": ["192.0.2.1"],
            "service": [{"id": "#1", "type": "T",
                         "serviceEndpoint": "https://a.example/t/<identifier>"}],
        },
        {
            "domain": "b.example", "anchors": ["198.51.100.1"],
            "service": [{"id": "#1", "type": "T",
                         "serviceEndpoint": "https://b.example/t/<identifier>"}],
        },
    ]})
    rc = main(["document", "--zone", str(p)])
    assert rc == 1
    assert "multiple" in capsys.readouterr().err


def test_records_emits_zone_snippet_to_stdout(tmp_path, capsys):
    p = _write_zone(tmp_path, {"domains": [
        {
            "domain": "x.example", "anchors": ["192.0.2.1"],
            "service": [{"id": "#1", "type": "T",
                         "serviceEndpoint": "https://x.example/t/<identifier>"}],
        },
    ]})
    rc = main(["records", "--zone", str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "1.2.0.192.in-addr.arpa. " in out
    assert "PTR" in out
    assert "URI" in out
    assert "TXT" in out


# --- hostname acceptance --------------------------------------------------

def test_generate_accepts_hostname_as_anchor(capsys):
    """A DNS name (here: localhost via /etc/hosts) resolves to an IP
    and produces a valid RUUID."""
    rc = main(["generate", "localhost", "42"])
    assert rc == 0
    ru = RUUID.from_str(capsys.readouterr().out.strip())
    # localhost is conventionally 127.0.0.1; even if a system overrides
    # it to ::1, the result is a well-formed RUUID anchored on a loopback.
    assert ru.identifier == 42
    assert ru.ip_network.network_address.is_loopback


def test_generate_rejects_unresolvable_hostname(capsys):
    rc = main(["generate", "no-such-host.invalid"])
    err = capsys.readouterr().err
    assert rc != 0
    assert "cannot resolve hostname" in err


def test_resolve_accepts_hostname_in_registry(test_ns, capsys):
    """`--registry dns://localhost:PORT` resolves the host to an IP and
    succeeds against the local test DNS server."""
    from ruuid import RUUID
    ru = str(RUUID.from_anchor("192.0.2.42", identifier=42, type_id=0))
    test_ns.add_ptr("42.2.0.192.in-addr.arpa", "example.com")
    test_ns.add_uri(
        "_uuid.example.com", "https://example.com/.well-known/uuid-document.json"
    )
    rc = main([
        "resolve", ru,
        "--registry", f"dns://localhost:{test_ns.port}",
    ])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == "https://example.com/.well-known/uuid-document.json"


def test_resolve_rejects_unresolvable_registry_host(capsys):
    rc = main([
        "resolve", "00000000-0000-8000-8000-000000000000",
        "--registry", "dns://no-such-host.invalid",
    ])
    err = capsys.readouterr().err
    assert rc != 0
    assert "ruuid resolve: --registry" in err
    assert "cannot resolve hostname" in err


# --- top-level no-arg behavior -------------------------------------------

def test_bare_command_prints_usage_only_no_error_line(capsys):
    """`ruuid` with no args prints usage to stderr without an `error:` line."""
    with pytest.raises(SystemExit) as exc:
        main([])
    captured = capsys.readouterr()
    assert exc.value.code == 2
    assert captured.out == ""
    assert captured.err.startswith("usage:")
    assert "error:" not in captured.err


def test_generate_missing_address_prints_usage_only(capsys):
    """`ruuid generate` with no address prints usage only — no `error:`."""
    with pytest.raises(SystemExit) as exc:
        main(["generate"])
    captured = capsys.readouterr()
    assert exc.value.code == 2
    assert captured.err.startswith("usage:")
    assert "error:" not in captured.err


def test_resolve_missing_uuid_prints_usage_only(capsys):
    """`ruuid resolve` with no UUID prints usage only — no `error:`."""
    with pytest.raises(SystemExit) as exc:
        main(["resolve"])
    captured = capsys.readouterr()
    assert exc.value.code == 2
    assert captured.err.startswith("usage:")
    assert "error:" not in captured.err
