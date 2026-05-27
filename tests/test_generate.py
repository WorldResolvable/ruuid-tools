"""Tests for ruuid.generate."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

import pytest

from ruuid import RUUID, new_ruuid
from ruuid.generate import (
    DAY_COUNT_BITS,
    SEQUENCE_BITS,
    STRUCTURED_IDENTIFIER_EPOCH,
    days_since_epoch,
    structured_identifier,
)


def test_new_ruuid_with_explicit_identifier_ipv4():
    r = new_ruuid("192.0.2.42", identifier=42, type_id=3)
    assert r.identifier == 42
    assert r.address_family == 4
    assert r.type_id == 3
    assert r.ip_network == ipaddress.IPv4Network("192.0.2.42/32")


def test_new_ruuid_with_explicit_identifier_ipv6():
    r = new_ruuid("2001:db8::1", identifier=42, type_id=5)
    assert r.address_family == 6
    assert r.ip_network == ipaddress.IPv6Network("2001:db8::/64")


def test_new_ruuid_default_uses_structured_construction():
    """Without `identifier` or `opaque=True`, the identifier follows
    the §7.3 construction: 20-bit day_count high, 28-bit sequence low."""
    expected_day = days_since_epoch()
    r = new_ruuid("192.0.2.42")
    assert 0 <= r.identifier < (1 << 48)
    actual_day = r.identifier >> SEQUENCE_BITS
    # The test might race across UTC midnight; accept either day.
    assert actual_day in (expected_day, expected_day + 1)


def test_new_ruuid_opaque_returns_48_bit_random():
    """`opaque=True` uses a plain 48-bit random value (no day prefix)."""
    seen = set()
    for _ in range(50):
        r = new_ruuid("192.0.2.42", opaque=True)
        assert 0 <= r.identifier < (1 << 48)
        seen.add(r.identifier)
    assert len(seen) == 50  # no duplicates in a small sample


def test_new_ruuid_day_pins_day_count():
    """`day` selects which tenure day the structured identifier uses."""
    pinned = STRUCTURED_IDENTIFIER_EPOCH + timedelta(days=42)
    r = new_ruuid("192.0.2.42", day=pinned)
    assert r.identifier >> SEQUENCE_BITS == 42


def test_new_ruuid_day_and_opaque_conflict():
    """`opaque=True` and `day` together is a programmer error."""
    pinned = STRUCTURED_IDENTIFIER_EPOCH
    with pytest.raises(ValueError, match="incompatible"):
        new_ruuid("192.0.2.42", opaque=True, day=pinned)


def test_new_ruuid_explicit_identifier_ignores_day():
    """When `identifier` is supplied, `day` is silently ignored."""
    pinned = STRUCTURED_IDENTIFIER_EPOCH + timedelta(days=42)
    r = new_ruuid("192.0.2.42", identifier=0xDEADBEEF, day=pinned)
    assert r.identifier == 0xDEADBEEF


def test_new_ruuid_accepts_ipv4_object():
    r = new_ruuid(ipaddress.IPv4Address("10.0.0.1"), identifier=1)
    assert r.address_family == 4
    assert r.network == 0x2002_0A00_0001_0000


def test_new_ruuid_accepts_ipv6_object():
    r = new_ruuid(ipaddress.IPv6Address("2001:db8::1"), identifier=1)
    assert r.address_family == 6
    assert r.network == 0x20010DB8_00000000


# --- structured_identifier ----------------------------------------------

def test_structured_identifier_layout():
    """day_count goes in the high 20 bits; sequence in the low 28."""
    now = STRUCTURED_IDENTIFIER_EPOCH  # day_count == 0
    ident = structured_identifier(now=now, sequence=0xABCDEF)
    assert ident == 0xABCDEF
    assert ident >> SEQUENCE_BITS == 0


def test_structured_identifier_uses_supplied_now():
    """Supplied `now` controls day_count rather than the wall clock."""
    later = datetime(2025, 4, 11, 12, 0, tzinfo=timezone.utc)  # 100 days in
    ident = structured_identifier(now=later, sequence=1)
    assert ident >> SEQUENCE_BITS == 100
    assert ident & ((1 << SEQUENCE_BITS) - 1) == 1


def test_structured_identifier_random_sequence_fits_28_bits():
    now = STRUCTURED_IDENTIFIER_EPOCH
    for _ in range(50):
        ident = structured_identifier(now=now)
        assert (ident & ((1 << SEQUENCE_BITS) - 1)) < (1 << SEQUENCE_BITS)
        assert ident >> SEQUENCE_BITS == 0


def test_structured_identifier_rejects_pre_epoch():
    before = STRUCTURED_IDENTIFIER_EPOCH.replace(year=2024)
    with pytest.raises(ValueError, match="day_count"):
        structured_identifier(now=before, sequence=0)


def test_structured_identifier_rejects_oversized_sequence():
    with pytest.raises(ValueError, match="sequence"):
        structured_identifier(
            now=STRUCTURED_IDENTIFIER_EPOCH,
            sequence=1 << SEQUENCE_BITS,
        )


def test_day_count_bit_widths_match_spec():
    """RUUID §7.3 fixes 20-bit day_count and 28-bit sequence; verify."""
    assert DAY_COUNT_BITS == 20
    assert SEQUENCE_BITS == 28
    assert DAY_COUNT_BITS + SEQUENCE_BITS == 48
