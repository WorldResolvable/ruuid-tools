"""Bit-layout and round-trip tests for the simplified RUUID core."""

from __future__ import annotations

import ipaddress
import uuid as std_uuid

import pytest

from ruuid import RUUID, VERSION, VARIANT_RFC4122, SIXTOFOUR_PREFIX


# --- Golden vectors --------------------------------------------------------

def test_all_zero_defaults_only():
    """Only the version + variant nibbles are set."""
    r = RUUID(identifier=0, network=0, type_id=0)
    assert str(r) == "00000000-0000-8000-8000-000000000000"


def test_minimal_type_id():
    """type_id=1 → group 4 ends with `10` (10 bits up-shifted by 4)."""
    r = RUUID(identifier=0, network=0, type_id=1)
    assert str(r) == "00000000-0000-8000-8010-000000000000"


def test_type_id_max_10_bits():
    """type_id=0x3FF (the 10-bit max) → group 4 = 0xBFF0."""
    r = RUUID(identifier=0, network=0, type_id=0x3FF)
    assert str(r) == "00000000-0000-8000-bff0-000000000000"


def test_identifier_in_top_48_bits():
    """identifier=0x123456789ABC occupies UUID bits 127..80 — top 12 hex chars."""
    r = RUUID(identifier=0x123456789ABC, network=0, type_id=0)
    assert str(r) == "12345678-9abc-8000-8000-000000000000"


def test_ipv4_6to4_network_textual_form():
    """IPv4 192.0.2.42 → network 0x2002_C000_022A_0000; nibble-aligned in text."""
    network = (SIXTOFOUR_PREFIX << 48) | (0xC000022A << 16)
    r = RUUID(identifier=0, network=network, type_id=0)
    assert str(r) == "00000000-0000-8200-8002-c000022a0000"


def test_ipv6_native_network_textual_form():
    """IPv6 2001:db8:abcd:1234::/64 → top 16 = 0x2001 (not 6to4)."""
    network = 0x20010DB8_ABCD1234
    r = RUUID(identifier=0, network=network, type_id=0)
    assert str(r) == "00000000-0000-8200-8001-0db8abcd1234"


# --- Per-field bit-position isolation -------------------------------------

def _only(**overrides):
    defaults = dict(
        identifier=0, network=0, type_id=0, version=0, variant=0,
    )
    defaults.update(overrides)
    return RUUID(**defaults)


def test_version_occupies_bits_79_76():
    assert _only(version=0xF).int == 0xF << 76


def test_variant_occupies_bits_63_62():
    assert _only(variant=0b11).int == 0b11 << 62


def test_type_id_occupies_bits_61_52():
    assert _only(type_id=0x3FF).int == 0x3FF << 52


def test_identifier_occupies_bits_127_80():
    assert _only(identifier=(1 << 48) - 1).int == ((1 << 48) - 1) << 80


def test_network_occupies_bits_around_variant():
    """Network straddles the variant: top 12 at 75..64, low 52 at 51..0."""
    network = (1 << 64) - 1
    r = _only(network=network)
    expected = 0xFFF << 64 | 0x000F_FFFF_FFFF_FFFF
    assert r.int == expected
    # None of these bits should leak into version/variant/type_id positions.
    assert (r.int >> 76) & 0xF == 0
    assert (r.int >> 62) & 0x3 == 0
    assert (r.int >> 52) & 0x3FF == 0


# --- Range validation -----------------------------------------------------

def test_identifier_overflow_rejected():
    with pytest.raises(ValueError):
        _only(identifier=1 << 48)


def test_network_overflow_rejected():
    with pytest.raises(ValueError):
        _only(network=1 << 64)


def test_type_id_overflow_rejected():
    with pytest.raises(ValueError):
        _only(type_id=1 << 10)


def test_negative_type_id_rejected():
    with pytest.raises(ValueError):
        _only(type_id=-1)


# --- Round-trip ----------------------------------------------------------

@pytest.mark.parametrize("identifier", [0, 1, 0xABCD, (1 << 48) - 1])
@pytest.mark.parametrize("network", [
    0,
    (SIXTOFOUR_PREFIX << 48) | (0xC000022A << 16),  # 192.0.2.42 6to4
    0x20010DB8_ABCD1234,                            # IPv6 native
    (1 << 64) - 1,                                  # all-ones
])
@pytest.mark.parametrize("type_id", [0, 1, 0x7F, 0xFF, 0x3FF])
def test_round_trip(identifier, network, type_id):
    ru = RUUID(identifier=identifier, network=network, type_id=type_id)
    assert RUUID.from_int(ru.int) == ru
    assert RUUID.from_str(str(ru)) == ru


def test_str_parses_as_standard_uuid():
    r = RUUID.from_anchor(
        ipaddress.IPv4Address("192.0.2.42"),
        identifier=0x123456789ABC,
        type_id=7,
    )
    parsed = std_uuid.UUID(str(r))
    assert parsed.version == VERSION
    assert (parsed.int >> 62) & 0b11 == VARIANT_RFC4122


# --- from_anchor ---------------------------------------------------------

def test_from_anchor_ipv4():
    r = RUUID.from_anchor(
        ipaddress.IPv4Address("192.0.2.42"),
        identifier=0x123456789ABC,
        type_id=5,
    )
    assert r.address_family == 4
    assert r.prefix_bits == 32
    assert r.network == 0x2002_C000_022A_0000
    assert r.ip_network == ipaddress.IPv4Network("192.0.2.42/32")
    assert RUUID.from_str(str(r)) == r


def test_from_anchor_ipv6():
    r = RUUID.from_anchor(
        ipaddress.IPv6Address("2001:db8:abcd:1234::1"),
        identifier=0xDEADBEEF,
        type_id=42,
    )
    assert r.address_family == 6
    assert r.prefix_bits == 64
    assert r.network == 0x20010DB8_ABCD1234
    assert r.ip_network == ipaddress.IPv6Network("2001:db8:abcd:1234::/64")
    assert RUUID.from_str(str(r)) == r


def test_from_anchor_str_form():
    r = RUUID.from_anchor("192.0.2.42", identifier=42, type_id=1)
    assert r.address_family == 4
    assert r.ip_network == ipaddress.IPv4Network("192.0.2.42/32")


def test_from_anchor_rejects_bad_type():
    with pytest.raises(TypeError):
        RUUID.from_anchor(42, identifier=1)  # type: ignore[arg-type]


def test_ipv4_6to4_round_trip_via_text():
    """A 6to4-encoded IPv4 RUUID survives a round-trip through textual form."""
    original = RUUID.from_anchor("10.20.30.40", identifier=0xABCDEF, type_id=3)
    parsed = RUUID.from_str(str(original))
    assert parsed == original
    assert parsed.ip_network == ipaddress.IPv4Network("10.20.30.40/32")
    assert parsed.address_family == 4


def test_ipv6_native_not_treated_as_ipv4():
    """A native IPv6 anchor not starting with 0x2002 is classified IPv6."""
    r = RUUID.from_anchor("2001:db8::1", identifier=1, type_id=0)
    assert r.address_family == 6
    assert r.network >> 48 != SIXTOFOUR_PREFIX
