"""Resolvable UUID core types and bit-level encoding.

Bit layout, treating the UUID as a 128-bit big-endian integer (bit 127 = MSB):

    bits 127..80 (48): identifier
    bits  79..76  (4): version          -- = 8 (RFC 9562 experimental)
    bits  75..64 (12): network_hi       -- high 12 of 64-bit network slot
    bits  63..62  (2): variant          -- = 0b10
    bits  61..52 (10): type_id          -- selects a type entry in the UUID document
    bits  51..0  (52): network_lo       -- low 52 of network slot

The 64-bit "network slot" (network_hi << 52 | network_lo) is the issuer's
namespace anchor. IPv4 anchors are encoded as a 6to4 IPv6 prefix: the
IPv4 /32 address W.X.Y.Z is placed into 2002:WXYZ::/48, with the high
64 bits (2002:WXYZ:0000:0000) occupying the slot. IPv6 anchors take the
high 64 bits of the /128 directly.

The encoding alone determines the address family at resolution time: if
the top 16 bits of the network slot are 0x2002, the next 32 bits are
the IPv4 anchor (reverse-resolved via in-addr.arpa at /32); otherwise
the full 64 bits form an IPv6 /64 (reverse-resolved via ip6.arpa).
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass


VERSION = 8               # RFC 9562 experimental; flip to 9 if/when IANA assigns
VARIANT_RFC4122 = 0b10    # standard 2-bit UUID variant

PREFIX_BITS_IPV4 = 32     # fixed /32 for IPv4-anchored RUUIDs
PREFIX_BITS_IPV6 = 64     # fixed /64 for IPv6-anchored RUUIDs
IDENTIFIER_BITS = 48
NETWORK_SLOT_BITS = 64
TYPE_BITS = 10

SIXTOFOUR_PREFIX = 0x2002   # top 16 bits of network for IPv4-encoded RUUIDs

_VERSION_MASK    = 0xF
_VARIANT_MASK    = 0x3
_TYPE_MASK       = (1 << TYPE_BITS) - 1
_IDENT_MASK      = (1 << IDENTIFIER_BITS) - 1
_NETWORK_MASK    = (1 << NETWORK_SLOT_BITS) - 1
_NETWORK_HI_MASK = (1 << 12) - 1
_NETWORK_LO_MASK = (1 << 52) - 1


def _is_sixtofour(network: int) -> bool:
    return (network >> 48) == SIXTOFOUR_PREFIX


@dataclass(frozen=True)
class RUUID:
    """A resolvable UUID.

    `identifier` is a 48-bit unsigned integer. `network` is the issuer's
    64-bit namespace anchor: an IPv4 /32 encoded as a 6to4 prefix, or
    the high 64 bits of an IPv6 /128. `type_id` is a 10-bit value
    that selects a service entry (`id` = `#<type>`) in the issuer's
    UUID document.
    """

    identifier: int
    network: int
    type_id: int
    version: int = VERSION
    variant: int = VARIANT_RFC4122

    def __post_init__(self) -> None:
        if not 0 <= self.version <= _VERSION_MASK:
            raise ValueError(f"version out of 4-bit range: {self.version}")
        if not 0 <= self.variant <= _VARIANT_MASK:
            raise ValueError(f"variant out of 2-bit range: {self.variant}")
        if not 0 <= self.type_id <= _TYPE_MASK:
            raise ValueError(
                f"type_id out of {TYPE_BITS}-bit range: {self.type_id}"
            )
        if not 0 <= self.identifier <= _IDENT_MASK:
            raise ValueError(
                f"identifier out of {IDENTIFIER_BITS}-bit range: {self.identifier:#x}"
            )
        if not 0 <= self.network <= _NETWORK_MASK:
            raise ValueError(
                f"network out of {NETWORK_SLOT_BITS}-bit range: {self.network:#x}"
            )

    # --- views -----------------------------------------------------------

    @property
    def address_family(self) -> int:
        """4 if the network field is a 6to4-encoded IPv4 anchor, else 6."""
        return 4 if _is_sixtofour(self.network) else 6

    @property
    def prefix_bits(self) -> int:
        """Effective network-prefix length for reverse DNS: 32 (IPv4) or 64 (IPv6)."""
        return PREFIX_BITS_IPV4 if self.address_family == 4 else PREFIX_BITS_IPV6

    @property
    def ip_network(
        self,
    ) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """The IP network identified by the network field."""
        if self.address_family == 4:
            ipv4_int = (self.network >> 16) & 0xFFFFFFFF
            return ipaddress.IPv4Network((ipv4_int, PREFIX_BITS_IPV4), strict=False)
        ipv6_int = self.network << 64
        return ipaddress.IPv6Network((ipv6_int, PREFIX_BITS_IPV6), strict=False)

    @property
    def int(self) -> int:
        network_hi = (self.network >> 52) & _NETWORK_HI_MASK
        network_lo = self.network & _NETWORK_LO_MASK
        return (
            (self.identifier & _IDENT_MASK) << 80
            | (self.version & _VERSION_MASK) << 76
            | network_hi << 64
            | (self.variant & _VARIANT_MASK) << 62
            | (self.type_id & _TYPE_MASK) << 52
            | network_lo
        )

    def __str__(self) -> str:
        return str(uuid.UUID(int=self.int))

    # --- constructors ----------------------------------------------------

    @classmethod
    def from_int(cls, n: int) -> RUUID:
        if not 0 <= n < (1 << 128):
            raise ValueError(f"value out of 128-bit range: {n:#x}")
        identifier  = (n >> 80) & _IDENT_MASK
        version     = (n >> 76) & _VERSION_MASK
        network_hi  = (n >> 64) & _NETWORK_HI_MASK
        variant     = (n >> 62) & _VARIANT_MASK
        type_id     = (n >> 52) & _TYPE_MASK
        network_lo  = n & _NETWORK_LO_MASK
        network     = (network_hi << 52) | network_lo
        return cls(
            identifier=identifier,
            network=network,
            type_id=type_id,
            version=version,
            variant=variant,
        )

    @classmethod
    def from_str(cls, s: str) -> RUUID:
        return cls.from_int(uuid.UUID(s).int)

    @classmethod
    def from_anchor(
        cls,
        anchor: ipaddress.IPv4Address | ipaddress.IPv6Address | str,
        *,
        identifier: int,
        type_id: int = 0,
    ) -> RUUID:
        """Build an RUUID from an IP anchor (a single IPv4 or IPv6 address).

        IPv4 anchors are encoded as a 6to4 prefix in the network slot
        (2002:WXYZ:0000:0000); the RUUID resolves via in-addr.arpa at /32.
        IPv6 anchors place the high 64 bits of the address in the network
        slot; the RUUID resolves via ip6.arpa at /64.
        """
        if isinstance(anchor, str):
            anchor = ipaddress.ip_address(anchor)

        if isinstance(anchor, ipaddress.IPv4Address):
            network = (SIXTOFOUR_PREFIX << 48) | (int(anchor) << 16)
        elif isinstance(anchor, ipaddress.IPv6Address):
            network = int(anchor) >> 64
        else:
            raise TypeError(
                f"expected IPv4Address, IPv6Address, or str; got {type(anchor).__name__}"
            )

        return cls(
            identifier=identifier,
            network=network,
            type_id=type_id,
        )
