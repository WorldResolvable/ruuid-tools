"""RUUID generation helpers.

The typical flow is identifier-first: the caller has an identifier
(database primary key, counter, timestamp, batch+sequence) and wraps it
together with an IP address and type_id to form an RUUID.

When the caller does not supply an identifier, one is generated
according to the recommended construction in RUUID §7.3:
20-bit day_count since 2025-01-01 UTC, followed by a 28-bit
cryptographically random sequence. Pass `opaque=True` to get a
plain 48-bit random identifier instead (the local-scope MAY form).
"""

from __future__ import annotations

import ipaddress
import secrets
from datetime import datetime, timezone

from ruuid.core import RUUID, IDENTIFIER_BITS
from ruuid.resolve import to_ip


# --- §7.3 recommended construction -------------------------------------

# Epoch from which day_count is measured (RUUID §7.3).
STRUCTURED_IDENTIFIER_EPOCH = datetime(2025, 1, 1, tzinfo=timezone.utc)

# 20-bit day_count in the high bits, 28-bit sequence in the low bits.
DAY_COUNT_BITS = 20
SEQUENCE_BITS = 28
assert DAY_COUNT_BITS + SEQUENCE_BITS == IDENTIFIER_BITS


def days_since_epoch(now: datetime | None = None) -> int:
    """Days elapsed since 2025-01-01 UTC at `now` (default: current UTC)."""
    if now is None:
        now = datetime.now(timezone.utc)
    return (now - STRUCTURED_IDENTIFIER_EPOCH).days


def structured_identifier(
    *,
    now: datetime | None = None,
    sequence: int | None = None,
) -> int:
    """Build a 48-bit identifier per RUUID §7.3.

    Returns `(day_count << 28) | sequence`, where `day_count` is a
    20-bit count of days since 2025-01-01 UTC and `sequence` is a
    28-bit value unique within `(network, type, day_count)`.

    Per the spec, `day_count` MUST be a day on which the generator
    held reverse-DNS authority over the network prefix and MUST
    NOT be a future day. Any such day is valid — `day_count` need
    not be the day of generation. If `now` is None, today's UTC
    day is used; pass `now` to pin to a specific tenure day (e.g.,
    a fixed early day reused until the 2^28 sequence space is
    exhausted, which dilutes the time-of-generation signal).

    If `sequence` is None, a cryptographically random 28-bit value
    is used. Random selection within 28 bits gives a 2^-14
    collision probability at ~16,000 RUUIDs per `(network, type,
    day)`; higher volumes need a coordinated scheme.

    Raises:
        ValueError: day_count doesn't fit in 20 bits (before
            2025-01-01 or after ~year 4896), or `sequence` doesn't
            fit in 28 bits.
    """
    days = days_since_epoch(now)
    if not 0 <= days < (1 << DAY_COUNT_BITS):
        raise ValueError(
            f"day_count {days} does not fit in {DAY_COUNT_BITS} bits "
            f"(epoch is 2025-01-01 UTC; wrap is ~year 4896)"
        )
    if sequence is None:
        sequence = secrets.randbits(SEQUENCE_BITS)
    elif not 0 <= sequence < (1 << SEQUENCE_BITS):
        raise ValueError(
            f"sequence {sequence:#x} does not fit in {SEQUENCE_BITS} bits"
        )
    return (days << SEQUENCE_BITS) | sequence


def new_ruuid(
    anchor: ipaddress.IPv4Address | ipaddress.IPv6Address | str,
    *,
    type_id: int = 0,
    identifier: int | None = None,
    opaque: bool = False,
    day: datetime | None = None,
) -> RUUID:
    """Create a fresh RUUID with an IP-derived network prefix.

    `anchor` is a single IP address (IPv4 or IPv6) whose reverse-DNS
    delegation the caller controls. IPv4 addresses are 6to4-encoded
    into the 64-bit network field; for IPv6, the high 64 bits of the
    address are taken as the network prefix. A hostname is accepted
    and resolved via the system resolver (IPv4 preferred).

    When `identifier` is None, the 48-bit identifier is generated:

      - `opaque=False` (default): structured form per RUUID §7.3 —
        20-bit day_count since 2025-01-01 UTC, then a 28-bit random
        sequence. `day` picks the tenure day to use (default:
        current UTC day); per the spec, callers MUST pass only a
        day on which they held the network prefix.
      - `opaque=True`: a plain 48-bit cryptographically random value
        (the local-scope MAY form). Hides tenure information at the
        cost of a ~2^24 birthday bound within `(network, type)`.
        Incompatible with `day`.

    When `identifier` is supplied, `opaque` and `day` are ignored.

    Raises:
        ValueError: `anchor` is an unresolvable hostname, `identifier`
            doesn't fit in 48 bits, or `opaque` and `day` are both
            specified.
    """
    if identifier is None:
        if opaque:
            if day is not None:
                raise ValueError("`opaque=True` is incompatible with `day=`")
            identifier = secrets.randbits(IDENTIFIER_BITS)
        else:
            identifier = structured_identifier(now=day)
    elif not 0 <= identifier < (1 << IDENTIFIER_BITS):
        raise ValueError(
            f"identifier {identifier:#x} does not fit in {IDENTIFIER_BITS} bits"
        )
    if isinstance(anchor, str):
        anchor = to_ip(anchor)
    return RUUID.from_anchor(
        anchor,
        identifier=identifier,
        type_id=type_id,
    )
