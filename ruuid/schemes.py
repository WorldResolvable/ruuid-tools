"""Identifier-scheme constants for UUID-document publishers and consumers.

These are not part of the RUUID wire format -- they are name-tags used
in the `identifier_scheme.type` field of a UUID document, per the
specification. The library exposes them as a convenience for callers
that construct or interpret UUID documents.
"""

from __future__ import annotations


class IdentifierScheme:
    """Identifier-scheme type names as used in the UUID document.

    See draft-motters-ruuid §7.3 for the semantics of each scheme.
    """

    OPAQUE    = "opaque"
    MONOTONIC = "monotonic"
    TIMESTAMP = "timestamp"

    ALL = frozenset({OPAQUE, MONOTONIC, TIMESTAMP})

    SORTABLE = frozenset({MONOTONIC, TIMESTAMP})
    """Schemes that make a sortability claim over the identifier."""
