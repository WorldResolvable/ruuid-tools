"""Load tests/test_vectors.json and assert this implementation matches.

If a downstream implementor adds a new vector, their CI run here
proves the vector itself is consistent with at least one impl
(this one), so they can confidently use the file as a fixture for
their own (e.g. Go, Rust) implementation.

The anchor_dns / anchor_http vectors describe what `ruuid anchor`
must produce; those are exercised via tests/test_integration.py
against the demo zone, not here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ruuid import RUUID, new_ruuid, substitute_template
from ruuid.resolve import reverse_dns_name


VECTORS_PATH = Path(__file__).parent / "test_vectors.json"


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())


def test_generate_vectors(vectors):
    for v in vectors["generate"]:
        ru = new_ruuid(
            v["address"],
            type_id=v["type_id"],
            identifier=v["identifier"],
        )
        assert str(ru) == v["expected_ruuid"], (
            f"generate({v['address']}, {v['identifier_hex']}, "
            f"class={v['type_id']}) produced {ru} but vector "
            f"expected {v['expected_ruuid']}"
        )


def test_decode_vectors(vectors):
    for v in vectors["decode"]:
        ru = RUUID.from_str(v["ruuid"])
        assert ru.version == v["version"]
        assert ru.type_id == v["type_id"]
        assert f"0x{ru.identifier:x}" == v["identifier_hex"]
        assert ru.address_family == v["address_family"]
        assert str(ru.ip_network) == v["network"]
        assert reverse_dns_name(ru) == v["reverse_dns_name"]


def test_referent_template_vectors(vectors):
    for v in vectors["referent_template"]:
        ru = RUUID.from_str(v["ruuid"])
        got = substitute_template(v["template"], ru, domain=v["domain"])
        assert got == v["expected"]
