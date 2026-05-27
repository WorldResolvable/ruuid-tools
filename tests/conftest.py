"""Test fixtures: programmable in-process DNS server backed by dnslib."""

from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from typing import IO, Iterable

import dnslib
import pytest
from dnslib import QTYPE, RCODE, RD, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer


# --- URI rdata class -----------------------------------------------------
# dnslib (0.9.x) doesn't ship a URI rdata class; add a minimal one so the
# test server can serve RFC 7553 URI records.

class URI(RD):
    """Minimal RFC 7553 URI record. Wire: prio(uint16) weight(uint16) target."""

    def __init__(self, priority: int, weight: int, target):
        self.priority = int(priority)
        self.weight = int(weight)
        self.target = target.encode() if isinstance(target, str) else target

    @classmethod
    def parse(cls, buffer, length):
        prio, weight = struct.unpack("!HH", buffer.get(4))
        target = buffer.get(length - 4)
        return cls(prio, weight, target)

    def pack(self, buffer):
        buffer.append(struct.pack("!HH", self.priority, self.weight))
        buffer.append(self.target)

    def __repr__(self):
        return f'{self.priority} {self.weight} "{self.target.decode()}"'


def _register_uri_once():
    if "URI" not in dnslib.RDMAP:
        dnslib.RDMAP["URI"] = URI
    # QTYPE.forward["URI"] -> 256 (reverse is already populated).
    try:
        dnslib.QTYPE["URI"]
    except dnslib.dns.DNSError:
        dnslib.QTYPE.forward["URI"] = 256


# --- Fake NS -------------------------------------------------------------

class FakeNS:
    """A programmable in-process DNS server bound to 127.0.0.1 on a free port.

    Use `add_ptr`, `add_uri`, `add_txt` to populate the response table before
    pointing a resolver at `(ns.address, ns.port)`. Names not in the table
    return NOERROR/NODATA if the name appears under any other type, else
    NXDOMAIN.
    """

    def __init__(self, *, log_stream: IO[str] | None = None):
        _register_uri_once()
        self._records: dict[tuple[str, str], list[tuple[int, RD]]] = {}
        self._known_names: set[str] = set()
        self._port = _free_udp_port()
        self.address = "127.0.0.1"
        self.port = self._port
        # log_stream=None → silent (dnslib's defaults log per-request to
        # stdout, which would pollute capsys.out in tests). Pass a stream
        # (e.g. sys.stderr) to surface the per-request lines there instead.
        if log_stream is None:
            logger = DNSLogger(logf=lambda s: None)
        else:
            logger = DNSLogger(logf=lambda s: print(s, file=log_stream))
        self._server = DNSServer(
            _Resolver(self), port=self._port, address=self.address,
            logger=logger,
        )
        self._server.start_thread()
        # Give the server thread a moment to bind.
        time.sleep(0.05)

    # --- public mutators ---

    def add_ptr(self, name: str, target: str, ttl: int = 60) -> None:
        target_full = target if target.endswith(".") else target + "."
        self._add(name, "PTR", ttl, dnslib.PTR(target_full))

    def add_uri(self, name: str, target: str, *, priority: int = 10,
                weight: int = 1, ttl: int = 60) -> None:
        self._add(name, "URI", ttl, URI(priority, weight, target))

    def add_txt(self, name: str, text: str, ttl: int = 60) -> None:
        # TXT rdata is a sequence of <=255-byte strings; we just use one.
        self._add(name, "TXT", ttl, dnslib.TXT(text.encode()))

    def stop(self) -> None:
        self._server.stop()

    # --- internals ---

    def _add(self, name: str, qtype: str, ttl: int, rdata: RD) -> None:
        key = (_canon(name), qtype)
        self._records.setdefault(key, []).append((ttl, rdata))
        self._known_names.add(_canon(name))

    def _lookup(self, name: str, qtype: str):
        return self._records.get((_canon(name), qtype), [])

    def _lookup_all(self, name: str):
        """Return [(qtype_str, ttl, rdata), ...] across all types at this name."""
        canon = _canon(name)
        out = []
        for (n, t), records in self._records.items():
            if n == canon:
                for ttl, rdata in records:
                    out.append((t, ttl, rdata))
        return out

    def _has_name(self, name: str) -> bool:
        return _canon(name) in self._known_names


class _Resolver(BaseResolver):
    def __init__(self, ns: FakeNS):
        self.ns = ns

    def resolve(self, request, handler):  # noqa: D401
        reply = request.reply()
        qname = request.q.qname
        qname_str = str(qname)
        qtype_int = request.q.qtype
        qtype_str = QTYPE[qtype_int]
        if qtype_str == "ANY" or qtype_int == 255:
            # Return all records at this name across all types.
            any_matches = self.ns._lookup_all(qname_str)
            if any_matches:
                for type_str, ttl, rdata in any_matches:
                    rr_type = (256 if type_str == "URI"
                               else dnslib.QTYPE.forward.get(type_str, qtype_int))
                    reply.add_answer(RR(qname, rr_type, ttl=ttl, rdata=rdata))
            elif not self.ns._has_name(qname_str):
                reply.header.rcode = RCODE.NXDOMAIN
            return reply
        matches = self.ns._lookup(qname_str, qtype_str)
        if matches:
            for ttl, rdata in matches:
                reply.add_answer(RR(qname, qtype_int, ttl=ttl, rdata=rdata))
        elif not self.ns._has_name(qname_str):
            reply.header.rcode = RCODE.NXDOMAIN
        # else: NOERROR with empty answer section -> NODATA
        return reply


def _canon(name: str) -> str:
    return name.lower().rstrip(".")


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- pytest fixture ------------------------------------------------------

@pytest.fixture
def test_ns():
    ns = FakeNS()
    try:
        yield ns
    finally:
        ns.stop()
