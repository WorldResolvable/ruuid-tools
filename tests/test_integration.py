"""End-to-end integration test: spawn a real Anchor, run the full
DNS + HTTP resolution path against it via the public CLI fetchers.

Catches wiring regressions that unit tests miss (port binding,
URI/TXT query path, Host-header dispatch, redirect/alias chains,
default-template fall-through).

The anchor runs in plain HTTP on ephemeral ports (no TLS), so tests
don't need root and don't need /etc/ruuid/anchor-cert.pem. The spec's
default referent template (https://<domain>/<type>/<identifier>)
encodes port 443, which we can't bind without root — so the fall-
through and zero-config tests verify the resolver's derivation
without actually fetching; the explicit-class and alias tests use
base_url / alias_to templates that include the ephemeral port.
"""

from __future__ import annotations

import json
import socket

import pytest

from ruuid import new_ruuid, resolve_referent_uri
from ruuid.anchor import Anchor, _Issuer
from ruuid.resolve import Resolver, fetch_document, fetch_url_body


def _free_port(kind: int) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def live_anchor():
    """Spawn an Anchor on ephemeral ports with a small in-memory zone."""
    dns_port = _free_port(socket.SOCK_DGRAM)
    http_port = _free_port(socket.SOCK_STREAM)
    # The daemon serves on an ephemeral http port, so we override the
    # default doc URL (https://<domain>/.well-known/uuid-document.json)
    # with `uuid_document_uri` carrying the host:port the test actually
    # binds. `service` is kept so the daemon still builds and serves
    # the UUID document at that URL.
    def _doc_uri(domain: str) -> str:
        return f"http://{domain}:{http_port}/.well-known/uuid-document.json"

    issuers = [
        _Issuer(
            domain="branch.example",
            anchor="192.0.2.1",
            ptr_name="1.2.0.192.in-addr.arpa",
            uuid_document_uri=_doc_uri("branch.example"),
            service=[{
                "id": "#7", "type": "Event",
                "serviceEndpoint": (
                    f"http://branch.example:{http_port}/events/<identifier>"
                ),
            }],
        ),
        _Issuer(
            domain="campus.example",
            anchor="2001:db8:abcd::1",
            ptr_name="0.0.0.0.d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa",
            uuid_document_uri=_doc_uri("campus.example"),
            service=[
                {
                    "id": "#4", "type": "Aliased",
                    "serviceEndpoint": (
                        f"http://campus.example:{http_port}/a/<identifier>"
                    ),
                    "alias_to": (
                        f"http://upstream.example:{http_port}"
                        "/<type>/<identifier>"
                    ),
                },
                {
                    "id": "#5", "type": "AliasedWithFullRuuid",
                    "serviceEndpoint": (
                        f"http://campus.example:{http_port}/w/<identifier>"
                    ),
                    "alias_to": (
                        f"http://upstream.example:{http_port}"
                        "/<type>/<identifier>"
                        "?network=<network>&uuid=<uuid>"
                    ),
                },
            ],
        ),
        _Issuer(  # alias target — zero-config, serves stub via default template
            domain="upstream.example",
            anchor="1.1.1.1",
            ptr_name="1.1.1.1.in-addr.arpa",
            service=None,
        ),
        _Issuer(  # zero-config: anchor exists only via PTR
            domain="bare.example",
            anchor="198.51.100.7",
            ptr_name="7.100.51.198.in-addr.arpa",
            service=None,
        ),
        _Issuer(  # class-0 issuer-wide default template
            domain="fallback.example.com",
            anchor="198.51.100.20",
            ptr_name="20.100.51.198.in-addr.arpa",
            uuid_document_uri=_doc_uri("fallback.example.com"),
            service=[{
                "id": "#0", "type": "default",
                "serviceEndpoint": (
                    f"http://fallback.example.com:{http_port}/r/<identifier>"
                ),
            }],
        ),
    ]
    anchor = Anchor(
        issuers, bind="127.0.0.1",
        dns_port=dns_port, http_port=http_port,
        serve_https=False,
    )
    anchor.start()
    try:
        yield anchor, dns_port, http_port
    finally:
        anchor.stop()


def _resolver_for(dns_port: int) -> Resolver:
    return Resolver(nameservers=["127.0.0.1"], port=dns_port, lifetime=2.0)


def _ns(dns_port: int) -> str:
    return f"127.0.0.1:{dns_port}"


def test_explicit_class_full_resolution(live_anchor):
    """RUUID with a class defined in the document: PTR → URI → doc → template."""
    _anchor, dns_port, _http_port = live_anchor
    ru = new_ruuid("192.0.2.1", type_id=7, identifier=0xABCD)

    out = _resolver_for(dns_port).resolve(ru)
    assert out["domain"] == "branch.example"
    assert out["reverse_name"] == "1.2.0.192.in-addr.arpa"
    assert "branch.example" in out["uuid_document_uri"]

    doc = fetch_document(out["uuid_document_uri"], nameserver=_ns(dns_port))
    assert doc is not None
    services = {s["id"]: s for s in doc["service"]}
    assert services["#7"]["serviceEndpoint"].endswith("/events/<identifier>")

    referent = resolve_referent_uri(ru, domain="branch.example", document=doc)
    body = fetch_url_body(referent, nameserver=_ns(dns_port))
    assert body is not None
    stub = json.loads(body)
    assert stub["type_name"] == "Event"
    assert stub["identifier"] == "00000000abcd"


def test_class_fall_through_url_derivation(live_anchor):
    """Document fetched but class not listed: resolver derives default template URL."""
    _anchor, dns_port, _http_port = live_anchor
    ru = new_ruuid("192.0.2.1", type_id=99, identifier=0xCAFE)

    out = _resolver_for(dns_port).resolve(ru)
    doc = fetch_document(out["uuid_document_uri"], nameserver=_ns(dns_port))
    assert doc is not None
    services = {s["id"]: s for s in doc["service"]}
    assert "#99" not in services

    referent = resolve_referent_uri(ru, domain=out["domain"], document=doc)
    assert referent == "https://branch.example/99/00000000cafe"


def test_zero_config_default_doc_and_template(live_anchor):
    """No record at _uuid.<domain>: resolver falls back to default doc URI."""
    _anchor, dns_port, _http_port = live_anchor
    ru = new_ruuid("198.51.100.7", type_id=8, identifier=0x1234)

    out = _resolver_for(dns_port).resolve(ru)
    assert out["domain"] == "bare.example"
    assert out["uuid_document_uri"] == (
        "https://bare.example/.well-known/uuid-document.json"
    )

    referent = resolve_referent_uri(ru, domain="bare.example", document=None)
    assert referent == "https://bare.example/8/000000001234"


def test_type_zero_template_is_issuer_default(live_anchor):
    """When the requested class is absent, class 0's template applies."""
    _anchor, dns_port, http_port = live_anchor
    ru = new_ruuid("198.51.100.20", type_id=8, identifier=0xC0FFEE)

    out = _resolver_for(dns_port).resolve(ru)
    assert out["domain"] == "fallback.example.com"

    doc = fetch_document(out["uuid_document_uri"], nameserver=_ns(dns_port))
    assert doc is not None
    services = {s["id"]: s for s in doc["service"]}
    assert "#8" not in services
    assert services["#0"]["serviceEndpoint"].endswith("/r/<identifier>")

    referent = resolve_referent_uri(ru, domain="fallback.example.com", document=doc)
    # class 0's path wins over the spec default /<type>/<identifier>.
    assert referent.endswith("/r/000000c0ffee")

    body = fetch_url_body(referent, nameserver=_ns(dns_port))
    assert body is not None
    stub = json.loads(body)
    # The route is class 0's; identifier echoes the request.
    assert stub["type_id"] == "0"
    assert stub["identifier"] == "000000c0ffee"


def test_alias_chain_followed_to_upstream(live_anchor):
    """alias_to triggers HTTP 302; fetcher follows to the upstream path."""
    _anchor, dns_port, _http_port = live_anchor
    ru = new_ruuid("2001:db8:abcd::1", type_id=4, identifier=0xBEEF)

    out = _resolver_for(dns_port).resolve(ru)
    doc = fetch_document(out["uuid_document_uri"], nameserver=_ns(dns_port))
    referent = resolve_referent_uri(ru, domain="campus.example", document=doc)

    trace: list = []
    body = fetch_url_body(referent, nameserver=_ns(dns_port), trace=trace)
    assert body is not None
    statuses = [hop.get("status") for hop in trace]
    assert 302 in statuses
    assert statuses[-1] == 200
    final_hop = trace[-1]
    assert "upstream.example" in final_hop["url"]


def test_alias_expansion_carries_network_and_full_uuid(live_anchor):
    """alias_to with <network>+<uuid> resolves end-to-end and the 302's
    Location carries the substituted values into the upstream URL."""
    _anchor, dns_port, _http_port = live_anchor
    ru = new_ruuid("2001:db8:abcd::1", type_id=5, identifier=0xBEEF)

    out = _resolver_for(dns_port).resolve(ru)
    doc = fetch_document(out["uuid_document_uri"], nameserver=_ns(dns_port))
    referent = resolve_referent_uri(ru, domain="campus.example", document=doc)

    trace: list = []
    body = fetch_url_body(referent, nameserver=_ns(dns_port), trace=trace)
    assert body is not None
    # The 302 redirect's URL is the trace entry's `location`; the next
    # hop's URL is what we actually fetched.
    redirect_hop = next(h for h in trace if h.get("status") == 302)
    location = redirect_hop["location"]
    assert "network=20010db8abcd0000" in location
    assert f"uuid={ru}" in location
    # And the final fetch lands at upstream's default-template stub.
    assert trace[-1].get("status") == 200
    assert "upstream.example" in trace[-1]["url"]


# --- CLI --registry end-to-end ------------------------------------------

def test_cli_resolve_with_registry_dns(live_anchor, capsys):
    """`ruuid resolve --registry dns://127.0.0.1:port ...` is equivalent
    to the older --nameserver form."""
    from ruuid.cli import main
    _anchor, dns_port, _http_port = live_anchor
    ru = new_ruuid("192.0.2.1", type_id=7, identifier=0xABCD)
    rc = main([
        "resolve",
        "--registry", f"dns://127.0.0.1:{dns_port}",
        str(ru),
    ])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert "branch.example" in out


def test_cli_resolve_rejects_unsupported_registry_scheme(capsys):
    """An unknown URL scheme on --registry produces a clear error."""
    from ruuid.cli import main
    rc = main([
        "resolve",
        "--registry", "ftp://example.com/",
        "00000000-0000-8000-8000-000000000000",
    ])
    err = capsys.readouterr().err
    assert rc != 0
    assert "--registry" in err
    assert "unsupported scheme" in err


# --- Anchor: DoH endpoint -----------------------------------------------

def test_doh_endpoint_post_proxies_to_dns(live_anchor):
    """POST a wire-format DNS message to /dns-query; the anchor proxies
    it to its own UDP DNS server and returns the wire-format reply."""
    import dns.message
    import dns.rdatatype
    _anchor, _dns_port, http_port = live_anchor
    q = dns.message.make_query("1.2.0.192.in-addr.arpa", "PTR")
    body = q.to_wire()

    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
    try:
        conn.request(
            "POST", "/dns-query",
            body=body,
            headers={
                "Host": "anchor.example",
                "Content-Type": "application/dns-message",
                "Content-Length": str(len(body)),
            },
        )
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.getheader("Content-Type") == "application/dns-message"
        reply_wire = resp.read()
    finally:
        conn.close()

    reply = dns.message.from_wire(reply_wire)
    assert reply.answer, "DoH reply has no answer section"
    ans = reply.answer[0]
    assert ans.rdtype == dns.rdatatype.PTR
    assert str(ans[0].target).rstrip(".") == "branch.example"


def test_doh_endpoint_get_with_base64url_form(live_anchor):
    """GET /dns-query?dns=<base64url-message> is also accepted (RFC 8484)."""
    import base64
    import dns.message
    _anchor, _dns_port, http_port = live_anchor
    q = dns.message.make_query("1.2.0.192.in-addr.arpa", "PTR")
    encoded = base64.urlsafe_b64encode(q.to_wire()).rstrip(b"=").decode()

    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
    try:
        conn.request("GET", f"/dns-query?dns={encoded}",
                     headers={"Host": "anchor.example"})
        resp = conn.getresponse()
        assert resp.status == 200
        reply_wire = resp.read()
    finally:
        conn.close()

    reply = dns.message.from_wire(reply_wire)
    assert reply.answer
    assert str(reply.answer[0][0].target).rstrip(".") == "branch.example"


def test_doh_endpoint_get_without_dns_param_400s(live_anchor):
    """A GET to /dns-query without ?dns=... is malformed → 400."""
    _anchor, _dns_port, http_port = live_anchor
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
    try:
        conn.request("GET", "/dns-query",
                     headers={"Host": "anchor.example"})
        resp = conn.getresponse()
        assert resp.status == 400
    finally:
        conn.close()


def test_doh_endpoint_post_wrong_content_type_415s(live_anchor):
    """POST to /dns-query with a non-DNS-message body → 415."""
    _anchor, _dns_port, http_port = live_anchor
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
    try:
        conn.request("POST", "/dns-query",
                     body=b"not-a-dns-message",
                     headers={
                         "Host": "anchor.example",
                         "Content-Type": "text/plain",
                         "Content-Length": "16",
                     })
        resp = conn.getresponse()
        assert resp.status == 415
    finally:
        conn.close()


def test_doh_resolver_resolves_against_live_anchor(live_anchor):
    """A Resolver over a DohTransport talks to the anchor's /dns-query
    endpoint over plain HTTP (the live fixture doesn't use TLS) and
    returns the expected (domain, doc_uri) pair."""
    from ruuid import Resolver, DohTransport
    _anchor, _dns_port, http_port = live_anchor
    reg = Resolver(DohTransport(
        f"http://127.0.0.1:{http_port}/dns-query",
        verify=False, timeout=2,
    ))
    ru = new_ruuid("192.0.2.1", type_id=7, identifier=0xABCD)
    out = reg.resolve(ru)
    assert out["domain"] == "branch.example"
    assert out["reverse_name"] == "1.2.0.192.in-addr.arpa"
    assert "branch.example" in out["uuid_document_uri"]
