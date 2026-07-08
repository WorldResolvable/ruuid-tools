"""Command-line entry point for `ruuid`.

This module is intentionally thin: it parses argv, validates the
form of the arguments (port numbers are integers, --follow values
are in the allowed set, etc.), and dispatches to API functions in
`ruuid.generate`, `ruuid.resolve`, and `ruuid.anchor`. The called
APIs validate the semantics of their own inputs (identifier range,
hostname resolvability, registry-URL scheme, ...) and raise
ValueError on bad input; the dispatcher just translates that into a
stderr line and a non-zero exit.

Subcommands:

    ruuid generate <address> [<identifier>] [--type N]
    ruuid resolve  <uuid> [--registry URL] [--nameserver HOST[:PORT]]
                          [--follow [WHAT]] [--verbose]
    ruuid document --zone FILE [--domain DOMAIN]
    ruuid records  --zone FILE [--domain DOMAIN] [--rrtype WHAT]
                              [--ttl N]
    ruuid anchor   --zone FILE [--bind HOST] [--dns-port N]
                               [--http-port N] [--https-port N]
                               [--rrtype WHAT]
    ruuid seal     <address> <domain> [--type N] [--day DATE] [--out DIR]
                               [--production] [--challenge WHAT] [--webroot DIR]
                               [--no-domain-cert] [--nameserver HOST[:PORT]]
                               [--acme PATH]
    ruuid coverage <address> [--day DATE] [--seals DIR]

Resolve has five output modes:
  - default: the UUID-document URI on one line (pipeable into curl).
  - --follow=referent_uri: just the referent URI string (no HTTP).
  - --follow=document / --follow=referent (bare --follow): the body
    of the UUID document or referent URI on stdout (pipeable into
    jq).
  - --follow=ruuid_document: the synthesised per-RUUID DID document,
    as JSON, on stdout.
  - --verbose: structured detail block + DNS/HTTP trace + UUID
    document + referent body, all to stdout.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import json
import os
import sys
from pathlib import Path

from ruuid import ResolveError, new_ruuid
from ruuid.generate import STRUCTURED_IDENTIFIER_EPOCH
from ruuid.resolve import resolve_ruuid


def _parse_int(s: str) -> int:
    """Accept decimal, 0x-hex, 0o-octal, 0b-binary."""
    return int(s, 0)


def _parse_day(s: str) -> _datetime.datetime:
    """Parse --day as YYYY-MM-DD or as a bare integer day_count."""
    if "-" not in s:
        try:
            n = int(s)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"--day expected YYYY-MM-DD or integer day_count, got {s!r}"
            )
        return STRUCTURED_IDENTIFIER_EPOCH + _datetime.timedelta(days=n)
    try:
        d = _datetime.date.fromisoformat(s)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"--day expected YYYY-MM-DD, got {s!r}"
        )
    return _datetime.datetime(
        d.year, d.month, d.day, tzinfo=_datetime.timezone.utc,
    )


def cmd_generate(args: argparse.Namespace) -> int:
    if args.opaque and args.day is not None:
        print(
            "ruuid generate: --opaque and --day are mutually exclusive",
            file=sys.stderr,
        )
        return 1
    if args.day is not None:
        today = _datetime.datetime.now(_datetime.timezone.utc).date()
        if args.day.date() > today:
            print(
                f"ruuid generate: --day must not be in the future "
                f"(today UTC is {today.isoformat()})",
                file=sys.stderr,
            )
            return 1
    try:
        ru = new_ruuid(
            args.address,
            type_id=args.type_id,
            identifier=args.identifier,
            opaque=args.opaque,
            day=args.day,
        )
    except (ValueError, TypeError) as e:
        print(f"ruuid generate: {e}", file=sys.stderr)
        return 1
    print(str(ru))
    return 0


def cmd_resolve(args: argparse.Namespace) -> int:
    follow = "referent" if args.verbose else args.follow
    registry_trace: list | None = [] if args.verbose else None
    fetch_trace: list | None = [] if args.verbose else None
    try:
        out = resolve_ruuid(
            args.uuid,
            registry=args.registry,
            follow=follow,
            registry_trace=registry_trace,
            fetch_trace=fetch_trace,
        )
    except ValueError as e:
        msg = str(e)
        flag = "" if msg.startswith("invalid UUID:") else "--registry: "
        print(f"ruuid resolve: {flag}{msg}", file=sys.stderr)
        return 1
    except ResolveError as e:
        print(f"ruuid resolve: {e}", file=sys.stderr)
        return 1

    if args.verbose:
        _emit_verbose(args.uuid, out, registry_trace, fetch_trace)
        return 0

    if args.follow:
        value = out[args.follow]
        if value is None:
            # The fetched-body keys ("document", "referent") can be None
            # if their URI wasn't reachable; the URI itself is reported
            # for the operator. "ruuid_document" is None only when the
            # Phase 2 template substitution failed (no domain and no
            # document template).
            uri_key = {
                "document": "uuid_document_uri",
                "referent": "referent_uri",
            }.get(args.follow)
            if uri_key is not None:
                print(
                    f"ruuid resolve: could not fetch {out[uri_key]}",
                    file=sys.stderr,
                )
            else:
                print(
                    "ruuid resolve: no Phase 2 referent URI available",
                    file=sys.stderr,
                )
            return 1
        if isinstance(value, (bytes, bytearray)):
            sys.stdout.buffer.write(value)
            if not value.endswith(b"\n"):
                sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
        elif isinstance(value, dict):
            print(json.dumps(value, indent=2))
        else:
            print(value)
        return 0

    print(out["uuid_document_uri"])
    return 0


def _emit_resolve_detail(uuid_str: str,
                         out: dict,
                         registry_trace: list | None,
                         quiet_trace: bool = False) -> None:
    """Render the detail block + registry trace.

    This is the parsing-and-resolution part of --verbose output (i.e.
    everything `ruuid parse` shows): the parsed fields of the UUID,
    the domain and document URI returned by Phase 1, the chosen
    referent template, and the DNS/HTTP trace of the registry lookup.
    Does not print the fetched UUID document, the synthesised DID
    document, or the referent body — see `_emit_verbose` for those.

    `quiet_trace=True` (used by `ruuid parse`) suppresses FAILOVR
    lines and per-hop error entries; only the successful hops are
    printed.
    """
    from ruuid.core import RUUID
    from ruuid.resolve import _select_service_entry

    ru = RUUID.from_str(uuid_str)
    print(f"uuid:              {uuid_str}")
    print(f"network:           {out['network']}")
    print(f"identifier:        {ru.identifier:012x}")
    print(f"                   {_identifier_structured_reading(ru)}")
    print(f"type_id:           {ru.type_id}")
    print(f"reverse_name:      {out['reverse_name']}")
    print(f"domain:            {out['domain']}")

    # Resolve which template was selected, for the parenthetical on the
    # uuid_document_uri line. The ladder is type-specific entry → #0
    # fallback → spec-wide default; label each so the operator can see
    # which path was taken.
    document = None
    body = out.get("document")
    if body:
        try:
            document = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            document = None
    entry, template = _select_service_entry(document, ru.type_id)
    if entry is None:
        label = "spec default" if document is not None else "no document; spec default"
    elif entry.get("id") == f"#{ru.type_id}":
        label = f"type #{ru.type_id}"
    else:
        label = "type #0 fallback"

    # If the selected template is a relative reference, the resolver
    # urljoined it against the document URI (RFC 3986 §5) to produce
    # the referent URI. Flag that on the doc-uri line so the operator
    # can see which URI got transplanted in.
    import urllib.parse as _urlparse
    template_is_relative = not _urlparse.urlparse(template).scheme
    base_marker = "  ← base for relative serviceEndpoints" if template_is_relative else ""
    print(f"uuid_document_uri: {out['uuid_document_uri']}{base_marker}")
    print(f"                   (template: {template} [{label}])")
    print(f"referent_uri:      {out['referent_uri']}")
    print()
    for hop in registry_trace or []:
        qtype = hop.get("qtype")
        if hop.get("step") == "failover":
            if quiet_trace:
                continue
            print(f"FAILOVR primary failed: {hop['reason']} — trying fallback")
            continue
        if "error" in hop and quiet_trace:
            continue
        if "error" in hop and qtype is None:
            print(f"HTTP    {hop['url']} → {hop['error']}")
        elif qtype is None and "status" in hop:
            if hop.get("location"):
                print(
                    f"HTTP    {hop['url']} → {hop['status']} → "
                    f"{hop['location']}"
                )
            else:
                print(f"HTTP    {hop['url']} → {hop['status']}")
        elif "error" in hop:
            target = hop.get("name") or hop.get("url", "")
            print(f"{qtype:7} {target} → {hop['error']}")
        elif qtype == "PTR":
            print(f"PTR     {hop['name']} → {hop['answer']}")
        elif qtype == "default":
            print(f"default {hop['name']} → using default {hop['uri']}")
        elif qtype == "REGISTRY":
            print(f"HTTP    {hop['url']} → {hop.get('uri', '?')}")
        else:  # URI or TXT
            print(f"{qtype:7} {hop['name']} → {hop['uri']}")


def _emit_verbose(uuid_str: str,
                  out: dict,
                  registry_trace: list | None,
                  fetch_trace: list | None) -> None:
    """Render the --verbose output: detail block, trace, document, referent body."""
    _emit_resolve_detail(uuid_str, out, registry_trace)
    print()
    print("--- UUID document ---")
    body = out.get("document")
    if body is None:
        print("(unavailable)")
    else:
        try:
            print(json.dumps(json.loads(body), indent=2))
        except (json.JSONDecodeError, ValueError):
            sys.stdout.buffer.write(body)
            if not body.endswith(b"\n"):
                sys.stdout.buffer.write(b"\n")
            sys.stdout.flush()
    print()
    print("--- did:uuid: Document ---")
    ruuid_doc = out.get("ruuid_document")
    if ruuid_doc is None:
        print("(no Phase 2 referent URI available)")
    else:
        print(json.dumps(ruuid_doc, indent=2))
    print()
    print("--- referent body ---")
    for hop in fetch_trace or []:
        if "error" in hop:
            print(f"GET {hop['url']} → {hop['error']}")
        elif hop.get("location"):
            print(f"GET {hop['url']} → {hop['status']} alias to {hop['location']}")
        else:
            print(f"GET {hop['url']} → {hop['status']}")
    body = out.get("referent")
    if body is not None:
        sys.stdout.flush()
        sys.stdout.buffer.write(body)
        if not body.endswith(b"\n"):
            sys.stdout.buffer.write(b"\n")
        sys.stdout.buffer.flush()
    else:
        print("(unavailable)")


def cmd_parse(args: argparse.Namespace) -> int:
    """Run the resolution pipeline through Phase 2 and print parsed fields.

    Equivalent to `ruuid resolve --verbose` minus the UUID document
    body, the synthesised DID document, and the referent fetch.

    Failure modes are handled quietly: when neither the primary
    registry nor the system-DNS fallback can answer (e.g. no anchor
    running and the prefix isn't in real reverse DNS either), the
    DNS-derived fields are shown as `not resolved` rather than as a
    pile of timeout output. The UUID's own bits print regardless.
    """
    registry_trace: list = []
    try:
        out = resolve_ruuid(
            args.uuid,
            registry=args.registry,
            follow="referent_uri",
            registry_trace=registry_trace,
        )
    except ValueError as e:
        msg = str(e)
        flag = "" if msg.startswith("invalid UUID:") else "--registry: "
        print(f"ruuid parse: {flag}{msg}", file=sys.stderr)
        return 1
    except ResolveError:
        _emit_parse_unresolved(args.uuid)
        return 0
    _emit_resolve_detail(args.uuid, out, registry_trace, quiet_trace=True)
    return 0


def _emit_parse_unresolved(uuid_str: str) -> None:
    """Detail block with `not resolved` placeholders for DNS-derived fields.

    Used by `ruuid parse` when registry resolution fails entirely.
    The UUID's bits don't depend on DNS, so those still print.
    """
    from ruuid.core import RUUID
    from ruuid.resolve import reverse_dns_name

    ru = RUUID.from_str(uuid_str)
    print(f"uuid:              {uuid_str}")
    print(f"network:           {ru.ip_network}")
    print(f"identifier:        {ru.identifier:012x}")
    print(f"                   {_identifier_structured_reading(ru)}")
    print(f"type_id:           {ru.type_id}")
    print(f"reverse_name:      {reverse_dns_name(ru)}")
    print(f"domain:            not resolved")
    print(f"uuid_document_uri: not resolved")
    print(f"referent_uri:      not resolved")


def _identifier_structured_reading(ru) -> str:
    """One-line interpretation of the identifier under the §7.3 layout.

    The resolver can't tell from the bits whether the identifier was
    constructed as 20-bit day_count + 28-bit sequence (§7.3) or as
    a 48-bit opaque random (the local-scope MAY form). This helper
    always interprets the bits as if structured, and flags the result
    when day_count falls in the future — a definite tell that the
    identifier is opaque rather than §7.3.
    """
    from datetime import datetime, timedelta, timezone
    from ruuid.generate import (
        SEQUENCE_BITS,
        STRUCTURED_IDENTIFIER_EPOCH,
    )

    day_count = ru.identifier >> SEQUENCE_BITS
    sequence = ru.identifier & ((1 << SEQUENCE_BITS) - 1)
    date = (STRUCTURED_IDENTIFIER_EPOCH + timedelta(days=day_count)).date()
    today = datetime.now(timezone.utc).date()
    if date > today:
        return (
            f"§7.3: day_count={day_count} ({date.isoformat()}, future — "
            f"identifier was likely opaque), sequence=0x{sequence:07x}"
        )
    return (
        f"§7.3: day_count={day_count} ({date.isoformat()}), "
        f"sequence=0x{sequence:07x}"
    )


def cmd_document(args: argparse.Namespace) -> int:
    """Print the UUID document JSON for a domain."""
    from ruuid.issue import emit_document

    try:
        sys.stdout.write(emit_document(args.zone, domain=args.domain))
    except FileNotFoundError as e:
        print(f"ruuid document: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"ruuid document: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_records(args: argparse.Namespace) -> int:
    """Print the DNS zone records the domain should publish."""
    from ruuid.issue import emit_records

    try:
        sys.stdout.write(
            emit_records(
                args.zone,
                domain=args.domain,
                rrtype=args.rrtype,
                ttl=args.ttl,
            )
        )
    except FileNotFoundError as e:
        print(f"ruuid records: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"ruuid records: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_anchor(args: argparse.Namespace) -> int:
    from ruuid.anchor import run

    try:
        return run(
            Path(args.zone),
            bind=args.bind,
            dns_port=args.dns_port,
            http_port=args.http_port,
            https_port=args.https_port,
            rrtype=args.rrtype,
        )
    except FileNotFoundError as e:
        print(f"ruuid anchor: {e}", file=sys.stderr)
        return 1
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"ruuid anchor: bad zone file: {e}", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(
            f"ruuid anchor: cannot bind port (try non-privileged ports "
            f"with --dns-port / --http-port / --https-port): {e}",
            file=sys.stderr,
        )
        return 1


def cmd_seal(args: argparse.Namespace) -> int:
    """Establish a CT-anchored genesis proof (experimental)."""
    from ruuid.seal import render_report, seal

    try:
        result = seal(
            args.address,
            args.domain,
            type_id=args.type_id,
            day=args.day,
            out_dir=args.out,
            production=args.production,
            challenge=args.challenge,
            webroot=args.webroot,
            domain_cert=args.domain_cert,
            nameserver=args.nameserver,
            acme_path=args.acme,
        )
    except ValueError as e:
        print(f"ruuid seal: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"ruuid seal: {e}", file=sys.stderr)
        return 1
    print(render_report(result))
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    """List / check which issue-days are already covered for an anchor."""
    import datetime as _dt

    from ruuid.generate import days_since_epoch
    from ruuid.resolve import to_ip
    from ruuid.seal import default_seals_dir, find_coverage, ip_coverage

    try:
        ip = to_ip(args.address)
    except ValueError as e:
        print(f"ruuid coverage: {e}", file=sys.stderr)
        return 1
    seals_dir = Path(args.seals) if args.seals else default_seals_dir()
    ranges = ip_coverage(
        ip, seals_dir=seals_dir, production_only=not args.include_staging
    )

    if args.day is not None:
        target = days_since_epoch(args.day)
        date = args.day.date().isoformat()
        span = find_coverage(ranges, target)
        if span is not None:
            print(
                f"{date} (day_count {target}): COVERED — "
                f"window {span.start_date.isoformat()}..{span.end_date.isoformat()} "
                f"(seal {span.seals[0]})"
            )
            return 0
        print(
            f"{date} (day_count {target}): NOT COVERED — run "
            f"`ruuid seal {ip} <domain>` on a day in range to cover it",
            file=sys.stderr,
        )
        return 1

    if not ranges:
        print(f"no sealed coverage for {ip} under {seals_dir}")
        return 0
    print(f"covered issue-days for {ip} (from {seals_dir}):")
    for span in ranges:
        print(
            f"  {span.start_date.isoformat()} .. {span.end_date.isoformat()}   "
            f"day_count {span.start_day}..{span.end_day}   "
            f"({len(span.seals)} seal(s): {', '.join(span.seals)})"
        )
    return 0


class _QuietParser(argparse.ArgumentParser):
    """ArgumentParser that suppresses the redundant 'error: ...' line.

    On any argparse-detected input error (missing positional, bad type,
    unknown subcommand, etc.) this prints only the usage line and exits
    with status 2. The usage line already conveys 'you got the syntax
    wrong'; the error wording is dead weight.
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        sys.exit(2)


def _build_parser() -> argparse.ArgumentParser:
    p = _QuietParser(
        prog="ruuid",
        description="Generate and resolve Resolvable UUIDs (RUUIDs).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="generate a new RUUID")
    g.add_argument(
        "address",
        help="IPv4 or IPv6 anchor address, or a DNS name to resolve "
             "(IPv4 preferred; via the system resolver including /etc/hosts).",
    )
    g.add_argument(
        "identifier",
        nargs="?",
        type=_parse_int,
        default=None,
        help="48-bit identifier (decimal or 0x-hex); when omitted, "
             "generated per the recommended construction (RUUID §7.3): "
             "20-bit days-since-2025-01-01 || 28-bit random sequence",
    )
    g.add_argument(
        "--type", dest="type_id", type=_parse_int, default=0,
        help="10-bit type field (default 0)",
    )
    g.add_argument(
        "--day", type=_parse_day, default=None, metavar="DATE",
        help="day_count to use for the structured identifier, as "
             "YYYY-MM-DD or as a bare integer day_count since "
             "2025-01-01 UTC. Per RUUID §7.3, MUST be a day on which "
             "the caller held the network prefix and MUST NOT be in "
             "the future. Default: today UTC. Mutually exclusive "
             "with --opaque.",
    )
    g.add_argument(
        "--opaque", action="store_true",
        help="when generating the identifier, use a plain 48-bit "
             "cryptographically random value instead of the "
             "recommended day_count + sequence construction; hides "
             "tenure information at the cost of a narrower collision "
             "bound. Mutually exclusive with --day.",
    )
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("resolve", help="resolve an RUUID to its referent URI")
    r.add_argument("uuid", help="RUUID in canonical text form")
    r.add_argument(
        "--registry", metavar="URL",
        default=os.environ.get("RUUID_REGISTRY"),
        help="Registry endpoint for the PTR + _uuid.<domain> lookups. "
             "Default: the system DNS resolver. Pass 'dns://HOST[:PORT]' "
             "for a DNS-protocol endpoint (e.g. 'dns://127.0.0.1:53' to "
             "use a local 'ruuid anchor') or 'doh://HOST[:PORT][/PATH]' "
             "for RFC 8484 DoH (path defaults to /dns-query). An explicit "
             "endpoint is tried first and falls back to the system "
             "resolver on failure. Also settable via the RUUID_REGISTRY "
             "environment variable; the --registry flag takes precedence.",
    )
    r.add_argument(
        "--follow", nargs="?", const="referent", default=None,
        choices=["document", "ruuid_document", "referent_uri", "referent"],
        metavar="WHAT",
        help="Fetch the chain and write the body to stdout. With no "
             "argument or =referent, fetches the referent URI body. "
             "With =document, stops at and fetches the UUID document. "
             "With =ruuid_document, stops at the synthesised per-RUUID "
             "DID document. With =referent_uri, stops at the "
             "referent_uri",
    )
    r.add_argument(
        "-v", "--verbose", action="store_true",
        help="Precede the primary output with reverse_name / domain / "
             "uuid_document_uri / referent_uri details.",
    )
    r.set_defaults(func=cmd_resolve)

    pa = sub.add_parser(
        "parse",
        help="parse an RUUID and run the resolution pipeline (no body fetches)",
        description=(
            "Print the parsed fields of an RUUID plus the result of Phase 1 "
            "and Phase 2 of the resolution pipeline (domain, UUID-document "
            "URI, referent URI, DNS/HTTP trace). Equivalent to "
            "`ruuid resolve --verbose` minus the UUID document body, the "
            "synthesised DID document, and the referent fetch."
        ),
    )
    pa.add_argument("uuid", help="RUUID in canonical text form")
    pa.add_argument(
        "--registry", metavar="URL",
        default=os.environ.get("RUUID_REGISTRY"),
        help="Registry endpoint for the lookups; same semantics and "
             "default as `ruuid resolve --registry` (system resolver by "
             "default, or the RUUID_REGISTRY environment variable).",
    )
    pa.set_defaults(func=cmd_parse)

    d = sub.add_parser(
        "document",
        help="print a domain's UUID document JSON",
        description=(
            "Print the UUID document to publish at "
            "https://<domain>/.well-known/uuid-document.json (or "
            "wherever the _uuid.<domain> URI/TXT record points). "
            "Domains in the zone file MUST have `base_url` set so the "
            "service `serviceEndpoint` templates can be built. If the "
            "zone contains multiple domains with classes, use --domain "
            "to select one."
        ),
    )
    d.add_argument(
        "--zone", required=True,
        help="path to the zone JSON file",
    )
    d.add_argument(
        "--domain", default=None,
        help="domain to emit (required when the zone "
             "describes more than one)",
    )
    d.set_defaults(func=cmd_document)

    z = sub.add_parser(
        "records",
        help="print the DNS zone records a domain should publish",
        description=(
            "Print the DNS records — PTR per anchor, URI/TXT at "
            "_uuid.<domain> — to install at the domain's "
            "authoritative DNS provider, in BIND-style zone format."
        ),
    )
    z.add_argument(
        "--zone", required=True,
        help="path to the zone JSON file",
    )
    z.add_argument(
        "--domain", default=None,
        help="restrict output to records for one domain's entries "
             "(default: emit records for all)",
    )
    z.add_argument(
        "--rrtype", choices=["both", "URI", "TXT"], default="both",
        help="restrict the records at _uuid.<domain> to URI only or "
             "TXT only (default: both — most resolvers prefer URI and "
             "fall back to TXT, so emitting both is the safe choice).",
    )
    z.add_argument(
        "--ttl", type=int, default=3600,
        help="TTL (seconds) in the emitted zone snippet (default: 3600)",
    )
    z.set_defaults(func=cmd_records)

    a = sub.add_parser(
        "anchor",
        help="run a daemon that serves DNS + HTTP for a JSON zone file",
    )
    a.add_argument("--zone", required=True, help="path to the zone JSON file")
    a.add_argument(
        "--bind", default="127.0.0.1",
        help="address to bind on (default: 127.0.0.1). May be an IP "
             "literal or a DNS name (resolved via the system resolver).",
    )
    a.add_argument(
        "--dns-port", type=int, default=53,
        help="UDP port for DNS (default: 53; needs root)",
    )
    a.add_argument(
        "--http-port", type=int, default=80,
        help="TCP port for HTTP (default: 80; needs root)",
    )
    a.add_argument(
        "--https-port", type=int, default=443,
        help="TCP port for HTTPS (default: 443; needs root). "
             "HTTPS is served whenever /etc/ruuid/anchor-cert.pem or "
             "./anchor-cert.pem exists; otherwise the daemon serves "
             "only HTTP on --http-port.",
    )
    a.add_argument(
        "--rrtype", choices=["both", "URI", "TXT"], default="both",
        help="restrict the records published at _uuid.<domain> to "
             "URI only or TXT only (default: both). Useful for testing "
             "a resolver's URI-preferred / TXT-fallback paths in isolation.",
    )
    a.set_defaults(func=cmd_anchor)

    s = sub.add_parser(
        "seal",
        help="(experimental) establish a CT-anchored genesis proof for an RUUID",
        description=(
            "EXPERIMENTAL. Prove control, as of the day of issuance, of the "
            "IP address, its reverse zone (PTR -> domain), and the domain, "
            "by verifying the PTR and obtaining Let's Encrypt certificates "
            "(an IP-SAN short-lived cert + a same-key dNSName cert) via "
            "acme.sh. The certs land in Certificate Transparency, so a third "
            "party can later find them and confirm control on the RUUID's "
            "anchor day. Mints an RUUID with a day_count inside the IP cert's "
            "window and writes a committing UUID document. Requires acme.sh "
            "and openssl. Defaults to the Let's Encrypt STAGING endpoint; "
            "pass --production for real CT logging."
        ),
    )
    s.add_argument(
        "address",
        help="IPv4/IPv6 address (or hostname) whose control is being sealed",
    )
    s.add_argument("domain", help="domain the address's PTR must map to")
    s.add_argument(
        "--type", dest="type_id", type=_parse_int, default=0,
        help="10-bit type field for the minted RUUID (default 0)",
    )
    s.add_argument(
        "--day", type=_parse_day, default=None, metavar="DATE",
        help="anchor day (YYYY-MM-DD or integer day_count since 2025-01-01 "
             "UTC) for the minted RUUID; MUST fall inside the IP cert's "
             "validity window and MUST NOT be in the future. Default: today "
             "UTC (clamped into the window).",
    )
    s.add_argument(
        "--out", default=None, metavar="DIR",
        help="directory for the key, CSRs, certs, UUID document, and "
             "seal.json manifest (default: ~/.ruuid/seals/<uuid>/)",
    )
    s.add_argument(
        "--production", action="store_true",
        help="use the real Let's Encrypt endpoint (real CT logging) instead "
             "of the default staging endpoint",
    )
    s.add_argument(
        "--challenge", choices=["auto", "http-01", "tls-alpn-01"],
        default="auto",
        help="ACME challenge for the IP anchor (DNS-01 is invalid for IPs). "
             "auto prefers TLS-ALPN-01 (no port-80 takeover) and falls back "
             "to HTTP-01 (default: auto). Ignored when --webroot is given.",
    )
    s.add_argument(
        "--webroot", default=None, metavar="DIR",
        help="serve the ACME HTTP-01 challenge from an already-running web "
             "server's webroot (acme.sh -w DIR) instead of a standalone "
             "listener — no port takeover, no downtime. Forces HTTP-01. The "
             "web server must serve DIR/.well-known/acme-challenge/ for BOTH "
             "the domain and the bare IP (add an Alias / ProxyPass exclusion "
             "if the site is otherwise proxied).",
    )
    s.add_argument(
        "--no-domain-cert", dest="domain_cert", action="store_false",
        help="skip the same-key 90-day dNSName cert; certify only the IP "
             "(domain control then rests on the local PTR check alone)",
    )
    s.add_argument(
        "--nameserver", default=None, metavar="HOST[:PORT]",
        help="DNS server for the PTR verification (default: system resolver)",
    )
    s.add_argument(
        "--acme", default=None, metavar="PATH",
        help="path to the acme.sh script (default: found on PATH or "
             "~/.acme.sh/acme.sh)",
    )
    s.set_defaults(func=cmd_seal)

    c = sub.add_parser(
        "coverage",
        help="(experimental) list/check which issue-days a seal already covers",
        description=(
            "For an anchor address, report the ranges of issue-days (day_count) "
            "already provable from recorded seals — each `seal.json` is one "
            "CT-logged genesis certificate, and its IP cert's validity window is "
            "a band of coverable days. A genesis cert never needs renewing for "
            "liveness; you only need a fresh `ruuid seal` to mint on a day no "
            "existing certificate covers. With --day, check one date and exit "
            "non-zero if it is not covered (scriptable: seal only when needed)."
        ),
    )
    c.add_argument(
        "address",
        help="IPv4/IPv6 address (or hostname) whose sealed coverage to report",
    )
    c.add_argument(
        "--day", type=_parse_day, default=None, metavar="DATE",
        help="check whether this day (YYYY-MM-DD or integer day_count since "
             "2025-01-01 UTC) is already covered; exit 1 if not",
    )
    c.add_argument(
        "--seals", default=None, metavar="DIR",
        help="directory of seal records to read (default: ~/.ruuid/seals/)",
    )
    c.add_argument(
        "--include-staging", action="store_true",
        help="also count staging seals (by default only production seals "
             "count; a staging cert proves nothing to third parties)",
    )
    c.set_defaults(func=cmd_coverage)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # Ctrl-C from `ruuid anchor` is the expected stop path; print a
        # newline so the shell prompt doesn't sit next to a stray ^C,
        # and exit 130 (128 + SIGINT) per shell convention.
        sys.stderr.write("\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
