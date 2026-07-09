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
    ruuid document [DOMAIN] [--zone FILE]
    ruuid anchor   --zone FILE [--export [FILE]] [--bind HOST]
                               [--dns-port N] [--http-port N]
                               [--https-port N] [--rrtype WHAT]
    ruuid seal     <address> <domain> [--type N] [--day DATE] [--out DIR]
                               [--production] [--challenge WHAT] [--webroot DIR]
                               [--no-domain-cert] [--nameserver HOST[:PORT]]
                               [--acme PATH]
    ruuid custody  [TARGET] [--seals [--seals-dir DIR]] [--summary [--day DATE]]

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


def _cmd_resolve_verify(args: argparse.Namespace) -> int:
    """`ruuid resolve --verify`: resolve the document, then check its committed
    key against the CT-established genesis key (the anti-commandeering step).

    The PTR path is a fast way to fetch a candidate document; CT is the
    authority. A document whose key is not the CT genesis key is rejected —
    and if the document also disclaims this RUUID (its minting day-range
    excludes it), that is flagged as an honest successor rather than an
    impostor.
    """
    from ruuid.core import RUUID
    from ruuid.verify import document_disclaims, render, verify_ruuid

    try:
        ru = RUUID.from_str(args.uuid)
    except ValueError as e:
        print(f"ruuid resolve: invalid UUID: {e}", file=sys.stderr)
        return 1
    try:
        out = resolve_ruuid(args.uuid, registry=args.registry, follow="document")
    except ValueError as e:
        print(f"ruuid resolve: {e}", file=sys.stderr)
        return 1
    except ResolveError as e:
        print(f"ruuid resolve: {e}", file=sys.stderr)
        return 1

    domain = out.get("domain")
    doc_uri = out.get("uuid_document_uri")
    body = out.get("document")
    print(f"resolved:     {domain}  ({doc_uri})")
    if not body:
        print("verification: UNVERIFIABLE — could not fetch the UUID document",
              file=sys.stderr)
        return 1
    try:
        document = json.loads(body)
    except (ValueError, TypeError):
        print("verification: UNVERIFIABLE — UUID document is not JSON",
              file=sys.stderr)
        return 1

    # --verify requires a SIGNED document: its content must be bound to the
    # committed key by a valid proof (else the committed key could be wrapped
    # around content the key-holder never authored).
    from ruuid.proof import verify_document_proof
    proof_ok = verify_document_proof(document)
    if proof_ok is None:
        print("verification: NOT VERIFIED — the UUID document is not signed "
              "(no proof); --verify requires a signed document", file=sys.stderr)
        return 1
    if proof_ok is False:
        print("verification: NOT VERIFIED — the UUID document's proof is "
              "invalid (content does not match its committed key)",
              file=sys.stderr)
        return 1

    day_count = ru.identifier >> 28
    disclaimed = document_disclaims(document, day_count)
    bundle_source = _ct_source(args)
    try:
        result, _ = verify_ruuid(
            ru, document, ct_source=bundle_source,
            cache=None if bundle_source is not None else _ct_cache(args),
        )
    except ValueError as e:  # no committed key, etc.
        print(f"verification: UNVERIFIABLE — {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"verification: error — {e}", file=sys.stderr)
        return 1

    print(render(result))
    if not result.verified and result.genuine_keys:
        if disclaimed:
            print(
                "note:         the fetched document DISCLAIMS this RUUID (its "
                "minting day-range excludes this day) — an honest successor at "
                "this IP. The genuine controller is the key above; fetch its "
                "document from the genuine anchor."
            )
        else:
            print(
                "note:         the document claims this RUUID but commits a key "
                "that is NOT the genesis key — treat as commandeered/impostor."
            )
    return 0 if result.verified else 1


def cmd_resolve(args: argparse.Namespace) -> int:
    if getattr(args, "verify", False):
        return _cmd_resolve_verify(args)
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


def cmd_anchor(args: argparse.Namespace) -> int:
    from ruuid.anchor import run

    # --export: at startup, print the DNS zone records a real deployment would
    # publish (to FILE, or stdout), then run the daemon.
    if args.export is not None:
        from ruuid.issue import emit_records
        try:
            records = emit_records(args.zone, rrtype=args.rrtype)
        except (FileNotFoundError, ValueError) as e:
            print(f"ruuid anchor: {e}", file=sys.stderr)
            return 1
        if args.export:                      # a filename was given
            Path(args.export).write_text(records)
            print(f"ruuid anchor: wrote DNS zone records to {args.export}",
                  file=sys.stderr)
        else:                                # no filename -> stdout
            sys.stdout.write(records)
            sys.stdout.flush()

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
            pre_rotate=args.pre_rotate,
            commit_host=args.commit_host,
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


def cmd_rotate(args: argparse.Namespace) -> int:
    """Rotate an RUUID's key to its pre-committed cold successor (experimental)."""
    from ruuid.seal import render_rotate, rotate

    try:
        result = rotate(
            args.state_dir,
            out_dir=args.out,
            production=args.production,
            challenge=args.challenge,
            webroot=args.webroot,
            commit_host=args.commit_host,
            acme_path=args.acme,
        )
    except (ValueError, RuntimeError, FileNotFoundError) as e:
        print(f"ruuid rotate: {e}", file=sys.stderr)
        return 1
    print(render_rotate(result))
    return 0


def cmd_sct(args: argparse.Namespace) -> int:
    """Verify a certificate's embedded CT SCTs against the trusted log list."""
    import datetime as _dt

    from ruuid.sct import SctUnavailable, load_log_list, verify_cert_scts

    try:
        pem = Path(args.cert).read_bytes()
    except OSError as e:
        print(f"ruuid sct: cannot read {args.cert}: {e}", file=sys.stderr)
        return 1
    log_list = None
    if args.log_list:
        try:
            log_list = json.loads(Path(args.log_list).read_text())["logs"]
        except (OSError, ValueError, KeyError) as e:
            print(f"ruuid sct: bad log list: {e}", file=sys.stderr)
            return 1
    try:
        result = verify_cert_scts(pem, log_list=log_list)
    except SctUnavailable as e:
        print(f"ruuid sct: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"ruuid sct: {e}", file=sys.stderr)
        return 1

    for s in result.scts:
        if s.verified:
            mark = "verified"
        elif s.log_description is None:
            mark = "UNTRUSTED LOG"
        else:
            mark = "BAD SIGNATURE"
        ts = _dt.datetime.fromtimestamp(
            s.timestamp_ms / 1000, _dt.timezone.utc
        ).isoformat()
        print(f"  [{mark}] {s.log_description or s.log_id_b64}  @ {ts}")
    print(f"verified {result.verified_count}/{len(result.scts)} SCT(s) from "
          f"{len(result.verified_operators)} independent operator(s)")
    ok = result.ok(args.min)
    print(f"verdict: {'OK' if ok else 'INSUFFICIENT'} "
          f"(require >= {args.min} from trusted logs)")
    return 0 if ok else 1


def _ct_cache(args: argparse.Namespace):
    """The IP -> CT-certs cache selected by --no-cache / --cache-dir, or None."""
    if getattr(args, "no_cache", False):
        return None
    from ruuid.verify import IpCertCache
    return IpCertCache(getattr(args, "cache_dir", None))


def _ct_source(args: argparse.Namespace):
    """The CT source implied by the flags, or None for the default live crt.sh.

    --fetch-bundles builds the discovery cascade (local bundles -> the issuer's
    published /.well-known/uuid-custody.json -> crt.sh); --bundles alone reads
    a directory of pre-downloaded bundles offline.
    """
    bundles = getattr(args, "bundles", None)
    verify_scts = getattr(args, "verify_scts", False)
    min_scts = getattr(args, "min_scts", 2)
    if getattr(args, "fetch_bundles", False):
        from ruuid.verify import CascadingSource
        return CascadingSource(
            bundles_dir=bundles, nameserver=getattr(args, "nameserver", None),
            verify_scts=verify_scts, min_scts=min_scts,
        )
    if bundles:
        from ruuid.verify import LocalBundleSource
        return LocalBundleSource(bundles, verify_scts=verify_scts, min_scts=min_scts)
    return None


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify an RUUID's genesis proof against CT (experimental)."""
    from ruuid.core import RUUID
    from ruuid.verify import render, verify_ruuid

    try:
        ru = RUUID.from_str(args.ruuid)
    except ValueError as e:
        print(f"ruuid verify: invalid UUID: {e}", file=sys.stderr)
        return 1
    document = None
    if args.document:
        try:
            document = json.loads(Path(args.document).read_text())
        except (OSError, ValueError) as e:
            print(f"ruuid verify: cannot read document: {e}", file=sys.stderr)
            return 1
    custody = None
    if args.custody:
        try:
            custody = json.loads(Path(args.custody).read_text())
        except (OSError, ValueError) as e:
            print(f"ruuid verify: cannot read custody: {e}", file=sys.stderr)
            return 1
    bundle_source = _ct_source(args)
    try:
        result, gathered = verify_ruuid(
            ru, document, custody=custody, ct_source=bundle_source,
            cache=None if bundle_source is not None else _ct_cache(args),
        )
    except (ValueError, RuntimeError) as e:
        print(f"ruuid verify: {e}", file=sys.stderr)
        return 1
    if args.emit_custody:
        Path(args.emit_custody).write_text(json.dumps(gathered, indent=2) + "\n")
    print(render(result))
    return 0 if result.verified else 1


def _custody_target_ip(target: str) -> str:
    """Resolve a custody target to an IP: an IP literal, a hostname, or a RUUID."""
    from ruuid.core import RUUID
    from ruuid.resolve import to_ip
    from ruuid.verify import anchor_ip
    try:
        return anchor_ip(RUUID.from_str(target))
    except (ValueError, TypeError):
        return to_ip(target)              # IP literal or hostname (may raise ValueError)


def _emit_coverage(ip: str, spans, args: argparse.Namespace) -> int:
    from ruuid.generate import days_since_epoch
    from ruuid.seal import find_coverage

    if args.day is not None:
        target = days_since_epoch(args.day)
        date = args.day.date().isoformat()
        span = find_coverage(spans, target)
        if span is not None:
            print(f"{date} (day_count {target}): COVERED — window "
                  f"{span.start_date.isoformat()}..{span.end_date.isoformat()}")
            return 0
        print(f"{date} (day_count {target}): NOT COVERED for {ip}", file=sys.stderr)
        return 1
    if not spans:
        print(f"no sealed coverage for {ip}")
        return 0
    print(f"covered issue-days for {ip}:")
    for span in spans:
        print(f"  {span.start_date.isoformat()} .. {span.end_date.isoformat()}   "
              f"day_count {span.start_day}..{span.end_day}   "
              f"({len(span.seals)} cert(s))")
    return 0


def cmd_custody(args: argparse.Namespace) -> int:
    """Build a custody bundle (custody.json) for an IP, or (--summary) print the
    day-coverage. Runs off an IP address, a hostname resolving to one, or a
    RUUID it can extract an IP from. `--seals` is an issuer optimization that
    reads the issuer's own certificate records instead of querying CT.
    """
    from ruuid.verify import (
        CrtShSource, build_published_custody, coverage_from_windows,
        gather_custody_for_ip,
    )

    # --summary: day-coverage spans instead of the full bundle.
    if args.summary:
        if not args.target:
            print("ruuid custody --summary: an IP/host/RUUID is required",
                  file=sys.stderr)
            return 1
        try:
            ip = _custody_target_ip(args.target)
        except ValueError as e:
            print(f"ruuid custody: {e}", file=sys.stderr)
            return 1
        try:
            if args.seals:
                from ruuid.seal import default_seals_dir, ip_coverage
                seals = args.seals_dir or str(default_seals_dir())
                spans = ip_coverage(ip, seals_dir=seals,
                                    production_only=not args.include_staging)
            else:
                # Coverage needs only validity windows, which are in the crt.sh
                # JSON — no per-cert PEM fetch (avoids the flaky ?d= endpoint).
                spans = coverage_from_windows(CrtShSource().ip_cert_windows(ip))
        except (OSError, ValueError, RuntimeError) as e:
            print(f"ruuid custody: {e}", file=sys.stderr)
            return 1
        return _emit_coverage(ip, spans, args)

    # Full bundle.
    if args.seals:
        from ruuid.seal import default_seals_dir
        seals = args.seals_dir or str(default_seals_dir())
        try:
            custody = build_published_custody(seals)
        except (OSError, ValueError) as e:
            print(f"ruuid custody: {e}", file=sys.stderr)
            return 1
    else:
        if not args.target:
            print("ruuid custody: an IP address, hostname, or RUUID is required "
                  "(or use --seals to build from the issuer's seals directory)",
                  file=sys.stderr)
            return 1
        try:
            ip = _custody_target_ip(args.target)
        except ValueError as e:
            print(f"ruuid custody: {e}", file=sys.stderr)
            return 1
        try:
            custody = gather_custody_for_ip(ip, CrtShSource())
        except (ValueError, RuntimeError) as e:
            print(f"ruuid custody: {e}", file=sys.stderr)
            return 1

    text = json.dumps(custody, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
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
    r.add_argument(
        "--verify", action="store_true",
        help="(experimental) after resolving, check the fetched UUID "
             "document's committed key against the Certificate-Transparency "
             "genesis key for the RUUID's IP and day (the anti-commandeering "
             "step). A document whose key is not the CT genesis key is "
             "rejected (exit non-zero); a day-range disclaim is flagged as an "
             "honest successor. Overrides the normal output modes.",
    )
    r.add_argument(
        "--no-cache", action="store_true",
        help="with --verify, do not use the local per-IP CT cache",
    )
    r.add_argument(
        "--cache-dir", default=None, metavar="DIR",
        help="with --verify, the per-IP CT cache directory "
             "(default: ~/.ruuid/ct-cache/)",
    )
    r.add_argument(
        "--bundles", default=None, metavar="DIR",
        help="with --verify, verify off a directory of pre-downloaded "
             "published custody bundles instead of live crt.sh",
    )
    r.add_argument(
        "--fetch-bundles", action="store_true",
        help="with --verify, discovery cascade: local --bundles -> the "
             "issuer's published /.well-known/uuid-custody.json -> crt.sh "
             "(fetched bundles are cached)",
    )
    r.add_argument(
        "--verify-scts", action="store_true",
        help="with --verify + bundles, gate bundle certs on valid embedded "
             "SCTs at ingest (needs ruuid[sct])",
    )
    r.add_argument(
        "--min-scts", type=int, default=2, metavar="N",
        help="with --verify-scts, minimum verified SCTs per cert (default: 2)",
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
            "https://<domain>/.well-known/uuid-document.json (or wherever the "
            "_uuid.<domain> URI/TXT record points). With a --zone file, a "
            "domain described there with a `service` array publishes that "
            "array; any other domain — not in the zone, or with no zone file "
            "at all — gets a basic document (just @context and id). Without "
            "DOMAIN, the domain is inferred from the zone when exactly one "
            "domain publishes a service array."
        ),
    )
    d.add_argument(
        "domain", nargs="?", default=None,
        help="domain to emit the document for (optional only when it can be "
             "inferred from a single-publishing zone)",
    )
    d.add_argument(
        "--zone", default=None,
        help="path to the zone JSON file (optional)",
    )
    d.set_defaults(func=cmd_document)

    a = sub.add_parser(
        "anchor",
        help="run a daemon that serves DNS + HTTP for a JSON zone file",
    )
    a.add_argument("--zone", required=True, help="path to the zone JSON file")
    a.add_argument(
        "--export", nargs="?", const="", default=None, metavar="FILE",
        help="at startup, print the DNS zone records a real deployment would "
             "publish (PTR per anchor + URI/TXT at _uuid.<domain>, BIND-style) "
             "to FILE, or to stdout if no FILE is given; then run the daemon.",
    )
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
        "--pre-rotate", action="store_true",
        help="(experimental) generate a successor key K2 COLD and publish a "
             "commitment to it in CT (a cert under the genesis key whose "
             "dNSName encodes spki(K2)), pinning the successor so a future "
             "`ruuid rotate` survives compromise of the genesis key. Needs a "
             "wildcard DNS record *.<commit-host> pointing at this host. Back "
             "up next-key.pem offline.",
    )
    s.add_argument(
        "--commit-host", default=None, metavar="HOST",
        help="host under which the pre-rotation commitment dNSName is issued "
             "(default: rotate.<domain>); *.<commit-host> must resolve here",
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

    v = sub.add_parser(
        "verify",
        help="(experimental) verify an RUUID's genesis proof against CT",
        description=(
            "Recover from Certificate Transparency the key that controlled the "
            "RUUID's network anchor on the day the RUUID encodes (crt.sh indexes "
            "the IP-address SAN), and — if a document is given — confirm it "
            "commits that key. With no document, report the genuine key and "
            "anchoring timeline straight from CT. Stage 1 assumes a single key "
            "from genesis to now (re-anchoring to other IPs/domains appears in "
            "the timeline). With a custody.json the check is offline and "
            "deterministic; without one it is built live from CT. Exits "
            "non-zero when not verified."
        ),
    )
    v.add_argument("ruuid", help="RUUID in canonical text form")
    v.add_argument(
        "document", nargs="?", default=None,
        help="path to the RUUID's uuid-document.json (optional; without it, "
             "report the genuine key from CT)",
    )
    v.add_argument(
        "--custody", default=None, metavar="FILE",
        help="pre-built custody.json bundle (else built live from CT)",
    )
    v.add_argument(
        "--bundles", default=None, metavar="DIR",
        help="verify off a directory of pre-downloaded published custody "
             "bundles (uuid-custody.json) instead of live crt.sh",
    )
    v.add_argument(
        "--fetch-bundles", action="store_true",
        help="discovery cascade: local --bundles dir (default ~/.ruuid/"
             "bundles) -> the issuer's published /.well-known/uuid-custody.json "
             "(resolved via the RUUID's IP) -> crt.sh; fetched bundles are "
             "cached, so unknown issuers become locally known",
    )
    v.add_argument(
        "--verify-scts", action="store_true",
        help="gate bundle certs on valid embedded SCTs at ingest: a bundle "
             "cert counts only if its CT log signatures verify (needs "
             "ruuid[sct]). Makes an untrusted bundle trustless; crt.sh is "
             "unaffected. Fabricated certs are dropped.",
    )
    v.add_argument(
        "--min-scts", type=int, default=2, metavar="N",
        help="with --verify-scts, minimum verified SCTs per cert (default: 2)",
    )
    v.add_argument(
        "--nameserver", default=None, metavar="HOST[:PORT]",
        help="with --fetch-bundles, DNS server for the PTR/domain lookup",
    )
    v.add_argument(
        "--emit-custody", default=None, metavar="FILE",
        help="write the custody bundle used for verification to FILE",
    )
    v.add_argument(
        "--no-cache", action="store_true",
        help="do not use the local per-IP CT cache",
    )
    v.add_argument(
        "--cache-dir", default=None, metavar="DIR",
        help="per-IP CT cache directory (default: ~/.ruuid/ct-cache/). "
             "Cached genesis facts are immutable, so entries never expire; "
             "one CT fetch per IP green-lights every RUUID for that IP locally.",
    )
    v.set_defaults(func=cmd_verify)

    cu = sub.add_parser(
        "custody",
        help="(experimental) build a custody bundle (custody.json) for an IP",
        description=(
            "Build a custody.json evidence bundle for a network anchor. TARGET is "
            "an IP address, a hostname that resolves to one, or a RUUID to extract "
            "the IP from. By default, query Certificate Transparency for the "
            "certificates carrying that IP plus their forward key chains — runnable "
            "anywhere with crt.sh access. With --seals, build the SAME bundle from "
            "the issuer's own certificate records instead of querying CT (an issuer "
            "optimization: immediate, offline, no crt.sh). With --summary, print "
            "the day-coverage (which issue-days the IP has provable genesis certs "
            "for) instead of the bundle. Host a bundle at "
            "https://<domain>/.well-known/uuid-custody.json."
        ),
    )
    cu.add_argument(
        "target", nargs="?", default=None,
        help="IP address, hostname, or RUUID (omit only with --seals for the "
             "whole-issuer bundle)",
    )
    cu.add_argument(
        "--seals", action="store_true",
        help="issuer optimization: build (or --summary) from the issuer's own "
             "certificate records instead of querying CT. Same output; no crt.sh, "
             "immediate. Private keys are never included.",
    )
    cu.add_argument(
        "--seals-dir", default=None, metavar="DIR",
        help="with --seals, the seals directory to read (default: ~/.ruuid/seals)",
    )
    cu.add_argument(
        "--summary", action="store_true",
        help="print the day-coverage for TARGET (which issue-days are provable) "
             "instead of the full bundle",
    )
    cu.add_argument(
        "--day", type=_parse_day, default=None, metavar="DATE",
        help="with --summary, check whether this day (YYYY-MM-DD or integer "
             "day_count since 2025-01-01 UTC) is covered; exit 1 if not",
    )
    cu.add_argument(
        "--include-staging", action="store_true",
        help="with --summary --seals, also count staging seals (default: only "
             "production seals, since a staging cert proves nothing to third "
             "parties)",
    )
    cu.add_argument(
        "--out", default=None, metavar="FILE",
        help="write the bundle to FILE (default: stdout)",
    )
    cu.set_defaults(func=cmd_custody)

    ro = sub.add_parser(
        "rotate",
        help="(experimental) rotate an RUUID's key to its pinned cold successor",
        description=(
            "Rotate the key of an RUUID sealed with --pre-rotate. STATE_DIR is "
            "the previous generation's directory (the seal, or an earlier "
            "rotate); it must contain the cold successor key next-key.pem and "
            "its record. Rotation activates that successor (verifying it "
            "matches the recorded commitment — no access to the old key is "
            "needed, so it works even if the old key is compromised), generates "
            "a fresh cold successor and publishes the new key's commitment to "
            "it in CT, and writes a new UUID document committing the new key. "
            "Needs a wildcard *.<commit-host> record pointing at the host."
        ),
    )
    ro.add_argument(
        "state_dir",
        help="previous generation's directory (seal dir or rotate dir)",
    )
    ro.add_argument(
        "--out", default=None, metavar="DIR",
        help="output directory (default: ~/.ruuid/seals/<uuid>/gen<N>/)",
    )
    ro.add_argument(
        "--production", action="store_true",
        help="use real Let's Encrypt (real CT) instead of staging",
    )
    ro.add_argument(
        "--challenge", choices=["auto", "http-01", "tls-alpn-01"], default="auto",
        help="ACME challenge for the commitment cert (default: auto)",
    )
    ro.add_argument(
        "--webroot", default=None, metavar="DIR",
        help="serve the HTTP-01 challenge from a running web server's webroot",
    )
    ro.add_argument(
        "--commit-host", default=None, metavar="HOST",
        help="host for the successor commitment dNSName (default rotate.<domain>)",
    )
    ro.add_argument(
        "--acme", default=None, metavar="PATH",
        help="path to the acme.sh script",
    )
    ro.set_defaults(func=cmd_rotate)

    sc = sub.add_parser(
        "sct",
        help="(experimental) verify a certificate's embedded CT SCTs",
        description=(
            "Verify the Signed Certificate Timestamps embedded in a certificate "
            "against a bundled list of trusted CT-log public keys (RFC 6962). A "
            "valid SCT is a log's unforgeable, signed proof that this exact "
            "certificate was logged — so it establishes the cert is genuine "
            "(went through a real CA + CT) WITHOUT trusting whoever supplied it. "
            "Fully offline. Needs a full-chain PEM (leaf + issuer) and the "
            "'cryptography' package (pip install 'ruuid[sct]')."
        ),
    )
    sc.add_argument("cert", help="certificate PEM (full chain: leaf then issuer)")
    sc.add_argument(
        "--min", type=int, default=2, metavar="N",
        help="minimum SCTs that must verify against trusted logs (default: 2)",
    )
    sc.add_argument(
        "--log-list", default=None, metavar="FILE",
        help="CT log list JSON in the bundled format (default: bundled ct_logs.json)",
    )
    sc.set_defaults(func=cmd_sct)
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
