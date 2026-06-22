# riverscape.info — a live did:uuid anchor

This is a worked, deployable example of an RUUID issuer anchored to a
real IP with a published reverse-DNS PTR:

```
52.22.50.16  →  PTR  →  riverscape.info
```

It backs the live test identifier used by the
[`did:uuid` Universal Resolver driver](../../uni-resolver-driver/README.md):

```
did:uuid:00000000-0001-8200-8002-341632100000
```

(`ruuid generate 52.22.50.16 1` — anchor `52.22.50.16`, identifier `1`,
type `0`.)

## Files

- `zone.json` — the `ruuid` input zone (regenerates everything below).
- `site/.well-known/uuid-document.json` — the UUID document to host.
- `site/things/000000000001` — the referent the test identifier
  dereferences to.

Regenerate the document and DNS records from the zone with:

```
ruuid document --zone zone.json
ruuid records  --zone zone.json
```

## Deploy

**1. Publish DNS** (PTR already exists; the rest go in the forward
`riverscape.info` zone):

```
16.50.22.52.in-addr.arpa. 3600 IN PTR riverscape.info.
_uuid.riverscape.info.    3600 IN URI 10 1 "https://riverscape.info/.well-known/uuid-document.json"
_uuid.riverscape.info.    3600 IN TXT "v=ruuid1 https://riverscape.info/.well-known/uuid-document.json"
```

The `_uuid.riverscape.info` record is optional: a resolver that finds
no record falls back to the well-known
`https://riverscape.info/.well-known/uuid-document.json` — which is
exactly where the document is hosted, so resolution works either way.
Publish the record anyway if you want to host the document somewhere
other than the well-known path.

**2. Host the site** — upload the contents of `site/` to the web root
of `https://riverscape.info/`, so that:

- `https://riverscape.info/.well-known/uuid-document.json` serves the
  UUID document, and
- `https://riverscape.info/things/000000000001` serves the referent.

## Resolution

Once deployed, resolving the test DID walks the full pipeline — PTR →
`_uuid.riverscape.info` (or the well-known fallback) → fetch the UUID
document → substitute the `/things/<identifier>` template — and yields
a DID document whose service endpoint dereferences to real content:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:uuid:00000000-0001-8200-8002-341632100000",
  "controller": "did:uuid:00000000-0000-8200-8002-341632100000",
  "service": [
    {
      "id": "did:uuid:00000000-0001-8200-8002-341632100000#0",
      "type": "Referent",
      "serviceEndpoint": "https://riverscape.info/things/000000000001"
    }
  ]
}
```

Before the document is hosted, the same DID still resolves (the PTR is
the only hard requirement) but the service endpoint uses the
spec-default template `https://riverscape.info/0/000000000001`.

Check it locally:

```
ruuid resolve --registry dns:// --follow ruuid_document \
  00000000-0001-8200-8002-341632100000
```

## Resolving all the way to the referent

DID resolution stops at the DID document — it returns the
`serviceEndpoint` URL but does not fetch what that URL points at
(dereferencing the resource is a separate, application-layer HTTP GET;
a resolver is not a proxy to arbitrary service endpoints). So going
"all the way through" to the referent is two hops: resolve the DID,
then GET the endpoint it hands back.

Against a DIF Universal Resolver instance (the `did:uuid` driver routes
the first hop; `$RESOLVER` is e.g. `http://localhost:8080` for a local
`docker compose` instance, or a public deployment):

```bash
DID="did:uuid:00000000-0001-8200-8002-341632100000"
curl -s "$RESOLVER/1.0/identifiers/$DID" \
  | jq -r '.didDocument.service[0].serviceEndpoint' \
  | xargs curl -s
```

The same two hops with the `ruuid` CLI alone (no Universal Resolver):

```bash
ruuid resolve --registry dns:// --follow referent \
  00000000-0001-8200-8002-341632100000
```

Both return the hosted referent at
`https://riverscape.info/things/000000000001`.
