# driver-did-uuid

A [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver)
driver for the **`did:uuid`** method. It packages this repository's
RUUID resolution pipeline as the small HTTP service the Universal
Resolver expects: a container that answers

```
GET /1.0/identifiers/<did>
```

with a DID document (or a DID Resolution Result). The Universal
Resolver's `uni-resolver-web` front end routes every `did:uuid:...`
query to this driver and wraps the response for its clients.

## No anchor required

This driver only *consumes* RUUID records over DNS; it does **not** run
`ruuid anchor`, serve any zone, or carry issuer data. The anchor in
this repository is a development/demo tool for *publishing* RUUID
records (PTR + `_uuid.<domain>` + the UUID document). A deployed driver
resolves against whatever DNS the container is pointed at — the system
resolver by default, or a `dns://` / `doh://` endpoint you configure.
So the image is self-contained: install the package, run the driver,
done.

## What it does

For each request the driver:

1. Validates the DID is `did:uuid:` and its method-specific id is a
   canonical RUUID of **version 8**, **variant RFC 4122**.
2. Runs the two-phase RUUID pipeline
   (`resolve_ruuid(..., follow="ruuid_document")`): reverse-DNS PTR →
   `_uuid.<domain>` URI/TXT → fetch the UUID document → synthesise the
   per-RUUID DID document.
3. Returns the synthesised DID document, or a DID Resolution Result
   carrying a resolution error.

Resolution errors map to HTTP status codes as follows:

| Outcome | `didResolutionMetadata.error` | HTTP |
|---|---|---|
| success | — (`contentType` set) | 200 |
| not a DID / malformed UUID / wrong version / wrong variant | `invalidDid` | 400 |
| DID method is not `uuid` | `methodNotSupported` | 501 |
| no PTR / registry lookup failed | `notFound` | 404 |
| other resolution/transport failure | `internalError` | 500 |

### Content negotiation

- Default (e.g. `Accept: application/ld+json`, what `uni-resolver-web`
  sends): the bare **DID document**, `Content-Type:
  application/did+ld+json`.
- `Accept: application/ld+json;profile="https://w3id.org/did-resolution"`:
  a full **DID Resolution Result**, `Content-Type: application/ld+json;profile="https://w3id.org/did-resolution"`.
- Errors always return a DID Resolution Result (there is no document to
  return) with the error in `didResolutionMetadata`.

### Other endpoints

- `GET /1.0/methods` → `["did:uuid"]` (also the container health check;
  needs no DNS).
- `GET /1.0/properties` → `{}`.
- `GET /` → a plain-text liveness banner.

## Build and run

Build from the **repository root** (the build context must be the repo
so the `ruuid` package is in scope):

```
docker build -f uni-resolver-driver/Dockerfile -t universalresolver/driver-did-uuid .
docker run --rm -p 8080:8080 universalresolver/driver-did-uuid
```

Or use the standalone compose in this directory (it sets the build
context for you):

```
docker compose -f uni-resolver-driver/docker-compose.yml up --build
```

Then (this DID is anchored to a real published PTR and resolves to a
200 — see "Registering with the Universal Resolver" below):

```
curl http://localhost:8080/1.0/identifiers/did:uuid:00000000-0001-8200-8002-341632100000
```

Without Docker, the package installs a console script:

```
pip install .
ruuid-did-uuid-driver --port 8080
# or: python -m ruuid.driver --port 8080
```

## Configuration

All flags have environment-variable equivalents (the Docker image is
driven entirely by env):

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--host` | `RUUID_DRIVER_HOST` | `0.0.0.0` | bind address |
| `--port` | `RUUID_DRIVER_PORT` | `8080` | bind port |
| `--registry` | `RUUID_DRIVER_REGISTRY` | `dns://` | registry-phase resolver |

`--registry` governs only the PTR + `_uuid.<domain>` lookups. Forms:
`dns://` (the system resolver), `dns://HOST[:PORT]`, or
`doh://HOST[:PORT][/PATH]` (RFC 8484; path defaults to `/dns-query`).
The UUID-document and referent HTTP fetches always use the system
resolver.

## Registering with the Universal Resolver

To add `did:uuid` to a Universal Resolver deployment, contribute two
entries upstream.

**1. Driver routing** — add to
`uni-resolver-web/src/main/resources/application.yml` under `drivers:`:

```yaml
    - pattern: "^(did:uuid:.+)$"
      url: ${uniresolver_web_driver_url_did_uuid:http://driver-did-uuid:8080/}
      testIdentifiers:
        - did:uuid:00000000-0001-8200-8002-341632100000
```

**2. Container** — add to the top-level `docker-compose.yml`:

```yaml
  driver-did-uuid:
    image: universalresolver/driver-did-uuid:latest
    ports:
      - "8101:8080"   # pick any unused host port
```

> **About `testIdentifiers`.** The Universal Resolver smoke-tests each
> driver by resolving its `testIdentifiers` against a *live* deployment,
> so a test identifier must be a **publicly anchored** RUUID — an IP
> prefix whose reverse-DNS PTR is published. The identifier above is
> anchored to `52.22.50.16`, whose PTR resolves to `riverscape.info`,
> so it resolves to a **200** today. The PTR lookup is the pipeline's
> only hard requirement; every later step degrades to a default. With
> no `_uuid.riverscape.info` record and no UUID document published, the
> synthesised `serviceEndpoint` uses the spec-default template
> (`https://riverscape.info/0/000000000001`). Publishing a UUID document
> at `https://riverscape.info/.well-known/uuid-document.json` (the
> well-known default, used when no `_uuid` record exists) replaces that
> with the issuer's real referent templates — see
> [`examples/riverscape.info/`](../examples/riverscape.info/).

## Tests

The driver is covered by `tests/test_driver.py` (run from the repo
root with `make test` or `pytest tests/test_driver.py`): method
validation and error→status mapping, an end-to-end resolve against the
in-process fake DNS server, and the HTTP contract (routing, content
negotiation, status codes).
