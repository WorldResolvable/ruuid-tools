# DIF Universal Resolver driver for the did:uuid method.
#
# Build from the repository root (the build context must be the repo,
# not this directory, so the ruuid package is in scope):
#
#   docker build -f uni-resolver-driver/Dockerfile -t universalresolver/driver-did-uuid .
#
# Run standalone (resolves against the host's DNS):
#
#   docker run --rm -p 8080:8080 universalresolver/driver-did-uuid
#   curl http://localhost:8080/1.0/identifiers/did:uuid:00000000-0001-8200-8002-341632100000
#
# Point the registry phase at a specific DNS or DoH server:
#
#   docker run --rm -p 8080:8080 \
#     -e RUUID_DRIVER_REGISTRY=doh://dns.example/dns-query \
#     universalresolver/driver-did-uuid

FROM python:3.12-slim

WORKDIR /app

# Only the package and its build metadata are needed; the spec
# documents, demo, and tests are not part of the runtime image.
COPY pyproject.toml /app/pyproject.toml
COPY ruuid /app/ruuid

RUN pip install --no-cache-dir .

ENV RUUID_DRIVER_HOST=0.0.0.0 \
    RUUID_DRIVER_PORT=8080 \
    RUUID_DRIVER_REGISTRY=dns://

EXPOSE 8080

# Liveness only — /1.0/methods needs no DNS, so it stays green even
# when no upstream resolver is reachable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import sys, urllib.request; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/1.0/methods', timeout=3).status == 200 else 1)"

ENTRYPOINT ["ruuid-did-uuid-driver"]
