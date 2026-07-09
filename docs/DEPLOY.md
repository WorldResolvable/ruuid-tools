# Deploying an RUUID issuer host

This is the recipe for standing up a host that can **issue** CT-anchored RUUIDs
— mint a genesis proof, pre-commit and rotate keys, and publish a custody
bundle — the way `uuid.zone` was set up during development. The `ruuid`
software is fully reproducible from a clone; this document + the scripts in
`deploy/` capture the *deployment* around it (DNS, web server, ACME) that the
repository can't hold on its own.

> **Experimental.** Matches the experimental `seal` / `rotate` / `verify`
> tooling; expect it to evolve alongside the custody-chain draft.

## What the host does

An issuer host controls an **IP** and a **domain**, and:

1. gets Let's Encrypt certificates for the IP (genesis) and for
   `k<base32>.rotate.custody.<domain>` commitment names (pre-rotation), which
   land in Certificate Transparency;
2. serves, over HTTPS at the domain:
   - `/.well-known/uuid-custody.json` — its published custody bundle (what the
     discovery cascade fetches);
   - `/.well-known/uuid-document.json` — the UUID document (resolution).

Verification never needs the host to be up (evidence is in CT and in the
published bundle), but *issuance* and *publishing* happen here.

## Prerequisites (cloud-level, mostly manual)

These aren't scriptable from the repo; set them up first.

1. **A host with a static, routable public IP.** On AWS: an EC2 instance with
   an **Elastic IP**. Let's Encrypt must be able to reach ports 80/443 at that
   IP, and it must not change (the RUUID anchors to it).
2. **DNS records** in the domain's zone:
   - `A`  — `<domain>` → `<ip>`.
   - **PTR (reverse DNS)** — `<ip>` → `<domain>`. `ruuid seal` verifies this.
     On AWS, set it on the Elastic IP (EC2 console → *Elastic IPs* → *reverse
     DNS*, or `aws ec2 modify-address-attribute`); it requires the matching
     forward `A` record to already exist.
   - **Custody namespace records** — `custody.<domain>` is the reserved parent
     for all CT custody names. Two records, both pointing at the host, cover it:
     - `*.custody.<domain>. CNAME <domain>.` — the wildcard. Validates every
       command name at any depth (the per-key commitment names
       `k<base32>.rotate.custody.<domain>` that `--pre-rotate`/`rotate` issue,
       and any future command type). One record covers the whole subtree.
     - `custody.<domain>. CNAME <domain>.` — the bare marker (used by
       `seal --ct-marker`). The wildcard does **not** cover its own parent, so
       this needs its own record.
     A wildcard `A` to the IP works in place of the CNAMEs.
3. **`acme.sh`** (the ACME client) — installed for the user that runs `ruuid`.
   `deploy/setup-host.sh` installs it if missing.
4. **A web server** (nginx assumed here) — `deploy/nginx-ruuid.conf.example`.

## 1. Install the tooling

```
git clone https://github.com/WorldResolvable/ruuid-tools.git
cd ruuid-tools
pip install -e .            # provides the `ruuid` command
```

## 2. Configure the web server

Use `deploy/nginx-ruuid.conf.example` as the template. The one non-obvious
piece is the **catch-all `:80` server** that serves `/.well-known/acme-challenge/`
for *any* Host — commitment names like `k<base32>.rotate.custody.<domain>` don't match
your `<domain>` server block, so without the catch-all their ACME validation
fails. `deploy/setup-host.sh` installs the config and creates the webroot:

```
RUUID_DOMAIN=uuid.zone deploy/setup-host.sh
```

Then issue the **web server's own** TLS certificate (separate from the RUUID
certs) and wire auto-renew — see the header of `nginx-ruuid.conf.example`.

## 3. Preflight

```
RUUID_DOMAIN=uuid.zone deploy/preflight.sh
```

Confirms the `A` record, that the PTR points back to the domain, that
`custody.<domain>` and `*.custody.<domain>` resolve to the IP, that the `:80` challenge path is
reachable (for both the domain and a wildcard host), and that `ruuid` /
`openssl` / `acme.sh` are present. Fix any `FAIL` before sealing.

## 4. Seal a genesis identity (with pre-rotation)

```
ruuid seal <ip> <domain> --pre-rotate --webroot /usr/share/nginx/html [--production]
```

- Defaults to **staging** (untrusted, but exercises the full flow). Add
  `--production` for real Let's Encrypt + real CT.
- `--webroot` is required when nginx owns 80/443 (the standalone challenge
  can't bind those ports).
- `--pre-rotate` also mints a **cold successor key** and its CT commitment;
  **back up the resulting `next-key.pem` off-box** — it is your pinned
  successor.
- **`--no-domain-cert`** if this host *also* runs an `acme.sh`-managed cert for
  the same domain (e.g. the web server cert above): `seal`'s domain cert would
  otherwise collide with it in `acme.sh`'s per-domain store. IP genesis +
  commitment certs are unaffected.
- Artifacts land in `~/.ruuid/seals/<uuid>/` (`--out` to override). The
  `key.pem` there is the **genesis private key** — back it up off-box too.

Then publish the UUID document for the minted RUUID at
`/.well-known/uuid-document.json` (or wherever your referent template points).

## 5. Publish the custody bundle

```
deploy/publish-custody.sh            # -> <webroot>/.well-known/uuid-custody.json
```

This aggregates the issuer's own `*-cert.pem` files (never private keys) into a
self-contained, self-authenticating bundle. Resolvers fetch it via
`--fetch-bundles`, so crt.sh stays off the hot path. **Cron it** (e.g. daily)
and run it again after every rotation, so the served bundle stays current.

## 6. Rotate a key

```
ruuid rotate ~/.ruuid/seals/<uuid> --webroot /usr/share/nginx/html [--production]
deploy/publish-custody.sh            # republish so the new generation is served
```

`rotate` activates the pinned successor (no access to the old key needed —
works even if it was compromised), commits a fresh cold successor, and writes a
new UUID document committing the new key. Publish that new document, back up the
new `next-key.pem`, and republish the bundle.

## 7. Verify (anyone)

```
# off the published bundle (no crt.sh):
ruuid verify <uuid> uuid-document.json --bundles ./bundles/

# discovery cascade for unknown issuers (local -> issuer bundle -> crt.sh):
ruuid verify <uuid> uuid-document.json --fetch-bundles
ruuid resolve <uuid> --verify --fetch-bundles
```

## Operational notes (lessons from the reference deployment)

- **Small hosts wedge.** The reference box occasionally OOM'd (legacy MySQL in
  Docker). Don't run production issuance during peak site hours if the box is
  shared; a `--webroot` seal only touches the file system briefly.
- **crt.sh indexing lag.** After production issuance, certs take minutes to
  appear in crt.sh, and its endpoints are flaky (retry). Staging certs are
  **not** on crt.sh at all — validate staging via `--bundles` against the local
  certs, and use `--production` when you need public crt.sh discovery.
- **Key hygiene.** `key.pem` (genesis) and every `next-key.pem` (cold
  successors) are the root of authority — back them up off-box; the cold
  successor especially, since pre-rotation's compromise-recovery depends on it.
- **`--always-force-new-domain-key`** is applied automatically by `seal`; no
  action needed. It exists because `acme.sh` with a cached cert could otherwise
  hand back a key/cert pair that disagree.

## What is NOT automated

The cloud primitives — provisioning the instance, allocating/attaching the
Elastic IP, and setting the reverse-DNS (PTR) — are provider-specific and left
manual (see Prerequisites). Everything from DNS-in-place onward is covered by
the `deploy/` scripts and the commands above.
