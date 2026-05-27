# Example zone configs

The files in this directory are sample inputs for `ruuid document` and
`ruuid records`. Copy one, edit the values for your domain and
network prefix, and feed it to either CLI.

The zone format is **domain-keyed**: each entry under `domains`
describes one domain, the list of IP addresses (the `anchors:` array)
that map to it via reverse DNS, and either the `service` array that
becomes the UUID document's service array (for domains that publish
their UUID document at the well-known location) or a
`uuid_document_uri` (for UUID documents hosted elsewhere — `data:`,
`file://`, `did:web:`, `did:plc:`, `did:uuid:`, or any HTTP(S) URL).

`uuid_document_uri` accepts a few shorthand forms in addition to a
full absolute URI:

| shorthand                              | resolves to                                                          |
|:---------------------------------------|:---------------------------------------------------------------------|
| `/path/to/doc.json`                    | `https://<domain>/path/to/doc.json`                                  |
| `http:/path/to/doc.json`               | `http://<domain>/path/to/doc.json` (use when serving on plain HTTP)  |
| `file:foo/doc.json`                    | `file://<absolute-path-of-zone-file's-dir>/foo/doc.json`             |

`data:`, `did:web:`, `did:plc:`, `did:uuid:`, and any URI with an
explicit `//` authority pass through unchanged.

## `single-domain.json`

The smallest viable config: one domain, one IP address in `anchors`, one service
entry. Replace the placeholder values:

| field          | what to put here                                                                                              |
|:---------------|:--------------------------------------------------------------------------------------------------------------|
| `domain`       | The DNS domain you control and will publish RUUIDs under (e.g. `acme.com`).                                   |
| `anchors`      | A list of IPv4 /32 or IPv6 /64 addresses you hold reverse-DNS authority for. Each address's PTR record points at your domain. |
| `service`      | The CID service array that will appear verbatim in your UUID document. Each entry has `id` (`#0`..`#1023`, the RUUID type), `type` (a free-form label), and `serviceEndpoint` (the URL template a resolver substitutes the 48-bit identifier into; `<identifier>` is the canonical 12-char lowercase hex placeholder). |

Type `0` is conventionally the domain-wide default — its
`serviceEndpoint` is the template a resolver falls back to when an
RUUID's type doesn't have its own entry. Adding more types is just
adding more entries to the `service` array.

## Workflow

Given your edited file (call it `my-domain.json`):

1. `ruuid document --zone my-domain.json` — prints the UUID-document JSON.
   Upload it to `https://<your-domain>/.well-known/uuid-document.json`
   (or wherever `_uuid.<your-domain>` will point).
2. `ruuid records --zone my-domain.json` — prints the BIND-style DNS
   records (PTR + URI/TXT). Install them in your authoritative zone.
3. `ruuid generate <IP-address> <48-bit-identifier> --type N` — generate
   individual RUUIDs as needed. Anyone can resolve them via the DNS +
   document pipeline.

## Larger example

The full demo zone at `../demo/demo-zone.json` shows what a richer
config looks like: multiple service entries, multiple sibling addresses
sharing one domain, and the externally-hosted document patterns
(`data:`, `file://`, `did:web:`, `did:uuid:` URIs). Use
`single-domain.json` as your starting point; peek at `demo-zone.json`
for what fancier setups look like.
