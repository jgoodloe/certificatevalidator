# PIV / PIV-I / CAC Certificate Validator

A self-hosted equivalent of the MAX.gov PIV Certificate Validator. Users pick
one of four options; the browser prompts for a smartcard certificate; the app
either shows the certificate's fields or validates it against the Federal PKI
(path build + OCSP/CRL revocation).

## How it works

Browser client-certificate selection happens during the **TLS handshake**, so
the four options map onto **two TLS endpoints**, not four URL paths:

| Option | Host | Query | Behaviour |
|---|---|---|---|
| 1. PIV, validate | `piv.` | (none) | Federal CAs only; full validation |
| 2. PIV, details | `piv.` | `?certDetailsOnly` | Federal CAs only; fields only |
| 3. Any, validate | `piv-any.` | (none) | All client certs; full validation |
| 4. Any, details | `piv-any.` | `?certDetailsOnly` | All client certs; fields only |

The `piv` vs `piv-any` split is the **CA filter** in the TLS
`CertificateRequest` (federal DNs advertised vs. empty list). The
`certDetailsOnly` split is just application logic behind the same endpoint.

## Deploy

1. **Server TLS cert.** Put `server.crt` / `server.key` in `./certs/` for the
   `piv.` and `piv-any.` subdomains (Let's Encrypt via DNS-01 works, since these
   are mTLS endpoints you may not want public HTTP-01 challenges on).

2. **Federal CA bundle.** Put the FPKI Common Policy root + issuing CA certs as
   a single PEM at `./certs/fpki-cas.pem`. Source: IDManagement.gov "FPKI
   certificates and CRLs". Its subject DNs become the browser's filter list on
   the `piv.` endpoint.

3. **Trust anchors for validation.** Drop root certs in `./trust/anchors/` and
   intermediates in `./trust/intermediates/`. For production use the FPKI
   Common Policy Root CA; for testing use the **NIST PIV test PKI** roots so you
   can validate NIST test PIV cards without a live credential.

4. **DNS.** Point `piv.certtesting.goodloe.xyz` and
   `piv-any.certtesting.goodloe.xyz` at the host running `mtls-nginx`. Front the
   `landing` container through your existing NPM as a normal proxy host at
   `certtesting.goodloe.xyz`.

5. `docker compose up -d --build`

## Notes

- **Do not** put the mTLS endpoints behind NPM as a normal HTTP proxy host —
  the client cert won't survive the hop. If you want a single public ingress,
  use NPM **Streams** (layer-4 SNI passthrough) to forward `piv.` / `piv-any.`
  raw to `mtls-nginx:443`.
- `revocation_mode` is `hard-fail`: a cert whose OCSP/CRL can't be reached is
  treated as INVALID. Switch to `soft-fail` in `main.py` if you want the
  opposite for testing.
- The app returns JSON. Add an HTML template in `_render()` if you want a
  browser-friendly result page.
- Reuse your `ocspcrltesting` OCSP/CRL responders as the revocation sources by
  pointing test certs' AIA/CRLDP at them.
