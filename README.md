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

Two supported modes. **Mode A (recommended)** plugs into an existing Nginx
Proxy Manager: NPM keeps port 443 and terminates the mTLS handshake itself via
per-host custom nginx config, so there is no port conflict, no SNI router, and
no extra IP. **Mode B (standalone)** runs the dedicated `mtls-nginx` container,
which needs port 443 to itself.

### Common setup (both modes)

1. **Federal CA bundle.** Put the FPKI Common Policy root + issuing CA certs as
   a single PEM at `./certs/fpki-cas.pem`. Its subject DNs become the browser's
   filter list on the `piv.` endpoint. Sources (GSA FPKI repository, documented
   at <https://www.idmanagement.gov/implement/trust-fcpca/>):

   - Root (Federal Common Policy CA G2): <http://repo.fpki.gov/fcpca/fcpcag2.crt>
   - CAs issued by the root (intermediates, PKCS#7):
     <http://repo.fpki.gov/fcpca/caCertsIssuedByfcpcag2.p7c>
   - Optional, for PIV-I / cross-certified partners — Federal Bridge CA G4:
     <http://repo.fpki.gov/bridge/fbcag4.crt> and
     <http://repo.fpki.gov/bridge/caCertsIssuedByfbcag4.p7c>

   Build the bundle (the `.crt`/`.p7c` files are DER; nginx needs PEM) — or
   run `./scripts/fetch-fpki-certs.sh`, which does all of this **and** step 2's
   production trust-store layout in one go (`--bridge` adds the Federal Bridge
   chain):

   ```sh
   curl -LO http://repo.fpki.gov/fcpca/fcpcag2.crt
   curl -LO http://repo.fpki.gov/fcpca/caCertsIssuedByfcpcag2.p7c
   openssl x509  -inform DER -in fcpcag2.crt -out fcpcag2.pem
   openssl pkcs7 -inform DER -in caCertsIssuedByfcpcag2.p7c \
     -print_certs -out issuedByfcpcag2.pem
   cat fcpcag2.pem issuedByfcpcag2.pem > certs/fpki-cas.pem
   ```

2. **Trust anchors for validation.** Drop root certs in `./trust/anchors/` and
   intermediates in `./trust/intermediates/` (the app accepts PEM or DER files
   with any name, but not `.p7c` — convert those as above).

   - **Production (real PIV/CAC):** `fcpcag2.pem` from step 2 goes in
     `./trust/anchors/`; `issuedByfcpcag2.pem` goes in `./trust/intermediates/`.
   - **Testing (NIST test PIV cards):** the **NIST PIV test PKI**, from the
     project page <https://csrc.nist.gov/projects/piv/nist-piv-test-cards>.
     Root trust anchor:
     <https://csrc.nist.gov/CSRC/media/Projects/PIV/documents/Self-signedTrustAnchorCertificate.cer>
     → `./trust/anchors/`; the intermediate-CA ZIP linked on the same page
     → unpack into `./trust/intermediates/`.

### Mode A — behind Nginx Proxy Manager (recommended)

NPM stays on port 443 for everything; it performs the client-cert handshake
for the two `piv` hosts itself, so no separate TLS listener is needed.

1. `docker compose up -d --build` — starts `landing` + `validator-app` only
   (`mtls-nginx` is behind a compose profile and does not run in this mode).
2. **Networking.** Uncomment the `proxynet` network in `docker-compose.yml`
   (and the extra `networks:` lines on `landing` / `validator-app`), set its
   `name:` to NPM's Docker network, and `docker compose up -d` again so NPM
   can reach both containers by name.
3. **CA bundle into NPM.** Copy `certs/fpki-cas.pem` into NPM's data volume:
   `cp certs/fpki-cas.pem <npm-data-dir>/custom_ssl/fpki-cas.pem` (the
   snippets reference it as `/data/custom_ssl/fpki-cas.pem`).
4. **Three NPM proxy hosts:**
   | Host | Forward to | Advanced config |
   |---|---|---|
   | `certtesting.…` | `landing:80` | (none) |
   | `piv.…` | `validator-app:8000` | paste `nginx/npm/piv.conf` |
   | `piv-any.…` | `validator-app:8000` | paste `nginx/npm/piv-any.conf` |

   Request/attach a normal SSL cert for each in the NPM UI (Let's Encrypt
   DNS-01 via the Cloudflare provider works). In the two snippets, adjust the
   `authentik-server` hostname to your authentik server container — NPM must
   share a network with it for the forward-auth subrequest.
5. **DNS.** All three hostnames point at the NPM host, as usual.

### Mode B — standalone `mtls-nginx`

For hosts where port 443 is free (no NPM, or a separate machine/IP).

1. **Server TLS cert.** Put `server.crt` / `server.key` in `./certs/` covering
   the `piv.` and `piv-any.` subdomains (Let's Encrypt DNS-01 works, since you
   may not want public HTTP-01 challenges on mTLS endpoints).
2. **DNS.** Point `piv.…` and `piv-any.…` at this host; front `landing`
   through your reverse proxy at `certtesting.…` as a normal proxy host.
3. `docker compose --profile standalone up -d --build`

### Cloudflare (both modes)

The `piv.` and `piv-any.` DNS records **must be DNS-only (grey cloud)**. A
proxied (orange-cloud) record terminates TLS at Cloudflare's edge, which never
requests a client certificate — the smartcard picker simply won't appear. The
landing page and authentik hostnames can stay proxied. Grey-clouding exposes
the origin IP on those two records; firewall accordingly.

## Alternative designs considered

- **NPM Streams / SNI router in front of `mtls-nginx`.** NPM streams are plain
  port forwards, not SNI-aware, so sharing 443 needs a hand-rolled
  `ssl_preread` stream router with NPM moved to an internal port — an extra
  moving part Mode A makes unnecessary.
- **Secondary IP or nonstandard port for `mtls-nginx`.** Works (it's Mode B),
  but requires spare address space or ugly URLs.
- **Cloudflare mTLS at the edge (API Shield).** Would allow keeping the
  orange cloud: Cloudflare requests the client cert and forwards it in
  `Cf-Client-Cert-Der-Base64`. Requires a paid/Enterprise plan for
  bring-your-own-CA (the FPKI bundle), and the app would need to read
  Cloudflare's header instead of `X-Client-Cert`. Viable future option.
- **No-handshake validation (paste/upload a `.cer` file).** Works behind any
  proxy including orange-cloud Cloudflare, since no TLS client cert is
  involved — but there's no live smartcard picker, so it complements rather
  than replaces the four options. Could be added as a fifth landing-page
  option later.

## Automated updates

Once these files are on the repo's **default branch**, GitHub keeps the
project updated with no routine intervention:

- **Dependabot** (`.github/dependabot.yml`) opens weekly PRs for the
  `nginx`/`python` images in `docker-compose.yml` and `app/Dockerfile`, the
  Python packages in `app/requirements.txt` (grouped), and the pinned
  workflow actions.
- **CI** (`.github/workflows/ci.yml`, check name `validate`) validates both
  compose modes, builds the app image, and smoke-tests it on every PR.
- **Auto-merge** (`.github/workflows/dependabot-automerge.yml`) approves and
  auto-merges Dependabot PRs once `validate` is green — **minor/patch only**;
  major bumps stay open for review.
- **FPKI watchdog** (`.github/workflows/fpki-source-check.yml`) re-runs the
  fetch script against GSA monthly. If GSA moves/breaks the files the run
  fails (GitHub emails you); its job summary logs the bundle hash, so the
  run history shows when the Federal PKI publishes changes.

**One-time GitHub setup (two switches):**

1. *Settings → General → Pull Requests* → enable **Allow auto-merge**.
2. *Settings → Rules → Rulesets → New branch ruleset*: target the default
   branch, add **Require status checks to pass** with the `validate` check,
   and add **Repository admin** to the bypass list so your own direct pushes
   are never blocked. Without this ruleset nothing breaks — auto-merge just
   can't arm itself, and Dependabot PRs wait for a manual merge instead.

**What GitHub can't do:** restart containers on your server. Pair it with a
host-side cron, e.g. monthly:

```sh
cd /path/to/certificatevalidator \
  && git pull \
  && ./scripts/fetch-fpki-certs.sh \
  && cp certs/fpki-cas.pem <npm-data-dir>/custom_ssl/fpki-cas.pem \
  && docker compose up -d --build \
  && docker exec <npm-container> nginx -s reload   # new CA bundle needs a reload
```

(Or run [Watchtower](https://containrrr.dev/watchtower/) if you prefer
image-based redeploys.)

## Builds, security gates & releases

Nothing becomes a release unless everything passes. The pipeline
(`.github/workflows/release.yml`) runs on every default-branch change to
`app/**`, on manual dispatch, and whenever `cve-watch` finds a fixable
vulnerability in the deployed image:

```
build (--pull: patched base image)
  -> smoke test (container really serves /healthz)
  -> CVE scan (pip-audit + Trivy, HIGH/CRITICAL)
  -> verdict:
     pass          -> push ghcr image :vTAG + :latest, publish release
     questionable  -> vulns with NO released fix: push :vTAG only, create a
                      DRAFT release, open an issue assigned to you — YOU
                      decide; publishing the draft retags :latest
     fail          -> fixable CVEs or broken build: NO release, issue alert
```

- **PRs are gated too**: `ci.yml` runs the same CVE gate, so an update that
  introduces a fixable HIGH/CRITICAL vulnerability can't even merge.
- **Rebuild-on-patch**: `cve-watch.yml` scans the *released* image daily.
  When a fix becomes available for a HIGH/CRITICAL finding, it triggers a
  rebuild automatically (patched OS packages come from `--pull`; patched
  Python libraries arrive as Dependabot PRs that auto-merge and trigger
  their own release). You stop being vulnerable without touching anything.
- **Alerts** are GitHub issues assigned to you, labeled `release-blocked`,
  `release-decision`, or `security-rebuild` (deduplicated — repeated runs
  comment on the open issue instead of spamming new ones).

**One-time setup:** *Settings → Advanced Security*: enable **Dependency
graph** and **Dependabot security updates** — that's what turns "a patched
library exists" into an immediate PR instead of waiting for the weekly
schedule. Optionally make the GHCR package public (Packages → package →
settings), or `docker login ghcr.io` on the host with a `read:packages` PAT.

**Deploying a release** on the host (instead of building locally):

```sh
docker compose -f docker-compose.yml -f docker-compose.release.yml pull validator-app
docker compose -f docker-compose.yml -f docker-compose.release.yml up -d
```

## Notes

- **Where the handshake lives is where the trust boundary lives.** Nothing may
  sit in front of the TLS listener that requests the client cert (NPM in
  Mode A, `mtls-nginx` in Mode B) except raw L4 passthrough — an HTTP proxy
  hop (including Cloudflare's orange cloud) strips the client cert. A plain
  NPM proxy host *without* the `nginx/npm/*.conf` advanced config has the same
  problem: it's the advanced config that makes NPM request the cert at its own
  handshake.
- **Header trust:** `validator-app` believes whatever `X-Client-*` /
  `X-Authentik-*` headers it receives, so the mTLS-terminating proxy must be
  the only thing that can reach it. `docker-compose.yml` doesn't publish its
  port; keep it that way, and be deliberate about what else is attached to the
  networks it joins.
- `revocation_mode` is `hard-fail`: a cert whose OCSP/CRL can't be reached is
  treated as INVALID. Switch to `soft-fail` in `main.py` if you want the
  opposite for testing.
- The app returns JSON. Add an HTML template in `_render()` if you want a
  browser-friendly result page.
- Reuse your `ocspcrltesting` OCSP/CRL responders as the revocation sources by
  pointing test certs' AIA/CRLDP at them.
