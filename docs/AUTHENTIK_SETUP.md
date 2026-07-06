# authentik OIDC gating (Option 1: forward-auth + NPM Streams)

This wires the validator to your existing authentik forward-auth pattern —
the same mechanism you use for other homelab services — with RBAC gating the
validator entirely (must be in the `piv-validator` group to do anything).

## Why Streams, not a normal proxy host

The mTLS endpoints terminate the client-cert TLS handshake themselves. A normal
HTTP reverse-proxy hop (NPM proxy host, or authentik's proxy in front) would
terminate TLS at that hop and the client cert would never reach `mtls-nginx`.
So NPM fronts these two subdomains as **layer-4 Streams (SNI passthrough)**:
NPM forwards the raw encrypted TCP by SNI to `mtls-nginx:443`, the cert survives,
and `mtls-nginx` both terminates mTLS and runs the `auth_request` to the outpost.

```
Browser --TLS--> NPM Stream (L4, no termination) --TLS--> mtls-nginx
                                                            |-- terminates client cert
                                                            |-- auth_request -> authentik outpost
                                                            |-- proxy_pass -> validator-app
```

## 1. authentik configuration

Identical shape to your other forward-auth apps:

1. **Proxy Provider** — mode: *Forward auth (single application)*.
   External host: `https://piv.certtesting.goodloe.xyz` (create a second
   provider/application for `piv-any.` or use a domain-level provider covering
   both subdomains).
2. **Application** — bind the Proxy Provider to it.
3. **Group** — create `piv-validator`. Add yourself / authorized users.
4. **Bind the group to the Application** (Policy / Group binding) so only
   members pass the outpost check at all. This is gate-level RBAC; the app
   re-checks the same group header as defence-in-depth.
5. **Embedded outpost** — ensure it serves these applications. Confirm the
   outpost forwards `X-authentik-username`, `X-authentik-groups`,
   `X-authentik-email` (default scope mappings do this).

The outpost must be reachable from `mtls-nginx` at the hostname used in
`nginx/mtls.conf` (`http://authentik-outpost:9000`). Rename to match your
actual outpost container/service, and attach `mtls-nginx` to the network the
outpost is on.

## 2. NPM Streams

In NPM: **Streams** -> add a stream for each subdomain forwarding TCP 443 to
`mtls-nginx` host:443. If your NPM build routes streams by SNI, set the
incoming SNI to the subdomain; otherwise dedicate a forwarding port. Cloudflare
DNS for `piv.` and `piv-any.` points at your NPM host as usual (proxied or
DNS-only per your setup — note Cloudflare's orange-cloud proxy does NOT pass
client certs on the free tier, so these two records likely need to be DNS-only
/ grey-cloud).

## 3. The landing page

Still a normal NPM **proxy host** (not a stream) at
`certtesting.goodloe.xyz` -> `landing:80`, gated with your usual forward-auth
snippet in NPM's Advanced tab and the same `piv-validator` group bound. This is
the only documented entry point, which mitigates the handshake-before-auth
wrinkle (see below).

## 4. The unavoidable UX wrinkle

The TLS handshake (cert picker) completes before nginx can run `auth_request`.
So a user who navigates DIRECTLY to `piv.certtesting.goodloe.xyz` without a
session will: see the cert picker -> pick a cert -> THEN get redirected to
authentik login. That's ugly but harmless. Mitigations:

- Publish only the gated landing page as the entry point. Authenticated users
  are the only ones who ever reach the handshake in normal use.
- The app also returns 403 (not a cert result) if the group header is missing,
  so even a forged/direct request that somehow reaches the app leaks nothing.

## 5. Header-forgery caveat (important)

App-side RBAC trusts the `X-Authentik-Groups` header. That is only safe because
`mtls-nginx` and `validator-app` are reachable ONLY through the controlled
Stream -> mtls-nginx -> app path, where the outpost sets those headers. If the
app or mtls-nginx is ever exposed on another interface, anyone could send
`X-Authentik-Groups: piv-validator` and bypass auth. Keep both off any public
network; only NPM's Stream should reach `mtls-nginx`, and only `mtls-nginx`
should reach `validator-app` (enforced here by the internal `pivnet` network).
