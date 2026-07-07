# authentik OIDC gating (forward-auth)

This wires the validator to your existing authentik forward-auth pattern —
the same mechanism you use for other homelab services — with RBAC gating the
validator entirely (must be in the `piv-validator` group to do anything).

It applies to both deployment modes from the README; the only difference is
*which* nginx runs the `auth_request`:

- **Mode A (NPM-integrated):** NPM's two `piv` proxy hosts run it — the pasted
  `nginx/npm/piv.conf` / `piv-any.conf` contain the forward-auth blocks.
- **Mode B (standalone):** `mtls-nginx` runs it — see `nginx/mtls.conf`.

```
Mode A:  Browser --TLS--> NPM proxy host --auth_request--> authentik (embedded outpost)
                              |-- terminates client cert
                              `-- proxy_pass -> validator-app

Mode B:  Browser --TLS--> mtls-nginx --auth_request--> authentik (embedded outpost)
                              |-- terminates client cert
                              `-- proxy_pass -> validator-app
```

## 1. authentik configuration (Admin UI)

Identical shape to your other forward-auth apps:

1. **Proxy Provider** — *Applications > Providers > Create > Proxy Provider*,
   mode: **Forward auth (single application)**. External host:
   `https://piv.certtesting.goodloe.xyz`. Create a second provider for
   `piv-any.` (or use one domain-level provider covering both subdomains).
2. **Application** — *Applications > Applications > Create*, one per provider,
   with the Proxy Provider bound.
3. **Group** — *Directory > Groups*: create `piv-validator`, add yourself /
   authorized users.
4. **Bind the group to each Application** — on the Application's *Policy /
   Group / User Bindings* tab, bind the `piv-validator` group. Only members
   pass the forward-auth check at all; the app re-checks the same group
   header as defence-in-depth.
5. **Assign the Applications to the embedded outpost** — *Applications >
   Outposts > edit "authentik Embedded Outpost"* and move both new
   Applications into **Selected applications**. The outpost only answers
   `auth_request` for applications assigned to it; forgetting this step is
   the classic cause of an endless redirect loop or 404 on
   `/outpost.goauthentik.io/...`.

**Identity headers — nothing to configure.** On every successful
`auth_request`, a proxy provider returns `X-authentik-username`,
`X-authentik-groups`, and `X-authentik-email` out of the box. The nginx
configs copy them upstream with `auth_request_set` + `proxy_set_header`. They
would only go missing if you had deleted the provider's default scope
mappings — if you haven't touched those, skip this concern entirely.

## 2. Networking — what "the outpost hostname" actually means

The **embedded outpost is not a separate container.** It is a listener on
**port 9000 inside the authentik *server* container** (the same container
that serves the authentik UI). So the `authentik-server` hostname in the
nginx configs is a placeholder for *your authentik server container's
Docker-DNS name* — there is no `outpost` container to point at.

1. **Find the real name:** `docker ps` on the authentik host. With authentik's
   official docker-compose the service is called `server`, which resolves as
   `server` on that project's network (the container name will look like
   `authentik-server-1`). If you set a `container_name`, use that.
2. **Replace the placeholder** in the file(s) your mode uses:
   - Mode A: both `proxy_pass http://authentik-server:9000/...` lines in
     `nginx/npm/piv.conf` and `nginx/npm/piv-any.conf` (i.e. in the text you
     paste into NPM's Advanced tab).
   - Mode B: the same lines in `nginx/mtls.conf`.
3. **Share a network with it.** Docker DNS only resolves the name if the
   container doing the `auth_request` is attached to a network authentik is
   on:
   - Mode A: the **NPM container** needs the attachment. If you already proxy
     authentik's own UI through NPM by container name, it's already attached
     and there is nothing to do. Otherwise:
     `docker network connect <authentik-network> <npm-container>`.
   - Mode B: the **mtls-nginx container** needs it — uncomment/adapt the
     external-network example in `docker-compose.yml`.
4. **Verify before debugging anything else:**

   ```sh
   # from the NPM container (it ships with curl); expect HTTP 204
   docker exec <npm-container> curl -s -o /dev/null -w '%{http_code}\n' \
     http://<authentik-server-name>:9000/outpost.goauthentik.io/ping

   # the plain nginx image has no curl; a DNS check still proves the network:
   docker exec mtls-nginx getent hosts <authentik-server-name>
   ```

(Only if you deliberately deployed a *separate* proxy-outpost container —
not the embedded one — point the hostname at that container instead; the
port is still 9000.)

## 3. The landing page

A normal NPM **proxy host** at `certtesting.goodloe.xyz` -> `landing:80`,
gated with your usual forward-auth snippet in NPM's Advanced tab and the same
`piv-validator` group bound. This is the only documented entry point, which
mitigates the handshake-before-auth wrinkle (see below).

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

App-side RBAC trusts the `X-Authentik-Groups` header. That is only safe
because `validator-app` is reachable ONLY through the nginx that terminates
mTLS and runs the forward-auth (NPM in Mode A, `mtls-nginx` in Mode B), which
overwrites those headers on every request. If `validator-app` (or, in Mode B,
`mtls-nginx`'s upstream side) is ever exposed on another interface or an
over-shared Docker network, anyone could send
`X-Authentik-Groups: piv-validator` and bypass auth. `docker-compose.yml`
never publishes `validator-app`'s port — keep it that way, and be deliberate
about which networks it joins.
