# mcp-oauth-proxy

An OAuth 2.1 **resource-server** proxy that puts Microsoft Entra ID authentication and
MCP-aware authorization in front of an MCP server that has no authorization support
of its own. The MCP server is not modified; it keeps speaking plain streamable
HTTP / SSE on loopback while the proxy terminates every token.

Authorization is decided **solely by Entra ID group membership**, resolved from
Microsoft Graph rather than from the token.

```
                      ┌──────────────────────── Pod ────────────────────────┐
 MCP client  ──TLS──▶ │  mcp-oauth-proxy :8080  ──http──▶  mcp-server :3000 │
 (Claude, VS Code,    │  • RFC 9728 metadata               (127.0.0.1 only) │
  Copilot, agent)     │  • RS256 / JWKS validation                          │
        │             │  • aud + iss + tid pinning                          │
        │             │  • group membership policy                          │
        │             └──────────────┬──────────────────────────────────────┘
        │                            │
        └──OAuth──▶ login.microsoftonline.com/<tenant>/v2.0
                                     └──Graph──▶ graph.microsoft.com
                                                 /users/{oid}/transitiveMemberOf
```

## Why groups, and why from Graph

A delegated scope says which permission a *client application* asked for. It does
not say who the caller is, and in a default tenant any user can consent to one.
Group membership is a statement by the directory about the *person*, which is
what an access decision actually needs.

Membership can be resolved two ways, selected by `authorization.oauth2.graph.flow`.

| | `app_permission` (default) | `obo` |
|---|---|---|
| Graph permission required | **Application** `GroupMember.Read.All` | **Delegated** `GroupMember.Read.All` |
| Calls Graph as | the proxy itself | the caller |
| Works for app-only callers | yes | no — there is no user to act for |
| Token exchange per user | no | yes, on each cache miss |
| Tenants it can serve | only the credential's own | any trusted tenant |
| `name:` display-name aliases | yes | yes |
| Graph endpoint | `/users/{id}/transitiveMemberOf` | `/me/transitiveMemberOf` |

**Which to choose.** `app_permission` is the better default: one credential, no
per-request exchange, and app-only callers work. Choose `obo` when your tenant
will not grant an application permission — a delegated `GroupMember.Read.All`
is a far easier approval in many organisations, because it only ever reads the
directory with the rights the signed-in user already has.

A common reason to end up on `obo`: the application has Graph permissions, but
they are **Delegated**. Client credentials ignore delegated permissions
entirely, so the `roles` claim comes back empty and every Graph call is refused
with `Authorization_RequestDenied`. `obo` consumes exactly those permissions.

**Consequences of `obo`:**

- The Graph credential and the API are necessarily the **same app registration**,
  because the exchange can only be performed by the application the inbound
  token was issued for. Leave `graph.credential.clientID` unset and it defaults
  to the right value; setting it to a different application is rejected.
- **`name:` aliases cost an extra directory read.** They are resolved with the
  first caller's token, which must therefore be allowed to read group objects.
- **App-only callers get no groups.** They are authorized by `allowRoles`
  instead, which is unchanged — the proxy never attempts an exchange for them.
- Cross-tenant works, because the exchange runs at the *caller's* token
  endpoint, not the credential's.

The exchanged Graph token is deliberately **not cached**; it is only requested
on a membership cache miss, and caching it would mean holding a user-scoped
credential long after the proxy has any use for it.

`transitiveMemberOf` is used rather than `memberOf`, because `memberOf` returns
only **direct** membership: a user in `mcp-operators`, which is itself nested in
`mcp-users`, would be refused by a `memberOf` check even though the directory
considers them a member.

Reading groups from the token's `groups` claim is supported (`groupsSource: jwt`)
but is not the default. Entra ID replaces the claim with a `_claim_names` overage
reference once a user is in roughly 200 groups, and the list is frozen for the
token's lifetime.

## What it implements

| Capability | Detail |
|---|---|
| Protected resource metadata | `GET /.well-known/oauth-protected-resource` (RFC 9728), at the root and the path-aware location |
| Discovery challenge | `401` + `WWW-Authenticate: Bearer resource_metadata="…", error="…"` so clients bootstrap OAuth unaided |
| Token validation | RS256 signature via tenant JWKS, `exp`/`nbf` with configurable skew, cached keys with rotation-triggered refresh |
| Audience binding | `aud` must match this MCP server (RFC 8707); blocks confused-deputy and token-replay |
| Issuer pinning | `iss` must be `…/<tid>/v2.0` (or `sts.windows.net/<tid>/` for v1), selected per trusted tenant |
| Caller allow list | Optional restriction on `azp`/`appid` so only approved client apps connect |
| Group gate | Mandatory `allowGroups`: a caller must be a transitive member of one of them to reach the MCP server at all |
| MCP authorization | Per-`method` and per-tool rules matched on group object ids, evaluated first-match-wins |
| App-only callers | Daemons have no group membership, so they are gated on app roles behind an explicit `allowAppOnly` switch |
| Directory caching | Per-user LRU cache with single-flight, negative caching, and a choice of fail-closed or serve-stale |
| No token passthrough | The client's token is never forwarded upstream; identity is injected as headers |
| Anti-spoofing | Client-supplied `X-Mcp-*` / `X-Forwarded-User` headers are stripped before forwarding |
| Streaming | SSE and streamable HTTP pass through unbuffered (`FlushInterval: -1`, no write timeout) |
| DCR shim | Optional `/register` endpoint, because Entra ID does not implement RFC 7591 |
| Observability | Prometheus metrics on `:9090`, structured JSON audit logs, `/healthz` and `/readyz` |

## Repository layout

```
cmd/mcp-oauth-proxy/     entrypoint, --config and --check-config
internal/config/         YAML configuration, defaults and validation
internal/auth/           JWKS cache, Entra ID token validator, principal
internal/graph/          Microsoft Graph client, group cache, lazy alias resolution
internal/authz/          MCP JSON-RPC parsing and policy evaluation
internal/proxy/          streaming reverse proxy and identity header injection
internal/server/         routing, metadata endpoints, middleware, metrics
deploy/helm/             Helm chart (proxy + MCP server sidecar)
deploy/manifests/        plain YAML equivalent
examples/                annotated config and production Helm values
```

## Entra ID setup

Three identities are involved: the API (this MCP server), the client application,
and the identity the proxy uses to read the directory.

**1. Register the MCP server API**

```bash
az ad app create --display-name "Platform MCP Server" --sign-in-audience AzureADMyOrg
APP_ID=$(az ad app list --display-name "Platform MCP Server" --query '[0].appId' -o tsv)

# Application ID URI -> this becomes the token audience
az ad app update --id "$APP_ID" --identifier-uris "api://$APP_ID"
```

Add **one delegated scope**, for example `mcp.access`. The proxy never makes an
authorization decision from it, but it is still required: Entra ID ignores the
RFC 8707 `resource` parameter, so a client must request `api://<app-id>/mcp.access`
to be issued a token with the correct `aud`, and `scopesSupported` needs a value
to advertise.

**2. Register the client application**

A public client with redirect URI `http://localhost:<port>/callback` and PKCE,
granted the `mcp.access` delegated permission.

**3. Give the proxy permission to read groups**

Create the identity the proxy authenticates as — a user-assigned managed identity
(recommended, used with workload identity federation) or a separate app
registration with a client secret:

```bash
# GroupMember.Read.All, APPLICATION permission, then admin consent.
az ad app permission add --id "$GRAPH_CLIENT_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 98830695-27a2-44f7-8c18-0c3ebc9698f6=Role
az ad app permission admin-consent --id "$GRAPH_CLIENT_ID"
```

`GroupMember.Read.All` is read-only and is the narrowest permission that covers
`transitiveMemberOf`. `Directory.Read.All` also works but grants far more.

**4. Federate the Kubernetes service account** (recommended, avoids a stored secret)

```bash
az identity federated-credential create \
  --name mcp-oauth-proxy \
  --identity-name "$MANAGED_IDENTITY" \
  --resource-group "$RG" \
  --issuer "$(az aks show -g "$RG" -n "$CLUSTER" --query oidcIssuerProfile.issuerUrl -o tsv)" \
  --subject system:serviceaccount:mcp:platform-mcp-mcp-oauth-proxy \
  --audience api://AzureADTokenExchange
```

The Azure Workload Identity webhook then projects a service account token into
the pod and sets `AZURE_FEDERATED_TOKEN_FILE`, which the proxy reads on every
token exchange — kubelet rotates that file in place, so it is never cached.

## The three identities

The configuration names several client IDs. They are different applications
with deliberately different trust levels, and the example uses distinct
placeholder GUIDs to make that obvious:

| Config field | Application | Credential | Why it is separate |
|---|---|---|---|
| `oauth2Client[].clientID` | the API this proxy fronts | none | A passive identity. The proxy never authenticates as it; it exists so Entra ID will mint tokens whose `aud` is `api://<clientID>`. Its value is public — clients put it in their token requests. It only seeds the default `audience`. |
| `graph.credential.clientID` | the proxy's own workload identity | federated to the Kubernetes service account, or a secret | Holds `GroupMember.Read.All`, an admin-consented permission to read *every* user's group membership in the tenant. |
| `allowedClientIDs[]` | the calling applications | n/a | An allow list matched against `azp`/`appid`; these are other people's apps. |
| `dynamicClientRegistration.staticClientID` | the public client MCP clients should use | none (public client) | Returned by the DCR shim, since Entra ID has no open registration endpoint. |

### Can the first two be the same registration?

Under `graph.flow: obo` the question is settled for you: they **must** be the
same registration, because the On-Behalf-Of exchange can only be performed by
the application the inbound token was issued for. Leave
`graph.credential.clientID` unset and it is filled in for you. The rest of this
section applies to `graph.flow: app_permission`, where you have a choice.

It works — nothing in Entra ID or in this proxy's validation stops you putting
`GroupMember.Read.All` and a federated credential on the API registration and
using one GUID. Whether the audience is internal-only does not really bear on
it, because the risk is not about who signs in.

It is about who *administers* the registration, and the answer therefore depends
on how your tenant is run.

**If your team owns the registration.** Keep them separate. An API registration
is a living object — scopes, app roles, pre-authorized clients, redirect URIs —
and anyone with Owner on it can also add a client secret. If that same
registration holds `GroupMember.Read.All`, application ownership becomes a path
to reading every user's group membership in the tenant. Splitting means the
API's owners cannot mint a directory-reading credential.

**If a central identity team owns all registrations** and hands your team a
credential, that escalation path is already closed by process, and a single
registration is a reasonable choice. The separation buys you comparatively
little, because the credential you are given is the one carrying
`GroupMember.Read.All` either way. Two things still apply:

- Ask for **workload identity federation rather than a client secret**. It is a
  one-time setup by the same team — a federated identity credential naming your
  cluster's OIDC issuer and service account — and no secret is ever issued,
  stored in a Kubernetes `Secret`, or rotated. This is the proxy's default
  (`type: federated`) and it matters far more than how many registrations you
  use. A user-assigned managed identity works identically here and cannot have
  secrets added to it at all.
- If a secret is unavoidable, treat it as a **tenant-wide directory-read
  credential**, because that is what it is, regardless of what else the
  registration is used for.

If you do merge them, note that there is then only **one** secret, not two. A
client secret belongs to an app registration, so sharing the client ID means
sharing the credential by definition — set `graph.credential.clientID` to the
same GUID and point `clientSecretEnv` at it. Worth being explicit about, because
the resource half of this design needs no credential at all: validating a token
uses only the tenant's public JWKS. The sole reason the registration needs a
secret is the outbound Graph call.

Running several MCP proxies tilts things back towards separation: each needs its
own audience, so merging means one `GroupMember.Read.All` grant and one
credential copy per deployment to track, instead of a single shared Graph
identity.

### Avoiding `GroupMember.Read.All` altogether

If the central team is reluctant to grant a tenant-wide directory read, there is
a legitimate alternative. In **Token configuration**, add a groups claim limited
to *Groups assigned to the application*, and set `groupsSource: jwt`. Entra ID
then emits only the groups explicitly assigned to this enterprise application,
which needs no Graph permission and no credential at all, and the assigned set is
usually small enough to stay clear of the overage limit described above. The
trade-offs are that someone must maintain the assignments, and that membership is
fixed for the token's lifetime rather than re-checked every `cacheTTL`.

## Configuration

A single YAML file, passed with `--config` (or `$CONFIG_FILE`). Unknown keys are
a fatal error, so a typo cannot silently disable a control. See
[`examples/config.yaml`](examples/config.yaml) for the fully annotated version.

```yaml
server:
  listenAddr: ":8080"
  metricsAddr: ":9090"
  maxBodyBytes: 4194304
  maxGroupsHeaderBytes: 2048

upstream:
  url: http://127.0.0.1:3000

authorization:
  oauth2:
    resource: https://mcp.example.com/mcp
    scopesSupported: ["api://22222222-.../mcp.access"]

    # Mandatory coarse gate.
    allowGroups:
      - 6f0d8f0e-0000-0000-0000-000000000001
      - name:mcp-operators

    oauth2Client:
      - tenantID: 11111111-...
        clientID: 22222222-...
        audience: ["api://22222222-...", "22222222-..."]

    # One block for the whole deployment, not one per application.
    graph:
      cacheTTL: 10m
      failureMode: closed
      credential:
        type: federated
        clientID: 99999999-...

  policy:
    defaultEffect: deny
    rules:
      - name: protocol-handshake
        effect: allow
        methods: ["initialize", "initialized", "ping", "notifications/*"]
      - name: operators
        effect: allow
        methods: ["tools/call"]
        tools: ["kubectl_get*"]
        groups: ["name:mcp-operators"]
```

Validate before rolling out — this also compiles the policy:

```bash
mcp-oauth-proxy --config /etc/mcp-proxy/config.yaml --check-config
```

### Key settings

| Setting | Default | Notes |
|---|---|---|
| `authorization.oauth2.allowGroups` | — | **Mandatory.** Without it every authenticated user in the tenant would reach the MCP server |
| `authorization.oauth2.allowAppOnly` | `false` | Admits client-credentials callers, which have no groups |
| `authorization.oauth2.allowRoles` | — | Required when `allowAppOnly` is true |
| `…oauth2Client[].groupsSource` | `msgraph` | `jwt` reads the `groups` claim instead, with the overage caveat above |
| `authorization.oauth2.graph.flow` | `app_permission` | `obo` exchanges the caller's token instead; see above |
| `authorization.oauth2.graph.cacheTTL` | `10m` | Also the delay before a group removal takes effect |
| `…graph.negativeCacheTTL` | `30s` | Stops a Graph outage becoming a request storm; a `Retry-After` extends it. Also how long an unresolvable `name:` alias is remembered |
| `…graph.failureMode` | `closed` | `closed` refuses with `503`; `stale` serves an expired entry for up to `staleGracePeriod` |
| `…graph.maxCacheEntries` | `10000` | LRU bound, so a large tenant cannot exhaust memory |
| `…graph.credential.tenantID` | first application's tenant | the only directory this credential can read |
| `server.maxGroupsHeaderBytes` | `2048` | Caps the forwarded `X-Mcp-Groups` header |
| `policy.defaultEffect` | `deny` | |

Only credentials come from the environment: `GRAPH_CLIENT_SECRET` (named by
`clientSecretEnv`) and `AZURE_FEDERATED_TOKEN_FILE`.

### Group references

Entries in `allowGroups` and in a rule's `groups` are **group object ids**, or a
`name:<displayName>` alias.

```yaml
allowGroups:
  - 7d2f1a3e-0b44-4a1b-9c3e-5f6a7b8c9d0e   # object id
  - name:mcp-operators                      # display-name alias
```

Both forms work in `allowGroups` and in a rule's `groups`, under either Graph
flow.

**An alias is never matched as a name.** It is looked up in the directory, once,
and from then on it stands for the single group object id it resolved to. A
caller is given the `name:mcp-operators` label only because they hold that
object id. So in a tenant with self-service group creation — the default — a
user who creates their own group called `mcp-operators` gains nothing, because
their group has a different object id. Authorization still rests entirely on
object ids.

The lookup happens on the **first request that needs it**, not at startup, which
is what allows aliases to work under `graph.flow: obo`: at startup there is no
caller token to exchange. The result is cached for the life of the process, so a
display name reassigned to a different group in the directory takes effect only
on restart. Consequences worth knowing:

- A name that is unknown, or that matches more than one group, fails the request
  **closed** rather than silently not matching. That is a fault in this server's
  configuration, so it is a `500` naming the group at fault — not a `503`, which
  would have clients retry a mistake that retrying cannot fix. It is logged once
  at `ERROR`, and the failed lookup is cached for `graph.negativeCacheTTL` so a
  single typo cannot turn into sustained load against Graph. Creating the
  missing group takes effect within that window, without a restart.
  `--check-config` cannot catch this; it has no directory.
- A directory that is merely unreachable stays a retryable `503`.

**Under `graph.flow: obo`, "no such group" is weaker than it sounds.** Delegated
permissions are the intersection of the application's grant and the signed-in
user's own privileges, so Graph returns only the groups *that caller* may see.
An empty result cannot distinguish a misspelled name from a group the user is
not allowed to see — which is routine for guest accounts and in tenants that
restrict directory reads. The proxy therefore says so rather than asserting the
group does not exist, and caches the miss **per caller**, so one restricted user
cannot deny the group to everyone else.

Two consequences follow, and both argue for object ids under `obo`:

- A successful resolution is cached for *all* callers, because the object id a
  name maps to is a fact about the directory. It is logged at `INFO`
  (`resolved a group display name to an object id`) — worth checking once, since
  it is the one decision a caller-scoped lookup does not otherwise expose.
- If two groups share the display name and a caller can see only one of them,
  the proxy cannot detect the ambiguity and will resolve to the one it was
  shown. In a tenant with self-service group creation that is a path to the
  wrong group being cached. An object id is immune.
- The lookup calls `GET /v1.0/groups`, a directory-wide read that is broader
  than reading one user's membership. It needs `Group.Read.All` or
  `GroupMember.Read.All` — as an *application* permission under
  `app_permission`, or as a *delegated* one under `obo`.
- Object ids need none of this: they are matched against the caller's own
  membership and cost no extra call.

Prefer object ids where a config file's readability does not suffer. A bare
display name without the `name:` prefix is always rejected, as are two aliases
differing only in case, which group matching cannot tell apart.

## Authorization policy

Two layers, both required to pass:

1. **`allowGroups`** — a coarse gate on reaching the MCP server at all.
2. **`policy.rules`** — fine-grained, per-method and per-tool.

Rules are evaluated **in file order, first match wins**. Ordering is explicit, so
a `deny` placed above the allows cannot be overtaken, and the decision never
depends on the order in which the directory happened to return a user's groups.

```yaml
rules:
  # Denied first, so no later allow can reach these tools.
  - name: block-destructive-tools
    effect: deny
    methods: ["tools/call"]
    tools: ["delete_*", "drain_node", "bash_*"]

  # The handshake carries no privilege; without it a session cannot start.
  - name: protocol-handshake
    effect: allow
    methods: ["initialize", "initialized", "ping", "notifications/*"]

  - name: readers
    effect: allow
    methods: ["tools/list", "resources/*", "prompts/*"]
    groups: ["6f0d8f0e-0000-0000-0000-000000000002"]

  # App-only callers match on roles; they have no groups.
  - name: pipeline
    effect: allow
    appOnly: true
    methods: ["tools/call"]
    tools: ["kubectl_get*"]
    roles: ["Mcp.Invoke.All"]
```

`methods` and `tools` accept `*` wildcards. A rule with no `groups` matches any
caller who already passed `allowGroups`. A batch request is allowed only if
**every** call in it is allowed, so a denied method cannot be smuggled in
alongside a permitted one.

Rules are checked at startup: `appOnly` rules cannot carry `groups`, non-`appOnly`
rules cannot carry `roles`, names must be unique, and every rule needs at least
one method pattern.

## What the upstream MCP server receives

The access token is **never** forwarded. The proxy injects:

| Header | Content |
|---|---|
| `X-Mcp-User` | login from `userLoginClaim`, after `userLoginTransformer` |
| `X-Mcp-Subject` | `sub` |
| `X-Mcp-User-Id` | `oid` — the stable user identifier, unlike the login |
| `X-Mcp-Tenant-Id` | `tid` |
| `X-Mcp-Client-Id` | `azp` / `appid` |
| `X-Mcp-Roles` | app roles from the token, for app-only callers |
| `X-Mcp-Groups` | space-separated group object ids, capped at `maxGroupsHeaderBytes` |
| `X-Mcp-Groups-Truncated` | `true` when the list did not fit |
| `X-Mcp-Matched-Group` | the group that satisfied `allowGroups`; always present, even when truncated |
| `X-Mcp-App-Only` | `true` for client-credentials callers |

Any inbound `X-Mcp-*` or `X-Forwarded-*` header is stripped first, so a client
cannot assert its own identity.

The cap on `X-Mcp-Groups` is not cosmetic. Transitive membership in a large
tenant runs to hundreds of groups, which exceeds the 4–8 KiB header buffers of a
typical ingress controller and surfaces as a `502` that is hard to trace.
`X-Mcp-Matched-Group` is therefore exempt from truncation.

## Operational behaviour

**Revocation lag.** Removing a user from a group takes effect after at most
`cacheTTL` (default 10 minutes), and after `cacheTTL + staleGracePeriod` if
`failureMode: stale`. Access token lifetime is a second, independent window.
Lower `cacheTTL` for faster revocation at the cost of directory traffic.

**Graph outage.** With `failureMode: closed` the proxy answers `503` with
`error="server_error"` — retryable, deliberately not `403`, so a client backs off
instead of treating the failure as a permanent denial. With `failureMode: stale`
it serves the last known membership for up to `staleGracePeriod`.

**Throttling.** Graph `429` responses are honoured: `Retry-After` extends the
negative cache entry rather than being retried immediately.

**Request coalescing.** Concurrent lookups for the same user collapse into one
Graph call, so a burst of requests after a cache expiry does not fan out.

**Readiness.** `/readyz` fails until every configured tenant's JWKS has been
fetched, so a pod never serves before it can validate a token.

## Deploy

### Helm

```bash
helm upgrade --install platform-mcp deploy/helm/mcp-oauth-proxy \
  -n mcp --create-namespace \
  -f examples/values-production.yaml
```

The chart renders the YAML configuration into a ConfigMap, annotates the
ServiceAccount for workload identity, adds the `azure.workload.identity/use`
pod label, and rolls the Deployment on a config change via a `checksum/config`
annotation. The chart refuses to render if `allowGroups` is empty, if
`allowAppOnly` is set without `allowRoles`, or if the Graph credential is
incomplete.

### Plain manifests

```bash
kubectl apply -f deploy/manifests/mcp-server.yaml
```

### Hardening checklist

- The MCP server binds `127.0.0.1` only; the Service never publishes its port.
- `resource` must be the **public** URL clients use, not the Service DNS name.
- Keep `defaultEffect: deny`.
- Keep `allowGroups` populated with object ids.
- Allow egress to `login.microsoftonline.com:443` **and** `graph.microsoft.com:443`;
  without the latter the proxy fails closed and answers every request with `503`.
- Prefer workload identity federation over a client secret.
- Disable ingress response buffering, or SSE will stall.
- Set `allowedOrigins` only for browser-based clients.

### stdio-only MCP servers

A server that speaks stdio has no HTTP endpoint to protect. Put a bridge such as
`mcp-proxy` in the pod to expose it on `127.0.0.1:3000`, then front that.

## Client configuration

Compliant clients need only the URL; they discover everything else:

```bash
curl -i https://mcp.example.com/mcp
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", ...
```

```json
{
  "mcpServers": {
    "platform": { "url": "https://mcp.example.com/mcp" }
  }
}
```

Scripted callers request a token explicitly:

```bash
TOKEN=$(az account get-access-token \
  --scope api://22222222-2222-2222-2222-222222222222/.default \
  --query accessToken -o tsv)
curl -H "Authorization: Bearer $TOKEN" https://mcp.example.com/mcp
```

### Clients that insist on dynamic client registration

Entra ID has no RFC 7591 endpoint. Set
`authorization.oauth2.dynamicClientRegistration.enabled: true` with a
pre-provisioned public `staticClientID`; the shim returns that id from
`/register` so the client's registration step succeeds.

## Observability

Prometheus metrics on `:9090/metrics`:

| Metric | Meaning |
|---|---|
| `mcp_proxy_requests_total{method,outcome,code}` | HTTP requests by outcome |
| `mcp_proxy_auth_failures_total{reason}` | tokens rejected during authentication |
| `mcp_proxy_policy_denials_total{mcp_method,rule}` | requests refused by the policy, and by which rule |
| `mcp_proxy_graph_lookups_total{result}` | directory lookups by cache outcome: `hit`, `miss`, `stale`, `error` |
| `mcp_proxy_request_duration_seconds{outcome}` | end-to-end latency, including the MCP server |
| `mcp_proxy_inflight_requests` | requests in flight, including open SSE streams |

A rising `result="miss"` rate means `cacheTTL` is short relative to traffic;
`result="error"` means the directory is failing and, with `failureMode: closed`,
that callers are being answered `503`.

Every decision is logged once with the subject, user id, matched group, method,
tool and rule name — enough to answer "who called what, and why was it allowed".

**Every log record carries the build's `version` field**, and the first record
written is a startup banner naming the version, the Go toolchain it was built
with, and the target platform:

```
level=INFO msg="mcp-oauth-proxy starting" version=0.1.0 go=go1.25.1 platform=linux/amd64
level=INFO msg="mcp-oauth-proxy ready" version=0.1.0 resource=https://mcp.example.com/mcp upstream=http://127.0.0.1:3000 tenants=1 listenAddr=:8080 metricsAddr=:9090
```

The banner is emitted before anything that can fail, so a proxy that dies while
priming Entra ID's signing keys still reports which build it was. `ready` is
written only once the listeners are up, which makes the two lines a reliable
pair to assert on in a rollout check. Errors that happen before the logger
exists — a malformed or missing configuration file — are printed to stderr with
the version prefixed (`mcp-oauth-proxy 0.1.0: read configuration: ...`), so a
crash-looping container names its version on every path. `--version` prints it
alone, for scripting.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401 invalid_token`, `aud` mismatch | Client requested a bare scope; it must use `api://<app-id>/<scope>` |
| `403 insufficient_scope` | Caller is not in a group any rule grants; check `X-Mcp-Groups` in the audit log |
| `403` immediately after login | Caller passed authentication but is in none of `allowGroups` |
| `503 server_error` | Graph is unreachable or egress to `graph.microsoft.com:443` is blocked |
| `oauth2Client[N].tenantID differs from …graph.credential.tenantID` | One app-only credential reads one directory; set `groupsSource: jwt` for the other tenant |
| Requests fail `500`, "the group ... matches more than one group" | Two groups share the display name used in a `name:` alias; use the object id |
| Requests fail `500`, "no group with this display name exists" | A `name:` alias does not match any group — check spelling and exact case. Names are resolved on first use, so this surfaces on the first request rather than at startup |
| Requests fail `500`, "not visible to the calling user" | Under `obo` the lookup uses the caller's own rights. Either the name is wrong, or that user cannot see the group (common for guests, and where the tenant restricts directory reads). Use the object id to settle it |
| `resolve group "...": graph returned HTTP 403: Authorization_RequestDenied` | A `name:` alias calls `GET /v1.0/groups`, a directory-wide read that is broader than reading one user's membership. Check for `GroupMember.Read.All` or `Group.Read.All` with admin consent: in the `roles` claim of the proxy's token under `app_permission`, or the caller's `scp` claim under `obo`. Using the group's object id skips the call entirely |
| `roles` claim empty, every Graph call `403` | The permissions are **Delegated**, which client credentials ignore. Either have them re-granted as Application permissions, or switch to `graph.flow: obo`, which consumes delegated permissions |
| `AADSTS50013` / `invalid_grant` on the exchange | Under `obo`, the inbound token's `aud` must be the application performing the exchange. Check `graph.credential.clientID` matches the API's `clientID` |
| Startup fails with "not resolved to an object id" | A rule references a group missing from the directory |
| `502` from the ingress, proxy logs `200` | Group header too large; lower `maxGroupsHeaderBytes` |
| Group removal has no effect | Within `cacheTTL`; lower it or restart the pod |
| SSE stalls | Ingress buffering is on |

## Testing a configuration locally

You can exercise a configuration on a workstation without a cluster. There are
two levels.

### 1. Validate it offline

```bash
make build
./bin/mcp-oauth-proxy --config ./config.yaml --check-config
```

This parses the file, rejects unknown keys, applies defaults, and compiles the
policy rules — all without network access. Credentials are resolved at parse
time, so the credential's environment variable must be set even for a check; any
value will do:

```bash
GRAPH_CLIENT_SECRET=dummy ./bin/mcp-oauth-proxy --config ./config.yaml --check-config
```

### 2. Run it against a real token

Three adjustments are needed for a copy of the config that runs off-cluster:

- **`graph.credential.type: federated` will not work.** There is no projected
  service account token outside the cluster. Use `type: secret` with
  `clientSecretEnv`, or set `groupsSource: jwt` to skip Graph entirely.
- **`policy.rulesFile`** must exist locally. A relative path resolves against
  the directory containing the config file, not the working directory, so a
  bare filename alongside it is usually what you want.
- **`tenantID` must be a real tenant.** The proxy fetches the OIDC discovery
  document and primes the signing keys at startup, so it exits immediately if
  the tenant does not resolve. That requires egress to
  `login.microsoftonline.com`, and to `graph.microsoft.com` if you are using
  `groupsSource: msgraph`.

Start the stub upstream, which stands in for the MCP server and prints the
identity headers the proxy attached:

```bash
make dev-upstream        # listens on 127.0.0.1:3000
```

Then run the proxy and call it with an access token your tenant issued for this
API:

```bash
GRAPH_CLIENT_SECRET=... ./bin/mcp-oauth-proxy --config ./config.local.yaml

curl -i -X POST http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}'
```

Reading the result:

| Response | Meaning |
|---|---|
| `200` plus a line in the stub's output | Allowed. The stub prints `X-Mcp-User`, `X-Mcp-Groups` and `X-Mcp-Matched-Group`, which is the resolved identity the policy acted on |
| `401` + `WWW-Authenticate` | The token was rejected. `error_description` says which check failed — audience, issuer, expiry, signature |
| `403` | Authenticated, but no rule allowed the method, or the caller is not in `allowGroups` |
| `503` | Group membership could not be resolved; Graph is unreachable or the credential is wrong |

The metadata endpoints need no token and are the quickest confirmation that the
process is up and reading the file you think it is:

```bash
curl -s http://127.0.0.1:8080/.well-known/oauth-protected-resource
curl -s http://127.0.0.1:9090/metrics | grep mcp_proxy_auth_failures_total
```

`mcp_proxy_auth_failures_total{reason=...}` and the proxy's own JSON logs are
usually faster than guessing from the status code alone.

## Development

```bash
make test           # go test -race ./...
make lint           # gofmt + go vet
make build
make image
make dev-upstream   # stub MCP server for local testing
```

### Versioning and the image

The release version lives in the `VERSION` file at the repository root, and it
is the single source of truth. `version.go` embeds it with `go:embed`, so even
`go run ./cmd/mcp-oauth-proxy --version` reports the real version rather than a
placeholder; `make build`, `make image` and the `Dockerfile` additionally stamp
it with `-ldflags -X main.version`. Either way `mcp-oauth-proxy --version` and
the `version` field on every log record match the artifact.

A linker-stamped value wins over the embedded one, so a pipeline can append a
commit or release-candidate suffix without editing the file:

```bash
docker build --build-arg VERSION=1.4.0-rc1 -t mcp-oauth-proxy:1.4.0-rc1 .
```

`version.go` has to live at the root next to `VERSION` because `go:embed`
cannot read outside its own package directory.

Bump `VERSION` and the chart's `appVersion` together — `image.tag` defaults to
`.Chart.AppVersion`.

The image is built on `chainguard/wolfi-base` and ships as a `scratch` image
holding exactly two files: the statically linked binary and the public CA
bundle, which the proxy needs to verify Entra ID's OIDC metadata and JWKS
endpoints, Microsoft Graph, and any https upstream. There is no shell, no
package manager, and no libc, so the usual `kubectl exec` debugging is not
available — use the logs and `/metrics`. It runs as uid/gid `65532`; the user is
numeric precisely because `scratch` has no `/etc/passwd`.

## Limitations

- Entra ID only; other issuers would need their own directory integration.
- Under `graph.flow: app_permission`, one Graph credential per deployment.
  Because it is an app-only credential it can only read its own tenant, so a
  second trusted tenant must use `groupsSource: jwt` or `graph.flow: obo`. The
  proxy refuses to start on a configuration that would have failed silently at
  request time.
- Under `graph.flow: obo`, app-only callers cannot be authorized by group,
  because there is no user to act on behalf of.
- Group membership is cached, so revocation is not instantaneous.
- The proxy authorizes MCP methods and tool names, not tool *arguments*; a tool
  that takes a free-form command is only as safe as the server implementing it.
- Microsoft Graph becomes a runtime dependency of every first request for a user.
