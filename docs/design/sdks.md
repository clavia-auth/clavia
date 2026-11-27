# Design: SDKs for Next.js and PHP applications

**Status:** proposed · **Date:** 2026-11-28 · **Issue:** clavia-auth/clavia#224 ·
**Specifications:** OpenID Connect Core 1.0 (§3.1, §5.3), OpenID Connect Discovery 1.0,
OpenID Connect RP-Initiated Logout 1.0, OpenID Connect Back-Channel Logout 1.0 (§2.4–§2.8),
RFC 6749 §10.4, RFC 7636, RFC 9126 (PAR), RFC 9207 (`iss` in the authorization response),
RFC 9449 (DPoP), RFC 9068 (JWT access tokens), RFC 7662 (introspection), RFC 7009
(revocation), RFC 6750 §3, RFC 9470 (step-up), RFC 9728 (protected resource metadata),
RFC 9457 (problem details), OAuth 2.0 for Browser-Based Applications (the backend for frontend),
RFC 9700 (OAuth security best current practice)

## 1. Summary

An application that signs people in with Clavia writes its own OpenID Connect client today: the
code flow with PKCE, a session, refresh, sign-out, back-channel logout. An API writes its own
token checks. A backend calling the Management API writes its own client from the OpenAPI
document. Each of them can get a rule wrong, and one of this server's rules makes the obvious
client wrong: **a refresh token is spent on every use, with no grace period** (CLAUDE.md,
*Refresh tokens*). A Next.js application renders its server components in parallel; two of them
refreshing the same token at once is a replay, and the whole family is revoked. The person is
signed out at random, under load, in production only.

The dashboard already solved this for itself (clavia-dashboard, `src/core/auth`): a backend for
frontend on `oauth4webapi`, the session on the server behind an opaque handle, refresh under a
lock held across processes, back-channel logout, step-up. This design turns that into SDKs, and
adds the PHP side the same way.

Auth0's open-source libraries are the bar for ergonomics: configure from a few settings, mount
the routes in one line, ask `getSession()` and `getAccessToken()` anywhere on the server. They
are not the model for every trade-off. Where Auth0 chose convenience over a rule this server
holds (a stateless cookie session that can refresh, an access token handed to the browser, a
sign-out on `GET`), the SDK keeps the rule, and says why in §2.

### Goals

- **`@clavia/nextjs`**: sign-in for a Next.js App Router application as a backend for frontend.
  Routes in one line, `session()` and `accessToken()` on the server, refresh serialised across
  processes, back-channel logout, RP-initiated logout, step-up (RFC 9470), PAR, opt-in DPoP.
- **`@clavia/api`**: access-token checks for any JavaScript server that speaks the Fetch API's
  `Request` (a Next.js route handler, Hono, Bun): JWT access tokens (RFC 9068), opaque ones by
  introspection (RFC 7662), the DPoP binding (RFC 9449 §7), RFC 6750 and RFC 9470 challenges,
  RFC 9728 metadata.
- **`@clavia/management`**: a typed Management API client generated from
  `docs/openapi/management-api.yaml`, with its own client-credentials token.
- **`clavia/sdk`** (PHP): the same three on PSR-7, PSR-15, PSR-17 and PSR-18, framework-free:
  `Clavia\Sdk\Application` (sign-in), `Clavia\Sdk\Api` (token checks), `Clavia\Sdk\Management`.
- **Standards only.** Each SDK configures itself from the issuer's discovery document and uses
  nothing only Clavia has, so it is certified with the OpenID Foundation's relying-party tests
  and works with any provider that holds the same rules.
- **No change to the server.** Everything the SDKs need is built; a need found while building
  one is a ticket in this repository, not a workaround in the SDK.

### Not in scope

- **Framework packages** (Laravel, Symfony, Express). The PHP SDK is PSR-only; a framework
  package is a thin layer someone can add later without changing it.
- **Browser and mobile SDKs** (a single-page application holding tokens, React Native, Swift,
  Kotlin). A browser application uses a backend for frontend, which is what `@clavia/nextjs` is;
  native applications are another design.
- **Several APIs per session.** A Clavia access token names one API (`audience`), and a refresh
  ignores `audience`. A session asks for one API at sign-in; a second API is a later design
  (RFC 8693 token exchange, or a second authorization).
- **What Clavia does not offer**: `private_key_jwt`, CIBA, token exchange, the implicit and
  hybrid flows, account linking from the application. The SDKs grow when the server does.
- **Stateless cookie sessions with refresh** (§2, question 1).

## 2. Decisions

| Topic | Decision | Why (the alternatives rejected) |
|---|---|---|
| Protocol layer (JavaScript) | **`oauth4webapi` and `jose`**, as the dashboard uses them; no protocol code of our own | Both are maintained, certified relying-party code on WebCrypto, with PAR, DPoP and RFC 9207 already. Auth0 writes its own layer (`@auth0/auth0-auth-js`) over the same libraries; one more layer to maintain buys nothing with one framework to serve |
| Protocol layer (PHP) | **Our own, small**, on `web-token/jwt-library` (verification and JWKs only, as the server uses it) and PSR-18, limited to the flows of §5 | There is no maintained PHP relying-party library that does PAR, DPoP, RFC 9207 and back-channel logout: `league/oauth2-client` is OAuth 2.0 only and leaves the ID token to the application; the OpenID Connect ones are unmaintained or incomplete. The server already shows the rules can be written from the RFCs and tested |
| Packages | **Two repositories**, `clavia-auth/clavia-js` (npm workspaces: `@clavia/nextjs`, `@clavia/api`, `@clavia/management`) and `clavia-auth/clavia-php` (one Composer package, `clavia/sdk`, three namespaces) | One repository per language keeps one CI, one release train and one example stack. JavaScript splits into packages because their dependencies differ (Next.js, nothing, `openapi-fetch`); PHP has no such cost, and one package is one version to state |
| Framework-free core (JavaScript) | **Inside `@clavia/nextjs`**, as the dashboard has it (`core/` with ports, `adapters/`), not a published package | Auth0 publishes `@auth0/auth0-server-js` for every framework; we have one. The split is kept in the code, so publishing the core later is a move, not a rewrite |
| Where the session lives | **On the server, in a store** (Redis, or the application's own through a port); the browser holds a 256-bit handle in one cookie, the store keys it by its SHA-256, the record is sealed (AES-256-GCM, the digest as associated data) | Refresh needs one lock per session across processes (next row), and a cookie cannot be locked: two requests carrying the same cookie both refresh. A handle never changes when the tokens do, so a server component, which cannot set a cookie, can still refresh. Auth0's default (the whole session in an encrypted cookie) works only because Auth0 offers a reuse interval; question 1 |
| Refresh | **Serialised per session**: under the store's lock, read the session again, refresh only if it is still due, save, release. A refresh refused (`invalid_grant`) ends the session. Refreshed a minute ahead of `exp` | The server spends a refresh token on every use and revokes the family on replay (RFC 6749 §10.4, RFC 9700 §4.14.2). Re-reading under the lock means the requests that waited take the new tokens instead of spending the old one |
| Tokens and the browser | **Never.** No route hands an access token to the browser; `session()` returns the person and the scopes, never a token; `accessToken()` is server-only (`server-only` import) | The point of a backend for frontend (Browser-Based Apps §6.1). Auth0's `/auth/access-token` route and its client-side `getAccessToken()` put the token where an XSS reads it |
| Client components | **No client package.** A server component reads the session and passes the person down as props | A `useUser()` hook needs a profile route the browser polls: one more endpoint, one more cache to keep fresh, for what a server component already has |
| Authorization request | **PAR whenever discovery names the endpoint**, then the authorization URL carries `client_id` and `request_uri` alone. PKCE S256, `state`, `nonce` always; RFC 9207's `iss` checked when `authorization_response_iss_parameter_supported` | The request's parameters never reach the address bar, and a client registered with `require_pushed_authorization_requests` works with no setting |
| Client authentication | `client_secret_basic` (the default) or `client_secret_post`, as registered. No public client | A server keeps a secret. What Clavia supports (`ClientAuthMethod`) |
| Who the person is | **Userinfo, once, at sign-in**, checked against the ID token's `sub` (OIDC Core §5.3.2) | Clavia's ID token carries only protocol claims; what a scope releases is served by userinfo alone (CLAUDE.md, *OpenID Connect*). Asking userinfo works with every provider |
| Return path | A **local path** only (`/` then not `/` or `\`, no control character), validated when the sign-in starts, held in the sign-in attempt, never in a URL after that | The server's own rule (`LocalPath`): rejected, never repaired. An open redirect after sign-in is the classic phishing aid |
| Sign-in attempt | In the store, claimed once (`take()`), for ten minutes, paired with a `__Host-clavia_tx` cookie compared in constant time | Login CSRF (RFC 9700 §4.7): a callback that reaches another browser is refused before any code is redeemed. A claimed attempt cannot be replayed |
| Cookies | `__Host-` prefix (`Secure`, `Path=/`, no `Domain`), `HttpOnly`, `SameSite=Lax`. Over `http://localhost` in development, the same without the prefix and `Secure`; plain http anywhere else is refused at start | `__Host-` makes the cookie impossible to set from a sibling subdomain (session fixation) |
| Sign-out | **`POST` only**, from the application's own form, with an `Origin` check; then RP-initiated logout with `id_token_hint` and the refresh token revoked (RFC 7009), best effort | A `GET` sign-out can be fired by any image tag. The server's own pages sign out by `POST` for the same reason. Auth0's `/auth/logout` is a `GET` |
| Back-channel logout | A route verifying the logout token (§7) and ending every session of its `sid`, or of its `sub` when there is no `sid` | The server sends one whenever a session ends there: an operator, a deactivation, a SCIM deprovisioning. Without it a deprovisioned person stays signed in to the application |
| Step-up | `accessToken()` and the API helpers raise **`StepUpRequired`** with the `acr_values` an API's `insufficient_user_authentication` challenge names (RFC 9470 §3); the sign-in route takes `acr_values` | What the dashboard does against the Management API's `mfa_policy`. The person adds a factor at Clavia instead of signing in again |
| DPoP (application) | **Opt-in** (`dpop: true`): one ES256 key per session, made at sign-in, sealed in the session record; server nonces (`use_dpop_nonce`) handled | Clavia binds a confidential client's access tokens, not its refresh family (RFC 9449 §5), so the key must outlive any one process: it lives with the session. Off by default because a client registered with `dpop_bound_access_tokens` is the one that needs it, and the server says so (`invalid_dpop_proof`) |
| Token checks (API) | **The key from the JWKS by `kid`, the algorithm the key's, never the header's**; `typ` `at+jwt` required; `iss` exact; `aud` **before any scope**; `exp` with a 30-second leeway. Opaque tokens by introspection, not cached unless asked (`cacheFor`, at most 60 s) | The server's own verifier rules (`JoseSignatureVerifier`, *Security invariants*). Caching introspection delays revocation, so it is the API's explicit choice |
| DPoP (API) | Verified as Clavia verifies its own resources (RFC 9449 §7, `CheckSenderConstraint`): `htu` from the **configured public URL**, never `Host`; `ath`; the key's thumbprint against `cnf.jkt`; `jti` once per key through a replay-cache port. A bound token as `Bearer` is refused | The `Host` header is the caller's; a proof checked against it proves nothing |
| Management API client | **Generated from the document of a Clavia release**: TypeScript by `openapi-typescript` and `openapi-fetch` (the dashboard's own), PHP by a small generator in the repository (one method per `operationId`, Psalm array shapes); CI fails when the generated code differs from the document | The document is the contract (CLAUDE.md, *Management API*). Hand-written resources drift; a generic generator (OpenAPI Generator) brings a JVM and code nobody would write |
| Management token | Client credentials for the Management API's `audience`, cached until a minute before `exp`, one request in flight per process; a `401` takes a new token once | A machine token has no refresh token. A second fetch at once is waste, not a replay, so a process-local guard is enough |
| Errors | Typed: `SignInRefused` with a reason (`unknown_attempt`, `access_denied`, `provider_error`, `unreachable`), `StepUpRequired`, `TokenRefused` (with the challenge to send), `ManagementError` (the RFC 9457 document: `status`, `type`, `title`, `errors[]`). A provider's `error_description` never reaches a page | The server's rule for external sign-in: a provider's words never reach the page. The application decides what to show; the SDK's default page says nothing more than "sign-in failed" |
| Configuration | Explicit options, each with an environment default the server never reads: `CLAVIA_ISSUER`, `CLAVIA_CLIENT_ID`, `CLAVIA_CLIENT_SECRET`, `CLAVIA_APP_URL`, `CLAVIA_SESSION_KEY` (32 bytes, base64url) | The dashboard's names. The issuer is the single source of every endpoint (Discovery §4); nothing else is configured by URL |
| Runtimes | `@clavia/nextjs`: Node.js, Next.js 16 and later (`proxy.ts`). `@clavia/api`, `@clavia/management`: any runtime with `fetch` and WebCrypto. PHP 8.3 and later | Next.js 16's proxy runs on Node.js, and a Redis store needs it; WebCrypto everywhere keeps the edge open later. PHP 8.3 is the oldest release with security support through 2027 |
| Versions | Semantic versions of their own; each release states the oldest Clavia release it is tested against, and CI runs both that release and `edge` | An SDK and the server ship apart; the matrix says when an SDK starts needing a newer server |

## 3. Settings

No `CLAVIA_*` setting on the server. The SDKs' options:

| Option (environment default) | Default | Range or rule |
|---|---|---|
| `issuer` (`CLAVIA_ISSUER`) | required | https; `http://localhost` and `127.0.0.1` in development only |
| `clientId`, `clientSecret` (`CLAVIA_CLIENT_ID`, `CLAVIA_CLIENT_SECRET`) | required | |
| `appUrl` (`CLAVIA_APP_URL`) | required | the application's public origin; https but in development |
| `sessionKey` (`CLAVIA_SESSION_KEY`) | required | 32 bytes, base64url; a list to rotate (the first seals, all open) |
| `scopes` | `openid profile email` | `openid` always added |
| `audience` | none | the one API the session's access token is for |
| `session.absoluteLifetime` | 7 days | 5 minutes to 90 days |
| `session.idleLifetime` | 1 day | 1 minute to `absoluteLifetime` |
| `routes.base` | `/auth` | a local path |
| `dpop` | false | |
| `api.introspection.cacheFor` | 0 s | 0 to 60 s |
| `api.leeway` | 30 s | 0 to 120 s |

A session never outlives its refresh family: the server's `CLAVIA_REFRESH_TOKEN_ABSOLUTE_LIFETIME`
ends it first when it is shorter.

## 4. Model

The same shape in both languages: a core that holds the rules and speaks through ports, and
adapters. Names below are TypeScript; PHP uses the same names as classes and interfaces.

**Values.** `TokenSet` (access token, its expiry, refresh token or null, ID token, scopes, DPoP
key or null), `Person` (`sub`, `name`, `email`, `email_verified`, `picture`), `Session` (person,
`sid`, tokens, `createdAt`, `expiresAt`, `lastSeenAt`, the application's own `data`, at most
4 KiB of JSON), `SignInAttempt` (`state`, `nonce`, verifier, `returnTo`, `acrValues`, DPoP key),
`ReturnTo` (the local path), `AccessToken` (for an API: `sub` or null for a machine, `client_id`,
scopes, `auth_time`, `acr`, `cnf.jkt`, every other claim as read).

**Ports.**

```ts
interface SessionStore {
  create(session: Sealed, ttl: number, index: { sid: string | null; sub: string }): Promise<Handle>;
  read(handle: Handle): Promise<Sealed | null>;
  save(handle: Handle, session: Sealed, ttl: number): Promise<void>;
  destroy(handle: Handle): Promise<Sealed | null>;
  destroyBySid(sid: string): Promise<number>;
  destroyBySubject(sub: string): Promise<number>;
  /** Run `work` while no other process holds this handle's lock. */
  exclusively<T>(handle: Handle, work: () => Promise<T>): Promise<T>;
}
interface AttemptStore { put(a: Sealed, state: string, ttl: number): Promise<void>; take(state: string): Promise<Sealed | null> }
interface ReplayCache { /** True the first time; false for a value already seen within `ttl`. */ claim(key: string, ttl: number): Promise<boolean> }
interface Clock { now(): number }
```

The store sees sealed records and handle digests only: a leaked store opens no session and
names nobody but by `sub`. Adapters: Redis (`ioredis`; ext-redis in PHP: `SET NX PX` with a
token, released by a script that checks it, a 10-second lease), and in memory for tests and a
single development process (refused when `NODE_ENV` or the PHP SDK's `environment` is
`production`). Each store ships with its **contract** (`SessionStoreContract`), published with
the package, so an application's own store (a database, Memcached) runs the same tests.

**Core.** `Authentication` (begin and complete a sign-in, `session()`, `accessToken()`, sign
out, back-channel logout), `Provider` (the protocol, on `oauth4webapi` or the PHP core: discovery
cached for its `max-age`, at most a day; JWKS fetched again on an unknown `kid`, at most once a
minute), `TokenVerifier` (§2's API rules), `ManagementClient`.

Nothing in the core reads a request, a cookie or the environment: the Next.js and PSR-15 layers
translate, as the server's primary adapters do.

## 5. Flows

### 5.1 Sign-in

1. `GET {base}/sign-in?return_to=…&acr_values=…`. `return_to` that is not a local path is
   refused (`400`); `acr_values` is kept only if every value is in discovery's
   `acr_values_supported`.
2. Discovery is read (cached). An `http` endpoint, or an `issuer` that differs from the one
   configured, is `SignInRefused('provider_error')` (Discovery §4.3).
3. A state, a nonce and a verifier are made; with DPoP, a key. The attempt is put in the store
   for ten minutes, and `__Host-clavia_tx` is set to the state.
4. With PAR, the request is pushed (with a DPoP proof when on); the browser is sent `303` to the
   authorization endpoint with `client_id` and `request_uri`. Without, `303` with the parameters.
5. `GET {base}/callback`. The `state` is compared with the cookie in constant time, then the
   attempt is taken; either failing is `unknown_attempt`, nothing redeemed. The cookie is
   deleted whatever happens.
6. `iss` is checked (RFC 9207) when the provider advertises it; `error=access_denied` is
   `access_denied`; any other error `provider_error` (logged by code, never description).
7. The code is redeemed with the verifier (and a proof). The ID token is checked: signature by
   the JWKS, `iss`, `aud` containing the client, `azp` when several audiences, `exp`, `iat`,
   `nonce` equal to the attempt's (OIDC Core §3.1.3.7).
8. Userinfo is asked with the access token; its `sub` must equal the ID token's.
9. The application's `onSignedIn(person, claims)` may return its `data`, or refuse.
10. The session is created: a new handle (never one the browser brought), sealed, indexed by
    `sid` and `sub`; `__Host-clavia_session` set; `303` to `returnTo`.

### 5.2 Using the session

`session()` reads the handle, opens the record (a record that does not open is no session), ends
it past `expiresAt` or idle past `idleLifetime`, writes `lastSeenAt` back at most once a minute,
and returns the person, the scopes and `data`. `accessToken()` does the same and, within a minute
of the access token's expiry, refreshes under `exclusively()`: read again; still due? refresh;
`invalid_grant` ends the session (`null`, so the application sends the person to sign in);
any other failure throws (`provider_error` or `unreachable`) and keeps the session, since the
refresh token was not spent. The handle never changes.

### 5.3 Sign-out

`POST {base}/sign-out`. An `Origin` that is not `appUrl`'s is `403`. The session is destroyed
first; its refresh token revoked, best effort; then `303` to the end-session endpoint with
`id_token_hint`, `post_logout_redirect_uri` (`appUrl` + `signedOutPath`, which must be registered)
and a `state`. No session: `303` to `signedOutPath`.

### 5.4 Back-channel logout

`POST {base}/backchannel-logout`, `application/x-www-form-urlencoded`, `logout_token` once. The
token is checked (§7); refused, `400` `invalid_request`. Then every session of its `sid` ends
(or of its `sub` without one), and `200`, `Cache-Control: no-store` (Back-Channel Logout §2.8).

### 5.5 Step-up

An API (the Management API, or one using `@clavia/api`) answers `401` with
`error="insufficient_user_authentication"` and `acr_values`. The helper the application calls
throws `StepUpRequired(acrValues, maxAge?)`; the application sends the browser to
`{base}/sign-in?acr_values=…&return_to=…`. Clavia raises the session with a factor and the new
tokens replace the old in a new session.

### 5.6 An API checking a token

1. Credentials from the `Authorization` header only (RFC 6750 §2.1; the query and the body are
   never read): `Bearer`, or `DPoP` with exactly one `DPoP` header. Anything else is a bare
   challenge.
2. A JWT is verified locally (§2); anything else, or every token when the API is configured
   so, goes to introspection: `active`, then the same `iss` and `aud` checks on what it returns.
3. `aud` is the configured audience, before any scope. Then the scopes the route requires
   (`403` `insufficient_scope`, naming them), then `acr` or `auth_time` when it requires a
   level or a recent sign-in (`401` `insufficient_user_authentication`, RFC 9470 §3).
4. A token bound to a key (`cnf.jkt`) needs `DPoP` and a proof (§2); one without sent as `DPoP`
   is refused too.
5. Every refusal is a `TokenRefused` that renders itself: status, `WWW-Authenticate` (`Bearer`
   or `DPoP` with `algs`, `error`, `scope`, `acr_values`, `resource_metadata`), `no-store`.

### 5.7 The Management API

`createManagementClient({ issuer, baseUrl, audience, clientId, clientSecret })` takes the
Management API's URL (`https://management.{domain}/api/v1`) and audience as given, never worked
out from the issuer (an operator can rename the audience, `CLAVIA_MANAGEMENT_API_IDENTIFIER`;
the default is `https://management.{domain}/api/v1/`, with its slash), gets a token by client
credentials, and calls the operations by their `operationId`: `client.users.create({...})` in
TypeScript, `$client->users()->create([...])` in PHP. A problem document is a `ManagementError`;
a `429` carries its `Retry-After`; nothing is retried but a `401` on an expired token, once.

## 6. Interfaces

**`@clavia/nextjs`**

```ts
// lib/clavia.ts
export const clavia = createClavia({ store: redisStore(redis), audience: "https://reports.example.com" });

// app/auth/[action]/route.ts: sign-in, callback, sign-out, backchannel-logout
export const { GET, POST } = clavia.routes();

// proxy.ts (optional): a browser without a session cookie is sent to sign in; a shortcut only
export const proxy = clavia.proxy({ public: [/^\/$/, /^\/pricing/] });

// a server component, a route handler, a server action
const session = await clavia.session();            // { person, scopes, data } | null
const session = await clavia.requireSession();     // redirects to sign in
const token = await clavia.accessToken();          // string | null; throws StepUpRequired
const response = await clavia.fetch(url, init);    // the token attached, DPoP when on
```

**`@clavia/api`**

```ts
const verifier = createVerifier({ issuer, audience, url: "https://reports.example.com" });
const token = await verifier.verify(request, { scopes: ["read:reports"], acr: "mfa" });
// on TokenRefused: return error.response()
export const GET = verifier.metadataRoute(); // /.well-known/oauth-protected-resource (RFC 9728)
```

**`clavia/sdk`** (PHP)

- `Clavia\Sdk\Application\Authentication`: `beginSignIn()`, `completeSignIn()`, `session()`,
  `accessToken()`, `signOut()`, `backChannelLogout()`, each taking a `ServerRequestInterface`
  and returning a `ResponseInterface` or a value.
- `Clavia\Sdk\Application\Routes`, a PSR-15 handler for the four paths; `RequireSession`, a
  PSR-15 middleware adding the session as a request attribute.
- `Clavia\Sdk\Api\RequireAccessToken`, a PSR-15 middleware (audience, scopes, level), adding
  `Clavia\Sdk\Api\AccessToken`; `ProtectedResourceMetadata`, a handler.
- `Clavia\Sdk\Management\ManagementClient`, generated; `ClientCredentials`, its token, cached in
  a PSR-16 cache when one is given.

**The server.** Nothing changes. The end-to-end stack is what the SDKs are tested against:
each repository runs it from `ghcr.io/clavia-auth/clavia:<release>` and `:edge`
(`CLAVIA_E2E_IMAGE`), and registers its example applications through the Management API as the
scenarios do. The last slice links the SDKs from `README.md` and the published guides.

**The dashboard** moves onto `@clavia/nextjs` and `@clavia/management` (slice 5) and deletes its
own `core/auth`: the first user of the SDK is the one it was taken from.

## 7. Security rules

- **A refresh token is presented at most once.** Refresh happens only under the session's lock,
  after reading the session again. *Test*: twenty parallel `accessToken()` calls across two
  processes against the stack make one refresh, and the session survives.
- **No token reaches the browser**: no route returns one, `session()` holds none, the record is
  sealed, and `accessToken()` cannot be imported into a client component.
- **A callback is honoured only by the browser that started it, once**: the state cookie, the
  attempt taken from the store, PKCE S256, the nonce, RFC 9207's `iss`.
- **An ID token is never trusted beyond its checks** (OIDC Core §3.1.3.7): the JWKS key by `kid`,
  the key's algorithm (never `none`, never the header's choice), `iss` exact, `aud`, `azp`,
  `nonce`, `exp`. Userinfo's `sub` equals the ID token's.
- **A logout token is accepted only as Back-Channel Logout §2.6 says**: `typ` `logout+jwt` when
  present, signed by the issuer's JWKS, `iss`, `aud` the client, `iat` within five minutes, the
  `http://schemas.openid.net/event/backchannel-logout` event, a `sid` or a `sub`, no `nonce`, and
  its `jti` claimed once (`ReplayCache`).
- **After sign-in, the browser goes only to a local path**, validated when the sign-in starts.
- **A session is fixed by nobody**: a new handle at every sign-in, `__Host-` cookies, sign-out
  by `POST` with an `Origin` check.
- **A leaked store opens nothing**: handles kept as digests, records sealed with the handle's
  digest as associated data (a record moved to another key does not open).
- **An access token's audience is checked before its scope**, its type is `at+jwt`, its
  algorithm the key's; a DPoP proof's `htu` is the configured URL, never `Host`; a bound token
  is never accepted as a bearer token.
- **A provider's error text never reaches a page**, and nothing logs a token, a code, a secret
  or a proof: errors are logged by kind and code.
- **Secrets stay on the server**: `@clavia/nextjs` and `@clavia/management` import `server-only`;
  the PHP SDK has no browser side.
- **Every outbound call goes to the issuer's endpoints**, over https, following no redirect.

## 8. Tests

- **Unit**, in each repository: the core against in-memory ports and a fake provider; every
  refusal of §5 and §7 with its reason; the ID-token, logout-token, access-token and DPoP checks
  against tokens signed by keys the test holds, attacks included (`alg: none`, a header naming
  another algorithm, a foreign `kid`, a wrong `typ`, an `htu` from `Host`).
- **Contracts**: `SessionStoreContract`, `AttemptStoreContract`, `ReplayCacheContract`, run by the
  in-memory adapters and by the Redis ones against a real Redis; published for applications' own
  stores.
- **End to end** against Clavia's stack (the release the SDK states, and `edge`): an example
  Next.js application and an example PHP application (PSR-15 on PHP's built-in server), driven by
  Playwright: sign in, refresh past an access token's lifetime, the parallel-refresh test above,
  sign out, back-channel logout when an operator ends the session, step-up against an API whose
  `mfa_policy` is `required`, DPoP. An example API with each `@clavia/api` and `Clavia\Sdk\Api`.
- **Conformance**: the OpenID Foundation's relying-party plans (Basic RP, Config RP, and the
  Back-Channel RP logout profile) run nightly in each repository against the suite, as
  `conformance/` does for the server, with a baseline.
- **Generated code**: CI regenerates the Management clients from the stated release's document
  and fails on any difference.

## 9. Slices

Each slice is a pull request in the repository named.

1. **`@clavia/management`** (clavia-js, new). The workspace, its CI and release workflow, the
   generated client, the client-credentials token, `ManagementError`. *Done when* `0.1.0` is
   published from a tag, an end-to-end test against the stack creates and lists a user, and CI
   fails when the client and the document part.
2. **`@clavia/nextjs`: sign-in** (clavia-js). The core and its ports, the Redis and in-memory
   stores with their contracts, sealing, `routes()` (sign-in, callback, sign-out), `session()`,
   `requireSession()`, `accessToken()` with the serialised refresh, PAR, the example application.
   *Done when* the example signs in, survives the parallel-refresh test, and signs out at Clavia.
3. **`@clavia/nextjs`: sessions ended elsewhere and step-up** (clavia-js). Back-channel logout
   with `ReplayCache`, `StepUpRequired`, `acr_values` at sign-in, `proxy()`, `fetch()`. *Done
   when* an operator ending a person's sessions at Clavia ends the application's, and an MFA-only
   API sends the person through a step-up and back.
4. **`@clavia/nextjs`: DPoP** (clavia-js). *Done when* a client registered with
   `dpop_bound_access_tokens` signs in, refreshes and calls userinfo with `dpop: true`.
5. **The dashboard on the SDK** (clavia-dashboard). `@clavia/nextjs` and `@clavia/management`
   replace `src/core/auth`, the identity provider and the generated contract. *Done when* the
   dashboard's Playwright suite passes unchanged and its own sign-in code is gone.
6. **`@clavia/api`** (clavia-js). JWT and introspection, the DPoP binding, the challenges, RFC
   9728 metadata. *Done when* the example API accepts a JWT, an opaque and a DPoP-bound token from
   the stack, and refuses each attack of §8 with the right challenge.
7. **`clavia/sdk`: the core and `Clavia\Sdk\Api`** (clavia-php, new). The repository, its CI and
   Packagist release; discovery, JWKS, the PSR-15 middleware, introspection, DPoP. *Done when*
   the example PHP API passes what slice 6's does.
8. **`clavia/sdk`: `Clavia\Sdk\Application`** (clavia-php). The sign-in flows of §5, the Redis
   store with its contract, the PSR-15 routes and middleware. *Done when* the example PHP
   application passes slices 2 and 3's scenarios.
9. **`clavia/sdk`: `Clavia\Sdk\Management`** (clavia-php). The generator and the client. *Done
   when* it passes slice 1's test, and CI fails when it and the document part.
10. **Conformance and documentation** (both repositories, and this one). The relying-party plans
    nightly with a baseline; a README per package; `README.md` and the published guides here
    linking them, and `CLAUDE.md` naming the repositories. *Done when* both repositories pass
    Basic RP and Config RP, and a newcomer reaches a signed-in example from Clavia's README.

## Open questions

1. **Stateless cookie sessions.** Auth0's default keeps the whole session in an encrypted cookie,
   which needs no store. With no reuse interval on the server, such a session can never refresh
   safely. *Recommendation*: not in the first release. Later, a cookie store allowed only with
   `refresh: false`, for applications that call no API and live by their ID token's session;
   refused at start otherwise. The server keeps its rule.
2. **Names.** The npm scope `@clavia` and the Packagist vendor `clavia` must be claimed before
   slice 1. *Recommendation*: claim both now, under the organisation's accounts.
3. **PHP native sessions.** Many PHP applications keep state in `$_SESSION`. Its file handler
   locks a session across requests, but the Redis handlers do not by default, so the refresh rule
   would hold for some deployments and not others. *Recommendation*: no `$_SESSION` store in the
   first release; the port and its contract let an application write one knowingly.
4. **Licence.** *Recommendation*: BSD-3, as the server, with the same header.
