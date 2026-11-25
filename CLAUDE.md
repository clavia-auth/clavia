# CLAUDE.md

Guidance for working in this repository: what Clavia is, how it is built, how its flows work,
and the rules a change must keep.

Clavia is an open-source OAuth 2.1 / OpenID Connect authorization server, a self-hosted
alternative to Auth0. It provides the OAuth 2.1 flows, interactive sign-in with second factors,
social and enterprise connections, and a Management API. It is written in PHP 8.5 on Mezzio,
with PostgreSQL and Redis, in a strict hexagonal architecture that the build enforces.

**The bar:** the code and the architecture are to be perfectly written and documented.
Conformance to the specifications and documentation of every public API are part of "done".
Write standard, modern PHP: strict types, PSR interfaces, well-maintained libraries used as they
are meant to be used, the platform's own defaults. Choose by what is correct, secure and
maintainable. Only the RFCs and the security invariants below are fixed; everything else is
open to a better design.

## Contents

1. [Working agreements](#working-agreements)
2. [Commands](#commands)
3. [Repository map](#repository-map)
4. [Architecture](#architecture)
5. [Hosts, surfaces and storage](#hosts-surfaces-and-storage)
6. [The domain](#the-domain)
7. [Flows](#flows)
8. [Security invariants](#security-invariants)
9. [Conventions](#conventions)
10. [Testing](#testing)
11. [Recipes](#recipes)
12. [Definition of done](#definition-of-done)
13. [Known issues and decisions](#known-issues-and-decisions)

---

## Working agreements

- **Work goes through the backlog and pull requests.** Claude takes an issue, works on a branch,
  commits, pushes and opens a pull request; the maintainer reviews and merges. Claude never
  merges, approves, or pushes to `main` (a ruleset protects it). The steps are skills in
  `.claude/skills/`: `ticket-pick`, `ticket-work`, `ticket-review`, `ticket-triage`,
  `ticket-design`, `ticket-release`; `CONTRIBUTING.md` describes the board they move issues on.
- **Files the maintainer owns**, changed only on request: `.env.example`, `setup-ssl.sh`,
  the `Makefile` and `.github/workflows/ci.yml`. (`release.yml` is new and ordinary.) Report what they need instead.
- **`php-db/*` is pinned. Never `composer update` it** (see
  [Known issues](#known-issues-and-decisions)).
- **Every PHP file starts with the BSD-3 header in `.docheader`.** `LicenseHeaderTest`
  enforces it.
- **`composer check` is green before anything is proposed.**

## Commands

Everything runs in the `php` container, so the host needs only Docker and mkcert.

| Command | What it does |
|---|---|
| `make up` / `make down` | Start or stop Caddy, PHP-FPM, PostgreSQL (development and test) and Redis |
| `make install` | `composer install` |
| `make migrate` / `make db-status` | Apply pending migrations / list them |
| `make seed` | Development data: user, clients, the Management API, a signing key, the dashboard client (`clavia seed-dev`) |
| `make authorize-url` | An authorization URL with a fresh PKCE pair, and the `curl` that redeems the code |
| `make config` | Every `CLAVIA_*` setting as the server sees it |
| `make check` | `composer check`: PHPCS, Psalm, deptrac, PHPUnit |
| `make test` / `lint` / `analyse` / `arch` | One part of `check` |
| `make shell` | A shell in the PHP container |

`composer check` runs `cs-check` (PHPCS, PSR-12, 120 columns), `static-analysis` (Psalm level 1,
no baseline), `arch` (deptrac, failing on uncovered classes) and `test` (PHPUnit 13). CI runs
the same command against PostgreSQL 17 and Redis 7.

The console is `bin/clavia`:

| Command | Purpose |
|---|---|
| `config` | Print the settings |
| `db:migrate`, `db:status` | Schema migrations |
| `secrets:generate-key` | A value for `CLAVIA_SECRET_ENCRYPTION_KEY` |
| `keys:generate`, `keys:rotate`, `keys:list` | Signing keys (the `postgres` backend only) |
| `saml-keys:generate`, `saml-keys:rotate`, `saml-keys:list` | The SAML service provider's signing and encryption keys (`postgres`): rotation is next → current → retired |
| `management-api:register`, `management-api:scopes` | Register the Management API; list its scopes |
| `clients:create-m2m [--third-party]`, `clients:grant` | Machine clients and their grants on an API |
| `clients:registration-token` | An initial access token for client registration, printed once |
| `jobs:run` | Run the queued bulk jobs on the users (imports, exports), then exit; run every minute |
| `webhooks:deliver` | Send the webhook deliveries due, then exit; run every minute |
| `users:import-sqs <queue-url>` | Import accounts from an AWS SQS queue, one per message, until stopped |
| `clients:purge-unused` | Delete self-registered clients never issued a token after `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` days; run daily |
| `roles:create`, `roles:assign`, `roles:list` | Roles, including the first administrator |
| `audit:purge` | Delete audit events older than `CLAVIA_AUDIT_RETENTION_DAYS`; run daily |
| `mail:outbox` | The last messages of the `console` mail backend (development) |
| `seed-dev`, `authorize-url` | Development only |

`bin/clavia` refuses every command on an invalid configuration (exit 78), and prints
`Settings::warnings()` to stderr.

## Repository map

```
bin/clavia                  console entry point
config/                     Mezzio entry files: config, container, pipeline, routes
public/index.php            HTTP entry point (PHP-FPM); public/auth/static/ served by Caddy
src/
  Domain/                   pure PHP: aggregates, value objects, policies, repository interfaces
    Shared/  Identity/  Client/  Connection/  ResourceServer/  Rbac/  Consent/
    OAuth2/  Oidc/  Authentication/  Audit/  Claims/  Webhook/
  Application/              use cases, by context, and the technical ports
    OAuth2/  Oidc/  Authentication/  Management/  Connection/  Clients/  Audit/
    Event/  Secrets/  Development/  Port/
  Adapter/
    Primary/                what calls the application
      Http/{OAuth2,Oidc,Auth,Management,OpenApi,Shared}/   Cli/
    Secondary/              what the application calls
      Persistence/{PhpDb,Migrations}/  Redis/  Signing/{Postgres,Remote,Jose}/
      Crypto/  Mail/  Http/  IdentityProvider/  Events/  System/
  Configuration/            the typed CLAVIA_* settings
  Bootstrap/                composition root: ConfigProvider and one factory per service
templates/                  server-rendered pages: layout/, auth/, error/, partial/
migrations/                 NNNN_name.sql, forward only
docs/openapi/               management-api.yaml, the Management API's contract
docs/site/                  the published API reference: Scalar over that document (docs.yml)
docs/SECURITY-REVIEW.md     review of every adapter against the invariants
docs/RELEASING.md           how a release is made: changelog, version, tag, the Release workflow
CHANGELOG.md                what each release changed, for operators
conformance/                OpenID Foundation conformance: results and how to run them
test/{Unit,Integration,Acceptance,Support}/
docker/php/                 the PHP-FPM image: `development` (default) and `production` (published)
.claude/                    the ticket-* skills and board.sh, which move work through the backlog
.github/                    CI, the release workflow, the @claude workflow, issue forms, the pull request template
Caddyfile, docker-compose.yml, setup-ssl.sh, Makefile
```

## Architecture

### The hexagon

Three rings. Dependencies point inward only, and nothing in an inner ring knows an outer one
exists.

```
            primary adapters                                  secondary adapters
 ┌──────────────────────────────┐                    ┌──────────────────────────────┐
 │ Http: handlers, middleware,  │                    │ Persistence (phpdb-pgsql)    │
 │   server-rendered pages      │                    │ Redis stores                 │
 │ Cli: console commands        │                    │ Signing (postgres, KMS…)     │
 └──────────────┬───────────────┘                    │ Crypto, Mail, HTTP client,   │
                │ calls                              │ events, clock, random        │
        ┌───────▼────────────────────────────┐       └──────────────▲───────────────┘
        │ Application                        │                      │ implements
        │   use cases                        │──── outbound ports ──┘
        │   ┌────────────────────────────┐   │
        │   │ Domain                     │   │
        │   │ aggregates, value objects, │   │
        │   │ policies, domain events,   │   │
        │   │ repository interfaces      │   │
        │   └────────────────────────────┘   │
        └────────────────────────────────────┘
```

Two namespaces sit outside the rings. `Clavia\Configuration` is the typed settings: plain data
with no dependency, readable by adapters and the composition root but never by the domain or
the application, which receive the values they need as constructor arguments.
`Clavia\Bootstrap` is the composition root: the only code that reads the container, and the
only code allowed to import every layer.

### Hexagonal architecture — the rules

A violation is a build failure, not a review comment.

1. **The domain imports nothing** outside `Clavia\Domain` and PHP's core: no PSR interface,
   no vendor class, no `new DateTimeImmutable()` for "now", no `random_bytes()`, no
   `getenv()`. Time and randomness arrive through the `Clock` and `RandomSource` ports in
   `Domain\Shared`.
2. **The application imports the domain only.** A use case receives scalars and value
   objects and returns a result, or throws a domain exception. It never sees a PSR-7 request,
   a cookie, an SQL row or an HTTP status.
3. **Repository interfaces live with their aggregate in the domain.** Technical ports live in
   `Application\Port`. Ports speak the domain's language and express intent, never mechanism:
   `lockForRedemption(Digest)`, not `selectForUpdate()`.
4. **Adapters never call each other.** A handler does not touch a repository or Redis; a
   repository does not sign tokens. A cross-cutting need goes through a use case or a port.
5. **Primary adapters translate.** A handler parses and validates the transport shape, calls
   one use case, and maps the result or exception to a response. Protocol decisions (which
   OAuth error, whether consent is needed, how scope narrows) belong to the domain or the
   application. Encoding them (redirect or JSON, `WWW-Authenticate`) belongs to the adapter.
6. **The composition root is the only place that knows everything.** Wiring lives in
   `Clavia\Bootstrap` and `config/`; nothing else in `src/` reads the container.
7. **Transactions are an application concern.** A use case that must be atomic wraps itself in
   `TransactionManager::transactional()`; the adapter decides what that means.
8. **Domain objects are immutable where they can be** (`readonly`, `clone with`), always valid
   (named constructors enforce invariants), and never anaemic: a rule lives on the aggregate
   that owns its data.
9. **Each port has an in-memory double** in `test/Support/Fake`, and each real adapter passes
   the same contract suite as its double.

### Enforcement

- **deptrac** (`deptrac.yaml`): layers Domain, Application, PrimaryAdapter, SecondaryAdapter,
  Configuration, Bootstrap, and a Vendor layer that Domain, Application and Configuration may
  not touch. The two kinds of adapter never depend on each other. A new vendor namespace joins
  the Vendor layer; an exception to the ruleset needs a note here.
- **`DependencyRuleTest`** checks the `use` statements of `src/Domain`, `src/Application` and
  `src/Configuration`: the cheap, unarguable version of rules 1 and 2.
- **Psalm** level 1 with no baseline; **PHPCS** PSR-12.

### Composition root and request lifecycle

- **HTTP**: `public/index.php` builds the container (`config/container.php`,
  laminas-servicemanager), pipes the middleware (`config/pipeline.php`) and the routes
  (`config/routes.php`), runs the request, then calls `fastcgi_finish_request()` and runs the
  deferred tasks (`System\AfterResponseTasks`).
- **The pipeline**: `ErrorHandler` → `AuditContextMiddleware` → routing → 405 → dispatch →
  404. There is no implicit `HEAD` or `OPTIONS`: a route answers the methods it lists. Mezzio's
  `ImplicitHeadMiddleware` is absent on purpose, because it would answer `HEAD
  /oauth2/authorize` by running the handler, which mints a code.
- **Per-surface authentication** is attached to route groups in `config/routes.php`, never
  piped globally. `ManagementApiMiddleware` fronts every `/api/v1/*` route.
- **Services**: `Bootstrap\ConfigProvider` maps each service to one factory class in
  `Bootstrap\Container`. No closures in configuration, no autowiring, no service location.
  Console commands are listed in `ConfigProvider::CONSOLE_COMMANDS`; event subscribers in
  `ConfigProvider::EVENT_SUBSCRIBERS`.
- **Settings**: `Configuration\Settings` is a readonly class whose constructor parameters *are*
  the `CLAVIA_*` variables (`rootDomain` ⇄ `CLAVIA_ROOT_DOMAIN`). `Settings::fromEnvironment()`
  coerces, bounds-checks (`#[Range]`) and cross-checks them. `Bootstrap\EnvironmentVariables`
  merges the process environment over `.env`.
- **Errors**: PHP runs with `error_reporting(E_ALL)`, and the pipeline turns every warning and
  notice into an exception. An uncaught error is logged (monolog to stderr) under a 12-character
  reference sent in `X-Error-Reference`, and the client gets a bare 500 that describes nothing,
  in every environment.
- **Connections are lazy.** Building the container opens neither PostgreSQL nor Redis, and
  `/healthz` touches neither.

## Hosts, surfaces and storage

### Hosts

Clavia never hard-codes a domain. `CLAVIA_ROOT_DOMAIN` names it, and every host is derived from
it. Two hosts must exist wherever Clavia runs, and their separation is a security property:

- **`auth.{domain}`**: OAuth 2.1, OpenID Connect and the sign-in pages. The session cookie is
  host-only (no `Domain` attribute), and no script runs on this origin but the one module a page
  that needs it loads (passkeys). Credentials are typed and tokens minted here, and nothing else
  shares it.
- **`management.{domain}`**: the Management API at `/api/v1/*`, and the dashboard at
  `/dashboard`. Keeping it apart means an XSS on the sign-in UI cannot reach the administrative
  session, and the reverse.

There is no `api.{domain}`: the Management API is a path on the dashboard's origin, so the
dashboard's calls need no CORS. That does not change who may call it: any client holding a
valid access token. In development the domain is under `.test` (`clavia.test`), which RFC 6761
reserves and every resolver answers from `/etc/hosts`. Never `.local`, which macOS resolves
through Bonjour at seconds per lookup, and never a real suffix such as `.dev`.

**Caddy** terminates TLS (mkcert in development, a wildcard for `*.{domain}`), serves
`public/auth/static/*` itself, sends everything else on `auth.*` and `/api/v1/*` to PHP-FPM
(`index.php` is the only script it runs), and reverse-proxies `/dashboard` to
`CLAVIA_DASHBOARD_UPSTREAM` with the `Host` header kept. No `X-Forwarded-*` header is trusted
unless `CLAVIA_TRUSTED_PROXIES` names the proxy, and the host never comes from a header.

### Four surfaces, four authentication mechanisms

| Path | Purpose | The caller proves itself with |
|---|---|---|
| `/oauth2/*` | Authorization server: authorize, token, introspect, revoke, device | Client credentials, PKCE |
| `/oidc/*`, `/.well-known/*` | Discovery, JWKS, userinfo, logout | A bearer token, or nothing |
| `/auth/*` | Sign-in, second factor, consent, device approval, sign-out | The browser session cookie |
| `/api/v1/*` | Management API | A bearer access token for the Management API |

Keeping them apart is the central design constraint. The failure to avoid is authenticating
`/api/v1/*` with the `/auth/*` session cookie: the Management API is a machine plane, reachable
only with an access token, and the dashboard is an OAuth client like any other.

### Storage split

- **PostgreSQL** holds whatever must survive a restart, be audited, or be consumed exactly
  once: users, clients, APIs, roles, connections, consents, authorization codes, access and
  refresh tokens, signing keys, the audit trail.
- **Redis** holds short-lived material: browser sessions, sign-in throttling, pending second
  factors, sign-in and consent handles, outbound social-login state, device and user codes,
  passwordless challenges, verification and reset links, WebAuthn ceremonies, nonces, cached JWKS
  and public keys.

Authorization codes and refresh tokens look like Redis material and deliberately are not:
single use needs a `SELECT … FOR UPDATE`, and replay detection must outlive any sensible TTL.

## The domain

One namespace per bounded context under `src/Domain`, each with its own aggregates, value
objects, repository interfaces, and an `Event` namespace for its domain events.

| Context | Holds | Key rules |
|---|---|---|
| `Shared` | `Clock`, `RandomSource`, `SecretGenerator`, `Digest`, `Scope`/`ScopeSet`, `Audience`, `Url`, `UuidId`, `Base64Url`, `PageRequest`/`Page`, `InvalidValue`, `AlreadyExists`, `DomainEvent` | Secrets are 43-character tokens; codes and tokens are stored as their SHA-256 `Digest`; URLs are kept byte for byte and compared exactly |
| `Identity` | `User`, `Profile`, `AppMetadata`, `PasswordPolicy`, `ExternalIdentity`, `AssertedIdentity`, `AccountLink` | Every account belongs to one connection; an address is unique within it; a changed address is unverified; an emailed link dies with the address or password it was issued against; application metadata is a JSON object only operators write (16 KiB, five levels, keys sorted), replaced whole |
| `Client` | `Client`, `ClientId`, `ClientType`, `ClientAuthMethod`, `GrantType`, `ResponseType`, `Ownership`, `BackChannelLogout`, `Registration\InitialAccessToken` | Type, auth method and secret agree; the code flow needs a redirect URI; `client_credentials` needs a confidential client; `tpc_…` ids are third-party |
| `Connection` | `Connection`, `ConnectionName`, `ConnectionStrategy` (database, social, OIDC, passwordless, SAML), `OidcSettings`, `BuiltInConnection`, `Saml\*` (`SamlSettings`, `SamlCertificate`, `SamlOptions`, `SamlRequestId`, `ServiceProviderKey[Set]`) | The default pool, social providers and `email` are switched, never created or deleted; only a pool takes sign-ups or requires a verified address; a SAML connection, and only one, has SAML settings: 1 to 3 pinned RSA certificates, https endpoints |
| `ResourceServer` | `ResourceServer` (an API: `rs_…` id, audience, permissions, `AccessTokenFormat`), `Permission`, `ClientGrant` | A system API (the Management API) can be renamed, never deleted, always enforces roles; tokens are opaque unless the API takes JWTs |
| `Rbac` | `Role`, `GrantedPermission`, `RoleRepository` (also the assignments) | A person holds a permission only through a role; `permissionsHeld(user, API)` is the question issuance asks |
| `Consent` | `UserConsent`, `ConsentPolicy`, `PendingConsent` | `ConsentPolicy` alone decides who is asked |
| `OAuth2` | `AuthorizationCode`, `AccessToken`, `AccessTokenClaims` (RFC 9068), `RefreshToken` (families), `DeviceAuthorization`, `UserCode`, `CodeChallenge`/`CodeVerifier` (S256), `Prompt`, `MaxAge`, `OAuth2Error`/`ErrorCode`, `BearerTokenError` | Single use, exact matching, rotation with replay revocation |
| `Oidc` | `SigningKey`, `SigningAlgorithm`, `PublicJwk`, `Nonce`, `OidcScope`, `IdentityClaims`, `IdTokenClaims`, `LogoutTokenClaims` | One active key; retired keys stay published until their tokens expire |
| `Authentication` | `Session`, `AuthenticationMethod` (RFC 8176 `amr`), `AuthenticationLevel` (`acr`), `AuthenticationContext`, `LocalPath`, `LoginState`, `MfaChallenge`, `Mfa\*` (`Totp`, `RecoveryCode`, `MfaFactor`), `Passkey\*` (`Passkey`, `CredentialId`, `PasskeyRepository`, `WebAuthnChallenge`, `RelyingParty`…), `PasswordlessChallenge`, `PendingExternalSignIn` | Sessions have idle and absolute lifetimes and a `sid`; a TOTP step is spent once; a passkey's signature counter must grow (a synced passkey's stays at zero), and its eligibility for backup never changes |
| `Audit` | `AuditEvent`, `AuditEventType`, `Actor`, `AuditTarget`, `Outcome`, `AuditQuery`, `AuditLog` | Append-only; facts, never secrets |
| `Claims` | `ClaimName`, `ClaimSource`, `ClaimMapping`, `ClaimMappings`, `ClaimSubject`, `CustomClaims` | A custom claim never has a reserved name (registered, standard, or this server's), checked when saved and again at issuance; its source is the account (address, connection, profile, `app_metadata`, roles) or a constant, never the request; a source with no value leaves its claim out; at most twenty per API, no two reading nested metadata; 32 KiB per token, refused rather than cut |
| `Webhook` | `WebhookEndpoint`, `WebhookEndpointId`, `WebhookSecret`, `EventFilter`, `WebhookEndpointRepository` | An endpoint is https, at most twenty, listening to known audit event types or `*`; its secret (`whsec_`, 32 random bytes) is the server's, shown once, sealed (`webhook:<id>:secret`), never hashed; after a rotation the previous one signs beside it for a day |

The application mirrors these contexts (`Application\OAuth2`, `Authentication`, `Oidc`,
`Management`, `Connection`, `Audit`…). `Application\Port` holds the technical ports: signing
(`TokenSigner`, `SigningKeyStore`, `SignatureVerifier`), secrets (`PasswordHasher`,
`SecretCipher`), persistence (`TransactionManager`, `SchemaMigrator`), the Redis stores
(`SessionStore`, `LoginStateStore`, `MfaChallengeStore`, `ConsentStateStore`,
`DeviceAuthorizationStore`, `PasswordlessChallengeStore`, `AccountLinkStore`,
`ExternalSignInStore`, `WebAuthnChallengeStore`, `NonceRegistry`, `AttemptCounter`), passkeys
(`PasskeyVerifier`), breached passwords (`BreachedPasswords`), mail (`Mailer`, `MailOutbox`),
identity providers (`IdentityProvider[s]`, `OidcDiscovery`), outbound URLs (`OutboundUrls`), deferred work
(`DeferredTasks`, `BackChannelLogoutDelivery`), events (`DomainEvents`) and SAML
(`Saml\SamlServiceProvider`: requests, responses, metadata in and out; nothing wired yet).

## Flows

### Authorization code with PKCE

`GET|POST /oauth2/authorize` runs `Application\OAuth2\Authorize\Authorize`, which returns
`CodeIssued`, `RequestRefused`, `LoginRequired` or `ConsentRequired`. It throws `OAuth2Error`
only when the error must not be redirected. The order is fixed:

0. **A pushed request** (RFC 9126): a `request_uri` this server handed out at `/oauth2/par`
   replaces the query with the parameters pushed, the query keeping only `client_id` (which
   must be the pushing client's); anything else in it is ignored. An unknown, expired or
   another client's `request_uri` is thrown, never redirected.
1. **Settle the client and the redirect URI**, or throw. That error is shown to the person,
   never redirected. Redirect URIs match as exact strings. A client registered with
   `require_pushed_authorization_requests` is refused (`invalid_request`) anything not pushed.
2. **Refuse repeated parameters** (RFC 6749 §3.1) and request objects: `request`, and any
   `request_uri` but a pushed request's (`request_uri_not_supported`).
3. **Validate everything else**: response type, PKCE (S256), scope, `audience` (the API whose
   permissions the scope may hold; unknown is `invalid_target`), `nonce`, `prompt`, `max_age`.
   Failures are sent *to* the redirect URI with `state` and `iss`. An invalid request never
   reaches the sign-in page.
4. **A third-party application asking for a system API** is refused here, before anyone signs
   in.
5. **Decide once whether the person must be seen**: no session, a session through a connection
   the client does not enable, `prompt=login` or `select_account`, or `max_age` exceeded.
   `prompt=none` then answers `login_required`. Otherwise the request is held behind an opaque
   handle (`LoginStateStore`) and the browser goes to `/auth/login`. A signed-in session that
   falls short of the requirement — `acr_values` (`AuthenticationRequirement`: known levels
   only, any one accepted) with the client's and the API's `MfaPolicy` as a floor
   (`withMinimum()`) — **steps up** (`docs/design/mfa-policies.md` §5.1): `prompt=none` answers
   `interaction_required`; a person who holds a factor that would be enough is sent to
   `/auth/mfa` with a step-up challenge (`BeginStepUp`, the request resumed as it is); a person
   with no second factor, a verified address and a requirement MFA meets **enrols on the way**
   (`BeginEnrolmentOnTheWay`: the request held behind a login state, the browser sent to
   `/auth/mfa/enroll?state=…`); anyone else gets `unmet_authentication_requirements`.
6. **Roles**: on an API that enforces them, somebody holding nothing there gets `access_denied`.
7. **Consent** (`ConsentPolicy`): `prompt=consent` asks; a first-party client is not asked for
   no API, or an API allowing skipping; otherwise a consent on record must cover every scope.
   A request needing consent is held behind a handle, and `/auth/consent` shows the screen.
8. **Issue the code**: bound to the client, redirect URI, challenge, nonce, audience and the
   session's `AuthenticationContext` (`auth_time`, `amr`, `sid`). The client is recorded on the
   session for back-channel logout.

A held request is **resumed, not replayed**: the sign-in page and the consent screen send the
browser back to `/oauth2/authorize` with every parameter (`AuthorizationRequest::resumption()`),
minus a `prompt` value already satisfied, and the endpoint decides again with everything as it
is then.

`POST /oauth2/token` runs `Token\IssueToken`, which owns what every grant shares (repeated
parameters, `grant_type`, client authentication, the client's right to the grant) and
dispatches to a `Token\Grant`. `AuthorizationCodeGrant`, inside one transaction:

1. locks the code (`lockForRedemption`, `FOR UPDATE`) and **spends it before checking the
   redirect URI and the verifier**, so a wrong guess burns it;
2. on replay, revokes everything the code minted, including its refresh family;
3. re-checks the audience, and narrows the scope with `UserScope`: the API's current
   permissions, cut to the person's roles when the API enforces them;
4. issues the access token, the refresh token (when the client holds the grant) and, for an
   OpenID Connect request, the ID token, signed inside the same transaction, so a signing
   failure leaves the code unspent.

A refusal that must survive (a replay) is returned from the transaction and thrown after
commit, because throwing inside would roll the spend back.

### Pushed authorization requests

`POST /oauth2/par` (RFC 9126, `Par\PushAuthorizationRequest`) takes an authorization request
over the back channel: the client authenticates as at the token endpoint (a public one names
itself), the request is held to the authorization endpoint's rules (`AuthorizationRequestRules`,
shared by both), and a `request_uri` (`urn:ietf:params:oauth:request_uri:…`) comes back, `201`,
good for `CLAVIA_PAR_LIFETIME` (60 s by default). A `request_uri` in the push is refused, and
`client_secret` is never stored. The pushed request lives in Redis
(`PushedAuthorizationRequestStore`): read as often as the browser comes back, spent when it
yields a code, and pushed again under a new handle — as long as the login state — when it is held
for the sign-in page, consent or a step-up. Discovery names the endpoint;
`require_pushed_authorization_requests` is per client (RFC 9126 §6), off by default.

### DPoP

A request to the token endpoint may carry a DPoP proof (RFC 9449, design in `docs/design/dpop.md`):
a JWT in the `DPoP` header, signed by a key the client holds. `ReadDpopProof` is the one door:
exactly one header; the cryptography in `JoseDpopProofVerifier` (`typ: dpop+jwt`; ES256, EdDSA or
RS256 with a key of the matching type; no private member; never PS256, whose pure-PHP
verification costs a second); the request in `ProofRequirement` (`htm`; `htu` against this
server's own URL, normalised, never the `Host`; `iat` within `CLAVIA_DPOP_PROOF_LIFETIME` and
5 s ahead; `ath` and the bound key where a token is presented); the server's nonce
(`DpopNonces`, one per `CLAVIA_DPOP_NONCE_LIFETIME`, the previous one accepted; `use_dpop_nonce`
with `DPoP-Nonce`); then the `jti`, claimed once per key (`DpopReplayCache`). The proof is read
before the grant runs, so a bad one spends no code. What the grant issues is bound to the key:
`token_type: DPoP`, `dpop_jkt` on the access token, `cnf.jkt` in JWT access tokens and
introspection. The answer carries the next `DPoP-Nonce`. A refusal is one
`invalid_dpop_proof`; the reason is logged. Without a proof a token is a bearer token, unless
the client is registered with `dpop_bound_access_tokens` (RFC 9449 §5.2, off by default, in the
Management API): then a token request without a proof is `invalid_dpop_proof`, refused before the
grant runs, so a code is not spent.

Codes and refresh tokens are bound too. `dpop_jkt` at `/oauth2/authorize` (validated with the
other parameters) binds the code; a `DPoP` header at `/oauth2/par` binds the pushed request to the
proof's key, and a `dpop_jkt` naming another is `invalid_dpop_proof`. A bound code redeemed without
a proof from its key is `invalid_grant`, and spent. A **public** client's refresh family is bound to
the key it started with; a refresh without it is `invalid_grant` and spends nothing. A
confidential client's family is not bound (RFC 9449 §5): its authentication binds it.

This server's own protected resources, userinfo and the Management API, check the binding
(`CheckSenderConstraint`, RFC 9449 §7): a bound token comes as `Authorization: DPoP` with a fresh
proof for the method and the URL this server knows (never the `Host`), naming the token (`ath`)
and signed by its key; no server nonce is asked there, the proof's age and the `jti` bound replay.
A bound token sent as `Bearer` is `invalid_token`, so binding is not optional for a thief; a
bearer token sent as `DPoP` is `invalid_token` too. A bad proof is `invalid_dpop_proof`, and a
DPoP request is challenged with `WWW-Authenticate: DPoP` and the `algs` accepted.

### Client authentication

One method per request, read from what the request carries: an `Authorization` header is
Basic, a body `client_secret` is `client_secret_post`, a bare `client_id` is `none`. Methods are
never tried in turn, and mixing them is refused. The method must equal the client's registered
`token_endpoint_auth_method`, so the right secret through the wrong door fails. Every failure
is the same `invalid_client` (401 with `WWW-Authenticate` at the token endpoint).

**Failures are limited** (`ClientFailureThrottle`) at the four endpoints that authenticate a
client: token, introspection, revocation, device authorization. Only failures count, so a busy,
well-behaved client is never refused. Every `invalid_client` counts against the client address
(`REMOTE_ADDR`); a grant refused as `invalid_grant` counts against the address and, when the
client proved itself with a secret, against the client. A client id alone is never a subject:
it is not secret (a public client's is in every authorization URL), and counting failures under it
would let anyone lock that client out. Past `CLAVIA_TOKEN_MAX_FAILURES` within
`CLAVIA_TOKEN_FAILURE_WINDOW` (every failure restarts it) the endpoint answers `429` with
`Retry-After` and `temporarily_unavailable`, before any secret is checked, which also bounds
the PBKDF2 work an address can cause. `authorization_pending` and `slow_down` are not failures.

### Sign-in

All first factors end at `SignIn\CompleteFirstFactor`, which either establishes the session or,
when a factor is confirmed, opens the second-factor challenge. A second factor therefore
applies however the person signed in.

- **Password** (`SignInWithPassword`): looks only in the pools the application enables. An
  unknown account, wrong password, deactivated account, missing password and throttled subject
  are one outcome (`CredentialsRejected`), one message, one status. `simulateVerification()`
  spends the same time when no hash is checked. Throttling counts per account and per client
  address (`REMOTE_ADDR` only).
- **Passkey** (`BeginPasskeySignIn`, `SignInWithPasskey`, design in `docs/design/passkeys.md`
  §6.2): the login page offers one in the address field's autofill and behind a button, wherever
  the application lets anybody in. No address is typed: the passkey names its owner by the user
  handle. The ceremony is bound to the page's login state (or, on a page reached directly, to its
  own handle), user verification is required, and the throttle counts per client address, since
  there is no account to count against first. The account must be active and its connection one
  the application allows. Every refusal is `CredentialsRejected`, a wrong password's answer. With
  `CLAVIA_PASSKEY_SATISFIES_MFA` (on by default) a verified passkey is multi-factor by itself
  (`amr` `hwk` or `swk`, then `mfa`); off, the second factor follows, and it cannot be a passkey
  (`MfaChallenge::firstFactorWasAPasskey()`): one device would count twice. An authenticator app
  or a recovery code finishes it. The last passkey of a pool
  account with no password and no linked identity cannot be removed: it is the only way in.
- **Second factor** (`CompleteSecondFactor`, `CompletePasskeySecondFactor`): asked of an account
  with a confirmed authenticator app or a passkey. The challenge lives in Redis behind the
  `clavia_mfa` cookie (`Path=/auth`). A TOTP code (RFC 6238: SHA-1, six digits, thirty seconds,
  one step either side) is checked with the factor row locked, and its step is recorded; a
  recovery code, which answers for either kind of factor, is spent by one conditional `UPDATE`.
  A passkey answers a ceremony the page opens each time it renders, bound to the challenge
  (`POST /auth/mfa/passkey`); presence is enough, its counter must grow, and its use is a
  conditional write. Guesses of every kind are bounded per challenge (`CLAVIA_MFA_MAX_ATTEMPTS`)
  and by the sign-in throttle. Seeds are sealed with `SecretCipher` (`user:<id>:totp` as
  associated data), never hashed. `amr` gains `otp`, or `hwk`/`swk` (and `user` when nobody was
  verified), then `mfa`. Turning the app off keeps the recovery codes while a passkey remains; an
  operator's reset takes them.
- **SAML connections** (`docs/design/saml-connections.md`, built in slices).
  `POST /api/v1/connections` with `strategy: saml` and a `saml` object reads the identity provider
  from `saml.metadata` (the document) or `saml.metadata_url` (fetched now, `SamlMetadataSource`
  through `OutboundUrlPolicy`, 1 MiB): `SamlConfiguration` holds it to `SamlServiceProvider::readMetadata()`
  (one `EntityDescriptor`, or an aggregate of exactly one as Keycloak sends; one SAML 2.0
  `IDPSSODescriptor`; an https HTTP-Redirect sign-on service; 1 to 3 RSA ≥ 2048 signing
  certificates), and each refusal is a `422` pointing at its field (`SamlMetadataRefused`).
  `POST …/{name}/refresh-metadata` reads the URL again (`409` for another kind or a document). The
  answer shows the certificates by SHA-256 and stated expiry (never enforced: keys are pinned), the
  options, and the service provider's entity ID, ACS and metadata URLs (`SamlServiceProviderEndpoints`:
  `https://auth.{domain}/auth/saml/{connection}`), with a warning when there are no keys.
  `GET /auth/saml/{connection}/metadata` (`DescribeSamlServiceProvider`) is this server's
  `EntityDescriptor` with the current and next certificates of each usage and the encryption methods,
  valid against the SAML metadata schema, public for an hour (Caddy's `no-store` excepts it); `404`
  for anything but an enabled SAML connection.
- **SAML sign-in** (`External\Saml\*`, design §5.3): the login page's button goes to `GET
  /auth/saml/{connection}` (`BeginSamlSignIn`): a pending sign-in carrying the `AuthnRequest`'s id,
  its handle the `RelayState` and the `clavia_external_state` cookie, the browser sent out by
  HTTP-Redirect, the request signed (Bindings §3.4.4.1: `SigAlg` RSA-SHA256 over the query as sent,
  through `ServiceProviderKeys::sign()`) whenever the connection's `sign_requests` is on and a
  current signing key exists. The identity provider POSTs to `…/acs` (`ReceiveSamlResponse`),
  a cross-site POST that carries no `Lax` cookie, so the response is only parked under a one-time
  handle (`SamlResponseStore`, 60 s) and the browser sent on with a `303` to `…/complete?h=…`
  (`CompleteSamlSignIn`), where the cookies come back: the parked response claimed; its `RelayState`
  equal to the cookie (constant time); the pending sign-in claimed for this connection; the
  application still allowing it; `SamlServiceProvider::consume()` with the connection's certificates
  and this request's id; the assertion id claimed until it expires (`SamlAssertionReplayCache`). An
  `EncryptedAssertion` is decrypted first: the content key unwrapped through `decryptKey()` (a
  `ContentKeyDecrypter` the use case hands the port: the key the `EncryptedKey`'s certificate names,
  or each encryption key, next, current and retired), RSA-OAEP only (`rsa-oaep-mgf1p`, or 1.1's
  `rsa-oaep` with SHA-1 or SHA-256 and MGF1 to match), never `rsa-1_5`; then AES-GCM, or AES-CBC
  unless the connection's `require_gcm`; `require_encryption` refuses a plain assertion. The
  plaintext is held to a plain response's rules, and its signature checked after. Every failure is
  the same page after the same steps, the handles spent first, and counts against the client address
  in the sign-in throttle (`LoginThrottle`, which refuses before anything is read once it is reached). The
  person is `(connection, subject)` (`ResolveExternalAccount`); the address comes from the attribute
  the operator named or an address `NameID`, verified only when the connection trusts the identity
  provider. An untrusted address still makes an account for a new subject, unverified and linked to
  nothing (`User::registerFromAssertion()`); no address at all signs nobody in. Then
  `CompleteFirstFactor` (`amr` `ext`), so a second factor applies. Every refusal is the external
  sign-in's one page and one `SignInRefused`; the handler logs the category (`signature`,
  `audience`, `replayed`…), never what the identity provider sent.
- **External** (`BeginExternalSignIn`, `CompleteExternalSignIn`): Google, GitHub, or an
  operator-registered OpenID Connect provider. Clavia holds itself to its own rules: an opaque
  `state` in the redirect and in the `clavia_external_state` cookie, compared in constant time
  and claimed with `GETDEL`; PKCE S256; a nonce; the code exchanged server-side. An identity
  is `(connection, subject)`, never an address. `ResolveExternalAccount` links a known subject;
  links a verified address matching exactly one account when `CLAVIA_SOCIAL_AUTO_LINK` allows;
  otherwise creates a verified, password-less account. A provider's words never reach the page.
  `amr` is `ext`.
- **Passwordless** (`Passwordless\*`): the built-in `email` connection. A six-digit code
  answers the browser whose `clavia_passwordless` cookie names the challenge, within
  `CLAVIA_PASSWORDLESS_MAX_ATTEMPTS`. A link answers whoever opens it, and only on a POST, so a
  mail scanner's GET spends nothing. Sends are limited per address and client address. Mail is
  sent synchronously; a failure is a 503, and the `none` backend makes the connection
  unusable. `amr` is `otp`.
- **Self-service accounts** (`Account\*`, design in `docs/design/self-service-accounts.md`).
  A pool may take sign-ups (`allow_sign_up`) and may require a verified address
  (`require_verified_email`), both off by default. `ConnectionAccess::signUpPool()` picks the
  pool: the default one when it is open, otherwise the first by name. `SignUp` creates the
  account unverified (`UserSignedUp`) and mails a verification link. In a pool requiring a
  verified address the answer is "check your inbox" whatever happened, and a taken address is
  mailed a notice instead; a pool that does not signs the new account in at once and says when an
  address is taken. Password sign-in refuses an unverified account in such a pool *after* its
  password verifies (`EmailVerificationRequired`) and sends a new link. `RequestPasswordReset`
  always answers the same and mails only existing accounts; `ResetPassword` screens the password
  before spending the link, changes the password, marks the address verified, and ends every
  session (`SessionEndReason::PasswordReset`). Links are `AccountLink`s in Redis (digest keys,
  `GETDEL`), spent only by a POST, and dead once the address changes or, for a reset, once the
  password does (a fingerprint of the hash). Account mail has its own `EmailSendLimit`
  namespace. Confirming an address never signs anyone in. An operator can mail the same link
  to an account (`POST /api/v1/users/{id}/password-reset`, `create:user_tickets`,
  `Management\Users\SendPasswordLink`): an invitation when the account has no password
  (`POST /api/v1/users` takes none: the account cannot sign in with a password until it
  chooses one), a reset when it has one, refused for a deactivated account or one outside a pool. The caller is
  authenticated, so unlike the public form it is told how it went: `202`, `429` when the send
  limit is reached, `503` when no mail can be sent.

- **Choosing a password** (`Account\PasswordScreen`): at sign-up, at a reset and through the
  Management API, `PasswordPolicy` first, then, with `CLAVIA_BREACHED_PASSWORD_CHECK` on (off by
  default), Have I Been Pwned's Pwned Passwords by k-anonymity (`PwnedPasswordsRange`: five
  characters of the SHA-1 leave, with `Add-Padding`, through `OutboundUrlPolicy`). A breached
  password is refused like one the policy refuses. An unreachable service lets the password
  through and logs a warning: NIST SP 800-63B §5.1.1.2 asks for the check, and somebody else's
  outage must not lock people out. At sign-up it runs after the limit per client address, which
  bounds how often a client can make this server ask.

- **MFA policies** (`MfaPolicy`, `optional` or `required`, on `Client` and `ResourceServer`,
  `mfa_policy` in the Management API): `required` on either is the MFA level, at the
  authorization endpoint and at device approval (`DecideDeviceRequest`, which steps up or sends
  to enrol and back to the same code). New authorizations only: refresh tokens issued before keep
  working. **Enrolment on the way** (§5.3): the enrolment pages carry the held request's `state`
  (`DescribeEnrolmentOnTheWay`); confirming an authenticator app raises the session
  (`FinishEnrolmentOnTheWay`: `otp`, `mfa`) and mails the owner a notice, outside the send
  limit; making a passkey goes back to the request, whose step-up then asks for it. The
  recovery codes lead back with `POST /auth/mfa/enroll/continue`. Trust on first use: only a
  verified address may enrol on the way.

- **Passkeys** (`Passkey\*`, design in `docs/design/passkeys.md`; phase 1, a second factor). The account page `/auth/passkeys` lists them; `POST /auth/passkeys/new` opens a
  registration ceremony (`BeginPasskeyRegistration`) and shows the page that runs `passkeys.js`,
  whose form posts the browser's `toJSON()` to `POST /auth/passkeys`
  (`CompletePasskeyRegistration`): claimed, verified (`PasskeyVerifier`), saved and announced in one
  transaction. The first passkey of an account with no authenticator app and no recovery codes
  brings a set, shown once. Rename and remove are `POST /auth/passkeys/{id}/name|remove`. With
  `CLAVIA_PASSKEYS_ENABLED=false`, or an issuer that is not https, the routes do not exist.
  Operators list a user's passkeys (`GET /api/v1/users/{id}/passkeys`, never a credential id or
  key) and remove them one by one (`DELETE …/passkeys/{passkey_id}`); a user's `mfa_enrolled`
  counts passkeys, and `passkey_count` says how many.

**Sessions** have one door per operation. `Sessions::establish()` is the only way a browser
becomes authenticated, and it always rotates the identifier. `resolve()` is the only way to read
one: it slides the idle window up to the absolute ceiling. `end()` is the only way to stop one.
`stepUp()` is the only way one gains a factor: only the browser's own session, named by the
`sid` the step-up challenge holds; `amr` gains the factor and `mfa`, `auth_time` becomes now, the
identifier rotates, and the `sid`, the clients signed in through it and the absolute expiry stay.
A step-up challenge (`MfaChallenge::stepUp()`) is answered only by a factor that makes the
session meet the request (`isAnsweredBy()`, `SecondFactors`): an app's code or a recovery code
never answers a request for `phr`.
The session identifier is stored as its digest; the `sid` is a second, unrelated token.
`ResolveEndUser` answers "who is this?" for every browser-facing handler, and re-checks that the
account is still active.

### Refresh tokens

A family starts at code redemption (or device approval). **Every refresh spends the token**
under the row lock and issues a new pair; there is no reuse grace. A spent token presented again
is a replay: the family and every access token it minted are revoked (RFC 6749 §10.4). Only a
successful refresh spends: a wider scope, another client, an expired or revoked token, a
deactivated account or roles taken away all leave it untouched, and every bad token is the same
`invalid_grant`. The refresh token carries the ceiling of what was authorized; `UserScope`
recomputes the access token's scope at every refresh. A family has an idle lifetime per token
(`CLAVIA_REFRESH_TOKEN_LIFETIME`) and an absolute deadline fixed at sign-in
(`CLAVIA_REFRESH_TOKEN_ABSOLUTE_LIFETIME`). A refresh issues no ID token, and ignores `audience`.

### Client credentials

A machine token always names its API: `audience` is required. `openid` is refused first; then a
scope beyond the client's `ClientGrant` is refused, never narrowed; and an omitted scope is the
whole grant. `grantableOn()` intersects the grant with the API's permissions now, so withdrawing
a permission takes effect on the next token. The token has no subject, so every surface that
describes a person (userinfo, introspection's `sub`) refuses it. Client grants are written
from the shell only (`clients:grant`): an endpoint writing them would let a caller widen its own
access. A third-party client never gets a token for a system API.

### Dynamic client registration

Design in `docs/design/dynamic-client-registration.md` (RFC 7591, RFC 7592), built in slices.
`CLAVIA_CLIENT_REGISTRATION` is `off` by default, or `token`: registration is only ever open to a
bearer of an **initial access token** an operator issued (`POST /api/v1/initial-access-tokens`,
`create:initial_access_tokens`, or `clients:registration-token`), never to anybody at all. A token
is its own kind, not a Management API token: a 43-character secret shown once and stored as its
digest, with a description, an expiry (a minute to ninety days, seven by default), a number of
uses (1 to 1000) and a revocation (`DELETE …/{id}`; the clients it registered keep working). Its
uses are spent by one conditional `UPDATE` (`InitialAccessTokenRepository::spendOne()`), never
written by `save()`, so two registrations cannot share the last. Its state (`active`, `expired`,
`used_up`, `revoked`) is worked out, never stored.

`POST /oauth2/register` (RFC 7591 §3, `RegisterClientDynamically`) exists only when registration
is on, and discovery names it (`registration_endpoint`) only then. In order: the client address
is counted (`CLAVIA_CLIENT_REGISTRATION_MAX_PER_ADDRESS` per `CLAVIA_CLIENT_REGISTRATION_WINDOW`,
valid or not; `429` past it); the initial access token (`Authorization: Bearer` only) is looked up
and spends nothing yet: missing is a bare challenge, anything else unusable one `401
invalid_token`; the JSON object is read by `RegistrationMetadata`, the one place the policy lives
(`400` with `invalid_redirect_uri`, `invalid_client_metadata` or `invalid_software_statement`,
the field named, never its value); then one transaction spends a use, registers the client and
its `ClientRegistration` (the digest of its registration access token, for RFC 7592), and
dispatches `ClientRegistered` with the client as the actor and the token as `registered_with`.
**A self-registered client is third-party by construction** (`tpc_…`, generated from nothing in
the request), so it never reaches a system API. It holds `authorization_code` and
`refresh_token` only (no machine client, no device flow), authenticates with `none`,
`client_secret_basic` (the default) or `client_secret_post`, keeps PKCE, has no connections of
its own, and may set `dpop_bound_access_tokens`; everything else of the operator's
(`mfa_policy`, PAR, `require_pkce`) and every unknown member is ignored and left out of the
answer. Redirect and post-logout URIs are https without a fragment, or, for a public client, http
on `127.0.0.1` or `[::1]` (RFC 8252 §7.3), never `localhost`. The `201` (§3.2.1) carries the
client secret (`client_secret_expires_at: 0`) and the registration access token, once.

`GET | PUT | DELETE /oauth2/register/{client_id}` (RFC 7592, `RegisteredClients` the one door) answer
only to the registration access token of the client in the path, `Authorization: Bearer`: an
operator's client has no registration, so no token reaches it, and every miss is one `401
invalid_token`. `GET` describes the client without its secret and rotates nothing. `PUT` replaces
the metadata under the same `RegistrationMetadata` (an omitted field takes its default): it needs
`client_id`, refuses the server's own fields (`registration_access_token`,
`registration_client_uri`, `client_secret_expires_at`, `client_id_issued_at`), a `client_secret`
that is not the current one, and a change of client type; it keeps the id, the secret and the
operator's settings, rotates the registration access token and returns the new one once.
`DELETE` deletes the client as the Management API does (`204`), but in its own use case:
`DeleteClient` refuses the client a token was issued to, which is the point here. Both changes
are the client acting as itself in the trail. The Management API shows a client's `registration`
(`initial_access_token_id`, `registered_at`, or null), read with the client (`ReadClients`).

**Unused clients** (§5.4): `MarkRegistrationUsed`, a subscriber to `AccessTokenIssued`, sets a
registration's `first_used_at` with one conditional `UPDATE` (a no-op for an operator's client and
after the first token), so no grant knows about it. `clients:purge-unused`
(`PurgeUnusedRegistrations`, daily, whatever `CLAVIA_CLIENT_REGISTRATION` says) deletes each
self-registered client still unused `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` days (30) after it
registered, one transaction each, with its own `ClientDeleted`. It reads registration rows only, so
it never reaches an operator's client, and a client used once is kept for good.

### Device authorization (RFC 8628)

`POST /oauth2/device/code` validates like an authorization request (`ReadRequestedAccess` is
shared) and stores the request in Redis: the device code as its digest, the user code as what a
person types. The person approves at `/auth/device`, where the session must come through a
connection the application enables, and roles are checked. An approval is a consent on record.
Polling follows §3.5: `authorization_pending`; `slow_down` adds five seconds for good;
`expired_token` for a minute past expiry. The device code is consumed before any token exists.
User-code guesses are throttled (`UserCodeThrottle`, §5.1).

### Introspection and revocation

- `POST /oauth2/introspect` (RFC 7662) answers only a client authenticating with a secret, and
  only about a token it has a stake in: its own, or one for an API it holds a grant on.
  Everything else, including unknown, expired, revoked and someone else's, is `{"active":
  false}`.
- `POST /oauth2/revoke` (RFC 7009) lets any client, a public one by its id, give back a token
  issued to it. Another client's token is `invalid_grant`; an unknown one a quiet 200. A refresh
  token takes its family along; an access token goes alone. `token_type_hint` says where to look
  first, never where to look only.

### Access token formats

Every grant mints through `Token\AccessTokenMinter`, which issues the form the token's API
chose (`access_token_format`, opaque by default; a token for no API is always opaque):

- **Opaque**: a 43-character secret the API resolves at introspection.
- **JWT** (RFC 9068): `typ: at+jwt`, signed through `TokenSigner` with the active key, claims
  from `AccessTokenClaims` (`iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti`, `scope`).
  `sub` is the client's id for a client acting as itself; `jti` is the recorded token's id. For
  a person, `auth_time` and `acr` too (RFC 9470 §6.1), from the sign-in that started the token's
  refresh family. No `amr` and no identity claims (userinfo releases those). Then the API's
  **custom claims** (`ResourceServer::$claims`, `Token\ApiClaims`, docs/design/custom-claims.md):
  worked out from the account at each issuance, a refresh included; constants only for a
  machine; nothing for a third-party application; `roles` the names of the person's roles holding
  a permission on this API. Introspection reports the same, worked out when asked, for opaque
  tokens too, so a JWT and its introspection can part ways after a change. A system API takes
  none. Past 32 KiB the grant fails as a signing failure does: a 500 under its reference, nothing
  spent (RFC 6749 §5.2 has no `server_error`).

Both are recorded by the digest of the value handed out, signed before the row is written, so
introspection, revocation, userinfo and the Management API treat them alike, and a signing
failure records nothing. **Revocation cannot reach an API that validates a JWT on its own**: it
accepts it until `exp`, so the access token lifetime bounds a revoked JWT's life there. The
OpenAPI document says so where the format is chosen.

### OpenID Connect

- **ID tokens** carry `sub` and protocol claims (`iss`, `aud`, `exp`, `iat`, `nonce`,
  `auth_time`, `amr`, `acr`, `sid`, `at_hash`), then the application's custom claims meant for
  them, and nothing else. What a scope releases (`IdentityClaims::of()`) is served by
  `/oidc/userinfo` alone, followed there by the custom claims meant for userinfo; an unknown value
  is left out, never null. `auth_time` and `amr` come from the session that approved the code.
- **An application's custom claims** (`Client::$claims`, `Oidc\ApplicationClaims`,
  docs/design/custom-claims.md): each `{name, source, value?, in}` goes to the ID token,
  userinfo or both, worked out from the account at issuance or at each request. A first-party
  application's only (refused for a third-party one, never set by dynamic registration); `roles`
  is not a name it may use, and the `roles` source gives all of the person's roles. A custom claim
  never replaces a protocol or standard claim: its name is never reserved, and both places add it
  after them.
- **Levels** (`AuthenticationLevel`, design in `docs/design/mfa-policies.md`): `acr` is worked
  out from `amr`, never stored. Two values: the PAPE multi-factor URI (`amr` has `mfa`), then
  `phr` (and a passkey, `hwk` or `swk`). One factor has no `acr`. No `phrh`: passkeys are
  registered without attestation, so a key's hardware is only its authenticator's word. Every token issued for a person keeps how they signed in (`auth_time`,
  `amr`, never the `sid`): a refresh family keeps its first sign-in, so its access tokens all say
  the same, and introspection reports `auth_time` and `acr` (RFC 9470 §6.2).
- **Discovery** (`/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`)
  names only what exists, and states every field whose default differs from the server.
  `ProviderMetadata` holds the paths; grant types and client authentication methods are read
  from `IssueToken`, so they cannot drift. `OidcTest` fetches every endpoint advertised.
- **Signing**: see [Signing keys](#signing-keys).

### Sign-out

- **RP-Initiated Logout** (`/oidc/logout`, `EndSession`): the session ends at once when
  `id_token_hint` is an ID token (`typ: JWT`), verifies against the published keys (retired
  ones included), names this issuer, and its `sub` is the session's person; the hint's expiry
  is not checked. Anything less
  shows a confirmation page whose form posts back (`confirmed=yes`, read from a POST only). The
  browser then goes to a registered `post_logout_redirect_uri` of the client (exact match, with
  `state`), or to the sign-in page.
- **Back-channel logout**: a session ended by any means (the logout endpoints, an operator,
  deactivation, deletion) dispatches `SessionsEnded`. The `BackChannelLogout` subscriber
  queues one delivery per application that was issued a code through that session and
  registered a `backchannel_logout_uri`. A logout token (`typ: logout+jwt`, `sid`, `events`) is
  posted after the response, best effort, logged on failure, never retried. A session that
  expires, or is replaced by a new sign-in, is not reported.

### Management API

Contract-first. `docs/openapi/management-api.yaml` (OpenAPI 3.0.3, written by hand) is the
source of truth. `ManagementApiMiddleware` checks every request in one order:

1. credentials (`AccessTokenCredentials`, the `Authorization` header only: `Bearer`, or `DPoP` with
   its proof);
2. the token: live, issued for the Management API (`aud` before any scope), its subject still
   active, and — when the Management API's own `mfa_policy` is `required` — a person's token
   from a sign-in meeting MFA, or `401 insufficient_user_authentication` with the `acr_values`
   to ask for (RFC 9470 §3; a machine token is not concerned; `seed-dev` turns it on);
3. the scope named by the operation's `security` requirement (there is no second list). A
   scope a *field* needs (`app_metadata` on a user needs `update:users_app_metadata`, since it
   feeds claims and authorization) is checked by the handler with `ManagementCaller::require()`,
   is marked by `ManagementPermission::isRequiredByAField()`, and is named in the operation's
   description; refused, it is the same `403`, before anything changes;
4. the request against the contract: a parameter twice, unreadable JSON or bad
   percent-encoding is 400; not JSON is 415; anything the contract or the domain refuses is
   422, with every violation listed (at most fifty).

Handlers then read a `ManagementRequest`, call one use case and render with `ManagementViews`.
The middleware maps expected refusals: `NotFound` is 404; `Conflict`, `AlreadyExists` and
`SystemApiProtected` are 409. Errors are RFC 9457 problem documents (`type`, `title`, `status`,
`detail`, `errors[]` with a `pointer` or `parameter`); bearer refusals stay RFC 6750 documents.
No error repeats the value at fault, and nothing is cacheable. Lists are
`{items, total, page, per_page}`, newest first, with a case-insensitive literal search. A
collection small by nature (an account's roles) is a plain array. Acceptance tests check every
response against the document (`ManagementFixtures::api()`).

The document is also the published reference, so it reads as one: each `summary` is a short label
and each tag has an `x-displayName` (`ManagementDocumentationTest`); each request body, success
response and shared refusal has an example, named in `components/examples` and reused across
operations (one cast: Ada, Acme Reports, the Reports API), and `ManagementExamplesTest` validates
every example against its schema with this validator, so none drifts from the contract. Example
secrets say they are not real. `info.version` is the API's own version (`1`, the `v1` of its
paths), never the server release. The Docs workflow publishes the reference (`docs/site/`, Scalar
pinned) to GitHub Pages for each release, `/vX.Y.Z/` and the root following the newest stable one
(`docs/RELEASING.md` §6).

The validator is Clavia's own (`Adapter\Primary\Http\OpenApi`). What it cannot enforce, it
refuses at load (unknown keywords, OpenAPI 3.1 forms, external references, non-JSON media
types, unsupported parameter styles). It reports every violation, never repeats a value,
coerces exactly (`"02"` is not an integer), and is strict where the specification is loose
(undescribed query parameters, a body sent to an operation without one, a single value sent
twice).

### Bulk jobs on the users

`POST /api/v1/jobs/users-imports` (`create:users`, `?connection=` a pool) takes NDJSON, one account
per line, at most 10,000 lines and 5 MiB, and only queues a `UserJob` (`QueueUserImport`): the
body is opaque to the contract (`application/x-ndjson`, `{type: string, format: binary}`, the one
non-JSON schema the validator takes), and nothing is read line by line in the request.
`bin/clavia jobs:run` (`RunUserJobs`, every minute) claims queued jobs one by one (`FOR UPDATE SKIP
LOCKED`, so workers never share one), and takes each line in its own transaction: `ImportLine`
holds it to the API's rules for a new user, with a `password_hash` instead of a password (only a
hash `PasswordHasher::canVerify()`, so PBKDF2 at any count from 1,000; a plaintext `password` or
any other member refuses the line), and an address already in the pool is refused, never updated.
Refused lines are reported by number and reason (`invalid_json`, `invalid_field`,
`unsupported_hash`, `already_exists`), never content, the first thousand listed. Each account is a
`UserCreated` by the caller who queued the job (its `Actor` is kept on the job). A finished job keeps
no input (a database check), only its report, `GET /api/v1/jobs/{job_id}` (`read:users`), for seven
days. A job running for an hour has lost its worker and is failed. Password sign-in replaces a hash
`needsRehash()` at today's count, which is how an imported one reaches 600,000 iterations.

**Exports** (`POST /api/v1/jobs/users-exports`, `read:users`, `?connection=` any connection, the
default pool without one; `QueueUserExport`) are jobs too, with no input (a database check).
`jobs:run` writes the connection out (`Export\ExportUsers`, by id a page at a time,
`UserRepository::inConnection()`) in the shape an import line takes, plus `user_id`, `connection`,
`created_at` and `updated_at`, which `ImportLine` ignores, so an export imports as it is. **Never a
password hash**, nor a factor, a passkey, a linked identity or a session. In one transaction the job
completes (`summary.total` the accounts written), its output is kept in `user_job_outputs` (apart from
the job row, which every status read loads; deleted with the job) and `UsersExported` is dispatched
(`user.exported`, the connection as target, the count, never who). `GET /api/v1/jobs/{job_id}/output`
(`read:users`) downloads it: `409` until the export is completed, `404` for an import.

**One door for an imported account**: `Import\UserImport` (`ImportUser`) reads a line, checks
the pool, and creates the account in its own transaction, or answers an `ImportRefusal` (the codes
above, and `invalid_connection`). `RunUserJobs` calls it for each line of a job; so does
`bin/clavia users:import-sqs` (`ImportUsersFromSqsCommand`, #108), a primary adapter reading one
account per SQS message (the `connection` attribute names the pool), through `Cli\Sqs\QueueMessages`,
a small interface of the adapter's own (`SqsQueueMessages` over `aws/aws-sdk-php`, a Composer
suggestion; `FakeQueueMessages` in tests). A refusal is final: the message is deleted and logged by
id and code, never body. An unexpected failure leaves it for the queue's redrive policy. The shell
acts, so the trail records the system.

### Webhooks

Design in `docs/design/webhooks.md`, built in slices.
`GET|POST /api/v1/webhooks`, `GET|PATCH|DELETE /api/v1/webhooks/{id}` and `POST …/rotate-secret`
(`read|create|update|delete:webhooks`) manage up to twenty endpoints (`Management\Webhooks\*`).
Creating one, or changing its `url` or `events`, also needs `read:audit_events`, checked by the
handler: streaming the trail is reading it. The URL goes through `OutboundUrlPolicy` at
registration (`WebhookUrl`); an unknown event type is `422`; a 21st endpoint `409`. The secret is
generated by `WebhookSecrets`, sealed with `SecretCipher`, and returned once (`201`, and at
rotation); the trail records the URL's host only (its path may carry a receiver's own token), and
the fields a change touched, never a value.

**Delivery is an outbox.** `Audit::record()` appends the event, then
`WebhookDeliveryRepository::enqueueFor()` writes one pending delivery per enabled endpoint whose
filter matches, in the same transaction (one `INSERT … SELECT`): a rolled-back change sends
nothing, a committed one is never lost. `bin/clavia webhooks:deliver` (`DeliverWebhooks`, every
minute, a 50-second budget) claims **endpoints**, not deliveries (`FOR UPDATE SKIP LOCKED`, a
30-second claim), so one worker sends an endpoint's deliveries one at a time; a failure stops that
endpoint for the run. The body is the audit event as `AuditEventDocument` renders it (the
Management API's own), in a Standard Webhooks envelope (`{type, timestamp, data}`), with
`webhook-id` (the audit event's id), `webhook-timestamp` and `webhook-signature`
(`StandardWebhookSignature`: both secrets during a rotation). `HttpWebhookSender` holds the URL to
the policy again (`refused_url`), connects to the addresses checked, follows no redirect, and never
downloads the answer (a client with `stream`). Failures retry on `RetrySchedule` (5 s … 10 h, ±10 %)
and end `abandoned` after the eighth attempt; a switched-off endpoint's deliveries and those whose
event was purged are abandoned at once; ended deliveries go after seven days, and a purged audit
event takes its pending ones along (a cascade).

**Operating them.** `GET …/deliveries` (`read:webhooks` and `read:audit_events`: it names the events
sent) is the log, newest first: status, attempts,
the last status code, duration and failure category, never a body. `POST …/test` (`update:webhooks`
and `read:audit_events`; `409` for an endpoint switched off) records `webhook.tested`, which the
outbox queues for its target endpoint alone: `EventFilter` never matches it, even `*`, and refuses
it by name. Each attempt moves the endpoint's `failing_since` (a conditional write, set by the first
failure, cleared by a success; `save()` resets it only when the endpoint is switched on or off);
one failing `WebhookEndpoint::DEAD_AFTER_DAYS` (5) is switched off by the worker
(`disableIfFailingSince()`, `disabled_reason: failing`, `WebhookDisabled`, `webhook.disabled` by the
system) until an operator switches it on. The payload is in the contract as `WebhookPayload`, with
a signed example `WebhookPayloadDocumentationTest` verifies.

### Domain events and the audit trail

A use case says what happened; it does not decide what follows. It dispatches a domain event
(past tense, typed with domain objects, never a secret) through `DomainEvents`, right after the
change. Subscribers (`Application\Event\EventSubscriber`, listed in
`ConfigProvider::EVENT_SUBSCRIBERS`) do the rest: the four audit trails
(`Application\Audit\Trail\{Authentication,Authorization,Configuration,Directory}Trail`) and
back-channel logout. The port is implemented on PSR-14 (`Adapter\Secondary\Events`).

- **Dispatch is synchronous, inside the use case's transaction**, so a rolled-back change leaves
  no event, and a subscriber's failure fails the use case. Work for other servers is deferred by
  its subscriber (`DeferredTasks`). A refusal worth recording (a wrong password, a replayed code)
  is dispatched outside any transaction that would roll it back.
- **Who acted comes from the request.** `AuditContext` is filled at the edge: origin and user
  agent by `AuditContextMiddleware`, the Management API caller by `ManagementApiMiddleware`. The
  shell leaves it empty, so the system is the actor.
- **The trail holds facts, never secrets.** Detail names containing `secret`, `password`,
  `token`, `credential`, `assertion`, `verifier`, `private` or `cookie` are refused with a
  `LogicException`. A change lists the fields it touched, not their values.
- **The trail is append-only**: a database trigger refuses `UPDATE`, and the only deletion is
  `audit:purge`, by age. It is read at `GET /api/v1/audit-events` (`read:audit_events`).
- **Every domain event is recorded by exactly one trail.** `AuditTrailsTest` fails otherwise.

### Signing keys

The port everything that issues a token goes through is **sign**, never **fetch the key**:

```php
interface TokenSigner
{
    public function activeKey(): SigningKeyReference;                             // kid + alg
    public function sign(SigningKeyReference $key, string $signingInput): string; // raw signature
    /** @return list<PublicJwk> */
    public function publicKeys(): array;                                          // the JWKS
}
```

An interface returning a private key could only be implemented by backends that let key material
into memory, which excludes every non-extractable option (cloud KMS, Vault Transit, an HSM), and
those are the ones worth having in production.

- **No JOSE library signs.** The compact JWS is assembled by hand (`CompactJws`) and signed by
  `TokenSigner::sign()`. `web-token/jwt-library` verifies (`JoseSignatureVerifier`: the key
  picked by `kid`, the algorithm the key's, never the header's) and handles JWKs, nothing more.
- **Exactly one class reads a private key**: the backend's own `sign()`. For `postgres` that is
  `PostgresTokenSigner::sign()`; `PostgresSigningKeyStore` generates and seals keys and never
  reads them back.
- **RS256 is spelled out** as RSASSA-PKCS1-v1_5 over SHA-256, because a remote backend must name
  the same primitive: AWS `RSASSA_PKCS1_V1_5_SHA_256`, GCP `RSA_SIGN_PKCS1_*_SHA256`, Azure
  `RS256`.
- **Every remote key is handed a digest**, never the message (AWS with `MessageType=DIGEST`).
  `RemoteTokenSigner` verifies each signature against the published key before returning it.
- **`kid` is the RFC 7638 thumbprint** for every backend: no ARN, project or vault URL is
  published. A remote reference names one immutable key version; an alias is refused at boot.
- **Backends** (`CLAVIA_SIGNING_BACKEND`): `postgres` (the default; the key sealed with
  AES-256-GCM under `CLAVIA_SECRET_ENCRYPTION_KEY`, `kid` as associated data; extractable, so a
  warning in production), `aws-kms`, `gcp-kms`, `azure-key-vault`, or the class name of a
  `RemoteSigningKey` implementation. `CLAVIA_SIGNING_KEY_REF` names the key version,
  `CLAVIA_SIGNING_RETIRED_KEY_REFS` the retired ones still published. The SDKs (`aws/aws-sdk-php`,
  `google/auth`) are Composer suggestions; Azure is REST. Nothing calls a provider at boot.
- **Lifecycle**: one active key (the database enforces it). `keys:generate` only when there is
  none; `keys:rotate` retires the active key for `RotateSigningKey::grace()` (twice the longest
  token lifetime plus a day). The Management API does what `keys:list` and `keys:rotate` do
  (`GET /api/v1/signing-keys`, `read:signing_keys`; `POST /api/v1/signing-keys/rotate`,
  `create:signing_keys`), naming keys by `kid`, algorithm and place in the rotation, never by
  their material; with a remote backend both answer `409`, and the key store is never built. Nothing creates a key on first use: issuing without one is
  `NoActiveSigningKey`, a loud error. With a remote backend, rotation is a new key made the
  reference and the old one listed as retired until its tokens expire. The JWKS and discovery
  cache lifetimes (`PublishSigningKeys::CACHE_MAX_AGE`, `DiscoveryHandler::CACHE_MAX_AGE`) are
  part of that reasoning.
- **SAML service provider keys** (`docs/design/saml-connections.md` §2, §5.1) follow the same rule
  behind their own port, `Saml\ServiceProviderKeys`: it signs (the current signing key, RSASSA-PKCS1-v1_5
  over SHA-256) and decrypts a content key (an encryption key, next, current or retired, RSA-OAEP
  only), and never returns a private key. One pair, RSA 3072, for the deployment: a signing key and
  an encryption key (one key, one usage), each published as a self-signed certificate built by hand
  (`Signing\X509\SelfSignedCertificate`, the encryption key's signed by the signing key, a known
  answer pinned). With `CLAVIA_SAML_KEY_BACKEND=postgres` they are sealed under `saml-sp:<kid>` and
  opened only in `PostgresServiceProviderKeys::sign()` and `decryptKey()`; `PostgresServiceProviderKeyStore`
  makes and seals them. With `aws-kms`, `gcp-kms` or `azure-key-vault` they never exist here
  (`Saml\Remote\RemoteServiceProviderKeys`): `CLAVIA_SAML_SIGNING_KEY_REF` and
  `CLAVIA_SAML_ENCRYPTION_KEY_REF` name them (a `NEXT_` pair, `RETIRED_ENCRYPTION_KEY_REFS`), each
  checked for its provider's form when the settings load (`Bootstrap\SamlKeyReferences`, an alias
  is exit 78, no provider called); signing reuses the token signers' keys (a digest, the signature
  verified before use), decrypting is `RemoteDecryptionKey` beside them; certificates are built once
  through the KMS and kept in `saml_remote_certificates`, so the metadata never calls it; there is no
  store, and `POST /api/v1/saml-keys/rotate` is `409`. Rotation (postgres) is a rollover in steps
  (`RotateServiceProviderKeys`, `saml-keys:rotate`, `POST /api/v1/saml-keys/rotate`): a next pair
  published, promoted after `CLAVIA_SAML_KEY_OVERLAP_DAYS` (14), the old pair retired, deleted after
  as long again. `GET /api/v1/saml-keys` (`read:signing_keys`) shows certificates, never keys.

## Security invariants

These follow from the RFCs and from mistakes already made once. Breaking one is a security bug.

**Protocol**

- PKCE is mandatory with S256; `plain` does not exist. The single exception is per client and
  off by default: a confidential client registered with `require_pkce: false` may omit PKCE
  from an OpenID Connect request carrying a `nonce` (OAuth 2.1 §7.5.1); a verifier presented for
  such a code is `invalid_grant`. A public client can never be relieved of PKCE (domain rule and
  database check).
- Authorization codes are single use, short-lived, and bound to the client, the redirect URI and
  the challenge. Redirect URIs are registered and matched exactly: no normalisation, prefix or
  wildcard, and a URI is appended to, never parsed and rebuilt.
- Refresh tokens rotate on every use; a replay revokes the family. No grace period.
- Client credentials: confidential clients only, no refresh token, no subject.
- A client that registered itself (RFC 7591) is third-party: its id is generated so, whatever the
  request says, and a third-party client never gets a token for a system API.
- Failures at the machine endpoints are counted per client address, and per client only once it
  has proved itself with a secret: nobody locks a client out by sending its id.
- A scope means nothing without an audience: check `aud` before any scope.
- A permission belongs to an API, and a client holds none of its own. Scope is narrowed at
  issuance (the API's permissions, then the person's roles or the machine's grant) and
  re-checked at redemption.
- A TOTP code is spent with its time step.
- Tokens are signed and verified through the JWKS; retired keys stay published until every token
  they signed has expired.
- Every token this server signs is explicitly typed (RFC 8725 §3.11): `JWT` for an ID token,
  `logout+jwt`, `at+jwt`. `SignatureVerifier` takes the type it accepts, so one kind is never
  taken for another (a JWT access token is no `id_token_hint`).
- Passwords and client secrets are PBKDF2-HMAC-SHA-256 hashes, for FIPS 140 (NIST SP 800-132):
  600,000 iterations, a 16-byte random salt each, a 32-byte key, derived through OpenSSL
  (`openssl_pbkdf2()`, so its FIPS provider when the system runs in FIPS mode, never PHP's own
  `hash_pbkdf2()`), stored as a PHC string (`$pbkdf2-sha256$i=…$salt$key`) and compared in
  constant time (`Pbkdf2PasswordHasher`). A secret is taken whole, up to 1,024 bytes, a bound on
  the work one request causes; there is no bcrypt left to verify. Codes and tokens are stored as
  SHA-256 digests, for indexed lookup.
- `prompt`, `max_age`, `request` and `request_uri` are one decision at the authorization
  endpoint (see the flow above). The one `request_uri` accepted is a pushed request's
  (RFC 9126): the URN `/oauth2/par` handed out, for the client that pushed it. It yields one
  code; a held request resumes pushed again, by reference, so its parameters never reach the
  address bar.
- Any repeated request parameter is refused.

**Browser**

- The sign-in pages share an origin with `/oauth2/authorize`; the session cookie has no
  `Domain`. No page runs script, except one that names its module (`HtmlPage::$script`, a file
  under `/auth/static`): that page alone allows `script-src 'self'`, with Trusted Types and no
  policy, so no inline script, no `eval`, no other origin, and no HTML written from a string. Data
  for the module travels in escaped `data-` attributes. The module decides nothing: the server
  builds every option and checks every answer. `Permissions-Policy` confines WebAuthn to this
  origin.
- **Passkeys**: the relying party id is the sign-in host, or a parent of it within the root
  domain, and the origin is matched exactly. A ceremony is single-use (`GETDEL`), short-lived,
  bound to its purpose and context (the account, or a login state's digest), and claimed before
  it is checked. Registration and signing in need user verification; a second factor needs only
  presence. `UsePasskey` is the one place a passkey answers a ceremony: found, verified, its
  counter grown, its use a conditional write. Adding, renaming or removing a passkey
  needs a sign-in within `CLAVIA_PASSKEY_REAUTH_WINDOW`; past it the person signs in again.
  Failures are one answer to the person; the log keeps the reason.
- A post-sign-in target never travels in a URL. It is held server-side behind an opaque handle,
  and whatever it resolves to is re-validated before becoming a `Location` (`LocalPath`, or for
  sign-out an https URL on an origin some client registered). Rejected, never repaired.
- No form says whether an address has an account: sign-in, sign-up into a pool requiring a
  verified address, and password reset answer alike. A link emailed to an address changes
  something only on the POST from the page it opens on, never on the GET a mail scanner makes.
- Every `/auth/*` state change is a POST with a CSRF token (double-submit, per browser). Sign-out
  and the theme toggle need none: a `SameSite=Lax` cookie never rides a cross-site POST. **The one
  `/auth/*` POST without a token is the SAML assertion consumer service** (`POST
  /auth/saml/{connection}/acs`): it comes from the identity provider's page, and it changes nothing
  but a one-minute handle; every check runs on the GET it is turned into.
- **The auth pages' CSP is built per page.** Chromium applies `form-action` to a form's whole
  redirect chain, and a successful sign-in ends at the client's `redirect_uri`. A page tied to an
  authorization request therefore lists that client's redirect origins next to `'self'`.
- An identity from another provider is `(connection, subject)`; only a *verified* address links
  to an existing account; `state` is paired with a cookie; provider errors are never echoed.
- Every URL fetched on an operator's say-so (OIDC discovery and endpoints, back-channel logout
  URIs, webhook endpoints), and the breached-password service, goes through `OutboundUrlPolicy`: https only, never a non-global address (as written or as
  resolved), checked at registration and again at send time, connecting to the addresses checked
  (`PinCheckedAddresses`). `CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES` waives this in development.
- Caddy sets `Cache-Control: no-store` on `auth.*` except discovery, the JWKS and static files,
  whose caching the application owns.

## Conventions

### PHP

- `declare(strict_types=1)` everywhere; PSR-12 at 120 columns; Psalm level 1 clean.
- **Value objects** are built by named constructors (`fromString`, `of`, `generate`) that throw
  `InvalidValue`; the real constructor is private. Prefer `readonly` classes, and `clone with`
  for a changed copy. Enums for closed sets (`GrantType`, `ErrorCode`, `ConnectionStrategy`).
- **Identifiers** are typed: UUID v4 value objects extending `UuidId`, never equal across kinds.
  `ClientId` is 1–64 visible ASCII characters without a colon (HTTP Basic cannot carry one).
- **Regular expressions** that anchor use the `D` modifier: without it, `$` accepts a trailing
  newline.
- **Never read a value back from an array key**: PHP turns `'10'` into `10`. Keys are for
  lookup.
- **Use PHP 8.5 on purpose**: `Uri\Rfc3986\Uri` for URIs that must compare exactly (never
  `parse_url`), `#[\NoDiscard]` on results that must be checked (verification, spending), the
  pipe operator where it clarifies a chain.
- Document every public class, and every non-obvious decision with the RFC section it follows.

### Use cases

- **An invokable class named for what it does** (`Authorize`, `RotateClientSecret`), taking a
  request object or value objects, returning a result object.
- **Expected outcomes are return values**, typically a union of result classes
  (`SignedIn | CredentialsRejected | SecondFactorRequired`). Exceptions are for the
  exceptional, and for protocol errors the specification answers with an error document
  (`OAuth2Error`, `BearerTokenError`).
- **A secret handed out is returned once** by the use case and stored only as its digest.
- **Development-only code checks for itself** (`DevelopmentAutoLogin`, `SeedDevelopmentData`
  receive `isDevelopment` and throw outside it), on top of the settings that forbid the
  combination.

### Persistence

- **One door to PostgreSQL**: `Adapter\Secondary\Persistence\PhpDb\Database`. SQL written out,
  named parameters, plain rows back (`fetchAll`, `fetchOne`, `fetchValue`, `execute`, which
  returns the affected-row count: the answer to "did my conditional `UPDATE` win?"). The query
  builder (`Database::adapter()`) is for dynamic filters only. Generated keys come from
  `INSERT … RETURNING`.
- **Transactions**: `transactional()` nests by joining the outer one; any exception rolls all of
  it back; there are no savepoints, and a database error cannot be caught to carry on (PostgreSQL
  refuses everything after a failed statement). Isolation is READ COMMITTED: exactly-once rests on
  row locks or conditional writes.
- **A unique constraint is the arbiter of uniqueness.** A repository turns SQLSTATE 23505 on the
  named constraint into `AlreadyExists`; nobody checks first and inserts second.
- **Repositories return copies**: a change exists only once saved. In-memory doubles clone on the
  way in and out.
- **Links are foreign keys**, cascading where the domain says so. A permission is a row a role
  references, so `PhpDbResourceServerRepository` reconciles permission rows instead of replacing
  them; the doubles apply the same cascades.
- **Columns**: only what the code reads. Lists are `jsonb`; instants are `timestamptz`, written
  and read through `Timestamp` (UTC, microseconds).
- **Migrations** are `migrations/NNNN_name.sql`: forward only, one transaction each, immutable once
  applied (checksummed), linear. No `CREATE INDEX CONCURRENTLY` (it cannot run in a transaction).
  A migration ships with the code that needs it.
- **Secrets that must be read back** go through `SecretCipher` with a row-specific context (`kid`,
  `user:42:totp`). The format is `base64(nonce ‖ ciphertext ‖ tag)`, pinned by a known-answer
  test.

### Redis

Keys are `<prefix>:<identifier>`, built by `Redis\Keys`: `forSecret()` digests anything a browser
could present (session ids, handles, device codes); `forIdentifier()` is for user ids and `sid`s.
A handle is claimed with `GETDEL`, so it works once. A handle that is unknown, spent, expired,
someone else's or names something deleted gives the same "expired" page.

### HTTP adapters

- **Status codes are named**: `Fig\Http\Message\StatusCodeInterface::STATUS_NOT_FOUND`, never `404`,
  in the adapters and the tests alike (the domain and the application hold none).
- **Parameters** are read with `RequestParameterReader`, never `getQueryParams()` or
  `getParsedBody()`, which keep the last of repeated values and rewrite names.
- **Cookies** are read from the `Cookie` header (`RequestCookies`, every value kept) and written
  through `SetCookie` (`HttpOnly; SameSite=Lax`, never a `Domain`, name and value validated).
  `AuthCookies` owns each cookie's name, path and lifetime, so a cookie is deleted with the path
  it was set with.
- **OAuth responses** go through `OAuth2Responder` (Diactoros `JsonResponse` on a PSR-17 factory).
  Token-endpoint errors are 400, or 401 with `WWW-Authenticate` for `invalid_client`. An
  authorization-endpoint error that cannot be redirected is a plain 400, never a challenge.
- **Protected resources** read tokens with `AccessTokenCredentials` and refuse with
  `BearerChallenger` (RFC 6750 status, challenge and error document; never cacheable).
- **Pages** are server-rendered laminas-view templates (`templates/`), with no script but a page's
  own module where it needs one (`public/auth/static/passkeys.js`: no build step, no dependency). A
  handler builds an `HtmlPage` view model; templates print and loop; a repeated block becomes a
  partial (`layout::page`, `auth::login`, `error::page`, `partial::field`). `PageRenderer` adds
  the layout and the headers every page carries (`no-store`, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: same-origin`, `Permissions-Policy`, the per-page CSP); `AuthPageResponder` adds
  the CSRF token.
  One stylesheet (`public/auth/static/auth.css`), light and dark through custom properties; the
  theme toggle is a POST setting a cookie.
- **Every printed value is escaped** with `escapeHtml()` or `escapeHtmlAttr()`: laminas-view does
  not escape on its own. `AuthPagesEscapingTest` renders every page with hostile values; a new
  page or variable gets a case there.
- **Errors are a page for a person and data for a program.** `ClientPreference::prefersHtml()`
  decides from `Accept` (HTML only when `text/html` weighs at least as much as JSON; `*/*` alone
  is a program). `ErrorResponder` sends the same status either way. Error text never comes from
  the request, an error page links nowhere onwards and sets no cookie. Endpoints whose format a
  specification fixes (token, introspection, revocation, userinfo) always answer JSON.
- **The QR code** for TOTP enrolment is drawn by the HTTP adapter (`QrCodeSvg`), sanitised for the
  page's CSP; the provisioning URI never appears in the markup.

### Outbound HTTP

PSR-18 is the port: adapters receive `Psr\Http\Client\ClientInterface` and PSR-17 factories,
never a concrete client. The composition root builds Guzzle (`HttpClientFactory`: 5 s to connect,
10 s in all, no redirects followed, no exception on a status). Tests use `Fake\FakeHttpClient`,
so the suite never reaches a real provider. Providers' failures are logged by endpoint and
status, never by body.

## Testing

Three suites, three base classes, all under `test/`:

| Suite | Base | Scope |
|---|---|---|
| `Unit` | PHPUnit `TestCase` | No I/O: domain rules, use cases with doubles, pure adapters (crypto, OpenAPI), architecture tests |
| `Integration` | `IntegrationTestCase` | One adapter against real PostgreSQL or Redis, with a scratch schema per test for tables of its own |
| `Acceptance` | `AcceptanceTestCase` | The whole application in-process: the real container, pipeline and routes |

- **Doubles and contracts**: every port has a double in `test/Support/Fake`. Where behaviour is
  shared, an abstract `test/Support/Contract/XContract` runs against both the double and the real
  adapter, so a double that drifts fails its own test.
- **Isolation**: integration and acceptance tests wipe every table and Redis database 1 before
  each test. `TestEnvironment` refuses a database whose name does not end in `_test`, and Redis
  database 0. Settings come from `TestEnvironment::variables()`, never the machine's `.env`.
- **Acceptance harness**: `get()`/`post()`, a cookie jar, `freezeClock()` (call it before the
  first request when a test moves time), deferred tasks run after each request, an active signing
  key installed before every test, a `RecordingLogger`. PHPUnit lowers `error_reporting`; the base
  class restores `E_ALL`.
- **Fixtures**: `OAuth2Fixtures` (users, clients, PKCE pairs, whole flows), `LoginFixtures`,
  `OidcFixtures` (`completeFlow`, `verifiedIdToken` checked against the JWKS fetched over HTTP),
  `MachineFixtures`, `ManagementFixtures` (`adminToken()`, `api()`, with every response checked
  against the OpenAPI document), `TestSigningKeys`, `Clients`, `Audits`, `BackChannelLogouts`.
- **Use cases** take `new InMemoryDomainEvents()` and assert on `ofType()`.
- **Conformance**: the OpenID Foundation suite passes the Config OP plan and, but for one test
  OAuth 2.1 forbids passing (a code flow without a nonce or PKCE), the Basic OP plan.
  `conformance/README.md` explains how to run it.

Tests state behaviour from the specifications, and name the RFC section where it matters.

## Recipes

- **A setting**: a constructor parameter of `Configuration\Settings`, with a default, a doc
  comment saying why it exists, a `#[Range]` for a number, and a test. Nothing else needs editing.
- **A console command**: a `symfony/console` command in `Adapter\Primary\Cli`, a factory in
  `Bootstrap\Container`, one line in `ConfigProvider::CONSOLE_COMMANDS`.
- **A port and its adapter**: the interface in the domain (a repository) or `Application\Port`;
  the double in `test/Support/Fake`; a contract in `test/Support/Contract` run by both the
  double's test and the adapter's integration test; a factory; the alias in `ConfigProvider`.
- **A table**: a new migration file, the repository through `Database`, an integration test.
- **A grant**: a class implementing `Token\Grant`, registered in `IssueTokenFactory`; discovery
  picks it up.
- **An endpoint**: a route in `config/routes.php` (with the methods it answers), a handler that
  translates, one use case. If it is advertised, add it to `ProviderMetadata`; `OidcTest` fetches
  it.
- **A Management API operation**: the path in `docs/openapi/management-api.yaml` (a short
  `summary`, examples of its body and its success), a route behind `ManagementApiMiddleware`, a
  handler, a use case. `ManagementApiTest` fails if the routes and the
  document disagree; `ManagementContractTest` if the document's scopes differ from
  `ManagementPermission::cases()`. The dashboard regenerates its types from the document.
- **A domain event**: a readonly class in the context's `Event` namespace, dispatched by the use
  case, recorded by one trail. `AuditTrailsTest` fails until it is.
- **A page**: a template in `templates/auth`, an `HtmlPage` built by the handler, an
  `AuthPagesEscapingTest` case.
- **A vendor library**: its namespace in deptrac's Vendor layer; reachable from adapters only.

## Definition of done

1. The behaviour is covered by acceptance tests; domain rules by unit tests with no adapter.
2. Each new port has a double and a contract test, and each new adapter passes it.
3. `composer check` is green: PHPCS, Psalm level 1, deptrac, PHPUnit.
4. Public classes and every non-obvious decision are documented, with the RFC section cited.
5. A change to the Management API is in the OpenAPI document; a change to discovery is in
   `ProviderMetadata`.
6. This file is updated when a rule, a flow or the architecture changes.

## Known issues and decisions

- **The database library is pinned, with a workaround.** At the pinned commit,
  `php-db/phpdb-pgsql` runs `SELECT LASTVAL()` after every statement. In a session that has not
  used a sequence, that query fails; the library swallows the exception, but PostgreSQL has
  already aborted the transaction, so its writes are silently discarded and `COMMIT` becomes a
  `ROLLBACK`. `PostgresConnection` overrides the lookup;
  `DatabaseTest::testReadingInsideATransactionDoesNotDiscardItsWrites` fails without it. The
  library is pre-1.0; persistence is behind ports, so a break touches
  `Adapter/Secondary/Persistence/PhpDb` alone.
- **Own OAuth 2.1 / OIDC engine.** The protocol is implemented from the RFCs in the domain and
  application layers; there is no external OAuth server library.
- **PHP-FPM behind Caddy**, share-nothing: no worker mode, no long-lived state in PHP. Work after
  the response runs through `DeferredTasks` after `fastcgi_finish_request()`; a queue adapter can
  replace it behind the same port.
- **Mail** goes through Symfony Mailer's ESMTP transport (`smtp`, STARTTLS required unless turned
  off, SMTPS on 465), plus `console` (development) and `none`. No queue: a sign-in email is sent
  while the person waits.
- **Libraries**: Mezzio (PSR-7/11/15, laminas-servicemanager, FastRoute) as the HTTP adapter;
  laminas-view for pages; symfony/console; Guzzle as the PSR-18 client; `web-token/jwt-library`
  for verification only; `web-auth/webauthn-lib` behind `PasskeyVerifier` (one adapter,
  `WebAuthn\WebAuthnLibPasskeyVerifier`); `simplesamlphp/saml2` and `xml-security` behind
  `Saml\SamlServiceProvider` (`Saml\SimpleSamlServiceProvider`; RSA signatures only, its plugin
  denied, `bcmath` in the image; `docs/design/saml-connections.md` §11); `bacon/bacon-qr-code`;
  monolog. No Twig, no front-end framework.
- **The passkey verifier has no double that runs its contract.** `PasskeyVerifierContract` feeds
  it genuine responses from `test/Support/SoftwareAuthenticator` (real EdDSA, ES256 and RS256 keys,
  real CBOR), which a double could only pass by being the adapter again. Use cases are tested with
  `FakePasskeyVerifier`, which answers what it is told; the exception to rule 9 is this port and
  the SAML service provider's: `SamlServiceProviderContract` signs genuine responses with
  `test/Support/Saml/TestIdentityProvider` (real RSA keys, attacks included), and use cases take
  `FakeSamlServiceProvider`.
- **The dashboard** is the Next.js application of the
  [clavia-dashboard](https://github.com/clavia-auth/clavia-dashboard) repository: a confidential
  client (a backend for frontend) that knows this server only by the OpenAPI document and
  discovery, and calls `auth.*` from its own server, never from a browser. `seed-dev` registers
  it with fixed development credentials and back-channel logout (`sid` required), and prints its
  settings. Caddy forwards `/dashboard` to `CLAVIA_DASHBOARD_UPSTREAM` (its dev server on the host,
  port 3000, by default).
- **Not built**: multi-tenancy. If it comes, the infrastructure subdomains (`auth`,
  `management`, `www`…) are reserved labels on any domain, and a new host stays a database row,
  not a redeploy.
