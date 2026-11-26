# Changelog

All notable changes to Clavia are written here, for the people who run it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Clavia follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A reference for the authorization server** (#93), beside the Management API's: every endpoint an
  application or an API calls on `auth.{domain}` (token, PAR, introspection, revocation, device code,
  registration, userinfo, the JWKS, discovery, authorize and end session), its parameters, answers and
  refusals, in `docs/openapi/authorization-server.yaml`, checked against what the server answers. The
  guides link its operations.

- **Guides for the Management API** (#98), published with the reference: getting a token (a machine
  client, or a person signing in), scopes and roles, errors and stepping up, paging and search,
  DPoP-bound tokens, and registering clients with an initial access token. The reference's bar and
  introduction link them, and each release keeps its own.

- **Prometheus metrics** (#23): tokens issued, sign-ins, sign-in refusals by reason, OAuth errors by
  code, mail sent and failed, and request latency by route, at `/metrics` on the internal listener
  (Caddy's port 8081, never `auth.*` or `management.*`), shared by every process through Redis. New
  setting **`CLAVIA_METRICS_ENABLED`** (on). The Helm chart gains a metrics Service and an optional
  ServiceMonitor. A proxy of your own in front of PHP-FPM must answer `/metrics` with `404` on both hosts,
  and pass `CLAVIA_LISTENER=internal` only from an internal listener.

- **A production deployment kit** (#22): [`docs/PRODUCTION.md`](docs/PRODUCTION.md), a guide to hosts,
  TLS, secrets, signing keys, the first start (the dashboard's client and the first administrator),
  backups and upgrades; a Docker Compose file for one host ([`deploy/compose`](deploy/compose), with
  Caddy obtaining certificates, migrations before the application starts, and the scheduled commands
  run every minute and daily); and a Helm chart ([`deploy/helm/clavia`](deploy/helm/clavia): PHP-FPM
  and Caddy in each pod, migrations as a Job before every install and upgrade, the scheduled commands
  as CronJobs, an Ingress for both hosts, and the dashboard). One production Caddyfile serves both.

### Fixed

- **The version reported** by `/healthz` and `bin/clavia --version` is the release's: 0.2.0 to 0.4.0
  reported `0.1.0`.
- **The image's files are readable by PHP-FPM's workers** whatever the permissions of the checkout it
  is built from. An image built from a checkout with private files answered every request with `500`;
  the published images, built from a fresh checkout, were not affected.

## [0.4.0] - 2026-11-25

Integrations: directories provisioning accounts through SCIM 2.0, enterprise sign-in through SAML 2.0,
webhooks for the audit trail, custom claims in tokens, and bulk jobs on the users
(`docs/design/scim-provisioning.md`, `docs/design/saml-connections.md`, `docs/design/webhooks.md`,
`docs/design/custom-claims.md`).

**Before upgrading, read Changed below: passwords and client secrets are now PBKDF2 hashes, and
bcrypt hashes no longer verify.**

### Added

**Directories: SCIM 2.0** (RFC 7643, RFC 7644)

- **Provisioning tokens** (#129): `/api/v1/provisioning-tokens` issues a token for one pool, OpenID
  Connect or SAML connection, shown once with the base URL to give the directory
  (`https://management.{domain}/scim/v2`). It lasts a year by default (two at most), is flagged
  `expiring_soon` thirty days before its end, and can be revoked. Its options: the attribute naming a
  person to an enterprise connection (`externalId` or `userName`), whether the directory's addresses
  are trusted (off by default), and whether a `DELETE` only deactivates (off by default). A wrong token
  is one `401`, and failed tokens are throttled per address like the machine endpoints.
- **Users** (#130, #131): a directory creates, reads, lists (filters on `userName`, `externalId`, `id`
  and `emails.value`), replaces, modifies (the `PATCH` forms Entra ID and Okta send) and deletes the
  accounts of its token's connection. Accounts have no password, and a password sent is refused.
  In an OpenID Connect or SAML connection, the account is linked ahead of the person's first sign-in,
  so that sign-in finds it. **Deactivating a leaver ends every session, with back-channel logout,
  and stops their tokens**, as an operator's deactivation does. Resources carry ETags, and
  `If-Match` is honoured.
- **Groups** (#132): `/scim/v2/Groups`. A role an operator marks **`provisionable`** is given to the
  members of the group named like it, and taken back when they leave or the group goes; a role also
  given by hand stays.
- **`require_provisioning`** on OpenID Connect and SAML connections (#130): only the people a
  directory provisioned sign in through it, and nobody else's account is created on the way.
- What a directory does is recorded with its token as the actor, a new actor kind, `provisioning`.

**Enterprise sign-in: SAML 2.0**

- **SAML connections** (#125): `POST /api/v1/connections` takes `strategy: saml` with the identity
  provider's metadata, as a document or a URL (Entra ID, Okta, ADFS and Keycloak read);
  `POST /api/v1/connections/{name}/refresh-metadata` reads the URL again. Each connection publishes
  this server's metadata at `GET /auth/saml/{connection}/metadata`.
- **Signing in** (#126): the login page offers each enabled SAML connection. A person is known by the
  connection and their subject, never by their address; an address is verified only when the
  connection trusts its identity provider for addresses (`email_trusted`). A second factor applies as
  after any sign-in, and a replayed assertion signs nobody in.
- **Signed requests and encrypted assertions** (#127): a connection signs its requests
  (`sign_requests`, on by default) and reads assertions encrypted to this server
  (`require_encryption` refuses plain ones). AES-CBC is refused unless the connection turns
  `require_gcm` off, for an identity provider such as ADFS that encrypts with it.
- **Service provider keys** (#123, #124): a signing key and an encryption key (RSA 3072), sealed in
  PostgreSQL, or kept in AWS KMS, Google Cloud KMS or Azure Key Vault, where they never leave the
  provider. `bin/clavia saml-keys:generate`, `saml-keys:rotate` (a next pair published, promoted after
  `CLAVIA_SAML_KEY_OVERLAP_DAYS`) and `saml-keys:list`; `GET /api/v1/saml-keys` and
  `POST /api/v1/saml-keys/rotate`. **Generate them before registering a SAML connection** that signs
  its requests or receives encrypted assertions.

**Webhooks**

- **Endpoints** (#118): `/api/v1/webhooks`, up to twenty https endpoints, each listening to audit
  event types or `*`, held to the outbound URL policy. The secret is generated, shown once and kept
  sealed; a rotation keeps the previous one signing for a day.
- **Delivery** (#119): every audit event an enabled endpoint subscribes to is queued in its own
  transaction and sent by **`bin/clavia webhooks:deliver`**, to run every minute: the event as
  `GET /api/v1/audit-events` shows it, signed per the Standard Webhooks specification, retried for
  about a day and a half, then abandoned.
- **Operating them** (#120): each endpoint's delivery log, a test event on demand, and endpoints failing
  for five days switched off until switched on again.

**Custom claims**

- **Application metadata** on accounts (#114): `app_metadata`, a JSON object only operators write,
  with a new scope, `update:users_app_metadata`.
- **On APIs** (#115): `claims`, up to twenty mappings read from the account (`email`,
  `email_verified`, `connection`, `profile.<field>`, `app_metadata.<path>`, `roles`) or a constant,
  in the API's JWT access tokens and in introspection.
- **On applications** (#116): `claims`, in the application's ID tokens, its userinfo answers, or both;
  first-party applications only.

**Bulk jobs on the users**

- **Import** (#19): `POST /api/v1/jobs/users-imports` queues an NDJSON file into one pool, at most
  10,000 lines and 5 MiB. A password hash is taken only as PBKDF2-HMAC-SHA-256, and an address
  already in the pool is refused, never updated.
- **Export** (#19): `POST /api/v1/jobs/users-exports` queues an export of one connection, in the shape
  an import takes, **never with a password hash**; `GET /api/v1/jobs/{job_id}/output` downloads it.
- **`bin/clavia jobs:run`**, to run every minute, runs the queued jobs.
- **`bin/clavia users:import-sqs <queue-url>`** (#108) imports accounts from an AWS SQS queue, one per
  message. It needs `aws/aws-sdk-php`.

**The Management API reference** is published to GitHub Pages for each release (#101), with a short
label for each operation and an example for each body and answer (#99, #100).

**Settings**

| Setting | Default | What it does |
|---|---|---|
| `CLAVIA_SAML_KEY_BACKEND` | `postgres` | Where the SAML service provider keys live: `postgres`, `aws-kms`, `gcp-kms` or `azure-key-vault` |
| `CLAVIA_SAML_SIGNING_KEY_REF` | none | With a KMS: the signing key's version (never an alias) |
| `CLAVIA_SAML_ENCRYPTION_KEY_REF` | none | With a KMS: the encryption key's version |
| `CLAVIA_SAML_NEXT_SIGNING_KEY_REF` | none | With a KMS: the next signing key, published ahead of a rotation |
| `CLAVIA_SAML_NEXT_ENCRYPTION_KEY_REF` | none | With a KMS: the next encryption key |
| `CLAVIA_SAML_RETIRED_ENCRYPTION_KEY_REFS` | none | With a KMS: encryption keys still tried after a rotation |
| `CLAVIA_SAML_KEY_OVERLAP_DAYS` | 14 | How long a next pair is published before it is promoted, and a retired one kept |

**Migrations**: `0036` to `0049`, applied by `bin/clavia db:migrate`. All of them add tables, columns,
indexes or checks; none rewrites existing data.

**Management API scopes**: `update:users_app_metadata`, `read:webhooks`, `create:webhooks`,
`update:webhooks`, `delete:webhooks`, `read:provisioning_tokens`, `create:provisioning_tokens` and
`delete:provisioning_tokens`. On an existing server, run `bin/clavia management-api:register` once
after upgrading, then give them to the roles (and the machine clients' grants, with `clients:grant`)
that should hold them: nobody holds a new scope until then.

**Scheduled commands**: run `bin/clavia jobs:run` and `bin/clavia webhooks:deliver` every minute.

### Changed

- **Passwords and client secrets are hashed with PBKDF2-HMAC-SHA-256** (#106), for FIPS 140 (NIST
  SP 800-132): 600,000 iterations, a 16-byte random salt each, derived through OpenSSL, so its FIPS
  provider does the work when the system runs in FIPS mode. **bcrypt hashes no longer verify**:
  every account must choose its password again (the reset link, or
  `POST /api/v1/users/{user_id}/password-reset`), and every confidential client needs a new secret
  (`POST /api/v1/clients/{client_id}/rotate-secret`, or a new `clients:create-m2m`). A password or a
  secret may now be up to 1,024 bytes, where bcrypt took 72, and a sign-in replaces a hash at another
  iteration count with one at today's.
- **Caddy routes `/scim/v2/*` on `management.*`** and refuses it on `auth.*` (#129), and leaves the
  caching of `/auth/saml/*/metadata` to the application (#125). A deployment with its own proxy must do
  the same: send `/scim/v2/*` to PHP as it does `/api/v1/*`.
- **The PHP image includes `bcmath`** (#122), which the SAML library needs. An image built from your own
  Dockerfile needs it too.
- **`CLAVIA_AZURE_FEDERATED_TOKEN_FILE` must be an absolute local path** (#104): a URL or a stream
  wrapper there now stops the server from starting.
- **New required fields in the Management API document**: an audit event's actor gains
  `provisioning_token_id`, and its kind `provisioning`; a user gains `app_metadata`; a client and an API
  gain `claims`; a connection gains `saml` and `require_provisioning`; a role gains `provisionable`.
  Clients that generate types from `docs/openapi/management-api.yaml` regenerate them.

### Security

- **No directory can make anyone an administrator of this server**: a provisionable role never holds a
  permission on a system API, refused by the role and by the database, and only provisionable roles are
  granted through groups.
- **A provisioning token reaches one connection.** Another connection's accounts and groups are not
  found, an address from a directory is verified only on the operator's word, and a token is shown
  once and stored as its digest.
- **SAML**: identity providers' certificates are pinned (RSA only, 1 to 3 per connection); content keys
  are unwrapped with RSA-OAEP only, never RSA PKCS#1 v1.5; AES-GCM is required unless a connection opts
  out; an assertion is accepted once; every failure gives the same page after the same steps, and
  failures of the response itself count toward the sign-in throttle.
- **Webhooks** go only to https URLs that pass the outbound URL policy at registration and at every
  delivery, connect to the addresses checked, follow no redirect, and never read the answer.
- An export never holds a password hash, a factor, a passkey or a session, and an import's input is
  let go when its job ends.

## [0.3.0] - 2026-11-23

Tokens and policies: JWT access tokens, authentication levels and step-up, MFA policies, pushed
authorization requests, DPoP, and dynamic client registration (`docs/design/mfa-policies.md`,
`docs/design/dpop.md`, `docs/design/dynamic-client-registration.md`).

### Added

**Tokens**

- **JWT access tokens** (RFC 9068), chosen per API with `access_token_format` (`opaque`, the
  default, or `jwt`) in the Management API. A JWT is `typ: at+jwt`, signed with the active key, and
  carries `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti` and `scope`, plus `auth_time` and
  `acr` for a person. An API that validates a JWT on its own accepts it until `exp`, so revocation
  cannot reach it there: the access token lifetime bounds a revoked JWT's life.
- **Authentication levels.** ID tokens, JWT access tokens and introspection carry `acr` (the PAPE
  multi-factor URI, or `phr` for a passkey) and `auth_time`, worked out from how the person signed
  in. A refresh family keeps its first sign-in. Discovery names `acr_values_supported`.
- **Signing keys in the Management API**: `GET /api/v1/signing-keys` (`read:signing_keys`) and
  `POST /api/v1/signing-keys/rotate` (`create:signing_keys`) do what `keys:list` and `keys:rotate`
  do, naming keys by `kid`, never by their material. With a remote signing backend both answer
  `409`.

**Policies and step-up**

- **`acr_values`** at the authorization endpoint (RFC 9470): a signed-in session that falls short
  steps up. `prompt=none` answers `interaction_required`; a person holding a factor that would do
  is asked for it; anyone else gets `unmet_authentication_requirements`.
- **MFA policies** per application and per API (`mfa_policy`: `optional`, the default, or
  `required`), at the authorization endpoint and at device approval. A person with no second
  factor and a verified address **enrols on the way**, then carries on with the request. New
  authorizations only: refresh tokens issued before keep working.
- **Step-up at the Management API**: when its own `mfa_policy` is `required`, a person's token
  from a one-factor sign-in is `401 insufficient_user_authentication`, with the `acr_values` to
  ask for. Machine tokens are not concerned. `seed-dev` turns it on.
- **Pushed authorization requests** (RFC 9126) at `POST /oauth2/par`: the client sends its request
  over the back channel and gets a `request_uri`, good for `CLAVIA_PAR_LIFETIME`. A client
  registered with `require_pushed_authorization_requests` must push. Discovery names the endpoint.
- **Breached passwords** (`CLAVIA_BREACHED_PASSWORD_CHECK`, off by default): a new password found
  in Have I Been Pwned's Pwned Passwords is refused, at sign-up, at a reset and through the
  Management API. Only five characters of its SHA-1 leave the server; when the service is down the
  password is let through and a warning logged.

**DPoP** (RFC 9449)

- **Sender-constrained tokens.** A token request carrying a `DPoP` proof gets tokens bound to the
  proof's key (`token_type: DPoP`, `cnf.jkt` in JWT access tokens and introspection). Proofs are
  ES256, EdDSA or RS256, checked against the method, this server's own URL, their age and the
  server's nonce, and accepted once each. Discovery names `dpop_signing_alg_values_supported`.
- **Bound codes and refresh tokens.** `dpop_jkt` at the authorization endpoint, or a `DPoP` proof
  at `/oauth2/par`, binds the code to a key; a public client's refresh tokens are bound to the key
  they started with.
- **Userinfo and the Management API** take a bound token as `Authorization: DPoP` with a fresh
  proof, and refuse it presented as a bearer token.
- **DPoP required per client** (`dpop_bound_access_tokens`, off by default): such a client is
  refused any token without a proof.

**Dynamic client registration** (RFC 7591, RFC 7592)

- **Initial access tokens**, issued by an operator (`POST /api/v1/initial-access-tokens` or
  `bin/clavia clients:registration-token`), listed and revoked. Each has a description, an expiry
  (a minute to ninety days, seven by default) and a number of uses (1 to 1000), and is shown once.
- **`POST /oauth2/register`**, when `CLAVIA_CLIENT_REGISTRATION=token`, for a bearer of an
  initial access token: software registers itself. A client registered this way is **always
  third-party**, so it never reaches a system API and is asked for consent. It may hold the code
  flow and refresh tokens, keeps PKCE, and uses https redirect URIs, or loopback ones for a native
  application. Discovery names `registration_endpoint` only when registration is on.
- **`GET`, `PUT` and `DELETE /oauth2/register/{client_id}`**, with the registration access token
  the client was given: it reads, replaces or deletes its registration, and the token is replaced
  at each update. An operator's client is never reachable there.
- **`bin/clavia clients:purge-unused`**, to run daily: deletes a self-registered client never
  issued a token after `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` days.

**Settings**

| Setting | Default | What it does |
|---|---|---|
| `CLAVIA_TOKEN_MAX_FAILURES` | 20 | Failed client authentications or grants per subject within the window before `429` |
| `CLAVIA_TOKEN_FAILURE_WINDOW` | 300 s | The window those are counted in; every failure restarts it |
| `CLAVIA_PAR_LIFETIME` | 60 s | How long a pushed request's `request_uri` is good for |
| `CLAVIA_DPOP_PROOF_LIFETIME` | 60 s | How old a DPoP proof may be |
| `CLAVIA_DPOP_NONCE_LIFETIME` | 300 s | How long a DPoP nonce is current |
| `CLAVIA_BREACHED_PASSWORD_CHECK` | `false` | Refuse passwords found in Pwned Passwords |
| `CLAVIA_CLIENT_REGISTRATION` | `off` | `token` opens `/oauth2/register` to holders of an initial access token |
| `CLAVIA_CLIENT_REGISTRATION_MAX_PER_ADDRESS` | 20 | Registrations one client address may ask for per window |
| `CLAVIA_CLIENT_REGISTRATION_WINDOW` | 3600 s | The window those are counted in |
| `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` | 30 days | How long a self-registered client never used is kept |

**Migrations**: `0026` to `0035`, applied by `bin/clavia db:migrate`. All of them add tables,
columns or indexes; none rewrites existing data.

**Management API scopes**: `read:signing_keys`, `create:signing_keys`,
`read:initial_access_tokens`, `create:initial_access_tokens` and `delete:initial_access_tokens`.
On an existing server, run `bin/clavia management-api:register` once after upgrading: it adds them
to the Management API, keeping its name. Then give them to the roles (and the machine clients'
grants, with `clients:grant`) that should hold them: nobody holds a new scope until then.

### Changed

- **Failures are limited at the token, introspection, revocation and device authorization
  endpoints.** Past `CLAVIA_TOKEN_MAX_FAILURES` within the window, the endpoint answers `429` with
  `Retry-After`, before any secret is checked. Failures count per client address, and per client
  only once it has proved itself with a secret, so nobody locks a client out by sending its id. A
  busy client that does not fail is never refused.
- **New required fields in the Management API document**: a client gains `mfa_policy`,
  `require_pushed_authorization_requests`, `dpop_bound_access_tokens` and `registration`; an API
  gains `access_token_format` and `mfa_policy`. Clients that generate types from
  `docs/openapi/management-api.yaml` regenerate them.
- Bearer refusals at userinfo and the Management API may now be `invalid_dpop_proof`, and a DPoP
  request is challenged with `WWW-Authenticate: DPoP`.

### Security

- Every token this server signs is explicitly typed and checked as such (RFC 8725 §3.11): a JWT
  access token is no longer accepted as an `id_token_hint` at sign-out.
- A DPoP-bound token presented as a bearer token is refused, so binding is not optional for
  whoever steals one. A bound code redeemed with another key is refused and spent.
- A self-registered client is third-party by construction, whatever its request says, and
  registration is never open to anybody: it is off by default, and on only for holders of an
  operator's initial access token, limited in uses and time.

## [0.2.0] - 2026-11-23

Passkeys: as a second factor, and as the way in (`docs/design/passkeys.md`, phases 1 and 2).

### Added

- **Passkeys as a second factor.** People add, rename and remove passkeys at `/auth/passkeys`, after
  a recent sign-in (`CLAVIA_PASSKEY_REAUTH_WINDOW`). An account with a passkey is asked for it after
  its password, at `/auth/mfa`; a recovery code works instead, for either kind of second factor.
  The first passkey of an account with no authenticator app and no recovery codes brings a set,
  shown once.
- **Signing in with a passkey.** The login page offers passkeys in the address field's autofill and
  behind a "Sign in with a passkey" button, wherever the application lets anybody in: no address is
  typed. A passkey whose authenticator verified the person (a biometric or a PIN) is multi-factor
  by itself (`CLAVIA_PASSKEY_SATISFIES_MFA`, on by default). Every refusal looks like a wrong
  password.
- **`amr`** carries `hwk` for a device-bound passkey and `swk` for a synced one (RFC 8176), with
  `user` when nobody was verified, then `mfa`.
- **Management API**: `GET /api/v1/users/{user_id}/passkeys` and
  `DELETE /api/v1/users/{user_id}/passkeys/{passkey_id}`; users gain `passkey_count`. No new scope.
- **Audit**: `passkey.registered`, `passkey.renamed`, `passkey.removed` and
  `passkey.counter_regressed`; failed sign-ins gain the reasons `unknown_passkey`,
  `invalid_passkey` and `passkey_counter_regressed`. Nothing records a credential id or a key.
- **Settings**: `CLAVIA_PASSKEYS_ENABLED`, `CLAVIA_WEBAUTHN_RP_ID`, `CLAVIA_WEBAUTHN_RP_NAME`,
  `CLAVIA_WEBAUTHN_CEREMONY_LIFETIME`, `CLAVIA_PASSKEY_MAX_PER_USER`, `CLAVIA_PASSKEY_REAUTH_WINDOW`
  and `CLAVIA_PASSKEY_SATISFIES_MFA`, documented in `src/Configuration/Settings.php`. Every default
  is ready to use; the relying party id is the sign-in host.
- **Migration `0025_passkeys`**: the `passkeys` table. Run `clavia db:migrate` when upgrading.

### Changed

- **The sign-in origin runs one script**, `/auth/static/passkeys.js`, on the pages that need it: the
  login page, the second-factor page and the passkey pages. Those pages allow `script-src 'self'`
  with Trusted Types and no policy (no inline script, no `eval`, no other origin); every other page
  still allows no script. Every page now sends `Permissions-Policy` confining WebAuthn to this
  origin. With `CLAVIA_PASSKEYS_ENABLED=false` no page runs script.
- **`mfa_enrolled`** on a user is true for a confirmed authenticator app *or* a passkey, and
  **`passkey_count` is a new required field** of `User`: clients that generate types from
  `docs/openapi/management-api.yaml` regenerate them.
- **Turning the authenticator app off** keeps the recovery codes while a passkey remains. An
  operator's reset (`DELETE /api/v1/users/{user_id}/mfa`) still removes them.

### Security

- Passkeys are bound to the sign-in origin, matched exactly. A ceremony is single-use, short-lived
  and bound to what it answers. A signature counter that goes back refuses the sign-in and is
  audited.
- After a passkey sign-in, a passkey is never accepted as the second factor, so one device cannot
  count twice.
- Passkeys need the sign-in pages on https: an issuer that is not (loopback in development) turns
  them off, with a warning.
- Verification uses `web-auth/webauthn-lib` 5.3, behind one adapter. Attestation is `none`: the
  make of an authenticator labels a passkey and never decides anything.

## [0.1.0] - 2026-11-22

The first release: an OAuth 2.1 / OpenID Connect authorization server with interactive sign-in,
second factors, social and OpenID Connect connections, and a Management API. The OpenID Foundation
conformance suite passes the Config OP plan and the Basic OP plan, but for one test that OAuth 2.1
forbids passing (a code flow with neither PKCE nor a `nonce`); see
[`conformance/README.md`](conformance/README.md).

### Added

**OAuth 2.1**

- Authorization code flow with PKCE (S256 only), exact redirect URI matching, single-use codes
  bound to the client, the redirect URI and the challenge, and an `iss` response parameter
  (RFC 9207).
- Refresh tokens that rotate on every use, with replay detection that revokes the whole family.
- Client credentials for machine clients, scoped by a grant on an API, and the device
  authorization grant (RFC 8628).
- Token introspection (RFC 7662) and revocation (RFC 7009).
- APIs (resource servers) with permissions, an `audience` on every request, and roles that narrow
  a person's token to what their roles grant.
- Applications owned by the operator or by a third party, with a consent screen where the policy
  asks for one.
- `prompt`, `max_age` and a decision made once at the authorization endpoint; request objects are
  refused.

**OpenID Connect**

- Discovery (`/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`),
  the JWKS, ID tokens and userinfo.
- RP-Initiated Logout and Back-Channel Logout, with browser sessions that have an idle and an
  absolute lifetime and a `sid`.
- Signing backends: `postgres` (the key sealed with AES-256-GCM), AWS KMS, Google Cloud KMS, Azure
  Key Vault, or your own `RemoteSigningKey` implementation. Keys rotate with a grace period during
  which the retired key stays published.

**Sign-in**

- Password sign-in with throttling per account and per client address, and a single answer for
  every kind of failure.
- Two-factor authentication: TOTP (RFC 6238) and recovery codes.
- Social sign-in with Google and GitHub, and any OpenID Connect provider an operator registers;
  an account is `(connection, subject)`, linked by address only when it is verified.
- Passwordless sign-in by email, with a code or a link.
- Self-service accounts: sign-up, email verification and password reset, each switched on per pool.
- Connections: which ways to sign in each application may use.
- Server-rendered sign-in pages with no JavaScript, light and dark.

**Management API** (`/api/v1/*`, contract in `docs/openapi/management-api.yaml`)

- Users, applications, APIs, roles and their permissions, connections, sessions and consents, with
  RFC 9457 problem documents and a request validator driven by the contract.
- Create a user without a password and mail them the link to choose one:
  `POST /api/v1/users` takes no password, and `POST /api/v1/users/{user_id}/password-reset`
  sends an invitation, or a reset to an account that has a password. It needs the new scope
  `create:user_tickets`.
- The audit trail at `GET /api/v1/audit-events`, append-only and recorded from domain events.

**Operations**

- The `bin/clavia` console: configuration, migrations, signing keys, the Management API and its
  scopes, machine clients and their grants, roles including the first administrator, audit
  purging, and development data.
- Docker Compose for development: Caddy, PHP-FPM, PostgreSQL, Redis.
- A container image for each release, `ghcr.io/clavia-auth/clavia`: the application and its runtime
  dependencies, PHP-FPM alone, configured by `CLAVIA_*` variables. How releases are made is in
  [`docs/RELEASING.md`](docs/RELEASING.md).
- A security review of every adapter in `docs/SECURITY-REVIEW.md`.

**Settings and migrations**

- Every setting is a `CLAVIA_*` variable, documented in `.env.example`; `clavia config` prints
  them as the server sees them. `CLAVIA_ROOT_DOMAIN` is the only one with no default: every
  host and the issuer derive from it, so changing it later invalidates the tokens already issued.
  Set `CLAVIA_ENV=production` in production; the default is development.
- Migrations `0001` to `0024` create the schema. They run forward only and are checksummed, so a
  migration that has been applied is never edited.
- Run `clavia management-api:register` after installing or upgrading, so the Management API's
  scopes include `create:user_tickets`.

### Security

- Passwords and client secrets are bcrypt hashes (cost 12); codes and tokens are stored as SHA-256
  digests.
- Every URL fetched on an operator's say-so (OpenID Connect discovery, back-channel logout) is
  checked against private and non-global addresses, at registration and at send time.
- No form says whether an address has an account, and a link emailed to an address changes
  something only on a POST, never on the GET a mail scanner makes.
- The sign-in session cookie is host-only and the sign-in origin runs no JavaScript.

### Not included

- Multi-tenancy.
- Request objects (`request`, `request_uri`) and the `address` and `phone` scopes.
- A queue for mail: a sign-in email is sent while the person waits.

[Unreleased]: https://github.com/clavia-auth/clavia/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/clavia-auth/clavia/releases/tag/v0.4.0
[0.3.0]: https://github.com/clavia-auth/clavia/releases/tag/v0.3.0
[0.2.0]: https://github.com/clavia-auth/clavia/releases/tag/v0.2.0
[0.1.0]: https://github.com/clavia-auth/clavia/releases/tag/v0.1.0
