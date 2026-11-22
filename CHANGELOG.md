# Changelog

All notable changes to Clavia are written here, for the people who run it. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Clavia follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/clavia-auth/clavia/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/clavia-auth/clavia/releases/tag/v0.2.0
[0.1.0]: https://github.com/clavia-auth/clavia/releases/tag/v0.1.0
