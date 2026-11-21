# Security review of the adapters (Step 20)

A review of every adapter group under `src/Adapter` against the invariants in `CLAUDE.md`,
made before cut-over, together with the OpenID Foundation conformance run
([`conformance/README.md`](../conformance/README.md)). It is the project's own review, not
a third-party audit; one is worth commissioning before Clavia holds real accounts.

## Method

- Each adapter group was read for what an attacker controls on the way in and what leaves on
  the way out, and checked against the test that pins it.
- Codebase-wide searches: dynamic code execution and deserialisation; SQL assembled from
  values instead of bound parameters; secrets compared with `==`/`===` instead of
  `hash_equals()`; non-cryptographic randomness; cookies without `Secure`/`HttpOnly`/`SameSite`.
- The conformance suite drove the protocol endpoints with a real browser.

## Findings

| # | Where | Finding | Status |
|---|---|---|---|
| 1 | `Http\Auth\DeviceHandler` | Typing user codes at `/auth/device` was not rate-limited. RFC 8628 §5.1 says it SHOULD be: a user code is about 34 bits, kept short-lived and typable because nobody can try codes without end. | **Fixed.** `Application\OAuth2\Device\UserCodeThrottle`: misses counted per signed-in person and per client address (`CLAVIA_LOGIN_MAX_ATTEMPTS` per `CLAVIA_LOGIN_ATTEMPT_WINDOW`), `429` once either is reached, before anything is looked up. |
| 2 | `/oauth2/authorize`, `/oauth2/token` | The conformance suite's OIDC tests send no PKCE, and every request was refused. | **Changed deliberately.** `require_pkce` per client, true by default; false only for a confidential client, and then only for an `openid` request with a `nonce` (OAuth 2.1 §7.5.1). A `code_verifier` presented for a code issued without a challenge is `invalid_grant` (§4.1.3, the downgrade). Enforced in the domain and by database checks. |
| 3 | `IdTokenClaims` | Scope claims (`email`, profile) went into the ID token as well as userinfo. Allowed, but OIDC Core §5.4 sends them to userinfo whenever an access token is issued, and an ID token travels further — the browser, `id_token_hint`, logs. | **Changed.** The ID token carries `sub` and the protocol claims only; scope claims come from userinfo. |
| 4 | `Http\Oidc\UserInfoHandler` | A bearer token in a form body (RFC 6750 §2.2) is refused. | **Kept.** RFC 6750: SHOULD NOT be used unless the header cannot be. |

## What was found sound

- **SQL** (`Persistence\PhpDb`): every value is a bound parameter. Concatenated fragments are class
  constants (column lists, ordering), placeholders built from a count (`IN (...)`), or
  `Search`'s escaped `ILIKE` patterns. Migrations are checksummed and refused when edited.
- **Redis**: every key reached through a secret (session, login state, codes, handles) is a
  SHA-256 digest of it (`Keys::forSecret()`); multi-step changes are single Lua scripts.
- **Secrets**: client secrets and passwords are bcrypt (cost 12; passwords capped at bcrypt's
  72 bytes by `PasswordPolicy`); codes, access and refresh tokens are stored as digests and
  compared with `hash_equals()`; TOTP seeds and the `postgres` backend's keys are AES-256-GCM
  with a random 96-bit nonce and their row's id as associated data.
- **Client authentication**: one method per request, the one the client is registered with;
  Basic credentials with a secret also in the body, or another client named there, fail.
- **Cookies**: all `HttpOnly`, `SameSite=Lax`, `Secure` outside development; the session id
  rotates at every sign-in; CSRF tokens are compared with `hash_equals()`.
- **Pages**: no script; CSP `default-src 'none'`, `form-action` limited to the flow's
  origins, `frame-ancestors 'none'`, `X-Frame-Options: DENY`; templates escape every value.
- **Redirects**: redirect URIs and post-logout URIs matched exactly; `next` is a local path or
  a registered client origin; an unregistered redirect URI gets an error page, never a redirect.
- **Outbound HTTP**: everything a registration can name (OIDC issuers, back-channel logout
  URIs) passes `OutboundUrlPolicy` — https, no private, loopback or link-local address, checked
  again at connection time (`PinCheckedAddresses`), no redirects followed, bounded timeouts.
  The signing client is the one exception, because the Azure metadata endpoint is link-local;
  every address it reaches comes from the operator's own configuration.
- **Signing**: no private key leaves a signing adapter; remote backends refuse references that
  could change; every remote signature is verified before it is used.
- **Management API**: every route is in the OpenAPI contract, authenticated by bearer token for
  the Management API audience, authorised by the operation's permission, and its body validated
  against the contract before a handler sees it.
- **Errors**: no stack trace or exception message reaches a response; throttled sign-ins take as
  long as a password check.
