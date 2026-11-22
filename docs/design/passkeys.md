# Design: passkeys (WebAuthn)

**Status:** proposed · **Date:** 2026-11-22 · **Specifications:** [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
(W3C Recommendation, 25 August 2026), RFC 8176 (`amr` values), CTAP 2.2 for authenticator
behaviour

## 1. Summary

Clavia gains passkeys: public-key credentials held by a phone, a laptop, a password manager or
a security key, and bound to Clavia's sign-in origin. A passkey is phishing-resistant: a
signature made for `auth.{domain}` is worthless anywhere else, unlike a password or a TOTP code
typed into a look-alike site.

A passkey serves two purposes:

- **as a second factor**, beside or instead of an authenticator app;
- **as the way in**: sign-in without a password, from the browser's autofill or a button. When
  the authenticator verified the person (biometrics or a PIN), a passkey is multi-factor by
  itself.

This document fixes the decisions, the model, the flows, the storage, the security rules and
the tests, and splits the work into three phases.

### Goals

- Register, name, list and remove passkeys from the account pages, and remove them from the
  Management API and the dashboard.
- Use a passkey as a second factor, and as a first factor with and without a username.
- Report how a person signed in (`amr`), record every passkey event in the audit trail, and keep
  recovery possible.

### Not in scope

- Attestation verification and authenticator allow-lists (enterprise policy): attestation is
  `none`.
- Related Origin Requests (one passkey across several domains), the PRF extension, cross-origin
  iframes.
- Passkey-only accounts with the password removed, and "require a passkey" policies: phase 3,
  designed separately.

## 2. Decisions

| Topic | Decision | Why |
|---|---|---|
| JavaScript on `auth.*` | **Allowed.** The "no JavaScript on the sign-in origin" invariant is withdrawn | The WebAuthn API exists only in JavaScript. Pages keep a strict CSP (§8) |
| Relying party id | `auth.{domain}`, overridable with `CLAVIA_WEBAUTHN_RP_ID` | Binds passkeys to the origin that mints tokens and nothing else. Changing it orphans every passkey, so it is a deployment decision, made once |
| Verification library | **`web-auth/webauthn-lib` ^5.3**, behind a port | CBOR, COSE keys, authenticator data and signature formats are a large, specialised surface. The library is mature and comes from the author of `web-token/jwt-library`, already used. It stays in one secondary adapter |
| Attestation | `none` | Privacy, and no use for the make of the authenticator. The AAGUID, still sent without attestation, is stored to label passkeys |
| Algorithms | EdDSA (-8), ES256 (-7), RS256 (-257), in that order | What platform authenticators and security keys produce; RS256 for Windows Hello |
| Discoverable credentials | `residentKey: required` | Needed for sign-in without a username, and what passkeys are |
| User verification | `required` to sign in with a passkey; `preferred` as a second factor | Without verification, a passkey proves possession only: fine after a password, not alone |
| A verified passkey satisfies MFA | **Yes**, by default (`CLAVIA_PASSKEY_SATISFIES_MFA`) | Possession plus inherence or knowledge. Asking for a TOTP code after a passkey would be redundant |
| User handle | The account's `UserId` (16 bytes) | Opaque, not personal data, stable for the account's life. Deleting the account deletes its passkeys |
| Storage | PostgreSQL for passkeys, Redis for ceremonies | Passkeys must survive restarts; challenges are single-use and short-lived |
| Browser code | One static ES module, no build step, using the Level 3 JSON helpers | `parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and `toJSON` ship in Chrome/Edge 129+, Firefox 119+ and Safari 18.4+, so the script holds no encoding code |

## 3. Concepts

- **Passkey**: a discoverable WebAuthn credential. It is **synced** when a credential manager
  backs it up across devices (iCloud Keychain, Google Password Manager, 1Password: the backup
  eligibility flag is set), or **device-bound** (a security key, some platform authenticators).
- **Ceremony**: one registration or one authentication, from the options the server sends to the
  response it verifies. Every ceremony has its own single-use challenge.
- **User presence (UP)**: someone touched or approved. **User verification (UV)**: the
  authenticator checked who (biometrics, PIN). The flags are in the authenticator data and are
  signed.
- **Signature counter**: incremented by some authenticators. Synced passkeys always report 0.

## 4. Domain model

### `Domain\Authentication\Passkey` (aggregate)

| Field | Type | Notes |
|---|---|---|
| `id` | `PasskeyId` (UUID v4) | Clavia's identifier, used in URLs and the API |
| `userId` | `UserId` | The owner; also the WebAuthn user handle |
| `credentialId` | `CredentialId` | Raw bytes, 16–1023 (the specification's bound); unique |
| `publicKey` | `CosePublicKey` | The COSE key as registered; opaque to the domain |
| `algorithm` | `CoseAlgorithm` (enum) | `EdDSA`, `ES256`, `RS256` |
| `signCount` | `int` | Last counter seen |
| `transports` | `list<Transport>` | `internal`, `hybrid`, `usb`, `nfc`, `ble`; for hints only |
| `aaguid` | `?Aaguid` | Labels the credential manager; all zeros is null |
| `backupEligible` | `bool` | Fixed at registration: synced or device-bound |
| `backedUp` | `bool` | Last backup state seen |
| `name` | `PasskeyName` | 1–64 characters, chosen by the person; a default from the AAGUID or the date |
| `createdAt`, `lastUsedAt` | instants | |

Rules on the aggregate:

- `Passkey::register(…)` is the only constructor; the credential must be new (the unique
  constraint is the arbiter, §7).
- `recordUse(int $signCount, bool $backedUp, DateTimeImmutable $at): void` updates the counter
  and the backup state. A counter that does not grow, when the stored one and the new one are
  not both zero, means the authenticator may be cloned: `CounterRegressed` is thrown, and the
  sign-in is refused and audited.
- `rename(PasskeyName)`. `backupEligible` never changes after registration (the specification
  forbids it), and a response saying otherwise is refused.
- `authenticationMethods(bool $userVerified): list<AuthenticationMethod>`: `hwk` for a
  device-bound credential, `swk` for a synced one (RFC 8176: proof of possession of a hardware
  or software-secured key), and `user` when only presence was tested.

`PasskeyRepository`: `save`, `ofCredentialId(CredentialId): ?Passkey`, `ofUser(UserId):
list<Passkey>`, `one(PasskeyId)`, `delete(PasskeyId)`, `countOf(UserId)`.

### Other changes

- `AuthenticationMethod` gains `HardwareKey = 'hwk'`, `SoftwareKey = 'swk'` and
  `UserPresence = 'user'`.
- `Domain\Authentication\WebAuthnChallenge`: a ceremony in progress. It holds the challenge (32
  random bytes), its purpose (`Registration`, `SignIn`, `SecondFactor`), the user for
  registration and second factor, the login state it belongs to (for sign-in), and its expiry.
- `MfaStatus` (what `DescribeMfa` answers) counts passkeys. An account "has a second factor" when
  it holds a confirmed TOTP factor or at least one passkey.
- Domain events in `Authentication\Event`: `PasskeyRegistered`, `PasskeyRenamed`,
  `PasskeyRemoved` (with who removed it: the person or an operator), and `PasskeyCounterRegressed`.
  `SignedIn` already carries the methods; `SignInRefusal` gains `UnknownPasskey` and
  `PasskeyCounterRegressed`.

## 5. Settings

| Setting | Default | Meaning |
|---|---|---|
| `CLAVIA_PASSKEYS_ENABLED` | `true` | Turns every passkey page and flow on or off |
| `CLAVIA_WEBAUTHN_RP_ID` | `auth.{CLAVIA_ROOT_DOMAIN}` | The relying party id. Validated as the sign-in host or a registrable suffix of it |
| `CLAVIA_WEBAUTHN_RP_NAME` | `CLAVIA_ROOT_DOMAIN` | The name authenticators show |
| `CLAVIA_WEBAUTHN_CEREMONY_LIFETIME` | `300` | Seconds a challenge lives (`#[Range(60, 600)]`) |
| `CLAVIA_PASSKEY_MAX_PER_USER` | `10` | Passkeys one account may hold (`#[Range(1, 50)]`) |
| `CLAVIA_PASSKEY_SATISFIES_MFA` | `true` | A verified passkey sign-in counts as multi-factor |
| `CLAVIA_PASSKEY_REAUTH_WINDOW` | `600` | Seconds since sign-in within which a person may add or remove a passkey |

`Settings` refuses an RP id that is not the sign-in host or one of its registrable suffixes:
browsers reject such an id, and every ceremony would fail.

## 6. Flows

The browser side of every flow is `public/auth/static/passkeys.js` (§8). The server puts the
options in the page as JSON (`<script type="application/json" id="webauthn-options">`). The
script reads them, calls the browser API, and posts the serialised response in an ordinary form
with the CSRF token. Every decision is made on the server.

Ceremonies follow the pattern already used for MFA challenges and consent. The challenge lives in
Redis under the digest of a handle the browser holds in `clavia_webauthn` (`Path=/auth`,
`HttpOnly`, the ceremony's lifetime). It is claimed with `GETDEL` when the response arrives, so
it works once, and a handle that is unknown, spent, expired or meant for another purpose gives
the same "start again" answer.

### 6.1 Registering a passkey

At `GET /auth/passkeys` (the account page next to `/auth/mfa/enroll`):

1. **A real session, signed in recently.** `ResolveEndUser::bySession()`, never the development
   auto-login. A session whose `auth_time` is older than `CLAVIA_PASSKEY_REAUTH_WINDOW` is sent
   through `RequireSignIn` with a fresh sign-in demanded, and comes back.
2. **Options** (`BeginPasskeyRegistration`):
   - `rp {id, name}`; `user {id: UserId bytes, name: email, displayName: name or email}`;
   - `pubKeyCredParams` as in §2;
   - `excludeCredentials`: the account's passkeys, so an authenticator holding one says so;
   - `authenticatorSelection {residentKey: required, userVerification: required}`;
   - `attestation: none`; `hints: ["client-device", "hybrid"]`;
   - the timeout, from the ceremony lifetime.

   Refused when the account already holds `CLAVIA_PASSKEY_MAX_PER_USER` passkeys.
3. **The browser** creates the credential, and the form posts it to `POST /auth/passkeys` with an
   optional name.
4. **Verification** (`CompletePasskeyRegistration`, through `PasskeyVerifier`):
   - `type` is `webauthn.create`; the challenge matches; the origin is exactly
     `https://auth.{domain}`; `rpIdHash` is the RP id's SHA-256;
   - UP and UV are set; the algorithm is one offered; the attestation format is `none` (or
     ignored);
   - the credential id is not registered to anybody: the unique constraint answers, and a
     duplicate is refused with the same message as any failure.
5. **Store and announce.** The passkey is saved, and `PasskeyRegistered` dispatched, in one
   transaction. When this is the account's first second factor and it holds no recovery codes,
   a set is generated and shown once, as when TOTP is turned on.

### 6.2 Signing in with a passkey

The login page (`GET /auth/login`, holding the authorization request's login state) offers two
entry points when passkeys are enabled and the application allows at least one connection:

- **Autofill**: the email field carries `autocomplete="username webauthn"`. On load, the script
  starts a conditional request (`mediation: "conditional"`) when
  `isConditionalMediationAvailable()` says so. The browser then offers passkeys in the field's
  suggestions.
- **A "Sign in with a passkey" button**, for browsers without conditional UI, and for a phone or
  security key reached over hybrid transport (QR code).

Both use one ceremony (`BeginPasskeySignIn`): `allowCredentials` empty (discoverable),
`userVerification: required`, `rpId`, `hints` from the device. The challenge is bound to the
login state, so a response answers this authorization request and no other. The response is
posted to `POST /auth/passkey`, and `SignInWithPasskey` decides:

1. **Claim the ceremony** (`GETDEL`); it must belong to the login state the form names.
2. **Find the passkey** by credential id; the response's `userHandle` must be its owner's id.
   Unknown is `CredentialsRejected`, and the page tells the script to call
   `PublicKeyCredential.signalUnknownCredential()`, so the credential manager hides the stale
   passkey.
3. **Verify** the assertion: `type` is `webauthn.get`; the challenge, origin and `rpIdHash`
   match; UP and **UV** are set; the signature over `authenticatorData ‖ SHA-256(clientDataJSON)`
   verifies with the stored key.
4. **The counter**: `recordUse()`. A regression refuses the sign-in, dispatches
   `PasskeyCounterRegressed` outside the transaction, so it survives, and the passkey stays for
   the person or an operator to look at.
5. **The account**: active, and its connection allowed for the client (`ConnectionAccess`, as for
   every first factor). Otherwise `CredentialsRejected`, the same outcome as a wrong password.
6. **Throttling**: the sign-in throttle counts per client address. There is no account to count
   against before step 2.
7. **`CompleteFirstFactor`** with the passkey's methods (`hwk` or `swk`). When
   `CLAVIA_PASSKEY_SATISFIES_MFA` is on and UV was set, `mfa` is added and the session is
   established directly, without a second-factor challenge. When it is off, the second factor
   follows as for a password.

The ID token's `amr` becomes, for example, `["swk", "mfa"]`, and `auth_time` is the passkey
sign-in.

### 6.3 A passkey as a second factor

On the second-factor page (`GET /auth/mfa`) of an account holding passkeys, `DescribeSecondFactorPage`
offers "Use a passkey" beside the code field. The ceremony (`BeginPasskeySecondFactor`) names
the account's passkeys in `allowCredentials`, with `userVerification: preferred` and the
challenge bound to the MFA challenge. `CompleteSecondFactor` gains a passkey attempt:

- it is verified as in §6.2, steps 3 and 4, against a passkey that must belong to the account in
  the challenge;
- a failure counts against `CLAVIA_MFA_MAX_ATTEMPTS`, like a wrong code;
- success establishes the session with `AuthenticationMethod::combined(first factor, [hwk|swk])`,
  so `mfa` is added.

### 6.4 Managing passkeys

- **The person**, at `/auth/passkeys`: each passkey with its name, synced or device-bound, the
  credential manager (from the AAGUID when known), and when it was created and last used.
  Rename (`POST /auth/passkeys/{id}/name`) and remove (`POST /auth/passkeys/{id}/remove`), both
  with CSRF and within the re-authentication window. After a removal, the page calls
  `PublicKeyCredential.signalAllAcceptedCredentials()` with the remaining ids, so the credential
  manager drops the removed one. After an email change, `signalCurrentUserDetails()` updates the
  name shown.
- **Recovery stays possible.** A person cannot remove their last way in: removing the last
  passkey of an account with no password, no other connection and no recovery codes is refused
  with an explanation.
- **Operators**, through the Management API (§9).

## 7. Storage

### Migration `0025_passkeys.sql`

```sql
CREATE TABLE passkeys (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id   bytea NOT NULL,
    public_key      bytea NOT NULL,
    algorithm       integer NOT NULL,
    sign_count      bigint NOT NULL DEFAULT 0,
    transports      jsonb NOT NULL DEFAULT '[]',
    aaguid          uuid,
    backup_eligible boolean NOT NULL,
    backed_up       boolean NOT NULL,
    name            text NOT NULL,
    created_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    CONSTRAINT uq_passkeys_credential_id UNIQUE (credential_id),
    CONSTRAINT ck_passkeys_credential_id_length CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    CONSTRAINT ck_passkeys_sign_count CHECK (sign_count >= 0),
    CONSTRAINT ck_passkeys_name_length CHECK (char_length(name) BETWEEN 1 AND 64),
    -- A passkey cannot be backed up without being eligible for backup (WebAuthn Level 3 §6.1.3).
    CONSTRAINT ck_passkeys_backup CHECK (backup_eligible OR NOT backed_up)
);

CREATE INDEX ix_passkeys_user_id ON passkeys (user_id);
```

- `PhpDbPasskeyRepository` goes through `Database`. A duplicate credential id (SQLSTATE 23505 on
  `uq_passkeys_credential_id`) becomes `AlreadyExists`. The credential id and the key are `bytea`,
  passed and read as hexadecimal (`decode`/`encode`), never as driver text.
- `PasskeyRepository::recordUse(Passkey, int $previousSignCount): bool` is a conditional update
  (`… WHERE id = :id AND sign_count = :previous`), so two
  sign-ins racing with one counter cannot both pass. The loser is refused like a regression,
  without the audit event.
- The public key is not secret and is stored in the clear. Nothing about a passkey goes through
  `SecretCipher`.

### Redis

`webauthn:<digest(handle)>`, built by `Redis\Keys::forSecret()`, holding the serialised
`WebAuthnChallenge`, with the ceremony's lifetime as TTL. `RedisWebAuthnChallengeStore`
implements the `WebAuthnChallengeStore` port (`open`, `claim`, named like the other handle
stores). The login state and the second-factor challenge a ceremony is bound to are kept as their
digests.

## 8. The browser side

### `public/auth/static/passkeys.js`

One ES module (`<script type="module" src="/auth/static/passkeys.js">`), served by Caddy like
`auth.css`, with no build step, no dependency, and about 150 lines. It:

- detects support (`window.PublicKeyCredential`, `PublicKeyCredential.getClientCapabilities()`
  where present, `isConditionalMediationAvailable()`), and reveals the passkey buttons only
  when the browser can use them: **a page without support looks exactly as today**;
- reads the options from the page's JSON block, converts them with
  `parseCreationOptionsFromJSON()` or `parseRequestOptionsFromJSON()`, calls `create()` or
  `get()`, and posts `credential.toJSON()` in a hidden field of the page's form;
- starts the conditional request on the login page, and aborts it (`AbortController`) when the
  person clicks the passkey button or submits the password form;
- treats `NotAllowedError` (cancelled, timed out) as nothing happened, and shows a short message
  for the other errors. The server's words come from the page, never from the exception;
- calls the signal methods when the page asks for it, through a `data-` attribute.

### Pages and headers

- The CSP every page carries keeps its strictness. It gains `script-src 'self'` and
  `require-trusted-types-for 'script'` with a `trusted-types 'none'` policy: the script writes no
  HTML, so it needs no policy. No inline script, no `eval`, no third party; the JSON block is
  data (`type="application/json"`), which the CSP does not execute.
- `Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self)`.
- New templates: `auth/passkeys.phtml` (the account page) and `partial/passkey-button.phtml`.
  `auth/login.phtml` and `auth/mfa-challenge.phtml` gain the buttons and the options block. Every
  new variable gets an `AuthPagesEscapingTest` case.

## 9. Management API and dashboard

### API (`docs/openapi/management-api.yaml`)

| Operation | Scope | Notes |
|---|---|---|
| `GET /api/v1/users/{user_id}/passkeys` | `read:users` | A JSON array (small by nature): `id`, `name`, `synced`, `backed_up`, `aaguid`, `created_at`, `last_used_at`. Never the credential id or the key |
| `DELETE /api/v1/users/{user_id}/passkeys/{passkey_id}` | `update:users` | 204; 404 if the passkey is not this user's |

- `DELETE /api/v1/users/{user_id}/mfa` keeps its meaning (the authenticator app and the recovery
  codes). Passkeys are removed one by one, so an operator sees what they remove.
- `mfa_enrolled` on a user becomes true when the account holds a confirmed TOTP factor or a
  passkey. A new `passkey_count` field says how many.
- The scopes do not change, so `ManagementPermission` and `ManagementContractTest` are untouched.

### Dashboard

A **Passkeys** tab on a user's page lists them and removes one through `ConfirmAction`. The
user's sign-in methods in the audit log show `swk`, `hwk` and `mfa` as words ("synced passkey",
"security key"). The types are regenerated from the contract.

## 10. Architecture

| Ring | New |
|---|---|
| Domain | `Authentication\Passkey`, `PasskeyId`, `PasskeyRepository`, `CredentialId`, `CosePublicKey`, `CoseAlgorithm`, `Transport`, `Aaguid`, `PasskeyName`, `WebAuthnChallenge`, `WebAuthnPurpose`, `CounterRegressed`; events; `AuthenticationMethod` cases |
| Application | `Authentication\Passkey\{BeginPasskeyRegistration, CompletePasskeyRegistration, BeginPasskeySignIn, SignInWithPasskey, BeginPasskeySecondFactor, DescribePasskeys, RenamePasskey, RemovePasskey}`; `CompleteSecondFactor` and `DescribeSecondFactorPage` extended; `Management\Users\{ReadPasskeys, RemoveUserPasskey}`. Ports `PasskeyVerifier`, `WebAuthnChallengeStore` |
| Secondary adapters | `WebAuthn\WebAuthnLibPasskeyVerifier`, `Redis\RedisWebAuthnChallengeStore`, `PhpDb\PhpDbPasskeyRepository` |
| Primary adapters | `Http\Auth\{PasskeysHandler, PasskeySignInHandler, PasskeyPages}`; `MfaChallengeHandler` and the login handlers extended; `Http\Management\UserPasskeysHandler` |
| Bootstrap | Factories; aliases; the trails subscribe to the new events |

### The `PasskeyVerifier` port

```php
interface PasskeyVerifier
{
    /** @throws PasskeyRejected with a reason the use case maps to one outcome */
    public function verifyRegistration(string $responseJson, WebAuthnChallenge $challenge, RelyingParty $rp): VerifiedRegistration;

    /** @throws PasskeyRejected */
    public function verifyAssertion(string $responseJson, WebAuthnChallenge $challenge, RelyingParty $rp, Passkey $passkey): VerifiedAssertion;
}
```

The use cases build the options themselves (the domain knows what to offer), and hand the
verifier only the raw response, the challenge and the relying party. `VerifiedRegistration`
carries what `Passkey::register` needs; `VerifiedAssertion` the new counter, the flags and the
user handle. Only the adapter knows CBOR or COSE. `credentialIdOf(string $responseJson):
CredentialId` lets a use case look the passkey up before verifying.

`web-auth/webauthn-lib` brings `Webauthn\`, `Cose\`, `CBOR\`, `SpomkyLabs\` and
`ParagonIE\ConstantTime\` namespaces, which join deptrac's Vendor layer. It also brings Symfony
serializer and property-access components (Clavia already uses Symfony 8).

## 11. Audit

| Event | Type | Trail |
|---|---|---|
| `PasskeyRegistered` | `passkey.registered` | Authentication |
| `PasskeyRenamed` | `passkey.renamed` | Authentication |
| `PasskeyRemoved` | `passkey.removed` (actor: the person or the operator) | Authentication |
| `PasskeyCounterRegressed` | `passkey.counter_regressed` (outcome: failure) | Authentication |
| `SignedIn` | `authentication.succeeded`, methods in the details | unchanged |
| `SignInRefused` | `authentication.failed`, reasons `unknown_passkey`, `passkey_counter_regressed` | unchanged |

Details carry the passkey's id and name, `synced`, and the AAGUID. Never the credential id, the
key or the response. `AuditTrailsTest` covers the new events.

## 12. Security rules

These join CLAUDE.md's invariants.

- **The origin is matched exactly**: `https://auth.{domain}`, the scheme and port included. No
  other origin, and no Related Origin Requests, until designed.
- **A challenge is single-use, short-lived, bound to its purpose and its context** (the account
  for registration and second factor, the login state for sign-in), and claimed before it is
  checked.
- **Signing in with a passkey needs user verification.** Presence alone is accepted only as a
  second factor, after a password.
- **The user handle must name the passkey's owner.** A response for one account cannot sign in
  another.
- **A counter regression refuses the sign-in** and is audited. Synced passkeys, always at zero,
  are unaffected.
- **Adding or removing a passkey needs a recent sign-in**, and the last way into an account cannot
  be removed.
- **Failures are one outcome**: an unknown credential, a bad signature and a deactivated account
  give the person the same message. The audit trail keeps the reason.
- **No attestation, no tracking**: the AAGUID labels a passkey for its owner and is never used to
  refuse one.
- **The browser decides nothing**: the script relays, and the server builds every option and
  checks every response.

## 13. Testing

- **Unit, domain**: `PasskeyTest` (counter rules, backup-eligibility immutability, the methods
  per flag), `WebAuthnChallengeTest`, `PasskeyNameTest`, the new `AuthenticationMethod` cases.
- **Unit, use cases**: each use case with doubles (`InMemoryPasskeyRepository`,
  `InMemoryWebAuthnChallengeStore`, `FakePasskeyVerifier`): limits, the re-authentication
  window, the last way in, `ConnectionAccess`, the MFA shortcut on and off, events dispatched.
- **Contract, verifier**: `PasskeyVerifierContract`, run against `WebAuthnLibPasskeyVerifier`
  with `test/Support/SoftwareAuthenticator`, a test authenticator that holds real EdDSA, ES256
  and RS256 keys and builds genuine responses (CBOR through the library's encoder). It also runs
  recorded responses from real authenticators (Apple, Google, Windows Hello, a YubiKey). Cases:
  every field tampered with (origin, RP id hash, challenge, type, flags, signature, algorithm,
  user handle) is refused.
- **Integration**: `PhpDbPasskeyRepositoryTest` (unique credential id, the cascade on account
  deletion, the conditional counter update under a race), `RedisWebAuthnChallengeStoreTest`.
- **Acceptance**: `PasskeyTest` through the pipeline with the `SoftwareAuthenticator`:
  registration, sign-in without a username, sign-in as a second factor, the `amr` of the ID
  token, the Management API operations against the contract, audit events, and every refusal.
- **Pages**: `AuthPagesEscapingTest` cases; a test pins the CSP and the Permissions-Policy.
- **Browser**: Playwright with a virtual authenticator (the CDP WebAuthn domain), signing in with
  a passkey through the dashboard's smoke suite: real JavaScript against real Clavia.

## 14. Phases

1. **Passkeys as a second factor.** The domain, storage, verifier and script; registration and
   the account page; the second-factor flow; the Management API and audit events; recovery
   rules. Everything else builds on it.
2. **Signing in with a passkey.** The login page's autofill and button, `SignInWithPasskey`, the
   MFA shortcut, the signal methods, the dashboard tab, the Playwright test.
3. **Policies** (designed separately): offering a passkey after a password sign-in (conditional
   create), "require a passkey" per application or role, and accounts without a password.

## 15. Changes to CLAUDE.md

- Remove "no JavaScript on that origin" from the browser invariants and the HTTP conventions.
  Replace it with: one first-party module per feature, under a CSP with `script-src 'self'` and
  Trusted Types; the server decides everything.
- Add the passkey rules of §12, the `PasskeyVerifier` port, the new settings and the routes.

## 16. Open questions

1. **AAGUID names**: label passkeys from the community list of known authenticators (a JSON file
  shipped with Clavia and refreshed by hand), or show only the person's own name? The list is
  small and useful, but must be kept current.
2. **Conditional UI on the email field**: the password form shares the field. If both are on the
  page, the autofill offers passkeys and passwords together, which is what browsers expect, but
  worth confirming on Safari, where conditional mediation behaves differently.
3. **Device-bound credentials as `hwk`**: a platform authenticator that is not backup-eligible
  (Windows Hello) is hardware-backed, but some security keys report backup eligibility
  unusually. `hwk` and `swk` follow the flag; a relying party that needs certainty must use
  attestation, which is out of scope.

## 17. As built

What phase 1 settled differently from the sections above, so the code and this document agree.

- **The options travel in an escaped `data-webauthn-create` attribute** of the page's form, not in
  a `<script type="application/json">` block (§6, §8): it is the same data, but no script element
  is ever printed but the module, and `escapeHtmlAttr()` is the only escaping involved.
- **Registration starts with `POST /auth/passkeys/new`** (with CSRF), which opens the ceremony and
  shows the page that makes the passkey; `GET /auth/passkeys` writes nothing. A browser asks for a
  passkey only on a click, so the page has a button rather than starting on load.
- **Only the page that makes a passkey loads the module** and allows `script-src 'self'`; every
  other page keeps a policy with no script at all (§8 put it on every page).
- **The relying party id** must be the sign-in host or a parent of it *within the root domain*:
  that is what keeps a public suffix or another site out without a public suffix list (§5). An
  issuer that is not https (loopback in development) turns passkeys off, with a warning, rather
  than refusing to start.
- **Removing the last passkey is not guarded yet** (§6.4): while a passkey is only a second
  factor, removing one never removes the way in. The guard comes with signing in by passkey.
- **`user` in `amr` is added to `hwk`/`swk`**, not used instead of them, when nobody was verified.
- **The second-factor page opens a ceremony each time it renders** (`GET /auth/mfa`, and again
  after a wrong answer), since a ceremony answers once; the page carries its options and
  `passkeys.js` posts to `POST /auth/mfa/passkey`. A recovery code answers for an account whose
  only second factor is a passkey.
- **A refused passkey is a refused second factor** (`authentication.failed`), with the reason
  `wrong_second_factor`, `unknown_passkey` or `passkey_counter_regressed`; a counter that went back
  is also `passkey.counter_regressed`. The loser of two racing uses is `wrong_second_factor`. The
  refusal names the passkey's method when the passkey is known, and none otherwise.
- **Turning the authenticator app off keeps the recovery codes while a passkey remains**; an
  operator's reset (`DELETE /api/v1/users/{id}/mfa`) still takes them, as §9 says.
- **With passkeys off, a passkey asks for nothing**: an account whose only second factor is a
  passkey signs in with its first factor, rather than being asked for something it cannot give.

Phase 2, signing in with a passkey:

- **A login page reached directly binds its ceremony to the ceremony's own handle**, there being
  no authorization request; it answers once, in the browser that holds it, and signs in to the
  default destination.
- **The autofill and the button share one ceremony.** The conditional request is aborted when the
  person presses the button or submits another form on the page, and the modal one uses the same
  options.
- **A passkey without user verification cannot sign in**: the verifier requires it at sign-in, so
  `CLAVIA_PASSKEY_SATISFIES_MFA` only ever applies to a verified passkey.
- **A refused passkey sign-in is `authentication.failed`** with `unknown_passkey`,
  `invalid_passkey`, `passkey_counter_regressed`, `throttled`, `expired`, `account_disabled` or
  `not_available`, and the page answers as for a wrong password. `UsePasskey` holds what the
  sign-in and the second factor share.
- **The last way in** (§6.4) is the last passkey of a pool account with no password and no identity
  at another provider. Recovery codes do not count: they answer a second factor.
- **Not built here**: the signal methods (`signalUnknownCredential()` and the others), the dashboard
  tab (clavia-dashboard#3) and the Playwright test, which belongs to the dashboard's end-to-end
  suite.

