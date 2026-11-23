# Design: MFA policies, `acr_values` and step-up

**Status:** built · **Date:** 2026-11-23 · **Issue:** clavia-auth/clavia#10 ·
**Specifications:** OpenID Connect Core 1.0 (§2 `acr`, §3.1.2.1 `acr_values` and `max_age`,
§3.1.2.6 errors), OpenID Connect Core Error Code `unmet_authentication_requirements` 1.0,
RFC 9470 (OAuth 2.0 Step Up Authentication Challenge Protocol), OpenID Connect EAP ACR Values
1.0 (`phr`), OpenID Provider Authentication Policy Extension 1.0 (the multi-factor
policy URI), RFC 8176 (`amr`), NIST SP 800-63B §4 (authenticator assurance levels)

**Amended** in the first slice's pull request: `phrh` withdrawn until attestation is verified
(§2, "No `phrh`").

## 1. Summary

Today a second factor is the person's own choice: an account with an authenticator app or a
passkey is asked for it at every sign-in, and an account without one never is. Nothing lets an
application, or the operator of an API, *require* a stronger sign-in, and an ID token says how
someone signed in (`amr`) but not to what level (`acr`).

This design adds three things:

- **Authentication levels**: two `acr` values, worked out from the `amr`
  a session already records, and put in the ID token, JWT access tokens and introspection.
- **Asking for a level**: a relying party asks with `acr_values` (OIDC Core §3.1.2.1), an
  operator requires one per application or per API with an **MFA policy**, and a resource
  server can send a client back for one (RFC 9470).
- **Step-up**: a signed-in person who falls short is asked for the missing factor only, and
  their session is raised in place, without signing in again from scratch. Someone with no
  second factor enrolls one on the way, when the policy demands it.

### Goals

- `acr` in the ID token, the JWT access token and the introspection response, and
  `acr_values_supported` in discovery.
- `acr_values` honoured at the authorization endpoint and the device approval page.
- An MFA policy on clients and APIs, from the Management API and the dashboard.
- Step-up of an existing session: one more factor, the same session, a new identifier.
- RFC 9470's loop working end to end: a resource server refuses a token for its `acr` or
  `auth_time`, the client asks again with `acr_values` or `max_age`, the person steps up.

### Not in scope

- The `claims` request parameter (OIDC Core §5.5) and essential claims: Clavia does not
  support `claims`, and `acr_values` covers the need.
- Trusting an external provider's MFA (its `amr` or `acr`): an external sign-in is one factor
  here, as today.
- Conditional or risk-based policies (new device, new country), and per-user policies.
- `phrh` (a hardware-protected key): it needs attestation verified at registration (§2).
- Passkey-only accounts and "require a passkey" policies: passkeys phase 3 (#8), which builds on
  the levels this design defines.

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| The levels | Two `acr` values: `http://schemas.openid.net/pape/policies/2007/06/multi-factor` (MFA) < `phr` (phishing-resistant) | The PAPE URI is the value Auth0 documents for asking for MFA, so relying parties written for it already send it. `phr` is the OpenID Foundation's value for phishing-resistant authentication, which passkeys are. Clavia-specific URNs would interoperate with nothing. NIST AAL numbers depend on things Clavia cannot attest |
| No `phrh` | **Not offered**, until attestation is verified | `phrh` promises a hardware-protected key, and relying parties use it for compliance (NIST AAL3). Passkeys are registered with attestation `none`, so whether a key is device-bound is only its authenticator's word (the backup eligibility flag): a software authenticator can claim it. Offering `phrh` needs attestation checked against trusted roots or the FIDO Metadata Service at registration, and a verified-hardware flag on the passkey: passkeys phase 3 (#8). `amr` keeps `hwk`, which describes what the authenticator reported, not a guarantee |
| No level for one factor | A single-factor session has **no `acr`**: the claim is left out | OIDC Core §2 makes `acr` optional, and `"0"` means "below ISO 29115 level 1" (a long-lived cookie), which overstates nothing a password session is. A relying party that needs a level asks for it; one that finds no `acr` knows it got one factor |
| Where the level comes from | Worked out from the session's `amr`, never stored | `amr` is the record of what happened (RFC 8176), and is already on sessions, codes and tokens. A stored level could disagree with it |
| `acr_values` | **A requirement**, not a hint: the request is satisfied when the session meets any listed value Clavia knows, or the person steps up to the first one they can reach. Unknown values are ignored; only unknown values means no requirement | OIDC Core calls `acr` a voluntary claim, so issuing a weaker one silently would be conforming. But RFC 9470's loop only ends if the server either reaches the level or says it cannot, and the hosted providers treat a value they know as a demand |
| Cannot be met | `unmet_authentication_requirements` sent to the redirect URI | The OpenID Foundation's registered error for exactly this. `access_denied` would read as "the person said no" |
| `prompt=none` | `interaction_required` when the session falls short | OIDC Core §3.1.2.6: the person is signed in, so `login_required` would be wrong |
| MFA policy values | `optional` (the default) and `required`, on a client and on an API. Required on either is required | The issue's "never" would ignore a relying party's own `acr_values`, which helps nobody. A person's own second factor is always asked, whatever the policy. "When asked" is `optional`: `acr_values` works under it |
| What `required` means | The MFA level. A stronger level is asked with `acr_values` | One policy value covers what an operator needs. A choice of levels per client is phase 3 of passkeys (#8) |
| Step-up | The session is **raised in place**: `amr` gains the new factor and `mfa`, `auth_time` becomes now, the identifier rotates. `sid`, the connection, the clients signed in through it and the absolute expiry stay | A new session would lose the applications signed in through this one, so back-channel logout would no longer reach them. Rotating the identifier on a privilege change is the usual rule against session fixation. `auth_time` is when the person last actively authenticated (§2), which a step-up is. The absolute expiry stays, so a stolen cookie cannot be stepped up into a longer life |
| Enrolment on the way | When a policy requires MFA and the account has no second factor, the person enrolls one (an authenticator app or a passkey), and that enrolment raises the session | Refusing would lock out every account that has not enrolled yet, which is all of them on the day a policy is turned on. Confirming a TOTP code or registering a passkey with user verification proves the factor at that moment. §7 discusses the cost |
| Existing tokens | A policy applies to new authorizations only. Refresh tokens issued before it keep working, and report the `acr` they were issued with | Revoking on a policy change would be a surprise outage. The `acr` the tokens carry is truthful, and an operator who wants everyone signed out ends sessions from the Management API |
| Refresh | A refreshed token carries the `amr` and `auth_time` of the sign-in that started its family, so its `acr` and `auth_time` | RFC 9470 §6 needs them on access tokens, and a refresh must not lose them. The JWT access tokens of #9 left `acr` and `auth_time` out for exactly this reason |

## 3. Concepts

- **Level** (`AuthenticationLevel`): what a set of `amr` values amounts to.

  | Level | `acr` | The session's `amr` contains |
  |---|---|---|
  | one factor | (none) | anything else |
  | MFA | `http://schemas.openid.net/pape/policies/2007/06/multi-factor` | `mfa` |
  | phishing-resistant | `phr` | `mfa`, and `hwk` or `swk` |

  `phr` meets MFA. A password followed by a passkey is `phr`: the
  password could have been phished, but the passkey's signature cannot be relayed to another
  origin. A recovery code is MFA, not `phr`.
- **Requirement**: the levels a request will accept, from `acr_values`, the client's policy and
  the API's policy. It is satisfied when the session meets any one of them.
- **Step-up**: raising a signed-in session to a requirement it falls short of, with one more
  factor.

## 4. Model

### Domain

- `Domain\Authentication\AuthenticationLevel` (enum: `Mfa`, `PhishingResistant`). `acr()` gives the value; `fromAcr(string): ?self` reads one, or
  gives null for a value Clavia does not know. `of(list<AuthenticationMethod>): ?self` gives the
  strongest level a set of methods meets, or null for one factor. `meets(self $required): bool`.
- `Domain\Authentication\AuthenticationRequirement` (value object): a list of acceptable
  levels in the requester's order of preference, possibly empty. `fromAcrValues(?string)` parses
  the parameter. `with(AuthenticationLevel)` adds a policy's level. `isMetBy(list<AuthenticationMethod>)`
  says whether a session meets it, and `nextReachable(available factors): ?AuthenticationLevel`
  picks the level a step-up should aim for.
- `Domain\Authentication\MfaPolicy` (enum: `Optional`, `Required`), with
  `level(): ?AuthenticationLevel`.
- `Client` and `ResourceServer` gain `mfaPolicy` (default `Optional`) and `withMfaPolicy()`.
- `AuthenticationContext::acr(): ?string`, from the methods.
- `Session::steppedUp(list<AuthenticationMethod> $added, DateTimeImmutable $now): self`: new
  methods (`AuthenticationMethod::combined`), `authenticatedAt` now, everything else kept.
- `MfaChallenge` gains `?string $stepUpOf` (the digest of the session being raised; null for a
  sign-in) and `?AuthenticationLevel $aim`. A step-up challenge has no first factor of its own.
- `AccessToken` and `RefreshToken` gain `AuthenticationContext $authentication` (when and how,
  no `sid`), copied from the code at redemption and from the family at refresh.
- Events: `Domain\Authentication\Event\SessionSteppedUp` (user, `sid`, the methods added, the
  level reached), recorded by `AuthenticationTrail` as `session.stepped_up`.

### Application

- `Application\Authentication\Sessions::stepUp(string $sessionId, list<AuthenticationMethod> $added): EstablishedSession`:
  the only way to raise a session. It resolves the session, raises it, stores it under a new
  identifier, removes the old one, and returns the new identifier once.
- `Authorize` step 5 gains a reason to stop: the session does not meet the requirement
  (§5.1).
- `Mfa\BeginStepUp`: opens a step-up challenge for a session and a level.
- `CompleteSecondFactor` and `CompletePasskeySecondFactor` finish either kind of challenge: a
  sign-in's establishes the session, a step-up's raises it.
- `ConfirmTotpEnrollment` and `CompletePasskeyRegistration` raise the session when they run
  inside a step-up (§5.3).
- `Oidc\IdTokenIssuer` adds `acr`. `AccessTokenClaims` adds `acr` and `auth_time` (RFC 9470
  §6.1), and `IntrospectToken` returns them (§6.2).

### Migrations

- `clients.mfa_policy` and `resource_servers.mfa_policy`: `text NOT NULL DEFAULT 'optional'`,
  checked against `('optional', 'required')`.
- `oauth2_access_tokens` and `oauth2_refresh_tokens`: `auth_time timestamptz NULL` and
  `amr jsonb NOT NULL DEFAULT '[]'`. Rows issued before the migration have neither: no `acr`, no
  `auth_time`, which is what they could have said anyway.

## 5. Flows

### 5.1 The authorization endpoint

The fixed order of `Authorize` (CLAUDE.md, "Authorization code with PKCE") changes at two steps:

- **Step 3** also validates `acr_values`. The parameter is a space-separated list
  (§3.1.2.1); an empty value or a repeated parameter is `invalid_request`. Unknown values are
  dropped.
- **Step 5** builds the requirement: `acr_values`, plus the MFA level when the client's or the
  API's policy is `required`. Then it decides whether the person must be seen:
  1. no session, or one that must be seen again (`prompt=login`, `max_age`…): sign in, as
     today. The resumed request keeps `acr_values`, so the endpoint decides again after the
     sign-in;
  2. a session that meets the requirement: carry on to roles, consent and the code;
  3. a session that falls short, with `prompt=none`: `interaction_required`;
  4. a session that falls short, and the person has a factor that reaches a level the
     requirement accepts: the request is held behind a login state, a step-up challenge is
     opened (`BeginStepUp`), and the browser goes to `/auth/mfa`;
  5. a session that falls short, the requirement is the MFA level, and the person has no second
     factor at all: the request is held, and the browser goes to enrolment (§5.3);
  6. anything else (`phr` asked of someone with only an authenticator app, or the MFA level of
     someone whose account cannot enroll, §5.3): `unmet_authentication_requirements`, redirected
     with `state` and `iss`.

`max_age` keeps its meaning. A step-up counts as an active authentication, so it satisfies a
`max_age` as a fresh sign-in would: RFC 9470's `max_age` challenge is answered by stepping up.

### 5.2 Step-up

`/auth/mfa` already shows a challenge's second factors. For a step-up challenge:

- the factors offered are those reaching the aim: for MFA, an authenticator app, a passkey or a
  recovery code; for `phr`, a passkey only. A factor
  already in the session's `amr` is not offered again: an authenticator app's code after a
  sign-in that already used one would count one device twice;
- the page says why it is asked: "*Application* asks you to confirm it's you";
- a right answer calls `Sessions::stepUp()`, sets the new session cookie, dispatches
  `SessionSteppedUp`, and sends the browser back to the held request;
- wrong answers count against the challenge (`CLAVIA_MFA_MAX_ATTEMPTS`) and the sign-in
  throttle, as today. A spent or expired challenge is the "expired" page;
- the session the challenge was opened for must still be the browser's when it is answered:
  the challenge holds its digest, and a different or missing session cookie is refused. A
  step-up therefore cannot be finished in another browser.

### 5.3 Enrolment on the way

When a policy requires MFA and the account has no second factor:

0. an account whose address is not verified cannot enroll here (§7): the request is answered
   `unmet_authentication_requirements`;
1. the browser goes to `/auth/mfa/enroll` with the login state. The page explains that
   *Application* requires a second factor, and offers an authenticator app and, where passkeys
   are on, a passkey;
2. confirming the app's first code (`ConfirmTotpEnrollment`) or registering a passkey with user
   verification (`CompletePasskeyRegistration`) raises the session (`otp` or `hwk`/`swk`, then
   `mfa`). The recovery codes are shown once, as today;
3. the browser goes back to the held request.

Enrolment inside a step-up does not need the recent sign-in that adding a passkey normally
does (`CLAVIA_PASSKEY_REAUTH_WINDOW`): the session it raises was just checked by the
authorization endpoint. Outside a step-up, the window applies as today.

### 5.4 Device approval

`/auth/device` builds the same requirement from the device client's policy and the API's (a
device request has no `acr_values`), and steps up or enrolls the same way before showing the
approval. Polling devices see `authorization_pending` meanwhile.

### 5.5 Tokens

- **ID token**: `acr` when the session that approved the code met a level (OIDC Core §2), next
  to `auth_time` and `amr`.
- **JWT access token** (#9): `acr` and `auth_time`, from the token's authentication context
  (RFC 9470 §6.1). Left out for a token issued to a client as itself.
- **Introspection**: `acr` and `auth_time` for an active token issued on a person's behalf
  (RFC 9470 §6.2).
- **Refresh**: the new access token copies the family's context. A refresh issues no ID token,
  as today.

### 5.6 RFC 9470, end to end

1. A resource server refuses a token: `401`,
   `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="phr"`.
   That is the resource server's code, not Clavia's. The Management API does the same when the
   Management API's policy is `required` and a token falls short.
2. The client sends the person to `/oauth2/authorize` with `acr_values=phr`.
3. The person steps up (§5.2) without typing their password again; the new code's tokens carry
   `acr: phr`.

## 6. Interfaces

- **Discovery**: `acr_values_supported` (the two values, weakest first), and `acr` in
  `claims_supported`. `ProviderMetadata` holds them, and `OidcTest` checks them.
- **Authorization endpoint**: `acr_values`; the errors `interaction_required` and
  `unmet_authentication_requirements`.
- **Pages**: `/auth/mfa` gains the step-up wording and the restricted factor list.
  `/auth/mfa/enroll` gains the "required by *Application*" variant, reached with a login state.
  New `AuthPagesEscapingTest` cases cover both.
- **Management API** (`docs/openapi/management-api.yaml`):
  - clients and resource servers gain `mfa_policy` (`optional` | `required`, default
    `optional`), readable and writable on create and update. The Management API itself may be
    set to `required`;
  - the audit event type `session.stepped_up`.
- **Management API, protecting itself**: with the Management API's policy `required`,
  `ManagementApiMiddleware` refuses a token whose `acr` falls short with RFC 9470's challenge,
  after the audience and before the scope. A machine token (no subject) is not concerned.
- **Dashboard** (clavia-dashboard): the policy on the application and API pages, and the
  step-up challenge handled when the Management API answers `insufficient_user_authentication`.
  A separate issue there.

## 7. Security rules

- **A level is never claimed for something that did not happen.** `acr` is worked out from
  `amr`, which records events; an unknown authentication (the development auto-login) has no
  `acr`.
- **A step-up raises the session it was opened for, in the browser that holds it, once.** The
  challenge holds the session's digest and is claimed with `GETDEL`; the identifier rotates, so
  a cookie captured before the step-up is worth nothing after it.
- **A step-up never extends a session's life.** The absolute expiry is kept, and only the idle
  window slides, as on any use.
- **One device never counts twice.** A factor already in `amr` is not offered again, and a
  passkey after a passkey is refused, as today.
- **A requirement is decided once, at the endpoint.** The resumed request carries `acr_values`
  and the endpoint decides again with everything as it is then. No page decides a level by
  itself.
- **Enrolment on the way is trust on first use.** Someone who stole a password from an account
  that has no second factor can enroll their own, and pass a `required` policy with it. No
  policy fixes that: only an earlier enrolment does. So the design limits the damage:
  - enrolment on the way is offered only to an account whose address is verified;
  - it is recorded (`mfa.enrolled`, `passkey.registered`) and mailed to the account, as a
    notice the owner can act on (§10, question 2).
- **Policies narrow, never widen.** `required` adds a demand; nothing in a policy can lower what
  a person's own enrolled factor already asks of them.

## 8. Tests

- **Unit**:
  - `AuthenticationLevel` over every `amr` combination the server produces;
  - `AuthenticationRequirement` parsing: order, unknown values, empty, repeated;
  - `Session::steppedUp` keeps `sid`, the clients and the expiry, and moves `authenticatedAt`;
  - `MfaPolicy` on `Client` and `ResourceServer`.
- **Acceptance** (`StepUpTest`):
  - `acr_values` met by the session: a code, `acr` in the ID token;
  - `acr_values` not met: the step-up page, then a code without typing the password again,
    with the same `sid` and a new session cookie;
  - `prompt=none` falling short: `interaction_required`;
  - `phr` asked of a person with only an authenticator app: `unmet_authentication_requirements`;
  - a client policy `required`, a person with no factor: enrolment, then a code;
  - an API policy `required`, through the device flow;
  - a step-up challenge answered with another browser's session is refused;
  - the absolute expiry survives a step-up;
  - refresh keeps `acr` and `auth_time` on the JWT access token and in introspection;
  - the Management API with policy `required` answers RFC 9470's challenge to a one-factor
    administrator token.
- **Contract**: the access and refresh token repositories keep the authentication context
  (`AccessTokenRepositoryContract`, `RefreshTokenRepositoryContract`).
- **Discovery**: `OidcTest` checks `acr_values_supported`.

## 9. Slices

1. **Levels in tokens.** `AuthenticationLevel`; `acr` in the ID token; `acr_values_supported`
   and `acr` in discovery; the migration and the model carrying the authentication context on
   access and refresh tokens; `acr` and `auth_time` in JWT access tokens and introspection.
   *Done when* an ID token, a JWT access token and introspection report `acr` and `auth_time`
   truthfully, refresh included, and discovery lists the values.
2. **`acr_values` and step-up.** `AuthenticationRequirement`; the authorization endpoint's new
   step 5 cases; `Sessions::stepUp`; step-up challenges on `/auth/mfa`;
   `interaction_required` and `unmet_authentication_requirements`; `SessionSteppedUp` and its
   trail. *Done when* a signed-in person asked for a level they can reach steps up without
   signing in again, keeping their `sid`, and every refusal of §5.1 is covered.
3. **MFA policies.** `MfaPolicy` on clients and APIs; the migration; the Management API fields;
   enrolment on the way (§5.3); the device approval page. *Done when* a `required` client or API
   takes nobody in on one factor, and a person without a factor can enroll and continue.
4. **RFC 9470 on the Management API.** The middleware challenge when the Management API's policy
   is `required`. *Done when* an administrator token below MFA is answered with
   `insufficient_user_authentication`, and one above passes.
5. **Dashboard** (clavia-dashboard): the policy fields, and the step-up answer to the Management
   API's challenge. *Done when* an operator can set the policies, and an administrator asked to
   step up is sent to do so and comes back.

## 10. Open questions

1. **No `acr` for one factor**, or a value of its own (§2)? *Recommendation:* none. Every value
   Clavia would invent for "a password" is one more thing to keep stable, and its absence already
   says it.
2. **Mail a notice when a factor is enrolled on the way** (§7)? *Recommendation:* yes, through
   the account mail of the self-service accounts design, and only when mail can be sent. It is
   the one signal an owner gets when someone else enrolled first.
3. **Should the Management API's policy default to `required`** once slice 4 ships? It is the
   most valuable account a deployment has. *Recommendation:* not by default, since it would lock
   every existing administrator without a factor out of the dashboard on upgrade. `seed-dev` sets
   it, and the release notes say how to turn it on.
4. **"Never" as a policy value** (§2). *Recommendation:* drop it, as above. If it is wanted, it
   would mean "ignore `acr_values` from this client", and it can be added later without a
   migration.

## 11. As built

What the slices settled differently from the sections above, so the code and this document agree.

- **A step-up challenge names its session by the `sid`** (§4, §5.2), not by a digest of the
  session identifier: the authorization endpoint knows the session, not the cookie. The `sid` is
  unique per session and kept by the step-up, and `Sessions::stepUp()` refuses unless the
  browser's own session carries it.
- **The step-up challenge is the sign-in's** (`MfaChallenge`, behind the `clavia_mfa` cookie),
  with the session's `amr` as its first factor. Its `nextUrl` is the resumed authorization
  request, so no login state is held.
- **Which factors answer** is one service, `SecondFactors`, for the page, the step-up and the
  answers; a code of a kind that cannot answer is refused without being looked at.
- **A passkey made on the way does not raise the session by itself** (§5.3): the browser goes
  back to the request, whose step-up asks for the new passkey, one more touch. Registration keeps
  the recent sign-in it needs (`CLAVIA_PASSKEY_REAUTH_WINDOW`); a session older than that signs in
  again first. Only confirming an authenticator app raises the session at enrolment.
- **The way back from enrolment** is `POST /auth/mfa/enroll/continue` with the held request's
  `state`, from the recovery codes page, so the target never travels in a URL.
- **The enrolment notice is sent outside the account mail limit** (§7): the limit can be
  exhausted by anyone with password-reset requests, which would silence the one signal an owner
  gets. It follows a completed sign-in, so nobody without the password can trigger it.
- **Device approval** returns to `/auth/device?user_code=…` after the step-up or enrolment, where
  the person allows the device again with the raised session.

