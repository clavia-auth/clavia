# Design: Dynamic client registration

**Status:** built · **Date:** 2026-11-23 · **Issue:** clavia-auth/clavia#15 ·
**Specifications:** RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol), RFC 7592
(Dynamic Client Registration Management Protocol), RFC 8414 §2 (`registration_endpoint`),
OpenID Connect Dynamic Client Registration 1.0, RFC 8252 §7.3 (loopback redirects),
OAuth 2.1 §2.3 (redirect URIs), RFC 9700 §2.1 (exact matching)

## 1. Summary

Today a client exists only because an operator made it: through the Management API, the
dashboard, or `clients:create-m2m`. That is right for the operator's own applications, and a
chore for everyone else: a partner, a developer portal, a tool that sets itself up (an MCP
client, a CI integration), each has to ask the operator, who types its redirect URIs by hand.

RFC 7591 lets software register itself: it posts its metadata to a registration endpoint and
gets back a `client_id` (and a secret, if it asked for one). RFC 7592 lets it read, change and
delete that registration afterwards, with a *registration access token* it was handed at
registration. Clavia implements both, with one rule above everything else: **a client that
registered itself is a third-party client, and so can never reach a system API**.

### Goals

- `POST /oauth2/register` (RFC 7591 §3), open only to a caller holding an **initial access
  token** an operator issued (§1.2, §3), never to anybody at all.
- A metadata policy (§2) that refuses whatever a self-registered client must not have, and says
  which field is at fault (`invalid_redirect_uri`, `invalid_client_metadata`, §3.2.2).
- `GET`, `PUT` and `DELETE` on the client's configuration endpoint (RFC 7592 §2), with its
  registration access token.
- Initial access tokens issued, listed and revoked through the Management API and the shell.
- `registration_endpoint` in discovery (RFC 8414 §2) when registration is on.

### Not in scope

- **Open registration** (no initial access token): later, #81.
- **Software statements** (RFC 7591 §2.3): a signed statement from a software publisher. Without
  a trust list of publishers there is nothing to verify it against; a request carrying one is
  refused (§2).
- **`private_key_jwt`, `jwks`, `jwks_uri`, `request_uris`, `sector_identifier_uri`, pairwise
  subjects**: Clavia supports none of them for any client, so none for a self-registered one.
- **Machine clients** (`client_credentials`): useless without a client grant, and client grants
  are written from the shell only (CLAUDE.md, *Client credentials*). An endpoint that registered
  machines would invite asking for one.
- **Private-use URI schemes** for native applications (RFC 8252 §7.1): `Url` needs a host today,
  for every client. Loopback redirects (§7.3) are enough for a native application now.

## 2. Decisions

| Topic | Decision | Why (the alternatives rejected) |
|---|---|---|
| Who may register | **A bearer of an initial access token** (RFC 7591 §3), issued by an operator. Registration is off unless `CLAVIA_CLIENT_REGISTRATION=token` | Open registration (anyone at all) makes this server a free client factory: phishing applications under the operator's sign-in page, and unbounded rows. An operator handing out a token knows who registers, and can stop it |
| Initial access token | **Its own kind of token**: a 43-character secret stored as its digest, with an expiry, a number of uses, a description, revocable. Not an access token for the Management API | A Management API token with `create:clients` would let the bearer do everything an operator can do to clients, including first-party ones. An initial access token does one thing: register third-party clients, at most *n* times, until a date |
| Uses | `max_uses` (1 by default, at most 1000), spent by a conditional `UPDATE` in the registration's transaction | One token per partner is the common case; a developer portal handing tokens out in bulk sets more. A conditional write means two registrations cannot share the last use |
| Ownership | **Always third-party**: the id is generated with `Ownership::ThirdParty` (`tpc_…`) | Ownership is read from the id (`Ownership`), and a third-party client is already refused a system API at the authorization endpoint (step 4) and at the token endpoint, asked for consent on every scope, and given no connections of its own. Nothing new has to be enforced; nothing a request says can change it |
| Connections | None of its own: third-party clients sign people in through the domain connections | `Client::register()` already refuses connections for a third-party client |
| Grant types | `authorization_code` (the default) and `refresh_token`. Anything else, `client_credentials` and the device grant included, is `invalid_client_metadata` | §2: the server may refuse a grant type. A machine client has nothing to do without a client grant. The device grant is first-party only (`Client::register()`): a device flow anybody can start is a phishing kit |
| Response types | `code` only, the default | OAuth 2.1 has no other |
| Authentication | `none` (a public client), `client_secret_basic` (the default, §2) or `client_secret_post` | What `ClientAuthMethod` supports. A secret is generated by the server, never chosen by the client |
| PKCE | **Always required** for a self-registered client: `require_pkce` is not part of the metadata | The one PKCE exception (CLAUDE.md, *Security invariants*) is the operator's decision about one client they know |
| Redirect URIs | Required for a code-flow client; each one `https` without a fragment, or `http` on a loopback literal (`127.0.0.1`, `[::1]`) for a public client (RFC 8252 §7.3). Never `localhost` by name, never another scheme | OAuth 2.1 §2.3.1. A loopback literal cannot be resolved elsewhere; `localhost` can be (RFC 8252 §8.3). Matching stays exact (RFC 9700 §2.1), except the loopback port, which RFC 8252 §7.3 says may vary: question 3 |
| Other URIs | `post_logout_redirect_uris` by the same rule; `backchannel_logout_uri` through `OutboundUrlPolicy`, as for an operator's client | A self-registered client is exactly the case the outbound policy is for: a URL this server will fetch, on somebody else's say-so |
| What it cannot set | `mfa_policy`, `require_pushed_authorization_requests`, connections, ownership, `require_pkce`: all the operator's. It **may** set `dpop_bound_access_tokens` | Every field it can set either describes it or restricts it. DPoP only makes its own tokens harder to use |
| Display metadata | `client_name` (required, the consent screen names it); `client_uri`, `logo_uri`, `tos_uri`, `policy_uri`, `contacts` are **not stored**, and not returned | CLAUDE.md, *Columns*: only what the code reads. RFC 7591 §3.2.1 has the response carry what was registered, so leaving a field out says it was not. A logo would be an image from somewhere else on the sign-in origin's consent page, which its CSP forbids |
| Unknown metadata | Ignored, and absent from the response | RFC 7591 §2: the server may ignore what it does not understand; the response says what was kept |
| Software statements | Refused (`invalid_software_statement`, §3.2.2) | Without a list of trusted publishers there is no key to check one with. Ignoring one would mislead a client that counts on its claims being honoured |
| The registration access token | 43 characters, stored as its digest on the client's registration row, **rotated on every `PUT`** and returned once each time (RFC 7592 §3) | A leaked one stops working at the next update. Not rotated on `GET`: a client that reads its configuration and loses the answer would lock itself out |
| Client secret | Generated at registration, `client_secret_expires_at: 0` (never expires); kept on `PUT` | RFC 7591 §3.2.1. An operator can still rotate it through the Management API |
| Which clients RFC 7592 can touch | **Only the ones registered through RFC 7591**: an operator's client has no registration access token | The configuration endpoint must never be a second door into the operator's own applications |
| Deletion | `DELETE` removes the client the same way the Management API does (its tokens, codes, consents, cascades), `204` | RFC 7592 §2.3. One deletion path, so nothing is left behind |
| Operator's view | The Management API shows a client's `registration` (by which initial access token, when), and may change or delete it like any other client | The operator stays in charge. A self-registered client is an ordinary client once it exists |
| Unused clients | A self-registered client that has **never been issued a token** is deleted `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` days after it registered (`clients:purge-unused`, run daily). A client used once is never purged | A token handed out in bulk leaves clients nobody finished setting up. "Never used" is one write per client's lifetime; "idle since" would be a write at every token, and would delete a legitimate client that is only dormant |
| Throttle | Registrations are limited per client address (`AttemptCounter`), counted before the token is checked | A bad token costs a digest lookup; a flood of them should still be bounded |

## 3. Settings

| Setting | Default | Range | Why |
|---|---|---|---|
| `CLAVIA_CLIENT_REGISTRATION` | `off` | `off`, `token` | `off`: there is no registration endpoint, and discovery does not name one. `token`: open to holders of an initial access token. A third value, `open`, is #81 |
| `CLAVIA_CLIENT_REGISTRATION_MAX_PER_ADDRESS` | 20 | 1–1000 | Registrations, valid or not, from one client address per window |
| `CLAVIA_CLIENT_REGISTRATION_WINDOW` | 3600 s | 60–86400 | The window those are counted in |
| `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` | 30 days | 1–365 | How long a self-registered client that has never been issued a token is kept (§5.4) |

The configuration endpoint follows the same switch: with registration `off`, it does not exist
either, and a self-registered client already made keeps working as a client.

## 4. Model

- **`Domain\Client\Registration\InitialAccessToken`** (aggregate): `InitialAccessTokenId`
  (UUID), `Digest`, `description` (1–120 bytes), `createdAt`, `expiresAt`, `maxUses`, `uses`,
  `revokedAt`. `issue()` returns it with the secret, once; `isUsableAt($now)`; `revoke($now)`.
  The secret is a `SecretGenerator::token()`.
- **`InitialAccessTokenRepository`**: `add`, `find`, `list(PageRequest)`, `save`, and
  `spendOne(Digest, DateTimeImmutable $now): ?InitialAccessTokenId`, one conditional
  `UPDATE … SET uses = uses + 1 WHERE digest = :d AND revoked_at IS NULL AND expires_at > :now
  AND uses < max_uses RETURNING id`: the answer to "may this caller register, and did it win the
  last use?".
- **`Domain\Client\Registration\ClientRegistration`**: the client's `ClientId`, the digest of its
  registration access token, the `InitialAccessTokenId` it came through, `registeredAt`, and
  `firstUsedAt` (null until the client is first issued a token). `rotate(Digest)` for a `PUT`.
- **`ClientRegistrationRepository`**: `add`, `findByAccessToken(Digest)`, `find(ClientId)`,
  `save`, `markUsed(ClientId, DateTimeImmutable)` (one conditional `UPDATE … WHERE first_used_at
  IS NULL`: a no-op for every token but the first), and `neverUsedSince(DateTimeImmutable):
  list<ClientId>`. Deleting the client deletes its registration (foreign key, cascade).
- **`Application\Clients\Registration\RegistrationMetadata`**: reads RFC 7591 metadata into a
  `NewClient` under the policy of §2, or a list of refusals by field. The one place the policy
  lives, so `POST` and `PUT` cannot drift apart.
- **Use cases**: `RegisterClientDynamically`, `ReadClientConfiguration`,
  `UpdateClientConfiguration`, `DeleteClientConfiguration` (the last reuses `DeleteClient`);
  `IssueInitialAccessToken`, `RevokeInitialAccessToken`, `ReadInitialAccessTokens`;
  `PurgeUnusedRegistrations` (each client deleted through `DeleteClient`).
- **Subscriber** `MarkRegistrationUsed`, on `AccessTokenIssued`: records the first use, so no
  grant changes. Listed in `ConfigProvider::EVENT_SUBSCRIBERS`; it records nothing in the audit
  trail (the token's own event already does).
- **Events**: `InitialAccessTokenIssued`, `InitialAccessTokenRevoked` (configuration trail);
  the client's own `ClientRegistered`, `ClientChanged` and `ClientDeleted`, as today. The actor
  of a self-registration, and of a later `PUT` or `DELETE`, is `Actor::application(ClientId)`:
  the client acting on itself. `ClientRegistered` names the initial access token
  (`registered_with` in the trail), which says who let it in without a new kind of actor, a new
  column or a new value in the Management API.
- **Migration** `00NN_dynamic_client_registration.sql`:
  - `initial_access_tokens (id uuid PK, digest bytea UNIQUE, description, created_at,
    expires_at, max_uses int CHECK (max_uses BETWEEN 1 AND 1000), uses int CHECK (uses <=
    max_uses), revoked_at)`;
  - `client_registrations (client_id PK REFERENCES oauth2_clients ON DELETE CASCADE,
    access_token_digest bytea UNIQUE, initial_access_token_id REFERENCES initial_access_tokens
    ON DELETE SET NULL, registered_at)`;
  - slice 5 adds `client_registrations.first_used_at timestamptz NULL`, in its own migration.

## 5. Flows

### 5.1 Registration (RFC 7591 §3)

`POST /oauth2/register`, `Content-Type: application/json`:

1. Registration `off`: the route does not exist (404).
2. The address is counted; past the limit, `429` with `Retry-After`.
3. `Authorization: Bearer <initial access token>` (RFC 6750 §2.1, nowhere else). Missing,
   unknown, expired, revoked or used up: **`401 invalid_token`**, one answer, with a `Bearer`
   challenge. The use is not spent yet.
4. The body: not a JSON object sent as `application/json` is `400 invalid_client_metadata`. A
   member sent twice keeps its last value, as everywhere else this server reads JSON.
5. `software_statement` present: `400 invalid_software_statement`.
6. The metadata, read by `RegistrationMetadata` (§2). The first refusal is the answer:
   `invalid_redirect_uri` for a redirect or post-logout URI, `invalid_client_metadata` for
   anything else, with an `error_description` naming the field, never its value.
7. In one transaction: spend one use (`spendOne`; lost the race, `401 invalid_token`), register
   the client (`Client::register()`, so every domain rule applies), add its
   `ClientRegistration`, dispatch `ClientRegistered`.
8. `201` with the client's metadata as registered (§3.2.1): `client_id`, `client_secret` and
   `client_secret_expires_at: 0` for a confidential client, `client_id_issued_at`,
   `registration_access_token`, `registration_client_uri`
   (`{issuer}/oauth2/register/{client_id}`), and every field kept. `Cache-Control: no-store`.

### 5.2 Reading, changing, deleting (RFC 7592 §2)

`GET | PUT | DELETE /oauth2/register/{client_id}`, with `Authorization: Bearer <registration
access token>`:

1. The token's digest finds a registration, and the registration's client is the one in the
   path; otherwise **`401 invalid_token`**, whatever the reason (RFC 7592 §2.1: the client must
   not learn whether another client exists).
2. **`GET`**: `200` with the configuration, as at registration, without the secret's value
   (RFC 7592 §2.1 allows sending it; there is no need to).
3. **`PUT`** (§2.2): the whole metadata, `client_id` included and equal to the path's. A
   `client_secret`, if sent, must be the current one; `registration_access_token`,
   `registration_client_uri`, `client_secret_expires_at` and `client_id_issued_at` must not be
   sent (`invalid_client_metadata`). Read by the same `RegistrationMetadata`; an omitted field
   takes its default, since a `PUT` replaces. The token type cannot change (a public client stays
   public, a confidential one confidential): `invalid_client_metadata`. Then, in one
   transaction: the client updated, the registration access token rotated, `ClientChanged`
   dispatched. `200` with the configuration and the new token.
4. **`DELETE`** (§2.3): the client deleted as the Management API deletes one, `204`. Its
   registration access token dies with it.

### 5.3 Initial access tokens

- `POST /api/v1/initial-access-tokens` (`create:initial_access_tokens`): `description`,
  `expires_in` (60 s to 90 days, 7 days by default), `max_uses`. `201` with the token, once.
- `GET /api/v1/initial-access-tokens` (`read:initial_access_tokens`): the list, newest first,
  with uses and state; never the token.
- `DELETE /api/v1/initial-access-tokens/{id}` (`delete:initial_access_tokens`): revoked at
  once, `204`. Clients it registered keep working.
- `bin/clavia clients:registration-token [--uses=N] [--expires-in=S] <description>` does what the
  `POST` does, for a server with no dashboard yet.

### 5.4 Unused clients

1. Whenever a token is issued to a client, `MarkRegistrationUsed` sets its registration's
   `first_used_at` if it is still null. An operator's client has no registration, and nothing
   happens.
2. `bin/clavia clients:purge-unused`, run daily like `audit:purge`, deletes every self-registered
   client whose `first_used_at` is null and whose `registered_at` is older than
   `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME`, through `DeleteClient`, so each deletion is a
   `ClientDeleted` in the trail with the system as the actor. It prints how many it deleted.
3. It runs whatever `CLAVIA_CLIENT_REGISTRATION` says: clients registered before the switch went
   `off` are still cleaned up.

## 6. Interfaces

- **Endpoints**: `POST /oauth2/register`; `GET | PUT | DELETE /oauth2/register/{client_id}`.
  Both on `auth.{domain}`, answering JSON only (`OAuth2Responder`), errors as RFC 7591 §3.2.2
  documents (`error`, `error_description`), bearer refusals as RFC 6750.
- **Discovery**: `registration_endpoint` (RFC 8414 §2), present only when registration is on.
  `OidcTest` fetches it.
- **Management API document**: the three initial access token operations and their schemas; three
  scopes in `ManagementPermission` and `securitySchemes`; a client's `registration`
  (`null`, or `{initial_access_token_id, registered_at}`), read-only.
- **Dashboard** (clavia-dashboard): an "Initial access tokens" page (issue, list, revoke, the
  token shown once), and the registration on a client's page.
- **No page on `auth.*`**: registration is a machine conversation. The consent screen already
  names a third-party client by its `client_name`.

## 7. Security rules

- **A self-registered client never reaches a system API.** It is third-party by construction
  (§2, *Ownership*): its id is generated as `tpc_…` by the use case, from no field of the
  request, and third-party clients are refused system APIs before anyone signs in and at the
  token endpoint. No client grant can be registered through this endpoint, and client grants are
  written only from the shell. A test asks for the Management API with every grant a
  self-registered client can hold, and is refused each time.
- **Registration is never anonymous**: off by default; on, only with an operator's initial access
  token, limited in uses and time, revocable, and stored as its digest.
- **No use is spent by a refusal**, and the last use goes to one registration only (a conditional
  `UPDATE` in the transaction that creates the client).
- **RFC 7592 cannot reach an operator's client**: only a client with a registration row has a
  registration access token, and a token only answers for the client in its row.
- **One answer for every bad token**, at both endpoints: the caller learns nothing about which
  tokens or clients exist.
- **Redirect URIs** are https, or loopback literals for public clients; matched exactly; no
  wildcard, no fragment, never `localhost` by name.
- **Every URL this server will fetch** (`backchannel_logout_uri`) goes through
  `OutboundUrlPolicy`, at registration, at every `PUT`, and at send time.
- **Secrets are returned once** (the client secret at registration, the registration access
  token at registration and each `PUT`, the initial access token at issuance) and stored as
  digests or bcrypt hashes. No error repeats a value from the request.
- **Only a self-registered client that never got a token is ever purged**: the purge reads
  registration rows only, so it cannot reach an operator's client, and one token issued settles
  it for good.
- **PKCE stays mandatory**, and the operator's levers (`mfa_policy`, PAR, connections) stay the
  operator's.

## 8. Tests

- **Unit**: `RegistrationMetadata`, case by case: each refused grant, response type, auth method
  and URI (`http` on a public host, `localhost`, a fragment, a private address for back-channel
  logout); defaults; unknown members ignored; `require_pkce` and `mfa_policy` ignored, never
  applied. `InitialAccessToken` rules (expiry, uses, revocation).
- **Contract** (double and PostgreSQL): both repositories, and `spendOne` refusing a used-up,
  expired or revoked token, and giving the last use to one of two concurrent callers.
- **Acceptance**:
  - registration off: no route, and no `registration_endpoint` in discovery;
  - no token, a bad token, an expired, revoked or used-up one: `401 invalid_token`, no use spent;
  - a confidential and a public client registered; the response checked against RFC 7591
    §3.2.1; the client completes a code flow, asked for consent;
  - **a self-registered client is refused the Management API**: at `/oauth2/authorize` with
    `audience`, and with a refresh token;
  - each refusal of §5.1, with its error code;
  - `GET` and `PUT` (the token rotated, the old one refused) and `DELETE` (the client and its
    tokens gone); another client's token, an operator's client: `401`;
  - the throttle answers `429`;
  - the Management API issues, lists and revokes initial access tokens, and shows a client's
    registration, every response checked against the document;
  - `clients:purge-unused` deletes a client registered past the lifetime and never used, keeps
    one used once, one still within the lifetime and every operator's client.

## 9. Slices

1. **Initial access tokens.** The aggregate, the repository, the migration (both tables), the
   Management API operations and scopes, `clients:registration-token`, the
   `CLAVIA_CLIENT_REGISTRATION` setting. *Done when* an operator can issue, list and revoke a
   token, and the token is stored only as its digest.
2. **Registration (RFC 7591).** `RegistrationMetadata`, `RegisterClientDynamically`,
   `POST /oauth2/register`, the throttle and its settings, `registration_endpoint` in discovery,
   the initial access token named in the trail. *Done when* a holder of a token registers a third-party client that signs
   a person in, and cannot get a token for the Management API.
3. **Configuration endpoint (RFC 7592).** `GET`, `PUT`, `DELETE`, the rotation, the client's
   `registration` in the Management API. *Done when* a registered client reads, changes and
   deletes itself, and nothing else.
4. **Dashboard** (clavia-dashboard): the initial access tokens page and a client's registration.
   *Done when* an operator does slice 1 without the shell.
5. **Unused clients.** The `first_used_at` migration, `MarkRegistrationUsed`,
   `PurgeUnusedRegistrations`, `clients:purge-unused`, the
   `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` setting, and `docs/` naming the command next to
   `audit:purge` as a daily job. *Done when* a self-registered client never issued a token is
   deleted after the lifetime, and no other client ever is.

## Open questions

1. **Open registration.** Some ecosystems (MCP clients finding an authorization server they have
   never seen) register with no initial access token at all. *Settled*: not now; #81 designs
   `open` later, with a per-address quota, expiry of clients that never sign anyone in, and a
   consent screen that says plainly that nobody has checked the application.
2. **Expiry of unused clients.** *Settled*: slice 5 deletes a self-registered client that has
   never been issued a token, after `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME`; an idle client
   that was used is kept.
3. **Loopback ports.** RFC 8252 §7.3 asks the server to accept any port on a loopback redirect,
   since a native application picks a free one at run time. Today Clavia matches every redirect
   URI exactly, for every client. *Recommendation*: accept any port for a loopback redirect URI
   registered without one, for public clients only. *Settled*: a separate change to
   `Client::allowsRedirectUri()` for every client, #82; this design does not depend on it.
