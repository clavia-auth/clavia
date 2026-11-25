# Design: Custom claims in tokens

**Status:** agreed · **Date:** 2026-11-24 · **Issue:** clavia-auth/clavia#17 ·
**Specifications:** RFC 7519 §4 (registered, public and private claim names), RFC 9068 §2.2
(JWT access tokens; §2.2.3.1 `roles`, `groups`, `entitlements`), OpenID Connect Core 1.0 (§2 the
ID token, §5.1 standard claims, §5.1.2 additional claims, §5.3 userinfo, §5.4 scopes), RFC 7662
§2.2 (introspection response), RFC 8725 §3.11 (explicit typing), the IANA "JSON Web Token Claims"
registry

## 1. Summary

A token says who someone is (`sub`) and how they signed in (`amr`, `acr`), and userinfo releases
the standard profile a scope asks for. Nothing else reaches an application or an API: an operator
whose API authorizes on a tenant, a plan or a department has to call the Management API at every
request, or keep a copy of the directory.

This design lets an operator **declare** what more a token carries:

- **Application metadata** on each account (`app_metadata`): a small JSON object only an operator
  writes, the place for facts like a tenant id or a plan.
- **Claim mappings**: a list of `{name, source}` pairs, on an **API** for its access tokens, and on
  an **application** for its ID tokens and userinfo. A source is a field of the account (address,
  profile, connection), a path in its `app_metadata`, its roles, or a constant.

Declarative first, as the issue asks: no script runs at issuance. A mapping is data the Management
API validates once, and issuance evaluates the same way every time.

### Goals

- `app_metadata` on users: read with `read:users`, written with a scope of its own.
- Mappings on APIs, in JWT access tokens and introspection; mappings on applications, in ID tokens
  and userinfo.
- Names that can never shadow a protocol or standard claim, checked when a mapping is saved and
  again when a token is built.
- Bounded sizes everywhere, so no account can make a token too large to carry.

### Not in scope

- **Code at issuance** (Auth0's Actions, Keycloak's script mappers). A later design, if declarative
  mappings fall short; webhooks (#18) are about telling other systems, not shaping tokens.
- **`user_metadata`**, a part the person edits: it waits for the account page (#26), and a claim
  the person can set is one no API should trust.
- **The `claims` request parameter** (OIDC Core §5.5): a client still asks with scopes only.
- **Mappings for third-party applications** (§2), and **`app_metadata` in imports** (§10, question 4).
- **Claims from an external provider** (an upstream ID token's `groups`): the identity is
  `(connection, subject)`, and nothing a provider says is copied into an account today.

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| Declarative mappings | A mapping is `{name, source}`, validated when saved. No expression language, no script | A script at issuance is code the operator writes and the server runs inside a transaction that mints tokens: a failure or a slow call there breaks sign-in. Mappings cover the common need (a value, a list of roles, a tenant id) and can be checked once |
| Where mappings live | **On the API** for its access tokens (and introspection about them); **on the application** for its ID tokens and userinfo | A claim is written for whoever reads it: an API reads its access tokens, an application its ID token. A server-wide list would send every claim to every application and every API, which is the disclosure the scopes exist to prevent |
| Which tokens | Access tokens: the **JWT** form, and introspection for both forms. ID token and userinfo: as each mapping says (`in: [id_token, userinfo]`, both by default) | An opaque token carries nothing; introspection is how its API reads it (RFC 7662 §2.2 allows any member). The ID token has carried protocol claims only (CLAUDE.md, "OpenID Connect"); an operator who wants a value there now says so per claim, and userinfo stays the default home of anything about the person |
| Names | An **https URI** (a public name, RFC 7519 §4.2), or a **plain name** (a private name, §4.3) that is not reserved: 1 to 64 characters `[A-Za-z0-9_.-]`, or a URI of at most 255 | URIs make a collision with a future registration impossible, and are what the specifications recommend for a public name. Requiring them everywhere is the burden Auth0 lifted in 2022; reserving every registered name (below) keeps a plain name from meaning something else (§10, question 1) |
| Reserved names | Never mapped: every name in the IANA JWT Claims registry, every OIDC Core §5.1 standard claim, and Clavia's own (`client_id`, `scope`, `cnf`, `sid`, `events`, `at_hash`, `c_hash`, `act`, `may_act`, `permissions`) | A mapping that could set `sub`, `iss`, `aud`, `exp` or `acr` would forge the token's meaning. One that could set `email` or `email_verified` would let an operator's typo make a relying party trust an address nobody verified. The list is a constant, `ClaimName::RESERVED`, kept with a test against the registry snapshot |
| RFC 9068 `roles` | The one registered name a mapping may use, and only on an API, from the `roles` source | RFC 9068 §2.2.3.1 defines `roles` in access tokens for exactly this. `groups` and `entitlements` stay reserved: Clavia has neither |
| Sources | `email`, `email_verified`, `connection`, a profile field (`profile.name`…), a path in `app_metadata` (`app_metadata.plan`, at most five levels), `roles`, or a constant (`value`) | What the account holds, and nothing a request carries. A constant covers "which deployment issued this" without metadata |
| `roles` on an API | The names of the person's roles that grant **a permission on that API**; on an application, all of the person's roles | An API needs the roles that mean something to it. Telling it about roles of every other API discloses the operator's whole access model to each of them |
| A missing value | The claim is **left out**, never sent as `null` | OIDC Core §5.1 does the same for an unknown standard claim. An API reading a missing claim denies, which fails closed |
| Machine tokens | Only constants apply | A `client_credentials` token has no subject, so every other source has no value. The constant is the one claim a machine token can carry |
| Third-party applications | **No application mappings**, and an API's mappings are **left out** of tokens issued to a third-party application | A third-party application sees the JWTs it is given, so an API's claims about a person would reach it without a consent screen naming them. A self-registered client is third-party by construction. Opening this needs consent to name the claims (§10, question 2) |
| The Management API | Mappings on a system API are **refused** (`409`, like any other change it refuses) | Its tokens are read by this server alone, which ignores them |
| Refresh | An access token's claims are worked out **at each issuance**, refresh included | As `UserScope` recomputes the scope: a changed plan or a role taken away shows on the next token, not after the refresh family ends |
| Introspection | Worked out **when asked**, from the account as it is then | Introspection already answers "is it still active" about now; storing claims per token would need a column for a value that is stale the moment metadata changes. A JWT and its introspection can therefore disagree after a change; the OpenAPI document says so (§10, question 3) |
| Sizes | `app_metadata` at most 16 KiB encoded, five levels deep, keys `[A-Za-z0-9_-]{1,64}`; at most 20 mappings per API or application, no two reading the same or nested `app_metadata` paths; a constant at most 1 KiB. At issuance, custom claims over **32 KiB** encoded refuse the token (`server_error`, the reason logged) | The definition-time rules bound what metadata and constants can add (16 KiB + 20 KiB), but not `roles`, whose count is the person's. A cap at issuance catches the rest. Refusing rather than truncating fails closed: a cut list of roles would be a different, wrong answer. Nobody reaches the cap without holding hundreds of roles |
| Who writes `app_metadata` | An operator, through the Management API, with **`update:users_app_metadata`** | It feeds the authorization of APIs: writing it is granting access, which `update:users` (a name, an address) should not imply. The person cannot write it, and neither can a provider at sign-in |

## 3. Concepts

- **Application metadata**: a JSON object on an account, written by operators only, copied into
  tokens by mappings. It holds facts, never secrets: anything in it can end up in a JWT that an
  application can read.
- **Claim mapping**: a name, a source, and (on an application) the places it goes.
- **Reserved name**: a claim the protocol, a registry or this server defines. No mapping produces
  one, whatever it is called on.

## 4. Model

### Domain

A new context, `Domain\Claims`, since access tokens (`OAuth2`) and ID tokens (`Oidc`) both use it:

- `ClaimName` (value object): `fromString()` refuses a reserved name, an invalid plain name, a URI
  that is not https or is too long. `RESERVED` is the list of §2.
- `ClaimSource` (value object, closed set): `Email`, `EmailVerified`, `Connection`,
  `ProfileField(field)`, `AppMetadata(path)`, `Roles`, `Constant(value)`.
- `ClaimDestination` (enum): `IdToken`, `UserInfo`, `AccessToken`.
- `ClaimMapping` (`name`, `source`, `destinations`) and `ClaimMappings` (at most 20, names unique).
  `forApi()` takes only `AccessToken` and allows `roles` as a name; `forApplication()` takes
  `IdToken` and `UserInfo`.
- `CustomClaims::of(ClaimMappings, ClaimSubject, ClaimDestination): array<non-empty-string, mixed>`:
  the evaluation, pure. `ClaimSubject` is what the sources read: the `User`, the role names that
  apply, or nothing (a machine token). It asserts again that no name is reserved, with a
  `LogicException`, so a stored mapping that predates a new reserved name can never reach a token.
- `Identity\AppMetadata` (value object): the bounds of §2; `User::changeAppMetadata()`, reported in
  `UserChanged` as the field `app_metadata`, never its value.
- `ResourceServer::$claims` and `Client::$claims`, with `withClaims()`. A system API refuses
  (`SystemApiProtected`), a third-party client refuses (`InvalidValue`).

### Application

- `Token\AccessTokenMinter` passes the API's mappings to `AccessTokenClaims::of()` (JWT), with the
  person's roles on that API, unless the client is third-party.
- `IdTokenIssuer` and `ReadUserInfo` pass the application's mappings for their destination.
- Introspection adds the API's mappings for a person's token about an API, worked out then.
- The Management API's resource server, client and user use cases take the new fields.

### Migrations

One, with the first slice that needs each column:

```sql
ALTER TABLE users ADD COLUMN app_metadata jsonb NOT NULL DEFAULT '{}';
ALTER TABLE resource_servers ADD COLUMN claims jsonb NOT NULL DEFAULT '[]';
ALTER TABLE oauth2_clients ADD COLUMN claims jsonb NOT NULL DEFAULT '[]';
```

## 5. Flows

### 5.1 Writing `app_metadata`

`PATCH /api/v1/users/{id}` with `app_metadata` replaces the object whole (no merge: what is sent is
what is kept, and a key is removed by leaving it out). It needs `update:users_app_metadata` in
addition to `update:users`; a request carrying it without the scope is `403`, and nothing is
changed. Refusals are `422` with the pointer: too large, too deep, an invalid key, not an object.
The trail records `user.updated` with `fields: ["app_metadata"]`. `GET` returns it with
`read:users`, and an export writes it.

### 5.2 Defining mappings

`PATCH /api/v1/resource-servers/{id}` and `PATCH /api/v1/clients/{id}` take `claims`, a list that
replaces the one there. Each entry is held to §2 and §4: a reserved or invalid name, an unknown
source, a path too deep, a duplicate name, more than twenty, a destination that does not belong
there. Each refusal is a `422` that points at the entry. On a system API the answer is `409`, and
on a third-party client `422`. The trail lists `claims` among the fields changed.

### 5.3 Issuing

1. The grant settles the token as today (scope, audience, the person).
2. For a JWT access token to an API with mappings, and a first-party client: the person's roles
   that hold a permission on the API; `CustomClaims::of(…, AccessToken)`; merged into
   `AccessTokenClaims` after the protocol claims, which a collision cannot replace (it throws).
   Past the 32 KiB cap the grant fails with `server_error` and spends nothing, as a signing
   failure does.
3. For an ID token: the application's mappings with `IdToken`, merged the same way into
   `IdTokenClaims`.
4. A source with no value leaves its claim out. A machine token takes constants only.

### 5.4 Userinfo and introspection

Userinfo adds the application's `UserInfo` mappings to what the scope releases. Introspection adds
an API's mappings to the answer about a person's token for that API (§2, worked out now). Neither
adds anything for a third-party application.

## 6. Interfaces

- **Management API** (`docs/openapi/management-api.yaml`):
  - `User.app_metadata` (object, read with `read:users`), writable on `PATCH /users/{id}`;
  - a new scope `update:users_app_metadata`;
  - `claims` on `ResourceServer`, and on `Client` (each entry `{name, source, value?, in?}`, with
    `source` one of `email`, `email_verified`, `connection`, `profile.<field>`,
    `app_metadata.<path>`, `roles`, `constant`);
  - examples for each, and the note that revocation and a JWT's claims part ways after a change.
- **Discovery**: unchanged. `claims_supported` lists what the server knows for everyone; a claim
  one application receives is not that.
- **Dashboard** (clavia-dashboard): a JSON editor for `app_metadata` on the user page; a list of
  mappings on the API and application pages, with the sources as a select and a preview of the
  claims for a chosen user.
- **Exports** write `app_metadata`; imports leave it out for now (§10, question 4).

## 7. Security rules

- **No mapping produces a reserved claim**, checked at definition (`ClaimName`) and again at
  issuance (`CustomClaims`, a `LogicException`): `sub`, `iss`, `aud`, `exp`, `acr`, `amr`, `cnf`,
  `email`… mean what this server says, whatever is stored.
- **Nothing in a request becomes a claim.** Sources read the account and the mappings only; there
  is no `claims` parameter and no value from a header or a body.
- **`app_metadata` is an operator's.** Only `update:users_app_metadata` writes it: not the person,
  not a provider, not `update:users` alone. A claim an API trusts must come from a party it trusts.
- **No claim reaches a third-party application**: there is no consent screen that names it.
- **An API learns only its own roles** (§2).
- **Sizes are bounded**: where they are written, and by a cap at issuance that refuses the token
  instead of truncating a claim (§2).
- **`app_metadata` is not a vault.** The document and the dashboard say it ends up in tokens a
  client can read. Its values never go to the log or the audit trail, which records only that it
  changed.
- **Fail closed.** A missing value leaves its claim out; nothing is replaced by a default an API
  could mistake for a grant.

## 8. Tests

- `ClaimNameTest`: every reserved name refused, the registry snapshot pinned, plain names and URIs
  at their bounds, `roles` only on an API.
- `CustomClaimsTest`: each source, a missing value left out, a machine token's constants only, a
  stored reserved name refused at evaluation, the cap at issuance.
- `ClaimMappingsTest`: at most twenty, names unique, no overlapping `app_metadata` paths.
- `AppMetadataTest`: size, depth and key bounds; replacement whole.
- Acceptance:
  - an API with mappings: a JWT access token carries them, refresh recomputes them after a change,
    introspection reports them for an opaque token, and a third-party client's token has none;
  - an application with mappings: the ID token and userinfo carry what each mapping says;
  - writing `app_metadata` needs its scope;
  - a system API and a third-party client refuse mappings;
  - every response checked against the OpenAPI document;
  - `AuditTrailsTest` unchanged: the existing events carry the field names.

## 9. Slices

1. **Application metadata.** `AppMetadata`, the column, `User.app_metadata` in the Management API
   and the export, the scope `update:users_app_metadata`. *Done when* an operator holding the scope
   can set and read it, one without it is refused, and the trail names the field only.
2. **Mappings on APIs.** `Domain\Claims`, the column on resource servers, `claims` in the
   Management API, the JWT access token and introspection. *Done when* a first-party client's
   token for an API carries its mappings, refreshed values included, and every refusal of §5.2 is
   covered.
3. **Mappings on applications.** The column on clients, `claims` there, the ID token and userinfo.
   *Done when* each destination carries what the mappings say, and a third-party client cannot
   have any.
4. **Dashboard** (clavia-dashboard): the `app_metadata` editor and the mapping lists, with the
   preview. *Done when* an operator can do all of the above without the API.

## 10. As built

What the slices settled differently from the sections above, so the code and this document agree.

- **Past the cap, a 500, not `server_error`** (§2, §5.3): RFC 6749 §5.2 defines no `server_error`
  at the token endpoint (only the authorization endpoint's redirect has one). The grant fails as a
  signing failure does: `CustomClaimsTooLarge`, logged under its error reference, the transaction
  rolled back, so nothing is spent and no token recorded.
- **Canonical JSON** (`Domain\Shared\CanonicalJson`): `app_metadata` and a constant's value are
  kept with their objects' keys sorted, because PostgreSQL's `jsonb` reorders them; the same value
  must read back as the same value.
- **A reserved name stored earlier still loads** (`ClaimName::fromStorage()`), and is refused at
  issuance (`LogicException`), so a name added to the list later never takes an API down at read.
- **Introspection** adds the claims to access tokens only, never to a refresh token.

## 11. Open questions

1. **Plain names beside URIs** (§2)? *Recommendation:* allow them, reserved names excepted. A URI is
   safer against future registrations, but operators read and type these, and the reserved list
   covers every name registered today.
2. **Claims for third-party applications** (§2)? *Recommendation:* not now. It needs the consent
   screen to name each claim, and a consent record that covers claims as well as scopes: a design
   of its own.
3. **Introspection worked out now, or as issued** (§2)? *Recommendation:* now. It matches what
   introspection already reports (`active`), and needs no storage. The price is that an opaque
   token's claims can change during its life, which the document states.
4. **`app_metadata` in imports**? *Recommendation:* later, in its own slice. The import is queued
   with `create:users`, and a line that sets metadata would need the caller to hold
   `update:users_app_metadata`, checked when the job is queued.
