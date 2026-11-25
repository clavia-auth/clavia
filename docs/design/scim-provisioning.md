# Design: SCIM 2.0 provisioning

**Status:** agreed · **Date:** 2026-11-24 · **Issue:** clavia-auth/clavia#21 ·
**Specifications:** RFC 7643 (SCIM core schema: §2 attributes, §3 common attributes and `meta`,
§4.1 `User`, §4.2 `Group`, §4.3 the enterprise extension, §5 `ServiceProviderConfig`, §6
`ResourceType`, §7 `Schema`), RFC 7644 (SCIM protocol: §3.3 create, §3.4.1 retrieve, §3.4.2 list
and filter, §3.5.1 replace, §3.5.2 modify with PATCH, §3.6 delete, §3.7 bulk, §3.11 `/Me`, §3.12
errors, §3.14 versioning, §7 security, §8.1 media type), RFC 6750 (bearer tokens)

## 1. Summary

An organisation's directory (Entra ID, Okta, Google Workspace, JumpCloud) knows who joins, changes
and leaves. Today Clavia learns of a person only when they sign in, and learns they left only when
an operator deactivates them by hand: a leaver keeps a working account, and a refresh token, until
somebody remembers.

This design makes Clavia a **SCIM 2.0 service provider**: a directory, holding a provisioning token
for one connection, creates, updates, deactivates and deletes that connection's accounts through
`/scim/v2`. Deactivation does what an operator's does: sessions end (with back-channel logout),
refresh tokens stop working.

It completes the enterprise connections: a SAML or OpenID Connect connection whose accounts the
directory provisions can refuse anyone it has not provisioned.

### Goals

- `/scim/v2/Users`: create, read, list with the filters directories send, replace, modify (PATCH),
  delete; `ServiceProviderConfig`, `ResourceTypes`, `Schemas`.
- Provisioning tokens managed from the Management API, each bound to one connection.
- Accounts provisioned into a pool, or into an external connection (SAML, OpenID Connect) so that
  the person's first sign-in finds them.
- `/scim/v2/Groups` mapped to roles, under rules that keep a directory from granting what it should
  not (§2).
- Interoperability with Entra ID's and Okta's provisioning clients, tested against their published
  behaviour.

### Not in scope

- **Bulk** (§3.7), **sorting**, **`/Me`** (§3.11), **filters beyond equality** on a few attributes:
  the directories this is for use none of them (§2).
- **Passwords through SCIM**: refused (§2).
- **Clavia pushing to a directory** (Clavia as a SCIM client): the other direction.
- **The enterprise extension's attributes** (department, manager…) stored: accepted and ignored for
  now (§10, question 3).
- **Provisioning social or passwordless connections**: their accounts are the provider's or the
  mailbox's.

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| A surface of its own | **`/scim/v2/*` on `management.{domain}`**, authenticated by a **provisioning token** (`Authorization: Bearer`), the fifth surface beside the four of CLAUDE.md | Directories are configured with a base URL and a secret token (Entra's "Tenant URL" and "Secret Token"; Okta's "HTTP Header" authentication). A Management API access token would mean an OAuth client per directory and a token the directory cannot refresh. The management host keeps it off the sign-in origin |
| The token | Like an initial access token: a 43-character secret **shown once**, stored as its digest, with a description, an expiry (default **one year**, at most two) and a revocation; **bound to one connection**, which is where its accounts live | One credential per directory per connection, revocable on its own. An expiry because a token pasted into a directory's settings is forgotten there; a year, because a provisioning outage is noticed and a monthly one is a burden. The Management API lists tokens expiring within 30 days |
| Which connections | **Pools** (`database`) and **enterprise connections** (`oidc`, `saml`); not social, not `email` | A directory owns its staff's accounts in a pool or an enterprise connection. Google's or GitHub's accounts are the provider's, and `email` has no account of its own to provision |
| Accounts in an external connection | Provisioning **creates the account and its external identity** `(connection, subject)` ahead of the first sign-in. The subject is the SCIM attribute the token names: `externalId` (default) or `userName` | The person's first SAML or OpenID Connect sign-in then finds them by `(connection, subject)`, as today, instead of creating a second account. Entra maps `externalId` from `mailNickname` by default and can map it from the object id, which its SAML `objectidentifier` claim carries; the guide (§6) tells operators to. Okta sends its login as `userName` |
| Only provisioned people | A connection option, **`require_provisioning`** (off by default): sign-in through it is refused to anyone without a provisioned account (`ExternalSignInFailure::NotAvailable`, logged as `not_provisioned`) | The directory then decides who gets in, and a person removed from the directory cannot come back in by signing in again. Off by default, so turning provisioning on changes nothing until the operator says so |
| `userName` and `emails` | `userName` is unique per connection, **case-insensitive** (RFC 7643 §4.1.1), kept in a provisioning record beside the account. The account's address is the **primary `emails` value**, or `userName` when it is an address and no email is given | Clavia's accounts are keyed by address; SCIM's by `userName`. Keeping both lets a directory rename one without the other. An address from a directory is **verified** for a pool's account when the token says the directory is trusted for addresses (`addresses_trusted`, off by default), as for SAML |
| Passwords | **Refused** (`400 invalidValue` naming `password`). A pool's provisioned account has no password; the operator sends it the invitation (`POST /api/v1/users/{id}/password-reset`), or it signs in through an enterprise connection | A plaintext password in a provisioning payload is a password in a directory's logs. Entra never sends one; Okta can, and is told not to |
| Unknown attributes | **Ignored**, where the Management API refuses them; supported attributes are validated as strictly as the Management API's | Directories send fixed attribute sets with extensions and their own schemas, and their provisioning fails against a server that rejects them. What is supported is listed in `Schemas`, and anything else is ignored, so a directory's administrator can see it |
| Deactivation | `active: false` (by PUT or PATCH) **deactivates**: sessions end (`SessionEndReason::Deactivated`, back-channel logout), refresh tokens stop at their next use, access tokens stop at introspection. `active: true` reactivates | What an operator's deactivation already does. This is the point of provisioning: a leaver loses access when the directory says so |
| Deletion | `DELETE` **deletes** the account, with its tokens and identities (RFC 7644 §3.6). A token option, `delete_deactivates`, makes it a deactivation instead (§10, question 2) | The protocol says delete. Entra deactivates first and deletes after its soft-delete window, which suits the default; an operator who must keep accounts for audit turns the option on |
| Filters | `eq` on `userName` (case-insensitive), `externalId`, `id`, `emails.value`, optionally joined by `and`; anything else `400 invalidFilter`. `startIndex` and `count` (at most 200) | Entra filters on its matching attribute (`userName` by default, or `externalId`) with `eq`; Okta on `userName eq`. A full filter grammar is a parser to secure for queries nobody sends |
| PATCH | `add`, `replace`, `remove` with no path (an object of attributes) or a path of `attr`, `attr.sub`, `emails[type eq "work"].value`, `emails[primary eq true].value`; the value `"True"`/`"False"` as a string accepted for `active` only | The forms Entra and Okta send. Entra's string booleans are a documented quirk of its client; accepting them for one attribute, by name, is cheaper than a provisioning failure and loosens nothing else |
| Groups | `/scim/v2/Groups` maps a group to a **role**: a group whose `displayName` names a role marked **provisionable** gives its members that role; any other group is stored and grants nothing. **A role holding a permission on a system API (the Management API) can never be provisionable** | A directory's groups are how organisations grant access, and roles are how Clavia does. But a directory token must not be a way to make someone an administrator of Clavia: whoever holds it would grant themselves the Management API. Marking a role provisionable is an operator's decision, refused for system API roles at the domain |
| Versioning | `meta.version` a weak ETag (`W/"<updated_at>"`); `If-Match` honoured on PUT, PATCH and DELETE (`412 Precondition Failed`); `ServiceProviderConfig` says `etag.supported: true` | RFC 7644 §3.14; a directory and an operator editing one account at once should not overwrite each other silently |
| Errors | RFC 7644 §3.12 documents (`schemas`, `status` as a string, `scimType`, `detail`), **never repeating a value**; `application/scim+json` (§8.1), `application/json` accepted | The same rule as the Management API's problem documents, in the shape SCIM clients parse |
| Failures | Every failed token is the same `401` (`WWW-Authenticate: Bearer`), counted per client address by the failure throttle the machine endpoints use; past the limit, `429` with `Retry-After` | A token is a secret; nobody may probe for one. A valid token is not throttled: a directory's initial sync sends thousands of requests |
| Who acted | A new actor kind, **`provisioning`**, naming the token: `user.created` by the token that made the account | The trail must say a directory did it, and which one; "system" would hide it, and "application" would name a client that does not exist |

## 3. Settings

None. The bounds (`count` at most 200, a body at most 1 MiB, tokens at most two years, 20 groups per
user in one request) are constants. `CLAVIA_TOKEN_MAX_FAILURES` and `CLAVIA_TOKEN_FAILURE_WINDOW`
bound failed tokens, as at the machine endpoints.

## 4. Model

### Domain

A new context, `Domain\Provisioning`:

- `ProvisioningToken` (aggregate, like `InitialAccessToken`): id (a UUID, as an initial access
  token's: the trail and the Management API name it by kind already), digest, connection,
  description, created, expires, revoked, the subject attribute (`externalId` or `userName`),
  `addresses_trusted`, `delete_deactivates`. `isUsableAt()`, `stateAt()`, `revoke()`.
- `ProvisionedAccount`: the user id, the connection, `userName` (and its case-folded key),
  `externalId`, the token that made it, created and updated. The link between SCIM's keys and an
  account; the account itself stays a `User`.
- `ScimUser` (value object): the supported attributes of RFC 7643 §4.1, read from a JSON object
  with the rules of §2; `toProfile()`, `toAddress()`.
- `ScimFilter` (value object): the equality filters of §2, parsed from a string, or `InvalidValue`.
- `ScimPatch`: the operations and paths of §2, applied to a `ScimUser`.
- `Role::$provisionable`, refused on a role holding a permission on a system API (`InvalidValue`), and
  a role given a system API permission while provisionable is refused too.
- `Connection::$requireProvisioning` (enterprise connections only).
- `ActorKind::Provisioning` and `Actor::provisioning(ProvisioningTokenId)`.
- Events: `ProvisioningTokenIssued`, `ProvisioningTokenRevoked` (configuration trail); account
  changes reuse `UserCreated`, `UserChanged`, `UserDeleted`, `RoleGiven`, `RoleTaken`, with the
  provisioning actor.

### Application

- `Provisioning\AuthenticateProvisioningToken` (the middleware's use case), `IssueProvisioningToken`,
  `RevokeProvisioningToken`.
- `Provisioning\Users\{CreateUser, ReadUser, ListUsers, ReplaceUser, PatchUser, DeleteUser}`, each in a
  transaction, each checking the token's connection.
- `Provisioning\Groups\*` (slice 4).
- `ResolveExternalAccount` honours `require_provisioning`.

### Migrations

`provisioning_tokens`; `provisioned_accounts` (`user_id` `ON DELETE CASCADE`, unique on
`(connection, user_name_key)` and on `(connection, external_id)`); `scim_groups` and
`scim_group_members` (slice 4); `roles.provisionable`; `connections.require_provisioning`; the audit
actor kind.

## 5. Flows

### 5.1 Issuing a token

`POST /api/v1/provisioning-tokens` (`create:provisioning_tokens`) with `connection`, `description`,
`expires_in` and the options of §4: the connection exists and is a pool or an enterprise connection
(`422` otherwise). `201` with the token once, and the base URL to give the directory
(`https://management.{domain}/scim/v2`). `GET` lists them (state, expiry, the connection, never the
secret); `DELETE …/{id}` revokes.

### 5.2 A request

1. `ProvisioningMiddleware`: the `Authorization: Bearer` token looked up by digest; unknown, expired
   or revoked is `401`, counted per client address; past the limit `429` before any lookup.
2. The token's connection still exists and is still provisionable, or `401` (the token is useless).
3. `AuditContext` gets `Actor::provisioning(token)`.
4. The body read as JSON (`application/scim+json` or `application/json`), at most 1 MiB; `400
   invalidSyntax` otherwise.

### 5.3 Users

- **Create** (`POST /Users`): `ScimUser` read; `userName` unique in the connection (`409
  uniqueness`); the address unique in the connection (`409 uniqueness`); the account created
  (active as `active` says, the profile, the address verified if the token trusts it), its
  `ProvisionedAccount`, and, for an external connection, its `ExternalIdentity` from the subject
  attribute (`400 invalidValue` when that attribute is missing). `201` with the resource and
  `Location`.
- **Read** (`GET /Users/{id}`): the token's connection only; anyone else's account is `404`.
- **List** (`GET /Users?filter=…&startIndex=&count=`): `ScimFilter`; a `ListResponse`.
- **Replace** (`PUT /Users/{id}`): the whole resource; attributes absent are cleared where they are
  optional; `active` applied as in §2; `If-Match` honoured.
- **Modify** (`PATCH /Users/{id}`): `ScimPatch` applied to the current resource, then as replace.
- **Delete** (`DELETE /Users/{id}`): deleted, or deactivated with `delete_deactivates`; `204`.

### 5.4 Signing in through a connection that requires provisioning

`ResolveExternalAccount` finds `(connection, subject)`; with `require_provisioning`, an identity
without a `ProvisionedAccount` is refused (`not_provisioned`), and no account is created on the way.

### 5.5 Groups (slice 4)

`POST|GET|PUT|PATCH|DELETE /Groups`: groups stored per connection with their members (accounts of
the same connection). A group whose `displayName` equals a provisionable role's name grants it to
its members, and takes it away when a member leaves or the group is deleted; renaming a group
re-evaluates. Grants and removals are `RoleGiven` and `RoleTaken` by the provisioning actor. A role
granted by hand and by a group is taken away by neither alone: a provisioned grant is recorded as
such, and removed only if it came from the group.

## 6. Interfaces

- **SCIM** (`management.{domain}/scim/v2`): `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`
  (behind the token like the rest: directories send it anyway),
  `/Users`, `/Users/{id}`, `/Groups`, `/Groups/{id}`. `/Bulk` and `/Me` answer `501`.
- **Management API**:
  - `GET|POST /api/v1/provisioning-tokens`, `GET|DELETE /api/v1/provisioning-tokens/{id}`; scopes
    `read:provisioning_tokens`, `create:provisioning_tokens`, `delete:provisioning_tokens`;
  - `require_provisioning` on enterprise connections; `provisionable` on roles;
  - a user's `provisioning` (`user_name`, `external_id`, the token, or null), read with the user.
- **Caddy**: `/scim/v2/*` on `management.*` sent to PHP-FPM, as `/api/v1/*` is.
- **Dashboard** (clavia-dashboard): provisioning tokens on the connection page (issue with the
  secret and base URL shown once, expiry, revoke), `require_provisioning`, `provisionable` on roles,
  a "provisioned by" badge on users.
- **Documentation**: a guide for Entra ID and Okta (base URL, token, attribute mappings, which
  attribute is the subject: for Entra with SAML, `externalId` mapped from the object id).

## 7. Security rules

- **A token reaches one connection**: every read and write is confined to its connection; another
  connection's account is `404`, never `403` (its existence is not told).
- **A token cannot make anyone an administrator of Clavia**: only provisionable roles are granted,
  and no role touching a system API can be provisionable, at the domain and in the database.
- **No password travels**: the `password` attribute is refused.
- **An address is trusted only on the operator's word** (`addresses_trusted`), so a directory cannot
  verify an address it does not own and take over a pool's account by linking.
- **Secrets**: the token is shown once, stored as its digest, compared by digest, never logged;
  failed tokens are throttled per address.
- **Nothing echoed**: errors name the attribute and the rule, never the value.
- **Deactivation is complete**: sessions ended, back-channel logout sent, refresh tokens refused, as
  for an operator's.
- **The trail says who**: the provisioning actor names the token on every change.

## 8. Tests

- Domain: `ScimFilterTest` (every supported form, every refusal), `ScimPatchTest` (each path form,
  Entra's string booleans for `active` only), `ScimUserTest` (attributes, ignored extensions,
  `password` refused), `ProvisioningTokenTest`, `Role` provisionable refusals.
- Repositories: contracts for tokens and provisioned accounts, against the doubles and PostgreSQL
  (case-insensitive `userName`, cascades).
- Acceptance, through `/scim/v2` (every response checked against the SCIM schemas):
  - the token: missing, unknown, expired, revoked, another connection's account, throttling;
  - the sequences Entra ID and Okta send, recorded from their documentation: the initial `GET
    /Users?filter=userName eq …`, create, the PATCH forms, deactivation, delete;
  - deactivation ending sessions, with back-channel logout delivered, and a refresh refused;
  - provisioning into a SAML connection, then the person's first sign-in finding the account;
    `require_provisioning` refusing a stranger;
  - groups granting and taking provisionable roles, and refusing a Management API role.
- Manual, before release: Microsoft's SCIM Validator and Okta's SCIM test suite against a staging
  deployment, with the results kept in `conformance/`.

## 9. Slices

1. **Tokens and the surface.** `ProvisioningToken`, its Management API, `ProvisioningMiddleware`
   (bearer, throttle, actor), the SCIM error documents, `ServiceProviderConfig`, `ResourceTypes`,
   `Schemas`, the Caddy route, the actor kind. *Done when* a directory can authenticate and read the
   service provider's configuration, and every token refusal is covered.
2. **Users: create, read, list.** `ScimUser`, `ScimFilter`, `ProvisionedAccount`, accounts in pools
   and in enterprise connections with their external identities, `require_provisioning`. *Done when*
   Entra's and Okta's initial sync creates accounts that sign in through their connection.
3. **Users: replace, modify, delete.** PUT, `ScimPatch`, DELETE with `delete_deactivates`, ETags,
   deactivation ending everything. *Done when* a leaver deactivated by the directory loses every
   session and token, and the PATCH sequences of both directories apply.
4. **Groups to roles.** `/Groups`, members, `provisionable` roles with the system API rule, grants
   and removals recorded. *Done when* a directory group grants and takes a provisionable role, and
   no group can grant a Management API role.
5. **Dashboard** (clavia-dashboard), and the Entra ID and Okta guide. *Done when* an operator can set
   up provisioning from either directory without the API.

## 10. Open questions

1. **Groups to roles** (§2, slice 4)? *Recommendation:* yes, with the provisionable flag and the
   system API rule. Without it, a directory can say who exists but not what they may do, which is
   half of what operators provision for.
2. **`DELETE` deletes** (§2)? *Recommendation:* yes, as RFC 7644 says, with `delete_deactivates` on
   the token for operators who must keep accounts. Entra and Okta both deactivate before they delete.
3. **The enterprise extension** (department, manager, employee number)? *Recommendation:* ignored
   for now. Once application metadata exists (#114), a token option can copy it into
   `app_metadata.scim`, which custom claims can then map into tokens.
4. **Token lifetime** (§2)? *Recommendation:* one year by default, two at most, with the Management
   API (and the dashboard) flagging tokens within 30 days of expiry. Never-expiring tokens are what
   leak from old directory configurations.

## 11. As built

What slice 1 (#129) settled:

- **The actor is a fifth kind with a column of its own**: `audit_events.actor_provisioning_token_id`,
  set for `provisioning` only (the actor check says so), and `provisioning_token_id` in the audit
  event's `actor` in the Management API and the webhook payload.
- **The failure throttle is the machine endpoints'** (`ClientFailureThrottle`), by client address only:
  a provisioning token has no client to count against. A request with no token at all is refused but
  not counted (it guesses nothing); past the limit it is `429` like the rest. A genuine token whose
  connection went away is refused without counting.
- **The surface states only what is built.** `ServiceProviderConfig` says no to PATCH, filtering and
  ETags until slices 2 and 3 build them; `ResourceTypes` and `Schemas` are empty lists until `User`
  joins with slice 2 and `Group` with slice 4, as discovery names only what exists. Any other path
  under `/scim/v2` is a SCIM `404` behind the token, so a caller without one learns nothing.
- **Reading a body** (§5.2, step 4: `application/scim+json` or `application/json`, 1 MiB,
  `invalidSyntax`) comes with slice 2, the first that takes one.
- **`expiring_soon`** is the thirty-day flag of question 4; `GET /api/v1/provisioning-tokens` takes
  `?connection=`, for the dashboard's connection page.

