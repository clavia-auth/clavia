# Design: Fine-grained authorization, AuthZEN over OpenFGA

**Status:** proposed · **Date:** 2026-11-25 · **Issue:** clavia-auth/clavia#133 ·
**Specifications:** OpenID AuthZEN Authorization API 1.0 (Final, January 2026: the information
model of subject, action, resource and context; the Access Evaluation and Access Evaluations APIs;
the Subject, Resource and Action Search APIs; the PDP metadata document), OpenFGA's API and
modelling language (schema 1.1), Zanzibar (Pang et al., USENIX ATC 2019) for the model it follows

## 1. Summary

Roles decide at token time: a person's token is narrowed to the permissions their roles hold on an
API, and that is all an API learns. Nothing answers "may Ada edit invoice 42, now?": each API codes
ownership, sharing, teams and hierarchies itself, and nothing can list what a person may open or
who may approve something.

This design makes Clavia the **front door of a policy decision point**:

- APIs ask, at request time, through the **AuthZEN Authorization API**: evaluation, batch
  evaluation, and subject, resource and action search.
- **OpenFGA**, a relationship-based engine (CNCF, Apache 2.0), works the answers out. It runs
  **beside Clavia, with its own database**: the relationship graph never enters Clavia's process or
  its database, and only Clavia talks to it.
- **Clavia feeds OpenFGA what it knows of people** (role memberships, and SCIM groups once #132
  ships), and APIs write the relationships of their own resources through Clavia.
- Everything goes through a **`DecisionEngine` port**, so another engine can replace OpenFGA without
  an API noticing.

### Goals

- The whole AuthZEN Authorization API 1.0 on `management.{domain}`, with its metadata document.
- Per-API authorization models, written and versioned through the Management API.
- A relationships API for APIs, confined to their own model.
- Clavia's identity data (roles, then groups) in OpenFGA, kept in step by an outbox.
- A deactivated or unknown person refused by Clavia before OpenFGA is asked.

### Not in scope

- **A policy engine of Clavia's own**: OpenFGA is the engine; the port leaves room for another.
- **Rich Authorization Requests** (RFC 9396, `authorization_details` in tokens): token-time grants,
  a separate design (§10, question 4).
- **Machine subjects** (`client:<id>` asking about itself): people first (§10, question 5).
- **Decisions in the audit trail** by default: their volume would drown it (§10, question 3).
- **APIs calling OpenFGA directly**: OpenFGA is reachable by Clavia alone (§2).

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| The engine | **OpenFGA**, run beside Clavia (its own container and PostgreSQL database), reached over its HTTP API with a **preshared key** only Clavia holds, on the private network | A mature Zanzibar implementation with intersections, exclusions, conditions (CEL), batch checks and list endpoints, which a custom engine would take months to match. Its own database keeps the graph out of Clavia's. A key only Clavia holds means no API can reach OpenFGA around the front door |
| The interface | **Clavia implements AuthZEN** (`/access/v1/evaluation`, `/access/v1/evaluations`, `/access/v1/search/subject`, `/search/resource`, `/search/action`, `/.well-known/authzen-configuration`) and translates to OpenFGA's **native** API (`check`, `batch-check`, `list-users`, `list-objects`) | OpenFGA's own AuthZEN endpoints are experimental, behind a flag. Implementing the Final Specification ourselves gives APIs a stable contract and keeps the engine replaceable |
| Where it is served | **`management.{domain}`**, beside the Management API | A machine plane, like `/api/v1`: never the sign-in origin. One host for every machine caller |
| Who calls | **An API's own client**, with a client-credentials token for a new **system API, the Authorization API** (audience `https://management.{domain}/access`), scopes `evaluate:access`, `search:access`, `write:relationships`, granted from the shell (`clients:grant`) like every client grant | The same credential model as everything else. A system API cannot be reached by a third-party client, and its scopes cannot be widened by an endpoint |
| Which API a caller speaks for | Each API with authorization on lists the **clients that speak for it**; a client speaks for **one** API at most; every request is answered from that API's model, and a type outside it is `400` | AuthZEN requests do not name the API. Tying the client to one API makes confinement implicit: an API cannot ask about, or write into, another's resources |
| One store per API | Each API with authorization on gets **its own OpenFGA store**, created when authorization is enabled, deleted (after a confirmation) when it is disabled | The store is OpenFGA's isolation unit: models, tuples and queries never cross it. A shared store would need the front door to police every type name. The cost is identity tuples written once per store that needs them (§2, "The identity feed") |
| Models | Written through the **Management API** as OpenFGA's **JSON** model (schema 1.1), each write a new immutable version (OpenFGA keeps them); the dashboard edits the DSL and converts it with OpenFGA's own syntax transformer | One place to configure, audited like any change to an API. The DSL has no PHP parser; JSON is what OpenFGA's API takes, and the conversion belongs where an operator types |
| Reserved types | Every model must declare **`type user`**; **`role`** (with `relation member: [user]`) and, later, **`group`** are Clavia's when declared. APIs never write tuples whose object is `user`, `role` or `group`, nor whose subject is a `user` that does not exist in Clavia | Clavia is the source of truth for people and their roles. An API writing `role:admin#member@user:mallory` would grant through the back door what roles grant |
| Identifiers | `user:<Clavia user id>` (the `sub`), `role:<role id>`; an API's own objects `type:id` as it chooses (OpenFGA's limits on characters and length) | Stable ids, never addresses or names, which change |
| The identity feed | Role assignments and removals, and account deletion, are written to OpenFGA through an **outbox** in Clavia's database, in the transaction of the change; sent **after the response** (`DeferredTasks`) and retried by `bin/clavia fga:sync` every minute; `fga:resync` rebuilds a store's identity tuples from Clavia | The two databases share no transaction, so an outbox is the only way a committed change is never lost. Sending after the response makes the delay sub-second in practice; the cron covers failures. A role reaches only the stores of the APIs it holds a permission on |
| Deactivation and deletion | **Before asking OpenFGA**, the front door refuses a subject that is unknown or deactivated (`decision: false`), whatever the store says. Deleting an account deletes its tuples in every store (read by subject, then deleted), through the same outbox | The feed is asynchronous; a leaver must lose access at once. Deletion cleans up so a reused id could never inherit (ids are UUIDs, but the graph should not keep the dead) |
| Consistency | OpenFGA runs with its **check cache off** (its default), so every read is strongly consistent; Clavia never caches decisions | Zanzibar's "new enemy" problem: answering from a stale copy after a revocation. With the cache off, OpenFGA's docs state every query is strongly consistent whatever the mode asked. Caching can come later with an explicit freshness rule |
| Context and conditions | AuthZEN's `context` is passed to OpenFGA as the check's context, for **conditions** (CEL) in the model; Clavia adds nothing to it | Conditions ("when `acr` is MFA", "amount under 10,000") come with OpenFGA. An API that wants the sign-in level in a condition sends it from the token it holds |
| Batch semantics | AuthZEN's `evaluations` with its three semantics (execute all, deny on first deny, permit on first permit), mapped to OpenFGA's `batch-check`, split to its per-request maximum (50 by default) | The semantics are AuthZEN's to honour; short-circuiting is applied by Clavia over the batch results |
| Search | Subject search → `list-users`; resource search → `list-objects`; action search → a batch check of every relation of the resource's type. Results are **capped** (OpenFGA's own maximum and deadline, both its server settings), and AuthZEN's page token is used to page through what OpenFGA returned | OpenFGA's list endpoints return up to a configured maximum, not pages. Paging over a capped result is honest: the metadata and the document state the cap, and an API needing more narrows its question |
| Answers | `{"decision": true|false}`, no reason by default; an operator may turn on reasons for **denials** per API, returning only the category (`no_relation`, `subject_inactive`, `unknown_type`) | AuthZEN allows a context in the answer. A reason that reveals the graph (who would have granted it) leaks more than the caller should know |
| Failures | OpenFGA unreachable, slow (2 s per call) or failing: **`503`**, never a decision. An API must treat that as a denial | Fail closed. A decision invented by the front door would be a grant nobody made |
| Limits | A batch at most 50 evaluations from a caller per request (higher only by splitting); 100 tuples per relationships write (OpenFGA's default); a request body at most 256 KiB | Bounded work per request, matching OpenFGA's defaults so nothing is split silently |

## 3. Settings

| Setting | Default | Range | Why |
|---|---|---|---|
| `CLAVIA_FGA_URL` | none | an http(s) URL | Where OpenFGA is. Unset, fine-grained authorization is off: the routes do not exist and discovery names nothing. Infrastructure, like the database's URL: it is **not** held to `OutboundUrlPolicy`, which would refuse its private address |
| `CLAVIA_FGA_API_KEY` | none | 16 to 512 characters | The preshared key OpenFGA is started with. Required when the URL is set (exit 78 otherwise) |
| `CLAVIA_FGA_TIMEOUT` | `2` | 1–10 seconds | One call to OpenFGA; past it, `503` |

## 4. Model

### Domain

A new context, `Domain\Authorization`:

- `AuthorizationSettings` on `ResourceServer`: enabled, the OpenFGA store id, the current model id,
  the client ids speaking for it, whether denials carry a reason. `ResourceServer::enableAuthorization()`
  and `disableAuthorization()`; refused on a system API.
- `ObjectRef` (`type`, `id`, OpenFGA's character and length rules), `SubjectRef` (a `user`, or a
  userset `type:id#relation`), `Relation` (a name), `Tuple` (`object`, `relation`, `subject`,
  optional condition name and context).
- `ReservedType` (`user`, `role`, `group`) and the rule that an API never writes one (§2).
- `AuthorizationModel` (value object): the JSON model, checked for `type user` and for the shape of
  reserved types before it is sent; OpenFGA validates the rest.
- Events: `AuthorizationEnabled`, `AuthorizationDisabled`, `AuthorizationModelWritten` (the
  configuration trail; the model's id, never its content).

### Application

- Port `DecisionEngine`: `createStore()`, `deleteStore()`, `writeModel()`, `write(store, writes,
  deletes)`, `check()`, `batchCheck()`, `listObjects()`, `listUsers()`, `readBySubject()`. Adapter
  `OpenFgaDecisionEngine` (PSR-18, the preshared key, the timeout); double `FakeDecisionEngine`, a
  small in-memory evaluator of the union subset, run by the same contract as the adapter.
- `Authorization\Evaluate`, `EvaluateMany`, `SearchSubjects`, `SearchResources`, `SearchActions`:
  the caller's API resolved from its client; types checked against the model; the subject checked
  active in Clavia; the engine asked; the answer mapped.
- `Authorization\WriteRelationships`, `ReadRelationships`: confined to the caller's store and to
  non-reserved types.
- `Authorization\IdentityFeed`: subscribers to `RoleGiven`, `RoleTaken`, `UserRolesReplaced`,
  `RoleChanged` (permissions moved between APIs), `UserDeleted`, writing to the outbox;
  `SyncIdentityFeed` (`fga:sync`) and `ResyncStore` (`fga:resync <api>`).
- Management API use cases for enabling, the model and the speaking clients.

### Migrations

`resource_servers` gains the authorization columns; `fga_outbox` (the store, writes and deletes as
`jsonb`, attempts, next attempt, created); nothing of the graph.

## 5. Flows

### 5.1 Enabling an API

`PUT /api/v1/resource-servers/{id}/authorization` with the model (`update:resource_servers`):
the model checked (§4), a store created if there is none, the model written, the store's identity
tuples queued (every holder of every role holding a permission on this API). `GET` returns the
settings and the current model; `DELETE` disables, and deletes the store after `?confirm=delete`.
Writing a new model keeps the store and its tuples; a model that drops a relation still used by
tuples is OpenFGA's to accept or refuse, and its refusal is a `422` with its error code only.

### 5.2 An evaluation

1. `ManagementApiMiddleware`-style checks for the Authorization API: credentials, the token live,
   issued for the Authorization API, the scope.
2. The caller's API: the one listing its client, with authorization on; none is `403`.
3. The request read against the AuthZEN schema (`subject`, `action`, `resource`, `context`);
   `subject.type` must be `user`; `resource.type` a type of the model; else `400`.
4. The subject: a Clavia account, active, in a connection the API may see; otherwise `{decision:
   false}` (with `subject_inactive` if reasons are on). Nothing is sent to OpenFGA.
5. `check(store, model, resource, action.name, subject, context)`; `{decision}` back.
6. OpenFGA failing or slower than the timeout: `503`.

### 5.3 Writing relationships

`POST /access/v1/relationships` (`write:relationships`; Clavia's own, not AuthZEN): writes and
deletes, at most 100, applied atomically by OpenFGA. Each tuple's object type must be a
non-reserved type of the model, and a `user` subject must be an existing Clavia account. `GET
/access/v1/relationships?object=…` reads them back, paged. Nothing of the tuples is stored in Clavia.

### 5.4 The identity feed

1. A role given, taken or replaced, a role's permissions moved, or an account deleted: the subscriber
   writes outbox rows (per affected store) in the same transaction.
2. After the response, `DeferredTasks` sends them; a failure leaves the row for `fga:sync`, which
   retries with a backoff (5 s, 1 min, 5 min, then every 10 minutes for a day) and logs a warning.
3. `fga:resync <api>` recomputes the store's `role` tuples from Clavia and writes the difference:
   the repair when a store and Clavia have drifted.

### 5.5 Search

- **Subject search** (`/search/subject`): `list-users` for `user` subjects of the relation on the
  resource; users unknown or deactivated in Clavia are removed from the answer.
- **Resource search** (`/search/resource`): `list-objects` of the type the subject has the relation
  to.
- **Action search** (`/search/action`): every relation of the resource's type checked in one batch.
- Each answer capped and paged as in §2.

## 6. Interfaces

- **AuthZEN** on `management.{domain}`: the five endpoints and `/.well-known/authzen-configuration`
  (the metadata names exactly the endpoints that exist), `application/json`, AuthZEN's error
  shapes, never a value echoed.
- **Relationships**: `POST|GET /access/v1/relationships`.
- **Management API**: `GET|PUT|DELETE /api/v1/resource-servers/{id}/authorization`; the speaking
  clients (`authorization.clients`); `management-api:register` also registers the Authorization API
  and its scopes.
- **Console**: `fga:sync` (every minute), `fga:resync <api>`.
- **Development and deployment**: an `openfga` service and its database in `docker-compose.yml`
  (its migration run before it starts); the production kit (#22) with the same; README and
  CLAUDE.md (the surface, the settings, the cron line).
- **Dashboard** (clavia-dashboard): authorization on an API's page (enable, the model edited as DSL
  through OpenFGA's syntax transformer, versions, the speaking clients); a relationship browser
  (read-only); a "try a decision" panel calling `evaluation` through the dashboard's own client.
- **Documentation**: a guide for API developers: getting a token, asking, writing relationships,
  what `503` means.

## 7. Security rules

- **Fail closed**: no decision without OpenFGA's answer; `503` is never a permit.
- **A leaver is out at once**: an inactive or unknown subject is refused before the engine is asked.
- **No back door into roles**: APIs never write `user`, `role` or `group` tuples; Clavia alone does.
- **Confinement**: a client speaks for one API; its requests reach that API's store only; another
  API's types are `400`.
- **OpenFGA is reachable by Clavia alone**: a preshared key only Clavia holds, a private network;
  never published, never in a response, never logged.
- **No graph in Clavia**: nothing of an API's tuples is stored or logged by Clavia; the outbox holds
  only Clavia's own identity tuples until they are sent.
- **No leak through answers**: decisions without reasons by default; categories only when on; search
  results stripped of inactive accounts.
- **Bounded work**: batch and write sizes, search caps, a timeout per call.

## 8. Tests

- `DecisionEngineContract`, run by `FakeDecisionEngine` and, in the integration suite, by
  `OpenFgaDecisionEngine` against a real OpenFGA (skipped when `CLAVIA_TEST_FGA_URL` is unset):
  stores, models, writes, checks through direct relations, computed relations and parents, batch,
  list users and objects, reading by subject.
- Domain: `ObjectRef`, `Tuple`, reserved types, `AuthorizationModel`'s checks.
- Acceptance (with the double): each AuthZEN endpoint against the specification's examples; the
  three batch semantics; confinement (another API's type, a client speaking for none); a
  deactivated subject refused without the engine asked; reserved tuples refused; `503` when the
  engine fails; the metadata naming what exists; every Management API answer against the OpenAPI
  document.
- The identity feed: a role given reaches the stores of its APIs only; taken, it leaves them; a
  deleted account's tuples removed; an outbox row surviving a failed send; `fga:resync` repairing a
  drift.
- Interop, before release: the AuthZEN working group's interop scenarios run against a staging
  deployment, results kept in `conformance/`.

## 9. Slices

1. **OpenFGA beside Clavia.** The settings, the `DecisionEngine` port, `OpenFgaDecisionEngine`,
   `FakeDecisionEngine`, the contract, the `openfga` service in `docker-compose.yml`. *Done when*
   the contract passes against the double and against a real OpenFGA locally.
2. **Authorization on an API.** `AuthorizationSettings`, models through the Management API, a store
   per API, the reserved types, the Authorization API and its scopes, the speaking clients, the
   trail. *Done when* an operator can enable authorization on an API with a model and name the
   client that speaks for it.
3. **The identity feed.** The outbox, the subscribers, `fga:sync` and `fga:resync`, deletion clean-up.
   *Done when* role changes reach exactly the stores they concern, survive OpenFGA being down, and a
   drift can be repaired.
4. **AuthZEN evaluation.** Evaluation, batch evaluation, the metadata, confinement, the deactivation
   rule, `503`. *Done when* an API's client gets correct decisions for direct, computed and inherited
   relations, and every refusal of §5.2 is covered.
5. **Relationships for APIs.** `POST|GET /access/v1/relationships`, confined, reserved types refused.
   *Done when* an API can keep its resources' relationships through Clavia alone.
6. **AuthZEN search.** Subject, resource and action search, caps and paging, inactive accounts
   removed. *Done when* the three searches answer the specification's examples and respect the caps.
7. **Dashboard** (clavia-dashboard), and the developer guide. *Done when* an operator can enable
   authorization, edit a model and try a decision without the API.

## 10. Open questions

1. **One OpenFGA store per API** (§2)? *Recommendation:* yes: isolation for free, at the price of
   role tuples written to each store that needs them.
2. **Models as JSON in the Management API, DSL in the dashboard** (§2)? *Recommendation:* yes. A
   DSL parser in PHP would be ours to keep in step with OpenFGA's language.
3. **Decisions in the audit trail**? *Recommendation:* not by default; an API option to record
   denials can follow, once someone needs it, with its volume understood.
4. **Rich Authorization Requests (RFC 9396)** in 0.6? *Recommendation:* a separate issue and design.
   They decide at token time, with consent, and complement this rather than depend on it.
5. **Machine subjects** (a client asking about itself as `client:<id>`)? *Recommendation:* after
   slice 6, as a reserved `client` type fed by Clavia from its clients.
6. **CI**: the integration contract against a real OpenFGA needs an `openfga` service in
   `.github/workflows/ci.yml`, which is the maintainer's file. *Recommendation:* add it with slice 1;
   until then the contract runs against the double in CI and against OpenFGA locally.
