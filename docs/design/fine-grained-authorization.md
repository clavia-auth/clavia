# Design: Fine-grained authorization, AuthZEN over OpenFGA

**Status:** agreed · **Date:** 2026-11-25 · **Issue:** clavia-auth/clavia#133 ·
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
- People (`user:<id>`) and machines (`client:<client id>`) as subjects, both known to Clavia.
- A deactivated or unknown person, or an unknown client, refused by Clavia before OpenFGA is asked.
- Clavia as an information point at decision time: what it knows of the subject, added to each
  question for OpenFGA's conditions, beyond an API's reach to forge.
- A PSR-15 enforcement middleware for PHP APIs, speaking AuthZEN to any decision point.

### The four points

| Point | Who | What |
|---|---|---|
| **PDP** (decision) | OpenFGA, behind Clavia's AuthZEN front door | OpenFGA works the answer out; the front door authenticates the caller, confines it, refuses inactive subjects first, and fails closed |
| **PEP** (enforcement) | Each API | Asks before acting, refuses on anything but `true`. Helped by a **PSR-15 middleware** for PHP APIs, in its own repository (slice 8), and the developer guide |
| **PAP** (administration) | The Management API and the dashboard | Each API's model and its versions, the clients that speak for it; relationship data written by the APIs through the relationships endpoint |
| **PIP** (information) | Clavia, and the APIs | Clavia pushes identity ahead of time (roles as tuples) **and adds what it knows of the subject to every question** (`context.clavia.subject`, §2); the APIs write their resources' relationships and send request facts in `context` |

### Not in scope

- **A policy engine of Clavia's own**: OpenFGA is the engine; the port leaves room for another.
- **Rich Authorization Requests** (RFC 9396, `authorization_details` in tokens): token-time grants,
  a separate design (§10, question 4).
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
| Reserved types | Every model must declare **`type user`**; **`client`**, **`role`** (with `relation member: [user]`) and, later, **`group`** are Clavia's when declared. APIs never write tuples whose object is `user`, `client`, `role` or `group`, nor whose subject is a `user` or a `client` that does not exist in Clavia | Clavia is the source of truth for people, applications and roles. An API writing `role:admin#member@user:mallory` would grant through the back door what roles grant |
| Machine subjects | A **client** can be the subject of a question (`subject.type: "client"`, `subject.id` its client id) and of a relationship (`invoice:42#viewer@client:reports-app`): an API grants an application access to its resources as it grants a person. A client is a valid subject while it exists in Clavia; deleting it deletes its tuples, as for a person | Machines act on resources too (a reporting job reading invoices, a partner's integration on one folder), and the same graph should answer for them. The client's own token says who is calling; the question's subject says who is acting, which may be another client the API serves |
| Identifiers | `user:<Clavia user id>` (the `sub`), `client:<client id>`, `role:<role id>`; an API's own objects `type:id` as it chooses (OpenFGA's limits on characters and length) | Stable ids, never addresses or names, which change |
| The identity feed | Role assignments and removals, and account deletion, are written to OpenFGA through an **outbox** in Clavia's database, in the transaction of the change; sent **after the response** (`DeferredTasks`) and retried by `bin/clavia fga:sync` every minute; `fga:resync` rebuilds a store's identity tuples from Clavia | The two databases share no transaction, so an outbox is the only way a committed change is never lost. Sending after the response makes the delay sub-second in practice; the cron covers failures. A role reaches only the stores of the APIs it holds a permission on |
| Deactivation and deletion | **Before asking OpenFGA**, the front door refuses a subject that is unknown or deactivated (`decision: false`): a `user` must be an active account, a `client` an existing client, whatever the store says. Deleting an account or a client deletes its tuples in every store (read by subject, then deleted), through the same outbox | The feed is asynchronous; a leaver must lose access at once. Deletion cleans up so a reused id could never inherit (ids are UUIDs, but the graph should not keep the dead) |
| Consistency | OpenFGA runs with its **check cache off** (its default), so every read is strongly consistent; Clavia never caches decisions | Zanzibar's "new enemy" problem: answering from a stale copy after a revocation. With the cache off, OpenFGA's docs state every query is strongly consistent whatever the mode asked. Caching can come later with an explicit freshness rule |
| Context and conditions | AuthZEN's `context` is passed to OpenFGA as the check's context, for **conditions** (CEL) in the model. **Clavia adds `context.clavia.subject`**: for a person, `id`, `connection`, `app_metadata` (#114), `roles` (the names of their roles holding a permission on this API), `mfa_enrolled`; for a client, `id`, `type` (`confidential` or `public`) and `first_party`. An API's own `context.clavia` is **refused** (`400`) | Conditions can then read identity facts (`subject.app_metadata.department == resource.department`, a plan, a tenant) without each API fetching and resending them, and an API cannot forge what Clavia says of a person. Roles are cut to the API's, as for custom claims, so an API learns nothing of other APIs' roles. The facts go to OpenFGA only, never back to the caller |
| Facts in a subject search | A condition reading `context.clavia.subject` **cannot hold** in a subject search, whose subject is the unknown being searched for: such relationships do not count there | Fail closed: OpenFGA cannot be told each candidate's facts in one listing, and assuming them would list people the evaluation would refuse. The document says so, and an API needing that list evaluates the candidates in a batch |
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
- `ObjectRef` (`type`, `id`, OpenFGA's character and length rules), `SubjectRef` (a `user`, a
  `client`, or a userset `type:id#relation`), `Relation` (a name), `Tuple` (`object`, `relation`, `subject`,
  optional condition name and context).
- `ReservedType` (`user`, `client`, `role`, `group`) and the rule that an API never writes one (§2).
- `AuthorizationModel` (value object): the JSON model, checked for `type user` and for the shape of
  reserved types before it is sent; OpenFGA validates the rest.
- Events: `AuthorizationEnabled`, `AuthorizationDisabled`, `AuthorizationModelWritten` (the
  configuration trail; the model's id, never its content).

### Application

- Port `DecisionEngine`: `createStore()`, `deleteStore()`, `writeModel()`, `write(store, writes,
  deletes)`, `check()`, `batchCheck()`, `listObjects()`, `listUsers()`, `readBySubject()`,
  `readByObject()` (added in slice 3: a role's members). Adapter
  `OpenFgaDecisionEngine` (PSR-18, the preshared key, the timeout); double `FakeDecisionEngine`, a
  small in-memory evaluator of the union subset, run by the same contract as the adapter.
- `Authorization\Evaluate`, `EvaluateMany`, `SearchSubjects`, `SearchResources`, `SearchActions`:
  the caller's API resolved from its client; types checked against the model; the subject checked
  in Clavia (an active account, or an existing client); the engine asked; the answer mapped.
- `Authorization\SubjectFacts` (the PIP): what Clavia knows of a subject, cut to the calling API,
  as the `context.clavia.subject` object; read once per subject per request (a batch about one person
  reads them once).
- `Authorization\WriteRelationships`, `ReadRelationships`: confined to the caller's store and to
  non-reserved types.
- `Authorization\IdentityFeed`: subscribers to `RoleGiven`, `RoleTaken`, `UserRolesReplaced`,
  `RoleChanged` (permissions moved between APIs), `UserDeleted`, `ClientDeleted`, writing to the
  outbox;
  `SyncIdentityFeed` (`fga:sync`) and `ResyncStore` (`fga:resync <api>`).
- Management API use cases for enabling, the model and the speaking clients.

### Migrations

`resource_servers` gains the authorization columns; `fga_outbox` (the API, the subject to bring into
step, a generation, attempts, next attempt, a claim, created; see §5.4); nothing of the graph.

## 5. Flows

### 5.1 Enabling an API

`PUT /api/v1/resource-servers/{id}/authorization` with the model (`update:resource_servers`):
the model checked (§4), a store created if there is none, the model written, the store's identity
tuples queued (every holder of every role holding a permission on this API). `GET` returns the
settings and the current model; `DELETE` disables, and deletes the store after `?confirm=delete`.
Decided in slice 2 (#136): the model is kept in Clavia's database beside the settings (configuration,
not the graph), so `GET` answers without the engine; `PUT` writes a new version only when the model
differs from the one in force; `DELETE` without the confirmation switches authorization off and keeps
the store (switching it on again brings its relationships back); `PUT` is a `409` while
`CLAVIA_FGA_URL` is unset (switching off still works, and deleting the store needs the engine: `503`);
deleting an API deletes its store, best effort. A speaking
client is a first-party client holding `client_credentials`, and an API has at most twenty.
OpenFGA's deletion of a store is soft (found in slice 1): the store is no longer listed, but
questions and writes naming its id are still answered, so Clavia forgets the id in the same step
and never asks with it again. Writing a new model keeps the store and its tuples; a model that drops a relation still used by
tuples is OpenFGA's to accept or refuse, and its refusal is a `422` with its error code only.

### 5.2 An evaluation

1. `ManagementApiMiddleware`-style checks for the Authorization API: credentials, the token live,
   issued for the Authorization API, the scope.
2. The caller's API: the one listing its client, with authorization on; none is `403`.
3. The request read against the AuthZEN schema (`subject`, `action`, `resource`, `context`);
   `subject.type` must be `user` or `client` (and declared by the model); `resource.type` a type of
   the model; else `400`.
4. The subject: for a `user`, a Clavia account, active, in a connection the API may see; for a
   `client`, a client that exists; otherwise `{decision: false}` (with `subject_inactive` if reasons
   are on). Nothing is sent to OpenFGA.
5. The context: the API's `context` (a `clavia` member there is `400`), with Clavia's
   `clavia.subject` facts added (§2).
6. `check(store, model, resource, action.name, subject, context)`; `{decision}` back.
7. OpenFGA failing or slower than the timeout: `503`.

Decided in slice 4 (#138):

- **AuthZEN's rules on the wire.** Members AuthZEN does not define are ignored (§10.1.1), so its
  schemas in `docs/openapi/authorization-api.yaml` are open; a request missing what it requires, or
  that the contract refuses, is `400` (and since #239, everywhere in Clavia's APIs). A request's `X-Request-ID` is sent
  back on every answer (§10.1.3). `properties` are not read.
- **A batch** (§7) takes the request's `subject`, `action`, `resource` and `context` as defaults an
  item replaces member by member; at most 50; answered in order, up to and including the first denial
  (`deny_on_first_deny`) or permit (`permit_on_first_permit`), the rest left out, as AuthZEN's
  examples show. An item that cannot be asked is a denial with `context.error` `{status, message}`
  (§7.2.1); a batch without items is one question.
- **A question the engine refuses to evaluate is a denial**, `condition_failed`, a fourth reason: a
  condition reading a parameter that is not there (an `app_metadata` key a person lacks) is OpenFGA's
  `validation_error`, which would otherwise be a `503` for everyone. A batch with such an item is asked
  again one question at a time, so only that one is denied. Conditions should guard with `has()`.
- **Facts are read through a parameter `clavia` of type `map<any>`**, which OpenFGA accepts and
  evaluates against nested, mixed values (checked against OpenFGA 1.22).
- **"In a connection the API may see"** has nothing to stand on yet: an API is tied to no connection.
  Every active account is a subject; whether an API should be confined to some connections is question
  6 below.
- **The metadata** (§9) is `GET /.well-known/authzen-configuration` on `management.{domain}`: the
  identifier `https://management.{domain}` and the two evaluation endpoints, public, an hour's cache;
  `404` on `auth.*`, and nowhere while `CLAVIA_FGA_URL` is unset.

### 5.3 Writing relationships

`POST /access/v1/relationships` (`write:relationships`; Clavia's own, not AuthZEN): writes and
deletes, at most 100, applied atomically by OpenFGA. Each tuple's object type must be a
non-reserved type of the model, and a `user` or `client` subject must exist in Clavia. `GET
/access/v1/relationships?object=…` reads them back, paged. Nothing of the tuples is stored in Clavia.

Decided in slice 5 (#139): the Authorization API is **contract-first**, like the Management API:
`docs/openapi/authorization-api.yaml` is what its front door (`AccessApiMiddleware`) validates
against, is kept equal to the routes by a test, and is published beside the other references; its
refusals are RFC 9457 problem documents (bearer refusals RFC 6750), never repeating a value. The front
door runs only while `CLAVIA_FGA_URL` is set. A relationship has AuthZEN's shape: `resource` and
`subject` as `{type, id}` (a subject's `relation` makes it a userset), `relation`, and an optional
`condition` `{name, context}` the model declares, its context (at most 4 KiB) kept with the tuple;
`204` for a write. A reserved or undeclared type, or a `user` or `client` subject Clavia does not know,
is `422` pointing at it (`/writes/0/resource/type`); a deletion does not look the subject up, so a
deleted person's relationships can still be taken away. The engine's own refusal (a tuple written
twice, deleted unwritten, or one the model does not take) is `422` naming its code. Reading is one
object at a time, of the API's own types (who holds a role is Clavia's to tell), a page of 1 to 100
with OpenFGA's continuation token passed through as `page_token`/`next_page_token`; a token it does
not take is `422`. Writes are not in the audit trail: they are the API's data, not Clavia's.

### 5.4 The identity feed

1. A role given, taken or replaced, a role's permissions moved, or an account or a client deleted:
   the subscriber
   writes outbox rows (per affected store) in the same transaction.
2. After the response, `DeferredTasks` sends them; a failure leaves the row for `fga:sync`, which
   retries with a backoff (5 s, 1 min, 5 min, then every 10 minutes for a day) and logs a warning.
3. `fga:resync <api>` recomputes the store's `role` tuples from Clavia and writes the difference:
   the repair when a store and Clavia have drifted.

Decided in slice 3 (#137): **an outbox row names a subject, not tuples**: `user:<id>` (the roles a
person holds in that store), `role:<id>` (a role's members), `client:<id>` (a deleted application), or
`*` (every role, queued when authorization is switched on, when a new model is written, and when an
API's permissions change). The events say what is, not what was (`UserRolesReplaced` and `RoleChanged`
do not carry what was held before, and a deleted person's relationships written by the API are known
to OpenFGA alone), so the sender reads the store and Clavia when it sends and writes the difference,
deletions first. That makes a send idempotent and order irrelevant: a row sent late, twice or after a
newer one still leaves the store as Clavia says. One row per API and subject; queuing it again moves a
`generation` on, and a worker deletes the row only at the generation it claimed, so a change committed
while it was sending is sent again. A role given or taken queues the person for the stores of the APIs
the role reaches; everything else queues every API with a store, switched on or off (a store switched
off keeps its relationships, so it is kept in step). A person or an application gone from Clavia loses
every relationship naming them, on every type of the model. A failure is never given up (after the
backoff, every ten minutes): a dropped row could leave a person a role they lost. Rows are queued
even while `CLAVIA_FGA_URL` is unset, for the APIs that kept a store (at most one per subject), and
sent once it is set again, so nothing that happened meanwhile is lost. `fga:resync` reconciles every
role Clavia knows: a role deleted is removed by its own row.
OpenFGA's Read API reads by object, or by type and subject, but not a whole type, which is why
`readByObject()` joined the port and the resync goes role by role.

### 5.5 Search

- **Subject search** (`/search/subject`): `list-users` for subjects of the type asked (`user` or
  `client`) holding the relation on the resource; accounts deactivated or unknown, and clients that
  no longer exist, are removed from the answer; relationships whose condition reads Clavia's subject
  facts do not count (§2).
- **Resource search** (`/search/resource`): `list-objects` of the type the subject has the relation
  to.
- **Action search** (`/search/action`): every relation of the resource's type checked in one batch.
- Each answer capped and paged as in §2.

Decided in slice 6 (#140): OpenFGA's list endpoints evaluate every conditional relationship and refuse
the whole listing (`validation_error`) when one lacks a parameter. A subject search cannot know each
candidate's facts, so `context.clavia` is an **empty map** there: a condition that starts with
`has(clavia.subject)` is false and its relationship does not count, as §2 asks; an unguarded one makes
the engine refuse, and the search answers no results with `context.error` saying why (failing closed),
as does any listing the engine refuses. Results are sorted by id, capped at 1,000 (OpenFGA's own list
maximum; `search_max_results` in the metadata, Clavia's own field, which AuthZEN clients ignore), and
paged statelessly: `page.limit` 1 to 1,000 (50 by default), `page.next_token` an opaque offset with a
digest of the search, so a token used on another search, or a search changed between pages, is `400`
(§8.2). Removed subjects are filtered as a page is filled, so `page.total` is not given (optional in
§8.2.2). A subject Clavia does not know has no resources and no actions, the engine not asked. Action
search answers in the model's order of relations, a relation the engine cannot evaluate not held.

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
- **A leaver is out at once**: an inactive or unknown subject, or a client that no longer exists, is
  refused before the engine is asked.
- **No forged identity facts**: `context.clavia` is Clavia's alone; an API sending one is refused,
  and the facts Clavia adds are cut to the calling API (its roles only).
- **No back door into roles**: APIs never write `user`, `client`, `role` or `group` tuples; Clavia
  alone does, and every subject an API names must exist in Clavia.
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
  deactivated person and a deleted client refused without the engine asked; a client as the subject
  of an evaluation and of a search; reserved tuples refused; `503` when the
  engine fails; the metadata naming what exists; every Management API answer against the OpenAPI
  document.
- The PIP: `context.clavia.subject` built from the account (its `app_metadata`, the API's roles only)
  and from a client; an API's `context.clavia` refused; a condition on `app_metadata` decided both
  ways; a subject search leaving conditional relationships on subject facts out.
- The identity feed: a role given reaches the stores of its APIs only; taken, it leaves them; a
  deleted account's and a deleted client's tuples removed; an outbox row surviving a failed send; `fga:resync` repairing a
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
3. **The identity feed.** The outbox, the subscribers, `fga:sync` and `fga:resync`, the clean-up of
   deleted accounts and clients.
   *Done when* role changes reach exactly the stores they concern, survive OpenFGA being down, and a
   drift can be repaired.
4. **AuthZEN evaluation.** Evaluation, batch evaluation, the metadata, confinement, the deactivation
   rule, `503`, people and clients as subjects, and Clavia's subject facts in the context (the PIP;
   `app_metadata` once #114 is in). *Done when* an API's client gets correct decisions for
   direct, computed and inherited relations, about a person and about a client, and every refusal of
   §5.2 is covered, and a condition on a subject fact decides both ways.
5. **Relationships for APIs.** `POST|GET /access/v1/relationships`, confined, reserved types refused.
   *Done when* an API can keep its resources' relationships through Clavia alone.
6. **AuthZEN search.** Subject, resource and action search, caps and paging, inactive accounts
   removed. *Done when* the three searches answer the specification's examples and respect the caps.
7. **Dashboard** (clavia-dashboard), and the developer guide. *Done when* an operator can enable
   authorization, edit a model and try a decision without the API.
8. **A PHP enforcement middleware** (its own repository, §10 question 5): an AuthZEN client on PSR-18
   (discovery from the metadata document, a client-credentials token cached through PSR-16), a PSR-15
   middleware that maps a request to a subject (the token's `sub` or `client_id`), an action and a
   resource through resolvers the API supplies, and refuses (`403`) on `false` and (`503`) when the
   decision point fails; usable with any AuthZEN decision point. *Done when* a PHP API protects a
   route in a few lines, and the package passes its tests against Clavia and against a recorded
   AuthZEN interop scenario.

## 10. Open questions

1. **One OpenFGA store per API** (§2)? *Recommendation:* yes: isolation for free, at the price of
   role tuples written to each store that needs them.
2. **Models as JSON in the Management API, DSL in the dashboard** (§2)? *Recommendation:* yes. A
   DSL parser in PHP would be ours to keep in step with OpenFGA's language.
3. **Decisions in the audit trail**? *Recommendation:* not by default; an API option to record
   denials can follow, once someone needs it, with its volume understood.
4. **Rich Authorization Requests (RFC 9396)** in 0.6? *Recommendation:* a separate issue and design.
   They decide at token time, with consent, and complement this rather than depend on it.
5. **The middleware's repository**: a new one (`clavia-auth/authzen-php`, say), with its own release
   cycle, published on Packagist. *Recommendation:* yes, under that name; creating the repository is
   yours.
6. **Connections an API may see** (§5.2, step 4): should an API's questions be confined to accounts
   of some connections? *Recommendation:* not until there is a reason: an API learns only decisions,
   and every account is a person Clavia knows. If it comes, it is a setting on the API's
   authorization, defaulting to every connection.
7. **CI**: the integration contract against a real OpenFGA needs an `openfga` service in
   `.github/workflows/ci.yml`, which is the maintainer's file. *Recommendation:* add it with slice 1;
   until then the contract runs against the double in CI and against OpenFGA locally.
