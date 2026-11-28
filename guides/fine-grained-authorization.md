# Fine-grained authorization

Roles decide when a token is issued: they say which permissions a person holds on an API, and
nothing more. They cannot answer "may Ada edit the Q3 report, now?". Fine-grained authorization
answers that kind of question while your API handles a request: who owns a document, which team
shares it, what a folder's parent grants.

Clavia is the front door. Your API asks it through the **Authorization API**, which speaks
[AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html). Clavia checks the question and
adds what it knows of the person, and [OpenFGA](https://openfga.dev), running beside Clavia, works
out the answer from the relationships your API has written. Only Clavia can reach OpenFGA.

This guide is for the developer of an API. It covers what the operator sets up first, getting a
token, asking for decisions, searching, writing relationships, the facts Clavia adds, and what to do
when there is no answer.

## Before you start

Fine-grained authorization exists only on a deployment that names an OpenFGA (`CLAVIA_FGA_URL`).
Without it, the Authorization API's routes don't exist. An operator then sets up three things for
your API.

1. **A model.** It says which types your API has and how relationships combine. It is written in
   OpenFGA's modelling language and sent to Clavia in OpenFGA's JSON form:

   ```text
   model
     schema 1.1

   type user
   type client
   type role
     relations
       define member: [user]
   type team
     relations
       define member: [user]
   type document
     relations
       define owner: [user]
       define editor: [user, team#member, role#member] or owner
       define viewer: [user, client, team#member, user with same_department] or editor

   condition same_department(clavia: map<string>, department: string) {
     has(clavia.subject) && has(clavia.subject.app_metadata.department) && clavia.subject.app_metadata.department == department
   }
   ```

   [OpenFGA's command line](https://github.com/openfga/cli) converts it. A condition that reads
   [Clavia's facts](#the-facts-clavia-adds) takes them as a parameter `clavia` of type `map<any>`,
   which the modelling language cannot write. So write `map<string>` there, and set the type in the
   JSON after converting:

   ```bash
   fga model transform --file model.fga \
     | jq '(.conditions[]?.parameters.clavia.generic_types) |= [{"type_name": "TYPE_NAME_ANY"}]' \
     > model.json
   ```

   `fga model validate` refuses the `map<string>` form, because a string has no fields. Check the
   JSON instead: `fga model test` accepts a `model_file` ending in `.json`.

   - **`type user` is required.** It stands for the people Clavia knows, by the `sub` of their
     tokens.
   - **`user`, `client`, `role` and `group` belong to Clavia.** `user` and `client` have no
     relations of their own. `role` and `group`, when the model declares them, are exactly
     `define member: [user]`. Clavia writes their relationships itself: who holds a role (one with
     a permission on your API) comes from Clavia's roles, by the role's id. Your API cannot write
     them.

2. **Authorization switched on**, with the model and the client that speaks for your API, through
   `PUT /api/v1/resource-servers/{resource_server_id}/authorization` (`update:resource_servers`):

   ```json
   {
     "model": {"schema_version": "1.1", "type_definitions": ["…"], "conditions": {"…": "…"}},
     "clients": ["Mc8tR3vN6qL1wZ4yB7hJ2dF9gS5aE0kX"],
     "denial_reasons": false
   }
   ```

   The first time, the API gets a store of its own in OpenFGA. A model that differs from the one in
   force becomes a new version, and the relationships stay. Switching authorization off keeps the
   store, so switching it back on brings everything back. Deleting the store
   (`DELETE /api/v1/resource-servers/{resource_server_id}/authorization` with `confirm=delete`)
   deletes every relationship in it, for good.

3. **A client that speaks for the API.** It is a first-party machine client, and it speaks for
   **one** API at most. Every question it asks is answered from that API's store and model: it
   cannot read or write another API's relationships. It is granted the Authorization API's scopes
   from the shell:

   ```bash
   $CLAVIA management-api:register     # registers the Authorization API, once CLAVIA_FGA_URL is set
   $CLAVIA clients:create-m2m "Reports API"
   $CLAVIA clients:grant Mc8tR3vN6qL1wZ4yB7hJ2dF9gS5aE0kX \
     --audience https://management.example.com/access \
     --scope "evaluate:access search:access write:relationships"
   ```

   | Scope | What it allows |
   |---|---|
   | `evaluate:access` | Asking whether a subject may act on a resource |
   | `search:access` | Searching subjects, resources and actions |
   | `write:relationships` | Writing, and reading back, the relationships of your resources |

   Grant only the scopes your API uses.

An operator can test a model before your API's client asks anything: with `read:relationships`,
`POST /api/v1/resource-servers/{resource_server_id}/authorization/evaluation` tries a decision, and
`GET /api/v1/resource-servers/{resource_server_id}/authorization/relationships` reads what was written
(see [Scopes and roles](scopes-and-roles.md)).

## Getting a token

Your API's client asks for a token with the client credentials grant, as in
[Getting a token](getting-a-token.md#a-machine-client), and names the Authorization API as the
`audience`, with no trailing slash:

```bash
curl -s https://auth.example.com/oauth2/token \
  -u 'Mc8tR3vN6qL1wZ4yB7hJ2dF9gS5aE0kX:<client_secret>' \
  -d grant_type=client_credentials \
  -d audience=https://management.example.com/access
```

Keep the token until it expires (`expires_in`) and reuse it: don't ask for a new one per decision.
Send it as `Authorization: Bearer <token>` to `management.example.com`, the host of the
Authorization API. A token bound with DPoP goes as `Authorization: DPoP` with a proof
([DPoP-bound tokens](dpop.md)).

A client that speaks for no API with authorization on is refused with `403`, whatever its token
carries.

## Asking for a decision

One question: may this subject take this action on this resource? Send it to
`POST /access/v1/evaluation` (`evaluate:access`):

```bash
curl -s https://management.example.com/access/v1/evaluation \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "subject": {"type": "user", "id": "3f8e2d1c-5b4a-4c9e-8d7f-6a5b4c3d2e1f"},
    "action": {"name": "viewer"},
    "resource": {"type": "document", "id": "q3-report"},
    "context": {"network": "office"}
  }'
```

```json
{"decision": true}
```

- **The subject** is a person (`user`, the `sub` of their tokens) or an application (`client`, its
  client id). Use the identifier, never an email address: addresses change.
- **The action** is a relation of the resource's type in your model (`viewer`, `editor`).
- **The resource** is one of your model's types, with your own identifier for it.
- **`context`** goes to your model's conditions. It must not have a `clavia` member: that is Clavia's
  (see [The facts Clavia adds](#the-facts-clavia-adds)).

**Act only on `true`.** A denial is a `200` too, `{"decision": false}`. When the operator turned
denial reasons on, it says which kind, and never more:

| `context.reason` | Why |
|---|---|
| `no_relation` | No relationship grants it |
| `subject_inactive` | The person is deactivated or unknown, or the application no longer exists |
| `unknown_type` | In a batch, an evaluation that could not be asked: a type or relation the model lacks, a subject that is neither `user` nor `client` |
| `condition_failed` | A condition could not be evaluated: it read a fact or a context member that was not there |

A person who is deactivated is refused at once, whatever relationships remain: Clavia checks the
subject before OpenFGA is asked.

A question that cannot be asked at all (a type or a relation your model does not declare, a subject
that is neither `user` nor `client`) is a `400` problem document. Fix the request: asking again
will not help.

The `X-Request-ID` you send comes back on the answer, to match them up in your logs.

### Several at once

`POST /access/v1/evaluations` asks up to fifty questions in one request. What they share goes at
the top, and each evaluation replaces only what differs:

```json
{
  "subject": {"type": "user", "id": "3f8e2d1c-5b4a-4c9e-8d7f-6a5b4c3d2e1f"},
  "resource": {"type": "document", "id": "q3-report"},
  "evaluations": [
    {"action": {"name": "viewer"}},
    {"action": {"name": "editor"}},
    {"action": {"name": "owner"}}
  ],
  "options": {"evaluations_semantic": "execute_all"}
}
```

```json
{"evaluations": [{"decision": true}, {"decision": true}, {"decision": false}]}
```

The answers come in the order asked. `evaluations_semantic` says how far to go:

- **`execute_all`** (the default) answers every question.
- **`deny_on_first_deny`** stops after the first denial, which is included.
- **`permit_on_first_permit`** stops after the first permit, which is included.

An evaluation that cannot be asked is a denial with `context.error` (`status` and `message`), and the
others are still answered.

## Searching

Three searches answer the questions an evaluation cannot (`search:access`):

| Operation | Question | Leave out |
|---|---|---|
| `POST /access/v1/search/subject` | Who may view the Q3 report? | `subject.id` |
| `POST /access/v1/search/resource` | Which documents may Ada view? | `resource.id` |
| `POST /access/v1/search/action` | What may Ada do to the Q3 report? | `action` |

```bash
curl -s https://management.example.com/access/v1/search/subject \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "subject": {"type": "user"},
    "action": {"name": "viewer"},
    "resource": {"type": "document", "id": "q3-report"},
    "page": {"limit": 2}
  }'
```

```json
{
  "page": {"next_token": "eyJvIjoyLCJmIjoiNGE5In0", "count": 2},
  "results": [
    {"type": "user", "id": "3f8e2d1c-5b4a-4c9e-8d7f-6a5b4c3d2e1f"},
    {"type": "user", "id": "9b2c7e4a-1d3f-4a6b-9c8e-2f1a0b3c4d5e"}
  ]
}
```

- **Results are sorted by id and capped** at what OpenFGA finds, 1,000 at most (`search_max_results`
  in the [metadata](#finding-the-endpoints)). A question with more answers than that needs to be
  narrower.
- **Pages:** `page.limit` is 1 to 1,000 (50 by default). For the next page, send the same request with
  `page.token` set to the previous answer's `page.next_token`. It is empty on the last page. Change
  anything else in the request and the token is refused (`400`).
- **A subject search leaves out** deactivated people and deleted applications. It also leaves out
  relationships whose condition reads Clavia's facts about the subject, since there is no subject yet
  to read them from. That needs the condition to start with `has(clavia.subject)`: an unguarded one
  makes OpenFGA refuse the whole listing, which then comes back empty with `context.error` saying
  why. When you need that list, search more widely and evaluate the candidates in a batch.
- **A subject Clavia does not know** has no resources and no actions.

## Writing relationships

Your API keeps its resources' relationships in Clavia, as they change: a document created, shared
or moved. `POST /access/v1/relationships` (`write:relationships`) writes and deletes up to a hundred
in one request, all of them or none:

```json
{
  "writes": [
    {
      "resource": {"type": "document", "id": "q3-report"},
      "relation": "viewer",
      "subject": {"type": "user", "id": "3f8e2d1c-5b4a-4c9e-8d7f-6a5b4c3d2e1f"}
    },
    {
      "resource": {"type": "document", "id": "q3-report"},
      "relation": "editor",
      "subject": {"type": "team", "id": "finance", "relation": "member"}
    },
    {
      "resource": {"type": "document", "id": "q3-report"},
      "relation": "viewer",
      "subject": {"type": "user", "id": "9b2c7e4a-1d3f-4a6b-9c8e-2f1a0b3c4d5e"},
      "condition": {"name": "same_department", "context": {"department": "finance"}}
    }
  ],
  "deletes": [
    {
      "resource": {"type": "document", "id": "q2-report"},
      "relation": "viewer",
      "subject": {"type": "user", "id": "9b2c7e4a-1d3f-4a6b-9c8e-2f1a0b3c4d5e"}
    }
  ]
}
```

The answer is `204`. Then:

- **A subject's `relation`** makes it a set: `team:finance#member` is everyone who is a member of the
  finance team. `role:<role id>#member` is everyone holding that Clavia role.
- **A `condition`** names one your model declares, with its stored context (4 KiB at most). It is
  checked at decision time, with the request's context and Clavia's facts.
- **Refused with `422`**, pointing at the first fault, nothing written: a resource of one of Clavia's
  types or of a type your model does not declare, a `user` or `client` subject Clavia does not know,
  or a relationship OpenFGA refuses (written twice, deleted when it was never written, or one the
  model does not allow), with OpenFGA's error code in `detail`.
- **A deletion** names the resource, relation and subject, whatever the condition. It does not look
  the subject up, so you can still remove what a deleted person held. Clavia removes a deleted
  person's or application's relationships on its own anyway.

`GET /access/v1/relationships?object=document:q3-report` reads back what was written on one of your
objects, as written (nothing worked out through other relations), a page at a time: `page_size` 1 to
100, and `page_token` set to the previous page's `next_page_token`, which is absent on the last page.

Clavia stores and logs nothing of your relationships. They live in OpenFGA alone.

## The facts Clavia adds

For each evaluation, resource search and action search, Clavia adds what it knows of the subject as
`context.clavia.subject`. Your model's conditions read it through a parameter `clavia` of type
`map<any>`:

| Subject | Facts |
|---|---|
| A person | `id`, `connection`, `app_metadata`, `roles` (the names of their roles holding a permission on **your** API), `mfa_enrolled` |
| An application | `id`, `type` (`confidential` or `public`), `first_party` |

- **Your API cannot forge them.** A request whose `context` has a `clavia` member is refused (`400`).
- **They are never sent back.** They reach OpenFGA, and nothing else.
- **Guard with `has()`.** A condition that reads a fact the subject lacks (an `app_metadata` key a
  person does not have) cannot be evaluated: that question is denied (`condition_failed`), and only
  that one. Start every condition that reads Clavia's facts with `has(clavia.subject)`, as the model
  above does.

## When there is no answer

When OpenFGA cannot be reached, fails or takes longer than its timeout (2 seconds by default),
Clavia answers `503`, never a decision:

```json
{
  "type": "about:blank",
  "title": "Service Unavailable",
  "status": 503,
  "detail": "The decision engine cannot answer now; nothing was done. Try again later."
}
```

**Treat a `503` as a denial.** Refuse the request your API was handling, and don't fall back on a
default. On a write, nothing was written: send the same changes again later.

The other answers, and what to do:

| Status | Meaning | What to do |
|---|---|---|
| `400` | The question cannot be asked: a type or relation your model lacks, a `context.clavia`, a malformed body or page token | Fix the request |
| `401` | No token, or one that is expired, revoked or for another API | Get a new token, for `https://management.example.com/access` |
| `403` | A scope missing (`insufficient_scope`), or a client that speaks for no API with authorization on | Ask the operator for the grant, or to name the client |
| `422` | A write a rule refuses | Fix the relationship it points at |
| `503` | No answer from OpenFGA | Deny, and try again later |

Problem documents and bearer refusals have the same shapes as everywhere in Clavia
([Errors](errors.md)), and never repeat a value you sent.

## Finding the endpoints

`GET /.well-known/authzen-configuration` on `management.example.com` is AuthZEN's metadata. It is
public, and can be cached for an hour:

```json
{
  "policy_decision_point": "https://management.example.com",
  "access_evaluation_endpoint": "https://management.example.com/access/v1/evaluation",
  "access_evaluations_endpoint": "https://management.example.com/access/v1/evaluations",
  "search_subject_endpoint": "https://management.example.com/access/v1/search/subject",
  "search_resource_endpoint": "https://management.example.com/access/v1/search/resource",
  "search_action_endpoint": "https://management.example.com/access/v1/search/action",
  "search_max_results": 1000
}
```

An AuthZEN client library can start from it. It lists only the endpoints that exist, and it is not
there at all when the deployment names no OpenFGA.
