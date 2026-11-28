# Scopes and roles

Each operation in the reference names one scope, such as `read:users` or `delete:clients`. A
token carrying that scope may call the operation; a token without it gets `403 insufficient_scope`.
The check comes after two others: the token must be live, and issued for the Management API.

## The scopes

A scope is a verb on a resource:

| Verb | What it allows |
|---|---|
| `read` | Listing, and fetching one. They disclose the same facts, so they are one scope. |
| `create` | Creating. For signing keys, rotating, which makes a new key. |
| `update` | Changing. |
| `delete` | Deleting, or revoking a token. |

The resources are `users`, `clients`, `resource_servers` (the APIs tokens are issued for), `roles`,
`connections`, `audit_events`, `signing_keys`, `initial_access_tokens`, `provisioning_tokens`,
`webhooks` and `relationships` (an API's fine-grained authorization data). Not every verb exists for every resource: the reference lists them all, and so does
`$CLAVIA management-api:scopes`.

A few scopes are worth knowing before you grant them:

- **`update:roles` is the one to guard most.** It can put any permission on any API into a role,
  and give that role to anyone, the caller included. Giving somebody a role always needs it, on
  the role (`POST /api/v1/roles/{role_id}/users`) or on the account
  (`PUT /api/v1/users/{user_id}/roles`). `update:users` never suffices.
- **`update:users_app_metadata`** is needed, on top of `update:users`, to send `app_metadata` in
  `PATCH /api/v1/users/{user_id}`. Application metadata feeds claims and authorization, so writing
  it is granting access. Without the scope, the whole request is refused before anything changes.
- **`read:relationships`** reads an API's relationships
  (`GET /api/v1/resource-servers/{resource_server_id}/authorization/relationships`) and tries its
  decisions (`POST …/authorization/evaluation`) about anyone. It is the API's data about people, so
  `read:resource_servers`, which shows the model, never suffices.
- **`create:user_tickets`** mails a person a link to choose a password
  (`POST /api/v1/users/{user_id}/password-reset`). It reaches their mailbox, not their record.
- **`read:audit_events`** is needed beside the webhook scopes to create an endpoint, change its
  `url` or `events`, send a test, or read its deliveries. Streaming the trail is reading it.

## Who holds what

A permission belongs to an API. Neither a client nor a person holds one directly:

- **A machine client** holds what its grant on the API allows. Grants are written from the shell
  (`$CLAVIA clients:grant`), never through the API. A token asks for some or all of the grant.
  Withdraw a scope from the grant and the next token goes without it.
- **A person** holds what **their roles** grant. A role is a named set of permissions, across APIs.
  The Management API always enforces roles, so a person's token carries only the scopes asked
  for that one of their roles holds there.

Roles are read **when a token is issued**, never trusted from an earlier one. Giving or taking a
role, or changing what a role holds, takes effect on the person's next token, a refresh included.
A token already issued keeps its scope until it expires.

## Managing roles

With `create:roles`, define one and what it grants. Each permission names its API by id:

```bash
curl -s https://management.example.com/api/v1/roles \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "name": "Support",
    "description": "Looks people up and resets their passwords.",
    "permissions": [
      {"resource_server_id": "rs_A7d2Kq9Lm4Xp1Zt8", "value": "read:users"},
      {"resource_server_id": "rs_A7d2Kq9Lm4Xp1Zt8", "value": "create:user_tickets"}
    ]
  }'
```

The Management API's id is in `GET /api/v1/resource-servers`. A permission the API doesn't define
is refused (`422`). In `PATCH /api/v1/roles/{role_id}`, `permissions` is the whole new set.

Then, with `update:roles`, give the role to up to a hundred people at once, with
`{"user_ids": ["…"]}` posted to `POST /api/v1/roles/{role_id}/users`. Or set all of one person's
roles with `PUT /api/v1/users/{user_id}/roles`.

A role marked `provisionable` may be granted by a SCIM directory's groups. Such a role can never
hold a permission on the Management API, so no directory can make anyone an administrator.
