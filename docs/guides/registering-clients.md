# Registering clients

Clients are usually created by an operator, with `POST /api/v1/clients` (`create:clients`). With
**dynamic client registration** ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)), a partner
registers their own application instead, holding an **initial access token** you gave them. They
never get a Management API token, and what they register is limited by construction.

Registration is off unless the deployment sets `CLAVIA_CLIENT_REGISTRATION=token`. There is no
open registration: every client registered this way was let in by a token you issued.

## 1. Issue an initial access token

With `create:initial_access_tokens`:

```bash
curl -s https://management.example.com/api/v1/initial-access-tokens \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"description": "Partner Analytics onboarding", "max_uses": 5}'
```

```json
{
  "id": "5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a",
  "description": "Partner Analytics onboarding",
  "created_at": "2026-01-30T16:00:00Z",
  "expires_at": "2026-02-06T16:00:00Z",
  "max_uses": 5,
  "uses": 0,
  "state": "active",
  "revoked_at": null,
  "token": "example-initial-access-token-not-real-00000"
}
```

- **`token` is shown once.** Hand it to the partner now: it's stored only as a digest.
- **`description` is how you'll tell it apart later.** It is required.
- **`expires_in`** is in seconds, from a minute to ninety days, seven days by default.
- **`max_uses`** is how many clients it may register, 1 to 1000, one by default.

The same can be done from the shell with `$CLAVIA clients:registration-token`.
`GET /api/v1/initial-access-tokens` shows each token's `state`: `active`, `expired`, `used_up` or
`revoked`. Revoking one (`DELETE /api/v1/initial-access-tokens/{initial_access_token_id}`) stops
further registrations; the clients it registered keep working.

## 2. The partner registers

They post their application's metadata to the registration endpoint, the initial access token as a
bearer token:

```bash
curl -s https://auth.example.com/oauth2/register \
  -H 'Authorization: Bearer example-initial-access-token-not-real-00000' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "Acme Reports",
    "redirect_uris": ["https://reports.acme.example/callback"],
    "grant_types": ["authorization_code", "refresh_token"]
  }'
```

```json
{
  "client_id": "tpc_iK0Bks4PODSlxzzSwo1zaKKRgd8ZZOtz",
  "client_secret": "example-client-secret-not-real-0000000000000",
  "client_secret_expires_at": 0,
  "client_id_issued_at": 1795709630,
  "registration_access_token": "example-registration-token-not-real-0000000",
  "registration_client_uri": "https://auth.example.com/oauth2/register/tpc_iK0Bks4PODSlxzzSwo1zaKKRgd8ZZOtz",
  "client_name": "Acme Reports",
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "redirect_uris": ["https://reports.acme.example/callback"],
  "dpop_bound_access_tokens": false
}
```

The `201` is the only time `client_secret` and `registration_access_token` are shown. Discovery
names the endpoint (`registration_endpoint`) only when registration is on.

### What a registered client may be

A self-registered client is always **third-party**: its id starts with `tpc_`, whatever the request
says. That has consequences:
- it never gets a token for the Management API;
- people are asked for their consent;
- it has no connections of its own.

Its metadata is held to these rules:

| Member | Accepted |
|---|---|
| `client_name` | Required |
| `redirect_uris` | Required. `https` without a fragment; a public client may also use `http` on `127.0.0.1` or `[::1]`, never `localhost` |
| `post_logout_redirect_uris` | The same rules |
| `grant_types` | `authorization_code`, and `refresh_token`; `authorization_code` alone by default |
| `response_types` | `code`, the default |
| `backchannel_logout_uri` | An `https` URL on a public address, told when a person's session ends; with `backchannel_logout_session_required` to receive the `sid` |
| `token_endpoint_auth_method` | `client_secret_basic` (the default), `client_secret_post`, or `none` for a public client |
| `dpop_bound_access_tokens` | `true` to [require DPoP](dpop.md) for its tokens |

PKCE stays mandatory. Members the operator sets (`mfa_policy`, pushed authorization requests,
`require_pkce`, custom claims) and members this server doesn't know are ignored, and left out of
the answer.

A refusal is a `400`, naming the member at fault, never its value:

```json
{"error": "invalid_redirect_uri", "error_description": "Each of 'redirect_uris' must be https without a fragment, or, for a public client, http on 127.0.0.1 or [::1]."}
```

| `error` | When |
|---|---|
| `invalid_redirect_uri` | A redirect or post-logout URI the rules above refuse |
| `invalid_client_metadata` | Anything else: a missing `client_name`, a grant or method it may not have (`client_credentials`, `private_key_jwt`), a body that isn't a JSON object |
| `invalid_software_statement` | A `software_statement`, which this server doesn't accept |

| Status | When |
|---|---|
| `401` with no `error` | No initial access token |
| `401` with `invalid_token` | An initial access token that is unknown, expired, revoked or used up |
| `429` | Too many registrations from one address (`CLAVIA_CLIENT_REGISTRATION_MAX_PER_ADDRESS` per `CLAVIA_CLIENT_REGISTRATION_WINDOW`) |

A refused registration spends no use of the token.

## 3. The partner manages their client

The registration access token, sent as a bearer token to `registration_client_uri`, lets the
partner manage that one client ([RFC 7592](https://www.rfc-editor.org/rfc/rfc7592)):

- **`GET`** reads its metadata, without the secret.
- **`PUT`** replaces its metadata. The body includes `client_id`, and states every member: a member
  left out takes its default. Leaving out `grant_types`, for instance, takes the refresh token
  away. The answer carries a **new registration access token**, and the old one stops working at
  once, so keep the new one. The client's id, secret and type never change.
- **`DELETE`** deletes the client (`204`).

Each operation answers to its own client's token only: any other is the same
`401 invalid_token`. Server-set members (`registration_access_token`, `registration_client_uri`,
`client_id_issued_at`, `client_secret_expires_at`) are refused in a `PUT`, and so are a
`client_secret` that isn't the current one and a change between public and confidential. A refused
`PUT` rotates nothing.

## Afterwards

- **`GET /api/v1/clients/{client_id}`** shows a client's `registration`: the initial access token
  that let it in, and when. An operator's own clients show `null`.
- **Clients never used are deleted.** `$CLAVIA clients:purge-unused` runs daily and removes a
  self-registered client that was never issued a token within
  `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME` days (30) of registering. A client used once is kept.
