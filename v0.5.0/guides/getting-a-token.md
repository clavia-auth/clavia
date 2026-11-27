# Getting a token

Every call to the Management API carries an access token issued **for the Management API**. Its
audience is the API's identifier, `https://management.example.com/api/v1/`, trailing slash
included. A token for another API is refused, whatever scopes it carries.

There are two ways to get one: a machine client asking as itself, or a person signing in.

## A machine client

A script, a back office or a provisioning job asks for a token with the client credentials grant.
This takes three commands on the server, run once by whoever operates it. `$CLAVIA` stands for
however you run the console: `docker compose exec php php bin/clavia`, for instance.

1. **Register the Management API**, once per deployment, and again after an upgrade that adds
   scopes:

   ```bash
   $CLAVIA management-api:register
   ```

2. **Create the client.** Its secret is printed once and stored hashed, so a lost secret means a new
   client:

   ```bash
   $CLAVIA clients:create-m2m "Reporting job"
   ```

   ```text
   Registered confidential client "Reporting job"
     client_id:     EXQQefLXZfX3jGqKZB3q7bw9nBvJU0kq
     client_secret: …
   ```

3. **Grant it what it needs**, and nothing more:

   ```bash
   $CLAVIA clients:grant EXQQefLXZfX3jGqKZB3q7bw9nBvJU0kq --scope "read:users read:clients"
   ```

   A client holds nothing until it is granted. Running `clients:grant` again replaces the grant,
   so fewer scopes take the others away. Without `--scope`, it grants every scope of the API.

Grants are written from the shell only. No endpoint writes them, because a token that could would
be able to widen its own access.

Then ask for a token ([`POST /oauth2/token`](../openapi/authorization-server.yaml#tag/tokens/POST/oauth2/token)). The client
authenticates with HTTP Basic, and names the API in `audience`:

```bash
curl -s https://auth.example.com/oauth2/token \
  -u 'EXQQefLXZfX3jGqKZB3q7bw9nBvJU0kq:<client_secret>' \
  -d grant_type=client_credentials \
  -d audience=https://management.example.com/api/v1/
```

```json
{
  "access_token": "example-access-token-not-real-0000000000000",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:users read:clients"
}
```

- **`audience` is required.** A machine token always names its API.
- **`scope` is optional.** Left out, the token carries the whole grant. Name fewer scopes to get
  a token that can do less. Asking for a scope outside the grant is refused, never narrowed:
  `{"error": "invalid_scope", "error_description": "The client may not request: delete:users."}`.
- **There is no refresh token.** When the token expires (`expires_in`, in seconds), ask for a new one.
- **The token is a string to pass along**, not to read: don't parse it.

A client created with `--third-party` is somebody else's machine. It can never be granted the
Management API.

## A person

People reach the Management API through the [dashboard](https://github.com/clavia-auth/clavia-dashboard).
It signs them in with the authorization code flow and holds their token on its own server.

A person's token carries only what **their roles** grant on the Management API (see
[Scopes and roles](scopes-and-roles.md)). Somebody with no role there is refused at sign-in
(`access_denied`). The first administrator is made from the shell:

```bash
$CLAVIA roles:create Administrator             # every Management API permission
$CLAVIA roles:assign Administrator you@example.com
```

After that, roles are managed through the API itself (`POST /api/v1/roles/{role_id}/users`), or the
dashboard.

An application of your own can do what the dashboard does. It must be a first-party client: a
third-party application never gets a token for the Management API. It sends the person to the
authorization endpoint ([`GET /oauth2/authorize`](../openapi/authorization-server.yaml#tag/browser/GET/oauth2/authorize)) with PKCE,
naming the API in `audience` and the permissions it needs in `scope`:

```text
https://auth.example.com/oauth2/authorize?response_type=code
  &client_id=<client_id>&redirect_uri=<registered redirect URI>
  &audience=https://management.example.com/api/v1/
  &scope=read:users%20update:users
  &code_challenge=<S256 challenge>&code_challenge_method=S256&state=<state>
```

It then redeems the code at `/oauth2/token`. The token's `scope` is what was asked for, cut to what
the person's roles hold. Check it rather than assuming it.

When the Management API's MFA policy is `required`, a token from a one-factor sign-in is refused
with `insufficient_user_authentication`. [Errors](errors.md#stepping-up) explains how to step up.

## Using the token

Send it in the `Authorization` header, and only there. A token in the query string or the body is
ignored, and the request is refused as if it carried none:

```bash
curl -s https://management.example.com/api/v1/users \
  -H "Authorization: Bearer $TOKEN"
```

A token bound to a key with DPoP goes as `Authorization: DPoP` instead, with a proof. See
[DPoP-bound tokens](dpop.md).
