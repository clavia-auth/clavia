# Clavia

An open-source OAuth 2.1 / OpenID Connect authorization server — a self-hosted alternative to
Auth0: OAuth2 flows, interactive login with MFA, and a Management API.

This is the PHP 8.5 implementation. It is being ported feature by feature from the Python
reference implementation; `CLAUDE.md` holds the migration plan and the current state.

**Status: Step 20 done; Phase E under way (audit logs).** A person signs in with a password at `/auth/login`, with
a code or a link sent by email, or with Google or GitHub once their credentials are configured (`CLAVIA_GOOGLE_CLIENT_ID` / `_SECRET`,
`CLAVIA_GITHUB_CLIENT_ID` / `_SECRET`; register
`https://auth.{domain}/auth/social/{provider}/callback` at the provider) — followed, once they
turn it on at `/auth/mfa/enroll`, by a code from an authenticator app or a single-use recovery
code — and completes the Authorization Code + PKCE flow in a browser;
`/oauth2/token` issues an opaque access token and, for an OpenID Connect request, an RS256 ID token. The provider metadata is
published at `/.well-known/openid-configuration` (and `/.well-known/oauth-authorization-server`),
the signing keys at `/oidc/jwks.json`, and `/oidc/userinfo` answers bearer tokens. Signing keys
are managed with `clavia keys:generate|rotate|list` (with the `postgres` backend). Machine clients (`clavia
clients:create-m2m`) get subject-less tokens through the Client Credentials grant for the API
they name in `audience`, within what their client grant on it allows. The Management API
(`https://management.{domain}/api/v1/`) manages users, clients and APIs; its contract is
[`docs/openapi/management-api.yaml`](docs/openapi/management-api.yaml), and every request is
checked against it. It is registered with `clavia management-api:register`, and machine
clients are granted access to it — or to any API — with `clavia clients:grant`. An operator
resets the second factor of somebody who lost both their phone and their recovery codes with
`DELETE /api/v1/users/{user_id}/mfa`. A client signs the person out with
`/oidc/logout` (OpenID Connect RP-Initiated Logout 1.0, `GET` or `POST`): an `id_token_hint`
the server signed for the signed-in person ends the session at once; without one the person is
asked first. The browser is then sent to one of the client's registered
`post_logout_redirect_uris`, with `state`, or to the login page.

Roles are how a person comes to hold an API's permissions. A role grants permissions on one
or several APIs and is given to users; on an API with `enforce_policies` on — always the case
for the Management API — a person's token carries only what their roles grant there, and
somebody holding nothing is refused. Roles are managed under `/api/v1/roles`; giving one
needs `update:roles`. The first holder is made at the shell: `clavia roles:create
Administrator` (every Management API permission by default), then `clavia roles:assign
Administrator you@example.com`. `clavia seed-dev` does both for the development user.

A connection is a way to sign in: a pool of accounts with passwords (`password`, the default
pool, and any other an operator creates), Google, GitHub, or any OpenID Connect provider
registered under `/api/v1/connections` — discovered from its issuer, its client secret stored
encrypted, its ID tokens verified against its published keys. Every account belongs to one
connection, and the same address in two pools is two accounts. A first-party application
signs people in through the connections it enables (`PUT /api/v1/clients/{client_id}/connections`;
a new one gets every connection), a third-party one through the domain connections; its login
page offers only those, and a session established through any other does not count for it.
The URLs an operator registers are fetched over https only, never at this server's own
network (`CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES` waives that in development). The accounts
an external connection linked to a user are listed and unlinked under
`/api/v1/users/{user_id}/identities`.

The dashboard (`frontend/`, React) is registered by `clavia seed-dev` as a public client, which
also writes its build configuration to `frontend/.env.local`. Run it with
`cd frontend && npm install && npm run dev`; Caddy serves it at
`https://management.{domain}/dashboard/`.

An API checks a token presented to it at `/oauth2/introspect` (RFC 7662), through a machine
client holding a grant on it; a client gives a token back at `/oauth2/revoke` (RFC 7009) —
a refresh token takes the whole chain with it.

A device without a browser — a television, a command-line tool — registered for the device
code grant (RFC 8628) asks `/oauth2/device/code` for a code, shows it, and polls the token
endpoint while a person approves it at `https://auth.{domain}/auth/device` on another screen.

Signing in by email needs no password: the login page's email form sends six digits, typed
back in the same browser, or a single-use link that opens on any device and signs in from the
page it opens on. Those accounts belong to the built-in `email` connection. Mail goes out
through `CLAVIA_EMAIL_BACKEND`: `smtp` (`CLAVIA_SMTP_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`,
`_STARTTLS`; `CLAVIA_EMAIL_FROM`), `none` — which switches email sign-in off — or, in
development only, `console`, which logs each message and keeps the last ones for
`bin/clavia mail:outbox`. Sends are limited per address and per client address
(`CLAVIA_PASSWORDLESS_SEND_LIMIT` an hour); a code takes `CLAVIA_PASSWORDLESS_MAX_ATTEMPTS`
wrong answers. Applications registered before the `email` connection existed are given it
with `PUT /api/v1/clients/{client_id}/connections`.

A client registered with a `backchannel_logout_uri` is told when a session it signed in
through ends (OpenID Connect Back-Channel Logout 1.0): signing out at `/auth/logout` or
`/oidc/logout`, an operator ending the person's sessions (`DELETE
/api/v1/users/{user_id}/sessions`, or one by its `sid`), the account being deactivated or
deleted. A logout token naming the session — the `sid` its ID tokens carried — is posted
to it after the response. `GET /api/v1/users/{user_id}/sessions` lists a person's sessions
and the applications that signed in through each.

An application decides how fresh the sign-in must be: `prompt=login` (or `select_account`)
asks the person to sign in again, `max_age` sets how old a sign-in may be, and `prompt=none`
answers `login_required` rather than showing a page. Request objects (`request`,
`request_uri`) are refused with the errors OpenID Connect defines for them.

Tokens are signed in the database by default (`CLAVIA_SIGNING_BACKEND=postgres`, keys sealed
with `CLAVIA_SECRET_ENCRYPTION_KEY`), or by a key that never leaves its provider: `aws-kms`
(`composer require aws/aws-sdk-php`), `gcp-kms` (`composer require google/auth`) or
`azure-key-vault`, with `CLAVIA_SIGNING_KEY_REF` naming the key version — a key ARN or id,
`projects/…/cryptoKeyVersions/N`, `https://<vault>.vault.azure.net/keys/<name>/<version>`.
To rotate, create a new key there, make it the reference, and list the old one in
`CLAVIA_SIGNING_RETIRED_KEY_REFS` until its tokens have expired. Azure uses the host's managed
identity, or an application named by `CLAVIA_AZURE_TENANT_ID`, `CLAVIA_AZURE_CLIENT_ID` and a
`CLAVIA_AZURE_CLIENT_SECRET` or `CLAVIA_AZURE_FEDERATED_TOKEN_FILE`. Any other value is the class
name of your own `RemoteSigningKey` — an HSM, Vault Transit — built from the key reference.

Clavia passes the OpenID Foundation's Config OP plan and, but for one test OAuth 2.1 forbids
passing, its Basic OP plan — results and how to run them in
[`conformance/README.md`](conformance/README.md). The suite sends no PKCE, so its clients are
registered with `"require_pkce": false`: a confidential client so registered may omit PKCE from
an OpenID Connect request that carries a `nonce` (OAuth 2.1 §7.5.1). Every other client, and
every public one, always uses PKCE.

Everything that changes who can sign in or what they hold is written to an append-only audit
trail: sign-ins and refused attempts (with the reason, never the password), sign-outs, second
factors turned on or off, consents and device approvals, tokens issued and replays caught,
and every change made through the Management API or at the shell — who acted (a person
through an application, a machine client, the system), on what, from which address. It is
read at `GET /api/v1/audit-events` (scope `read:audit_events`), filtered by type, actor,
application, target, outcome and time. Rows cannot be updated, by the application or by
anyone with SQL; the only deletion is `clavia audit:purge`, which removes what is older than
`CLAVIA_AUDIT_RETENTION_DAYS` (90 by default) — run it daily from a scheduler
(`0 3 * * * bin/clavia audit:purge`, or a scheduled task in your platform).

A client registered for the `refresh_token` grant (beside `authorization_code`) gets a
refresh token with the code flow's tokens. Every refresh returns a new pair and spends the
old refresh token; presenting a spent one revokes the whole chain and every access token it
issued. A chain lives `CLAVIA_REFRESH_TOKEN_LIFETIME` without use (30 days by default) and
`CLAVIA_REFRESH_TOKEN_ABSOLUTE_LIFETIME` at most (90 days).

An application is first-party (the operator's own) or third-party (`"is_first_party": false`
at registration, or `clavia clients:create-m2m --third-party`; its id starts with `tpc_`).
A third-party application asks the person on a consent screen at `/auth/consent` for every
scope, and the answer is remembered; a first-party one asks only when the API it names has
`allow_skipping_consent` off, or when it sends `prompt=consent`. A third-party application
never gets a token for the Management API. A user's consents are listed and withdrawn under
`/api/v1/users/{user_id}/consents`.

## Architecture

Strict hexagonal (ports and adapters), enforced by the build:

| Namespace | Role | May depend on |
|---|---|---|
| `Clavia\Domain` | Aggregates, value objects, policies, repository interfaces | nothing |
| `Clavia\Application` | Use cases and technical ports | `Domain` |
| `Clavia\Adapter\Primary` | Primary (driving) adapters — what calls the application: HTTP (Mezzio, PSR-15) and the console | `Domain`, `Application`, libraries |
| `Clavia\Adapter\Secondary` | Secondary (driven) adapters — what the application calls: PostgreSQL, Redis, signing, mail… | `Domain`, `Application`, libraries |
| `Clavia\Configuration` | The typed `CLAVIA_*` settings | nothing |
| `Clavia\Bootstrap` | Composition root: wires adapters to ports | everything |

## Getting started

Requirements: Docker, and [mkcert](https://github.com/FiloSottile/mkcert) for local TLS.

```sh
cp .env.example .env     # set CLAVIA_ROOT_DOMAIN (e.g. clavia.local)
./setup-ssl.sh           # certificate for *.{CLAVIA_ROOT_DOMAIN} + /etc/hosts entries
make up install migrate  # Caddy, PHP-FPM, PostgreSQL, Redis; composer install; schema
make seed                # a development user, clients, the Management API and a key
curl https://auth.clavia.local/healthz
```

| Command | What it does |
|---|---|
| `make check` | Coding standard, static analysis, architecture rules, tests |
| `make test` | PHPUnit only |
| `make config` | Print every `CLAVIA_*` setting as the server sees it |
| `make migrate` / `make db-status` | Apply the pending SQL migrations / list them |
| `make seed` | Create the development user (`dev@{domain}` / `devpassword`), a public client, the Management API and a machine client granted every management scope; safe to repeat |
| `make authorize-url` | Print an authorization URL with a fresh PKCE pair, and the `curl` that redeems the code |
| `make shell` | A shell in the PHP container |

### Trying the flow

```sh
make seed
make authorize-url       # open the link and sign in as dev@clavia.local / devpassword,
                         # copy ?code=… from the address bar, then run the printed curl
```

### Calling the Management API

```sh
make seed                # prints the machine client and the token request below
TOKEN=$(curl -s https://auth.clavia.local/oauth2/token \
  -u '<client_id>:dev-m2m-secret-for-local-development-only' \
  -d grant_type=client_credentials \
  -d audience=https://management.clavia.local/api/v1/ | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" https://management.clavia.local/api/v1/users
```

Differences from the Python server are listed in [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md).

## Configuration

Every setting is a `CLAVIA_*` environment variable, read from the process environment first and
`.env` second. They are declared, documented and validated in one place:
[`src/Configuration/Settings.php`](src/Configuration/Settings.php).

## License

BSD-3-Clause — see [LICENSE](LICENSE).
