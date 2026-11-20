# Clavia

An open-source OAuth 2.1 / OpenID Connect authorization server — a self-hosted alternative to
Auth0: OAuth2 flows, interactive login with MFA, and a Management API.

This is the PHP 8.5 implementation. It is being ported feature by feature from the Python
reference implementation; `CLAUDE.md` holds the migration plan and the current state.

**Status: Step 6 — the Management API.** A person signs in with a password at `/auth/login` and
completes the Authorization Code + PKCE flow in a browser; `/oauth2/token` issues an opaque
access token and, for an OpenID Connect request, an RS256 ID token. The provider metadata is
published at `/.well-known/openid-configuration` (and `/.well-known/oauth-authorization-server`),
the signing keys at `/oidc/jwks.json`, and `/oidc/userinfo` answers bearer tokens. Signing keys
are managed with `clavia keys:generate|rotate|list`. Machine clients (`clavia
clients:create-m2m`) get subject-less tokens through the Client Credentials grant for the API
they name in `audience`, within what their client grant on it allows. The Management API
(`https://management.{domain}/api/v1/`) manages users, clients and APIs; its contract is
[`docs/openapi/management-api.yaml`](docs/openapi/management-api.yaml), and every request is
checked against it. It is registered with `clavia management-api:register`, and machine
clients are granted access to it — or to any API — with `clavia clients:grant`.

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
