# Clavia

An open-source OAuth 2.1 / OpenID Connect authorization server — a self-hosted alternative to
Auth0: OAuth2 flows, interactive login with MFA, and a Management API.

This is the PHP 8.5 implementation. It is being ported feature by feature from the Python
reference implementation; `CLAUDE.md` holds the migration plan and the current state.

**Status: Step 2 — Authorization Code + PKCE.** `/oauth2/authorize` and `/oauth2/token` issue
single-use codes and opaque access tokens to public and confidential clients. The login page
comes next; until then a development deployment can sign a user in with
`CLAVIA_DEV_AUTOLOGIN_EMAIL`.

## Architecture

Strict hexagonal (ports and adapters), enforced by the build:

| Namespace | Role | May depend on |
|---|---|---|
| `Clavia\Domain` | Aggregates, value objects, policies, repository interfaces | nothing |
| `Clavia\Application` | Use cases and technical ports | `Domain` |
| `Clavia\Infrastructure` | Driven adapters: PostgreSQL, Redis, signing, mail… | `Domain`, `Application`, libraries |
| `Clavia\Ui` | Driving adapters: HTTP (Mezzio, PSR-15) and the console | `Domain`, `Application`, libraries |
| `Clavia\Configuration` | The typed `CLAVIA_*` settings | nothing |
| `Clavia\Bootstrap` | Composition root: wires adapters to ports | everything |

## Getting started

Requirements: Docker, and [mkcert](https://github.com/FiloSottile/mkcert) for local TLS.

```sh
cp .env.example .env     # set CLAVIA_ROOT_DOMAIN (e.g. clavia.local)
./setup-ssl.sh           # certificate for *.{CLAVIA_ROOT_DOMAIN} + /etc/hosts entries
make up install migrate  # Caddy, PHP-FPM, PostgreSQL, Redis; composer install; schema
make seed                # a development user and a public PKCE client
curl https://auth.clavia.local/healthz
```

| Command | What it does |
|---|---|
| `make check` | Coding standard, static analysis, architecture rules, tests |
| `make test` | PHPUnit only |
| `make config` | Print every `CLAVIA_*` setting as the server sees it |
| `make migrate` / `make db-status` | Apply the pending SQL migrations / list them |
| `make seed` | Create the development user (`dev@{domain}` / `devpassword`) and client; safe to repeat |
| `make authorize-url` | Print an authorization URL with a fresh PKCE pair, and the `curl` that redeems the code |
| `make shell` | A shell in the PHP container |

### Trying the flow

Set `CLAVIA_DEV_AUTOLOGIN_EMAIL=dev@clavia.local` in `.env` (development only — the server
refuses to start with it anywhere else), then:

```sh
make seed
make authorize-url       # open the link, copy ?code=… from the address bar, run the curl
```

Differences from the Python server are listed in [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md).

## Configuration

Every setting is a `CLAVIA_*` environment variable, read from the process environment first and
`.env` second. They are declared, documented and validated in one place:
[`src/Configuration/Settings.php`](src/Configuration/Settings.php).

## License

BSD-3-Clause — see [LICENSE](LICENSE).
