<p align="center">
  <img src="public/auth/static/clavia-icon.svg" alt="" width="96" height="96">
</p>

<h1 align="center">Clavia</h1>

<p align="center">
  <strong>An open-source OAuth 2.1 and OpenID Connect authorization server.</strong><br>
  Self-hosted sign-in, tokens and user management, a standards-first alternative to Auth0.
</p>

<p align="center">
  <a href="https://github.com/clavia-auth/clavia/actions/workflows/ci.yml"><img src="https://github.com/clavia-auth/clavia/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/PHP-8.5-777BB4?logo=php&logoColor=white" alt="PHP 8.5">
  <img src="https://img.shields.io/badge/OpenID-Config%20OP%20%C2%B7%20Basic%20OP-52B788" alt="OpenID conformance">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause-blue" alt="BSD-3-Clause"></a>
</p>

---

## Why Clavia

Your users' identities are the most sensitive data you hold. Clavia lets you run the identity
layer yourself, on your own domain and infrastructure, without giving up what a hosted provider
offers: a complete OAuth 2.1 and OpenID Connect server, polished sign-in pages, second factors,
social and enterprise connections, roles, an audit trail, and an API to manage it all.

It is built to be trusted. The protocol is implemented directly from the RFCs, with no
shortcuts. Every security rule is covered by tests, and the architecture is enforced by the
build. Signing keys can live in a cloud KMS so that they never touch the server's memory.

## Features

**OAuth 2.1 and OpenID Connect**
- Authorization code with PKCE (S256), client credentials, refresh tokens with rotation and
  replay detection, device authorization for TVs and CLIs
- ID tokens, userinfo, discovery and JWKS; `prompt`, `max_age` and `nonce`
- Token introspection and revocation
- RP-Initiated Logout and Back-Channel Logout

**Sign-in**
- Server-rendered sign-in pages with no JavaScript, light and dark
- Self-service sign-up, email verification and password reset, opened per connection
- Passwords, email codes and magic links, Google, GitHub, and any OpenID Connect provider
- Two-factor authentication with authenticator apps and recovery codes
- Consent screens for third-party applications; per-application connections

**Administration**
- A contract-first Management API for users, applications, APIs, roles, connections,
  sessions and consents
- Role-based access control: permissions per API, granted through roles
- An append-only audit trail of every sign-in, token and change
- [Clavia Dashboard](https://github.com/clavia-auth/clavia-dashboard), the administration
  console

**Operations**
- Signing keys in PostgreSQL or in AWS KMS, Google Cloud KMS, Azure Key Vault, or your own HSM
- Any domain: every host derives from one setting
- Passes the OpenID Foundation's Config OP plan and its Basic OP plan, except one test that
  OAuth 2.1 forbids passing ([results](conformance/README.md))

## Standards

| Specification | Coverage |
|---|---|
| OAuth 2.1 (draft), RFC 6749, RFC 6750 | Authorization code, client credentials, refresh tokens, bearer tokens |
| RFC 7636 | PKCE, S256 only |
| RFC 8628 | Device authorization grant |
| RFC 7662, RFC 7009 | Introspection, revocation |
| RFC 8707 | Audience-restricted tokens: the `audience` parameter, with its `invalid_target` error |
| RFC 8414, OpenID Connect Discovery 1.0 | Server metadata |
| OpenID Connect Core 1.0 | ID tokens, userinfo, `prompt`, `max_age` |
| OpenID Connect RP-Initiated Logout 1.0, Back-Channel Logout 1.0 | Sign-out |
| RFC 6238, RFC 4226 | TOTP second factor |
| RFC 9457 | Problem details for Management API errors |

## Quick start

You need [Docker](https://docs.docker.com/get-docker/) and
[mkcert](https://github.com/FiloSottile/mkcert).

```sh
git clone https://github.com/clavia-auth/clavia.git && cd clavia
cp .env.example .env        # set CLAVIA_ROOT_DOMAIN=clavia.test
./setup-ssl.sh              # local certificate for *.clavia.test, and /etc/hosts entries
make up install migrate     # containers, dependencies, database schema
make seed                   # a development user, clients, the Management API, a signing key
curl https://auth.clavia.test/healthz
```

> **Pick a domain under `.test`.** It is reserved for local use (RFC 6761) and resolved from
> `/etc/hosts` alone. Avoid `.local`, which macOS resolves through Bonjour at seconds per
> lookup, and real suffixes such as `.dev`, which leak to the internet without your hosts
> entries.

### Sign in through the flow

```sh
make authorize-url
```

Open the link it prints, sign in as `dev@clavia.test` / `devpassword`, copy the `code` from the
address bar, and run the `curl` command it printed to exchange the code for tokens.

### Call the Management API

`make seed` prints a machine client holding every Management API scope:

```sh
TOKEN=$(curl -s https://auth.clavia.test/oauth2/token \
  -u '<client_id>:dev-m2m-secret-for-local-development-only' \
  -d grant_type=client_credentials \
  -d audience=https://management.clavia.test/api/v1/ | jq -r .access_token)

curl -s -H "Authorization: Bearer $TOKEN" https://management.clavia.test/api/v1/users
```

The API is described by [`docs/openapi/management-api.yaml`](docs/openapi/management-api.yaml),
and every request is validated against it.

### Run the dashboard

Clone [clavia-dashboard](https://github.com/clavia-auth/clavia-dashboard) and follow its
README. `make seed` prints the settings it needs, and Clavia serves it at
`https://management.clavia.test/dashboard`.

## Configuration

Every setting is a `CLAVIA_*` environment variable, read from the environment first and `.env`
second. All of them are declared, documented and validated in
[`src/Configuration/Settings.php`](src/Configuration/Settings.php); `make config` prints what
the server sees. The essentials:

| Setting | Purpose |
|---|---|
| `CLAVIA_ROOT_DOMAIN` | Your domain. Clavia serves `auth.{domain}` (sign-in and tokens) and `management.{domain}` (Management API and dashboard) |
| `CLAVIA_ENV` | `development`, `staging` or `production` |
| `CLAVIA_SECRET_ENCRYPTION_KEY` | Encrypts stored secrets; generate one with `bin/clavia secrets:generate-key` |
| `CLAVIA_SIGNING_BACKEND` | `postgres` (default), `aws-kms`, `gcp-kms`, `azure-key-vault`, or your own class |
| `CLAVIA_SIGNING_KEY_REF`, `CLAVIA_SIGNING_RETIRED_KEY_REFS` | The provider key version that signs, and the retired ones still published |
| `CLAVIA_DATABASE_URL`, `CLAVIA_REDIS_URL` | PostgreSQL and Redis (or the individual `_HOST`, `_PORT`… settings) |
| `CLAVIA_EMAIL_BACKEND`, `CLAVIA_SMTP_*`, `CLAVIA_EMAIL_FROM` | Mail for passwordless sign-in: `smtp`, `none`, or `console` in development |
| `CLAVIA_GOOGLE_CLIENT_ID`/`_SECRET`, `CLAVIA_GITHUB_CLIENT_ID`/`_SECRET` | Social sign-in; register `https://auth.{domain}/auth/social/{provider}/callback` at the provider |
| `CLAVIA_ACCESS_TOKEN_LIFETIME`, `CLAVIA_REFRESH_TOKEN_LIFETIME`, `CLAVIA_REFRESH_TOKEN_ABSOLUTE_LIFETIME` | Token lifetimes (1 hour, 30 days idle, 90 days at most) |
| `CLAVIA_AUDIT_RETENTION_DAYS` | How long audit events are kept (90 days) |
| `CLAVIA_VERIFICATION_LINK_LIFETIME`, `CLAVIA_RESET_LINK_LIFETIME` | How long verification and reset links work (a day, 30 minutes) |
| `CLAVIA_TRUSTED_PROXIES` | Proxies whose `X-Forwarded-Proto` is believed (none by default) |

### In production

- **Keep signing keys out of the server**: use a KMS backend. With `aws-kms`, the task role needs
  only `kms:Sign` and `kms:GetPublicKey`. To rotate, create a new key version, make it
  `CLAVIA_SIGNING_KEY_REF`, and list the old one in `CLAVIA_SIGNING_RETIRED_KEY_REFS` until its
  tokens have expired.
- **Bootstrap an administrator** from the shell:
  `bin/clavia management-api:register`, then `bin/clavia roles:create Administrator` and
  `bin/clavia roles:assign Administrator you@example.com`.
- **Open sign-up** per pool from the Management API, with a verified address required so nobody
  can register someone else's:
  `PATCH /api/v1/connections/password` with `{"allow_sign_up": true, "require_verified_email": true}`.
- **Purge old audit events daily**: `0 3 * * * bin/clavia audit:purge`.
- **Serve `auth.{domain}` and `management.{domain}` as separate origins.** Their separation is a
  security property.

## Architecture

Clavia is a strict hexagonal application (ports and adapters), and the build fails on any
dependency that points the wrong way.

```
   HTTP (Mezzio) · Console          PostgreSQL · Redis · KMS · SMTP · HTTP
            │                                      ▲
            ▼                                      │ implements
   ┌──────────────────────────────────────────────────────────┐
   │ Application: use cases, ports                            │
   │   ┌──────────────────────────────────────────────────┐   │
   │   │ Domain: OAuth 2.1, OIDC, identity, roles, audit… │   │
   │   │ pure PHP, no dependencies                        │   │
   │   └──────────────────────────────────────────────────┘   │
   └──────────────────────────────────────────────────────────┘
```

| Layer | Namespace | May depend on |
|---|---|---|
| Domain | `Clavia\Domain` | nothing |
| Application | `Clavia\Application` | Domain |
| Primary adapters (HTTP, console) | `Clavia\Adapter\Primary` | Domain, Application, libraries |
| Secondary adapters (persistence, Redis, signing, mail…) | `Clavia\Adapter\Secondary` | Domain, Application, libraries |
| Settings | `Clavia\Configuration` | nothing |
| Composition root | `Clavia\Bootstrap` | everything |

The stack: PHP 8.5 on PHP-FPM behind Caddy, Mezzio, PostgreSQL, Redis. The OAuth and OpenID
Connect engine is Clavia's own, written from the specifications. [`CLAUDE.md`](CLAUDE.md) is
the full guide to the architecture, the flows and the conventions.

```
src/
├── Domain/          aggregates, value objects and rules, by bounded context
├── Application/     use cases and ports
├── Adapter/
│   ├── Primary/     HTTP handlers and middleware, console commands
│   └── Secondary/   PostgreSQL, Redis, signing backends, mail, identity providers
├── Configuration/   typed settings
└── Bootstrap/       wiring
config/  templates/  migrations/  docs/openapi/  test/  conformance/
```

## Development

| Command | What it does |
|---|---|
| `make check` | Everything a change must pass: coding standard, static analysis, architecture, tests |
| `make test` | The test suite |
| `make lint` · `make analyse` · `make arch` | PHPCS (PSR-12) · Psalm (level 1) · deptrac |
| `make migrate` · `make db-status` | Apply migrations · list them |
| `make shell` | A shell in the PHP container |

The tests come in three suites: unit (no I/O), integration (each adapter against real
PostgreSQL and Redis), and acceptance (the whole application, in process). Every port has an
in-memory double and a contract test run against both the double and the real adapter.

## Contributing

Contributions are welcome: bug reports, documentation, and code.

1. **Open an issue first** for anything beyond a small fix, so the design can be agreed before
   the work.
2. **Read [`CLAUDE.md`](CLAUDE.md)**: the architecture rules, the security invariants and the
   conventions a change must keep.
3. **Keep `make check` green.** Add acceptance tests for behaviour, and unit tests for domain
   rules. Changes to the Management API start in its OpenAPI document.
4. **Start every PHP file with the licence header** in [`.docheader`](.docheader).
5. **Open a pull request** that explains what changes and why, citing the RFC where the protocol
   is involved.

## Security

Please do not report vulnerabilities in public issues. Use GitHub's
[private vulnerability reporting](https://github.com/clavia-auth/clavia/security/advisories/new)
instead. Clavia's own review of its adapters is in
[`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md).

## License

Clavia is released under the [BSD 3-Clause License](LICENSE).
