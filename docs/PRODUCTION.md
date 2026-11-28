# Running Clavia in production

This guide takes a release of Clavia to production, with Docker Compose on one host or with the
Helm chart on Kubernetes. Both are in [`deploy/`](../deploy): the
[Compose file](../deploy/compose/compose.yaml) and the [chart](../deploy/helm/clavia). Every
setting is declared and documented in
[`src/Configuration/Settings.php`](../src/Configuration/Settings.php).

## 1. What you deploy

```
 browsers, applications,         ┌──────────────────────── auth.{domain} ───────────┐
 directories, identity providers │  sign-in, OAuth 2.1, OpenID Connect, SAML        │
             │                   ├──────────────────────── management.{domain} ─────┤
             ▼                   │  Management API, SCIM, the dashboard             │
       ┌───────────┐  FastCGI    └──────────────────────────────────────────────────┘
       │   Caddy   │───────────▶ PHP-FPM (ghcr.io/clavia-auth/clavia)  ──▶ PostgreSQL 17
       │  (edge)   │                                                   ──▶ Redis 7
       │           │                                                   ──▶ OpenFGA, optional (§8)
       └───────────┘───────────▶ the dashboard (ghcr.io/clavia-auth/clavia-dashboard)
                                 the scheduled commands (bin/clavia …, every minute and daily)
```

- **Two hosts, both required**: `auth.{domain}` and `management.{domain}`. Their separation is a
  security property: a script injected on one can reach nothing on the other. Serve them as two
  origins, never one under the other's path.
- **Caddy** terminates TLS (or sits behind an Ingress that does), serves the sign-in pages' static
  files, and sends everything else to PHP-FPM. It is the one place that decides a request's client
  address: the application believes no forwarded header.
- **PHP-FPM** is share-nothing: run as many as you like behind one Caddy, or one pod each. Its image,
  and the dashboard's, is published for `linux/amd64` and `linux/arm64` (Graviton, Ampere, Apple
  silicon) from 0.6.1.
- **PostgreSQL** holds everything durable: accounts, clients, tokens, keys sealed with the postgres
  backend, the audit trail. **Redis** holds what is short-lived: sessions, challenges, throttling.
  Losing Redis signs everyone out and corrupts nothing.
- **OpenFGA**, only for fine-grained authorization (§8), holds the relationship graph of the APIs
  that use it, in a PostgreSQL of its own. Only Clavia calls it.
- **The scheduled commands** each exit when done:

  | Command | When | What |
  |---|---|---|
  | `bin/clavia jobs:run` | every minute | queued bulk jobs on the users (imports, exports) |
  | `bin/clavia webhooks:deliver` | every minute | the webhook deliveries due, within 50 seconds |
  | `bin/clavia fga:sync` | every minute | identity changes OpenFGA has not taken yet; nothing while `CLAVIA_FGA_URL` is unset |
  | `bin/clavia audit:purge` | daily | audit events older than `CLAVIA_AUDIT_RETENTION_DAYS` |
  | `bin/clavia clients:purge-unused` | daily | self-registered clients never used |

  Running one twice at once is safe. The Compose file runs them from its `scheduler` service, and
  the chart as CronJobs.

## 2. Before you start

- **DNS**: `auth.{domain}` and `management.{domain}` point at the host (Compose) or the Ingress
  (Kubernetes). Both must resolve to a **public** address from the server itself too: every URL
  Clavia calls on an operator's say-so is refused when it resolves to a private one, and the
  dashboard's back-channel logout URI is on `management.{domain}`. Split-horizon DNS that answers a
  private address inside your network blocks it.
- **PostgreSQL 17** and **Redis 7**: the Compose file runs both, or point the settings at managed
  ones.
- **A mail server** (SMTP with STARTTLS, or SMTPS on 465), unless you sign nobody in by email: then
  `CLAVIA_EMAIL_BACKEND=none`.
- **For the signing keys, a KMS** (AWS KMS, Google Cloud KMS or Azure Key Vault) if you can (see §4).
- **For fine-grained authorization**, if your APIs will use it: OpenFGA. The Compose file can run it;
  on Kubernetes it is yours, like the databases (§8).

## 3. Settings and secrets

`CLAVIA_ENV=production` makes the server refuse to start, with exit code 78 and the reason, on
any of these:

- an issuer that is not https;
- `CLAVIA_SESSION_COOKIE_SECURE=false`;
- `CLAVIA_EMAIL_BACKEND=console`;
- `CLAVIA_OUTBOUND_ALLOW_PRIVATE_ADDRESSES=true`;
- `CLAVIA_DEV_AUTOLOGIN_EMAIL`;
- `CLAVIA_AWS_KMS_ENDPOINT_URL`.

It warns about the postgres signing backend. `bin/clavia config` prints every setting as the server
sees it, with secrets masked.

| Setting | Notes |
|---|---|
| `CLAVIA_ROOT_DOMAIN` | The domain. The issuer is `https://auth.{domain}` |
| `CLAVIA_ENV` | `production` |
| `CLAVIA_SECRET_ENCRYPTION_KEY` | Seals the secrets stored in the database: signing keys with the postgres backend, OpenID Connect client secrets, webhook secrets, TOTP seeds. `bin/clavia secrets:generate-key` prints a whole `CLAVIA_SECRET_ENCRYPTION_KEY=…` line. **Keep a copy out of the server and out of its backups**: without it, what it sealed cannot be read back, and with a backup it opens everything |
| `CLAVIA_DATABASE_URL` | `postgresql://user:password@host:5432/clavia`. Add `?sslmode=verify-full&sslrootcert=/path/to/ca.pem` for TLS to the database. Or the separate `CLAVIA_POSTGRES_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_DB` |
| `CLAVIA_REDIS_URL` | `redis://[user:password@]host:6379/0`, or `rediss://` for TLS |
| `CLAVIA_EMAIL_BACKEND`, `CLAVIA_EMAIL_FROM`, `CLAVIA_SMTP_*` | `smtp`, or `none` |
| `CLAVIA_TRUSTED_PROXIES` | Leave empty: Caddy reports the client address to PHP itself |
| `CLAVIA_FGA_URL`, `CLAVIA_FGA_API_KEY` | Fine-grained authorization (§8). Unset, it is off. The key is a secret |

Keep secrets in a secret store: Compose's `.env` file, readable by root only, or a Kubernetes
Secret. Never put them in a values file, an image or a repository.

## 4. Signing keys

Every token is signed through the backend `CLAVIA_SIGNING_BACKEND` names.

- **`aws-kms`, `gcp-kms`, `azure-key-vault`**: the private key never leaves the provider. Create an
  asymmetric signing key (RSA 2048 or more for RS256, or P-256 for ES256), and name **a key
  version**, never an alias, in `CLAVIA_SIGNING_KEY_REF`. With AWS, the server's role needs
  `kms:Sign` and `kms:GetPublicKey` on that key, and nothing else. Nothing calls the provider at
  boot.
- **`postgres`** (the default): the key is generated by the server and sealed in the database with
  `CLAVIA_SECRET_ENCRYPTION_KEY`. Anyone holding a backup and that key can mint tokens, hence the
  warning. Create the first key with `bin/clavia keys:generate`.

**Rotating.**
- With a KMS: create a new key version and make it `CLAVIA_SIGNING_KEY_REF`. List the old one in
  `CLAVIA_SIGNING_RETIRED_KEY_REFS` until every token it signed has expired, at least the longest
  token lifetime plus the JWKS cache's hour.
- With postgres: run `bin/clavia keys:rotate`. It keeps the old key published for that long by
  itself.

**SAML connections** have keys of their own, a signing key and an encryption key, behind
`CLAVIA_SAML_KEY_BACKEND`.
- `postgres`: create them once with `bin/clavia saml-keys:generate`, and roll them over with
  `saml-keys:rotate` (`docs/design/saml-connections.md` §2).
- A KMS: name them with `CLAVIA_SAML_SIGNING_KEY_REF` and `CLAVIA_SAML_ENCRYPTION_KEY_REF`.

## 5. With Docker Compose

On a host with Docker, ports 80 and 443 open to the Internet, and both names pointing at it:

```bash
git clone https://github.com/clavia-auth/clavia.git && cd clavia/deploy/compose
cp env.example .env && cp dashboard.env.example dashboard.env
chmod 600 .env dashboard.env
docker compose run --rm --no-deps php php bin/clavia secrets:generate-key   # into .env
# fill in .env: CLAVIA_ROOT_DOMAIN, the database password, mail, the signing backend
docker compose up -d db redis migrate php scheduler caddy
```

What happens next:
- **Certificates:** Caddy obtains them for both hosts from Let's Encrypt, and redirects plain HTTP
  to HTTPS.
- **Migrations:** they run before PHP-FPM starts, on every `up`.
- **Static files:** `assets` copies the image's static files where Caddy serves them, so an
  upgrade's are the ones served.
- **The dashboard:** start it once its client is registered (§7): `docker compose up -d dashboard`.

Keep two volumes:
- **`pgdata`:** the database, unless it is managed elsewhere.
- **`caddy-data`:** the certificates and the ACME account. Losing it means new certificates, within
  Let's Encrypt's rate limits.

To keep storage elsewhere, delete the `db` and `redis` services and point the settings at your
servers. The `depends_on` entries on them are optional, so nothing else needs changing.

OpenFGA and its database run only with the `fga` profile (§8): `COMPOSE_PROFILES=fga` in `.env`, or
`--profile fga`. Keep its volume, `openfga-pgdata`, too.

## 6. On Kubernetes

The chart runs:
- **A Deployment** of pods with PHP-FPM and Caddy side by side, Caddy serving plain HTTP behind
  your Ingress.
- **The migrations** as a Job before every install and upgrade.
- **The scheduled commands** as CronJobs.
- **The dashboard.**
- **One Ingress** for both hosts.

PostgreSQL and Redis are yours: a managed service, or an operator. So is OpenFGA, if your APIs use
fine-grained authorization (§8).

```bash
kubectl create namespace clavia
kubectl -n clavia create secret generic clavia \
  --from-literal=CLAVIA_SECRET_ENCRYPTION_KEY='…' \
  --from-literal=CLAVIA_DATABASE_URL='postgresql://clavia:…@db:5432/clavia?sslmode=require' \
  --from-literal=CLAVIA_REDIS_URL='rediss://:…@redis:6379/0' \
  --from-literal=CLAVIA_SMTP_PASSWORD='…'
helm install clavia deploy/helm/clavia -n clavia \
  --set rootDomain=example.com \
  --set existingSecret=clavia \
  --set dashboard.enabled=false \
  --set ingress.className=nginx \
  --set ingress.tlsSecretName=clavia-tls \
  --set env.CLAVIA_EMAIL_FROM='Clavia <no-reply@example.com>' \
  --set env.CLAVIA_SMTP_HOST=smtp.example.com
```

- **TLS** is the Ingress's. `ingress.tlsSecretName` names a certificate for both hosts. With
  cert-manager, add its annotation to `ingress.annotations` and give the Secret a name it will
  fill.
- **The client address** is read from the Ingress's `X-Forwarded-For`, right to left, believed only
  from `caddy.trustedProxies` (`private_ranges` by default). Every per-address limit counts against
  it. `private_ranges` also believes any pod that reaches Caddy directly, so narrow it to your Ingress
  controller's pod CIDRs, or turn on `networkPolicy` (with its `from` naming the controller), which
  lets nothing else reach the server pods.
- **Scaling**: `replicaCount` pods, all equal: sessions are in Redis.
- **Probes**: Caddy is ready when PHP's `/healthz` answers through it, on a port no Service
  exposes.
- **The dashboard**: enable it (`dashboard.enabled=true`, `dashboard.existingSecret`) once its
  client is registered (§7).

Run the shell commands of §7 in a pod:
`kubectl -n clavia exec deploy/clavia -c php -- php bin/clavia …`.

## 7. First start

Once, on a new installation. `$CLAVIA` stands for how you run a command:
- Compose: `docker compose exec php php bin/clavia`
- Kubernetes: `kubectl -n clavia exec deploy/clavia -c php -- php bin/clavia`

1. **Keys**, with the postgres backends: `$CLAVIA keys:generate`, and, for SAML,
   `$CLAVIA saml-keys:generate`.
2. **The Management API**: `$CLAVIA management-api:register`. Run it again after an upgrade that
   adds scopes; the release notes say when.
3. **A bootstrap client**, to make the two registrations below. It prints its secret once:
   ```bash
   $CLAVIA clients:create-m2m Bootstrap
   $CLAVIA clients:grant <client_id> --scope "create:clients create:users"
   TOKEN=$(curl -s https://auth.example.com/oauth2/token -u '<client_id>:<client_secret>' \
     -d grant_type=client_credentials -d audience=https://management.example.com/api/v1/ \
     | jq -r .access_token)
   ```
4. **The dashboard's client**: a confidential, first-party client with the code flow, refresh tokens
   and back-channel logout. The answer carries its `client_id` and `client_secret`, once:
   ```bash
   D=https://management.example.com/dashboard
   curl -s https://management.example.com/api/v1/clients -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{
       "name": "Clavia dashboard", "client_type": "confidential",
       "redirect_uris": ["'$D'/auth/callback"], "post_logout_redirect_uris": ["'$D'/signed-out"],
       "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
       "connections": ["password"],
       "backchannel_logout_uri": "'$D'/auth/backchannel-logout", "backchannel_logout_session_required": true
     }'
   ```
   Put them in the dashboard's settings (`dashboard.env`, or its Secret), with a fresh
   `DASHBOARD_SESSION_SECRET`, and start the dashboard.
5. **The first administrator**: an account, then the role.
   - Create the account with a password:
     ```bash
     curl -s https://management.example.com/api/v1/users -H "Authorization: Bearer $TOKEN" \
       -H 'Content-Type: application/json' \
       -d '{"email": "you@example.com", "password": "…", "email_verified": true}'
     ```
   - Or create it without one, and mail it a link with `POST /api/v1/users/{id}/password-reset`.
     That needs `create:user_tickets` in the grant.
   - Then give it the role: `$CLAVIA roles:create Administrator` (every Management API
     permission), and `$CLAVIA roles:assign Administrator you@example.com`.
6. **Sign in** at `https://management.example.com/dashboard`. The Management API requires a second
   factor when its MFA policy says so; enrol one when asked. Then **delete the Bootstrap client**
   from the dashboard's Applications: a client cannot delete itself.

## 8. Fine-grained authorization

An API can ask Clavia who may do what to its own resources (AuthZEN, at
`https://management.{domain}/access/v1`). The answers come from [OpenFGA](https://openfga.dev),
which runs beside Clavia with a PostgreSQL of its own and is reached by Clavia alone. The feature is
off until `CLAVIA_FGA_URL` names OpenFGA.

**Run OpenFGA.**
- **Compose**: the kit's `fga` profile runs `openfga`, `openfga-db` and `openfga-migrate`, which
  brings OpenFGA's schema up to date before it starts, on every `up`. In `.env`:
  ```bash
  COMPOSE_PROFILES=fga
  CLAVIA_FGA_URL=http://openfga:8080
  CLAVIA_FGA_API_KEY=…            # openssl rand -base64 32
  OPENFGA_POSTGRES_PASSWORD=…     # openssl rand -hex 24: OpenFGA's database, not Clavia's
  ```
  then `docker compose up -d`. No port of OpenFGA is published.
- **Kubernetes**, or OpenFGA run any other way (OpenFGA's own Helm chart, for instance): it must be set
  up as the Compose file sets it up, since Clavia relies on each of these:

  | OpenFGA setting | Value | Why |
  |---|---|---|
  | `OPENFGA_DATASTORE_ENGINE` | `postgres` | A database of its own, never Clavia's; `memory` loses everything on a restart |
  | `OPENFGA_AUTHN_METHOD`, `OPENFGA_AUTHN_PRESHARED_KEYS` | `preshared`, the key in `CLAVIA_FGA_API_KEY` | Nobody but Clavia may read or write the graph |
  | `OPENFGA_CHECK_QUERY_CACHE_ENABLED`, `OPENFGA_CHECK_ITERATOR_CACHE_ENABLED`, `OPENFGA_LIST_OBJECTS_ITERATOR_CACHE_ENABLED` | `false` | Every answer strongly consistent: a relationship taken away is never answered from a cache |
  | `OPENFGA_PLAYGROUND_ENABLED` | `false` | The playground is a development tool |

  Run its `migrate` command before every start of a new version, as its documentation says. Let no
  one but the server pods reach it (a NetworkPolicy on OpenFGA's side). Then set
  `env.CLAVIA_FGA_URL` in the chart's values, and `CLAVIA_FGA_API_KEY` in its Secret.

**Then, once:**
1. `$CLAVIA management-api:register`. With `CLAVIA_FGA_URL` set it registers the **Authorization
   API** (`https://management.{domain}/access`) beside the Management API, and gives the Management
   API `read:relationships`. Give that scope to the roles of administrators who should read an API's
   relationships.
2. Check it: `https://management.{domain}/.well-known/authzen-configuration` answers, and names
   `https://management.{domain}`.
3. Turn it on for an API: in the dashboard (the API's Authorization tab), or
   `PUT /api/v1/resource-servers/{id}/authorization`, naming the API's own machine client among the
   clients speaking for it. Grant that client on the Authorization API:
   ```bash
   $CLAVIA clients:grant <client_id> --audience https://management.example.com/access \
     --scope "evaluate:access search:access write:relationships"
   ```
   The [guide](guides/fine-grained-authorization.md) is for the API's developers.

`fga:sync` (every minute, §1) sends OpenFGA the changes to people and roles. A failure is retried
for as long as it takes, so OpenFGA can be stopped for an upgrade. While it cannot be reached, every
decision is `503`, never a grant.

## 9. Backups

| What | How | Why |
|---|---|---|
| **PostgreSQL** | Point-in-time recovery, or `pg_dump --format=custom` daily at least | Everything durable lives there |
| **`CLAVIA_SECRET_ENCRYPTION_KEY`** | In your secret store, **apart from the database's backups** | Without it the sealed secrets cannot be read; with a backup, it opens them |
| **OpenFGA's PostgreSQL**, with fine-grained authorization | Like Clavia's: `pg_dump --format=custom` daily at least (Compose: `docker compose exec openfga-db pg_dump -U openfga --format=custom openfga > openfga.dump`), or point-in-time recovery | The relationships your APIs wrote are only there |
| Redis | Nothing to back up | Losing it signs everyone out |
| Caddy's data (Compose) | Keep the volume | New certificates otherwise |

A restore is the database and the same encryption key, then the same release, or a later one whose
migrations run over it. Practise it on a copy.

Restore OpenFGA's database from a backup taken at the same time as Clavia's. Clavia's database keeps
which store belongs to which API, and OpenFGA's keeps what is in that store, so the two must come
from the same point. Then run `$CLAVIA fga:resync <api>` for each API that uses it: it rewrites the
role memberships Clavia knows. The relationships an API wrote itself come back only from OpenFGA's
backup.

## 10. Upgrades

1. **Read the release notes** (`CHANGELOG.md`). They say what changes, and what you must do.
2. **Back up the database.** Migrations are forward only: rolling back is restoring that backup.
3. **Change the version**:
   - Compose: `CLAVIA_VERSION` and `CLAVIA_DASHBOARD_VERSION` in `.env`, then
     `docker compose pull && docker compose up -d`.
   - Kubernetes: `helm upgrade` with the release's chart.

   The migrations run before the new version starts.
4. **Do what the notes ask.** The usual steps:
   - `bin/clavia management-api:register` when there are new scopes, then give them to the roles
     that should hold them;
   - a new scheduled command, such as `bin/clavia fga:sync` every minute from 0.6: with Compose,
     take the release's `scheduler.sh`, which your copy of the kit mounts; with Helm, the chart's
     CronJobs come with `helm upgrade`;
   - a change to the proxy in front.

## 11. Operating it

- **Logs**: one line per event on stderr, from every container. An unexpected error is logged
  under a 12-character reference, which the client receives in `X-Error-Reference` and nothing
  else.
- **Health**: `GET /healthz` answers `{"status":"ok","version":"…"}` without touching the database
  or Redis.
- **Metrics**, for Prometheus, at `/metrics` on the internal listener: Caddy's port 8081, which
  nothing publishes. It answers only there, and is `404` on both hosts.
  - Compose: a Prometheus on the `clavia` network scrapes `caddy:8081`.
  - Kubernetes: the chart's `<release>-metrics` Service, or its ServiceMonitor
    (`metrics.serviceMonitor.enabled`). Every pod reports the same numbers, kept in Redis, so
    scrape the Service and not every pod.

  | Metric | Labels | What |
  |---|---|---|
  | `clavia_tokens_issued_total` | `grant_type` | Access tokens issued |
  | `clavia_sign_ins_total` | `methods` (`pwd`, `pwd+otp+mfa`…) | Sessions established |
  | `clavia_sign_in_refusals_total` | `reason`, `method` | Sign-ins refused (`wrong_password`, `throttled`…) |
  | `clavia_oauth_errors_total` | `endpoint` (`token`, `authorize`), `error` | OAuth error answers |
  | `clavia_mail_total` | `outcome` (`sent`, `failed`) | Mail handed to the mail server |
  | `clavia_http_request_duration_seconds` | `route`, `method`, `status` | Request latency (a histogram) |

  Labels are kinds, never an account, a client or an address. A request's samples are written to
  Redis in one round trip once its response is out. `CLAVIA_METRICS_ENABLED=false` measures nothing.
- **The audit trail**: `GET /api/v1/audit-events`, or the dashboard, or stream it to your SIEM with
  webhooks.

## 12. Before you go live

- [ ] Both hosts are served over https, as two origins.
- [ ] `bin/clavia config` shows `CLAVIA_ENV production` and no warning you did not choose.
- [ ] Signing keys are in a KMS, or you accept the postgres backend's warning.
- [ ] `CLAVIA_SECRET_ENCRYPTION_KEY` is kept apart from the database backups, and a restore has
      been practised.
- [ ] The scheduled commands run: `jobs:run`, `webhooks:deliver` and `fga:sync` every minute, `audit:purge`
      and `clients:purge-unused` daily.
- [ ] The Bootstrap client is deleted, and administrators hold a second factor.
- [ ] Nothing but Caddy (or your Ingress) is reachable from outside: PHP-FPM, PostgreSQL,
      Redis and OpenFGA listen on the private network only.
- [ ] With fine-grained authorization, OpenFGA takes only the preshared key, its caches are off, and
      its database is backed up with Clavia's.
- [ ] On Kubernetes, `caddy.trustedProxies` names only the Ingress controller, or `networkPolicy`
      is on.
