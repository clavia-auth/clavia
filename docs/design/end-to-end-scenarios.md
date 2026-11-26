# Design: End-to-end scenarios through the real stack, and nightly conformance

**Status:** proposed · **Date:** 2026-11-26 · **Issue:** clavia-auth/clavia#39 (and
clavia-auth/clavia-dashboard#17) ·
**Specifications:** OpenID Connect Core 1.0, RFC 6749, RFC 7009, RFC 9700 (OAuth 2.0 Security Best
Current Practice), OpenID Connect Back-Channel Logout 1.0, the OpenID Foundation conformance suite
(`conformance/README.md`)

## 1. Summary

The PHPUnit acceptance suite runs every flow in-process: the real container, pipeline and routes, but
no Caddy, no PHP-FPM, no TLS, no real cookie jar enforcing `Secure` and `Path`, no real mail, no
second application. The dashboard's Playwright smoke suite (`e2e/`) runs only by hand, against a
stack its author started. The OpenID Foundation conformance plans are run by hand from a README.

This design runs Clavia **as it is deployed**, in CI, and drives it from outside:

- **One stack definition**, owned by clavia, that CI and a developer both start: Caddy, PHP-FPM,
  PostgreSQL, Redis, a mail catcher and the dashboard, behind the real Caddyfile and TLS.
- **Two suites against it**: Behat scenarios in Gherkin in clavia (HTTP, no browser), Playwright in
  clavia-dashboard (a real browser). Both on every pull request.
- **The conformance plans nightly**, against the same stack, compared with a recorded baseline.

### Goals

- A change that breaks what only the deployment shows (a header Caddy drops, a cookie a browser
  refuses, a host that answers what it should not, a mail that is never sent, a back-channel logout
  that never arrives) fails a pull request.
- The stack starts the same way on a laptop and in CI, so a red run reproduces locally with one
  command.
- Both repositories test the pair, at the version each will ship with the other.

### Not in scope

- **Replacing the acceptance suite.** Protocol rules stay there: it is faster and finer. Scenarios here
  prove the seams (§5).
- **Load, performance and fuzzing tests.**
- **Passkeys and any flow needing a WebAuthn authenticator** in a first pass: Playwright's virtual
  authenticator can come later, as a slice of its own.
- **Testing other deployments** (the Helm chart on Kubernetes, managed storage): the Compose topology
  is the one tested; the chart shares its Caddyfile and images.
- **A hosted test environment.**

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| Whose stack | clavia owns `test/e2e/compose.yaml`; the dashboard's workflow checks clavia out (both repositories are public) and uses it | One definition of "Clavia, running". Two would drift, and the dashboard's suite is the dashboard talking to *this* server. Rejected: a copy in each repository |
| Which topology | The production topology (`deploy/compose/compose.yaml`: Caddy with the shared Caddyfile, `php`, `migrate`, `assets`, `scheduler`, `dashboard`, `db`, `redis`, the `edge` network with the host aliases), plus a mail catcher | The issue is "Clavia as it is deployed". The development compose runs the dashboard on the host and PHP with a bind mount, which is none of that. The `edge` network matters: it is what lets the dashboard reach `auth.{domain}` by name (and is the reason the back-channel logout URI passes the outbound URL policy) |
| Images | Clavia's from the pull request (the production target of `docker/php`, built in the job); the dashboard's from the pull request when the dashboard's workflow runs, else `ghcr.io/clavia-auth/clavia-dashboard:edge`. Each repository publishes `:edge` from `main` | Each side tests its change against the other's `main`. Building the other repository in every job doubles the minutes; a pinned release tag hides a break until the next release. Publishing `:edge` is new (the Release workflow only publishes tagged images), see open question 1 |
| TLS and names | `mkcert` in the job issues `*.clavia.test`; its CA is trusted by the runner (`NODE_EXTRA_CA_CERTS`, the NSS store for Chromium) and by the containers that call Clavia; `auth.`, `management.` and the apex resolve to `127.0.0.1` through `/etc/hosts`. Never `.local` | The same tools `setup-ssl.sh` uses, so a laptop is the same. `.test` is the project's rule (RFC 6761). The CA is made per run and never committed |
| Seeding | The stack runs `CLAVIA_ENV=development` and is seeded by `seed-dev`, which `CLAVIA_ENV` gates; scenarios then create their own data through the Management API | `isDevelopment()` gates the seed commands, the plain-http loopback issuer and the autologin (left unset). None of the three changes how a request is handled, which a slice-1 check confirms (§9). Rejected for now: a production-mode seed, which needs a new command; open question 3 |
| Behat or other | Behat 3 with Gherkin, a small set of contexts over Guzzle with a cookie jar that follows the browser's rules, against `https://auth.clavia.test` and `https://management.clavia.test` | Decided in the issue. Scenarios read as the behaviour; the contexts hold the HTTP. Rejected: more PHPUnit (it is the in-process suite again) |
| Mail | Mailpit as the SMTP server (`CLAVIA_EMAIL_BACKEND=smtp`); a context reads its HTTP API for the message and the link in it | The `console` backend only prints to `mail:outbox`, which would not test the SMTP adapter, the From header or the link as delivered. Mailpit is one small image |
| Data between scenarios | No database wipe. Each scenario makes its own user, client or connection with a unique name, through the Management API, and does not depend on another's; the stack is shared by the whole run | A wipe forbids running Behat and Playwright at once against one stack, and a scenario that must clean up after itself is a scenario that fails when it is interrupted. Unique names also let Playwright keep `fullyParallel` |
| Order and retries | Behat serial, no automatic retry; Playwright keeps `retries: 1` in CI (already set) | A retry in Behat would hide a real race in the server; the browser suite's one retry absorbs a slow render |
| Triggers | Both on every pull request, concurrency cancelling the older run; not required at first, required after two weeks of green runs | Decided in the issue (every pull request). A required check on an unproven suite blocks the maintainer on a flake; making it required is a ruleset change that is the maintainer's |
| Conformance | A scheduled workflow in clavia, nightly, plus manual dispatch: the stack, the suite and the two plans of `conformance/README.md`, the result compared with `conformance/baseline.json`; a regression fails the run and opens or updates one issue | The results vary by what a person must review (screenshots), so "all green" cannot be the test: the baseline records each module's expected outcome, including the deliberate failure, and a *change* is the signal |
| Artifacts | On failure: `docker compose logs`, Playwright's traces, Behat's JUnit and the Mailpit messages; on the conformance run: the suite's exported HTML | A red end-to-end run without logs cannot be diagnosed from the CI page |

## 3. Settings

No new `CLAVIA_*` setting. The stack sets existing ones (`CLAVIA_ROOT_DOMAIN=clavia.test`,
`CLAVIA_ENV=development`, `CLAVIA_EMAIL_BACKEND=smtp`, `CLAVIA_SMTP_HOST=mailpit`) in `test/e2e/e2e.env`,
whose secrets are throwaway and published, and it publishes ports on `127.0.0.1` only.

## 4. Model

No domain change. What is added is test infrastructure:

- `test/e2e/compose.yaml`, `test/e2e/e2e.env`, `test/e2e/dashboard.env`, `test/e2e/up.sh` (certificate,
  hosts, `docker compose up --wait`, `seed-dev`) and `down.sh`; `make e2e-up`, `make e2e`, `make e2e-down`.
- `behat.yml`, `test/e2e/features/*.feature` and `test/e2e/Context/` (`Http`, `Browserlike` cookie jar,
  `Mail`, `Management`, `Dashboard`). Behat is a `require-dev` dependency, outside deptrac's
  application layers (it is test code).
- In clavia-dashboard: `.github/workflows/e2e.yml`, and `e2e/` growing as §5 lists.
- `conformance/baseline.json`, `conformance/run.sh` (the README's steps as a script) and
  `.github/workflows/conformance.yml`.

## 5. Flows

Scenarios prove what the in-process suite cannot, grouped by the seam they cross. The first batch of
each (marked ●) is the Done when of its slice.

**Through Caddy and the headers (Behat)**
- ● Host separation: `/api/v1/*` and `/scim/v2/*` answer `404` on `auth.`; `/oauth2/*` and `/auth/*` answer
  `404` on `management.`.
- ● The internal listener (`:8081`, `/healthz`, `/metrics`) is not reachable on either public host or published port.
- Security headers on the sign-in pages and the token endpoint (`Cache-Control: no-store`, the CSP, frame
  denial, HSTS) as Caddy sends them; static assets served by Caddy with their versioned URLs.

**Sign-in as a browser does it (Behat, cookie jar with real attribute rules)**
- ● Authorization code with PKCE through the real login page: the form post, the session cookie set with
  `Secure`, `HttpOnly`, `SameSite` and no `Domain`, consent, the redirect, the token, userinfo and the
  ID token verified against the JWKS fetched over TLS.
- ● Refresh rotation and reuse: a refresh token used twice revokes the family.
- Device authorization, introspection and revocation by a machine client; a refused client gets
  `invalid_client` and then `429` past the failure limit.

**Mail (Behat with Mailpit)**
- ● Sign-up with verification: the message arrives, From and subject are right, the link verifies the address.
- Password reset and invitation links, single use.

**The dashboard behind Clavia (Playwright)**
- ● The existing smoke suite (every section opens; the operator finds themselves; sign-out ends the Clavia
  session) and the sign-out then sign-in again case.
- ● Back-channel logout: ending the session at Clavia (another application's sign-out, or an admin
  revoking it) signs the dashboard out at its next request.
- Step-up: with the Management API's MFA policy on, an operator with one factor is sent round once and
  returns to the page they were on.
- An operator with a narrow role sees only what their scopes allow; a forbidden page is explained.
- The audit log's CSV export returns the events a filter shows, from a live Clavia.
- A provisioning token issued from the connection page provisions a user through `/scim/v2` (a Behat-side
  call with the token the browser showed), and a webhook endpoint receives a signed delivery (a small
  receiver container in the stack, whose log the test reads).

**Conformance (nightly)**
The Config OP and Basic OP plans, as `conformance/README.md` runs them, with `provision.py` run by the
script. A module whose outcome differs from `baseline.json`, in either direction, is reported: a new
failure is a regression, a new pass means the baseline is stale and the run says so.

Every refusal in these scenarios is asserted as the outside sees it (status, headers, body), never by
reading the server's storage.

## 6. Interfaces

- **clavia**: `test/e2e/` (stack, scripts, features, contexts), `behat.yml`, `composer.json` (dev
  dependency, a `composer e2e` script), `Makefile` (`e2e-up`, `e2e`, `e2e-down`),
  `.github/workflows/e2e.yml`, `conformance.yml`, and a step in `image.yml` publishing `:edge` from `main`.
- **clavia-dashboard**: `.github/workflows/e2e.yml` (checks out clavia's `test/e2e`, brings the stack up
  with the dashboard built from the pull request, builds and serves it as the production image, runs
  `npm run e2e`), `playwright.config.ts` (reads the URL the stack gives it), a workflow publishing `:edge`,
  `CLAUDE.md` (the commands table, Testing) and `.env.example` untouched.
- **Documentation**: `CLAUDE.md` Testing section in clavia (a fourth suite and how to run it), `docs/RELEASING.md`
  (conformance is nightly; the release is cut only from a green night, or the baseline's diff explained).
- **No Management API change.**

## 7. Security rules

- **The stack is never reachable beyond the machine.** Ports bind `127.0.0.1`; the compose file carries
  no real secret, and its secrets are marked as published throwaways. A scenario that would need a
  real credential is not written.
- **Pull requests from forks run the suites with no secret.** Nothing here needs one, so the workflows
  use `pull_request`, never `pull_request_target`, and `permissions: contents: read` (the conformance
  workflow adds `issues: write`, on a schedule only, never on a pull request).
- **The test CA and its key are made per run**, kept in the runner, never uploaded as an artifact, never
  committed. `setup-ssl.sh`'s `certs/` is untouched.
- **Artifacts hold no token.** Server logs never log a token (an invariant); Playwright traces are the
  exception to watch, since they record requests: they are kept only on failure, for the shortest
  retention the repository allows, and the test credentials are the published ones.
- **`:edge` images are built from `main` by the repository's own workflow**, with `GITHUB_TOKEN`, never
  from a pull request, so an unreviewed change is never published under a name another repository's
  CI then trusts.
- **A scenario states a refusal it must see**: a test that passes because a host answered `200` to what
  it should refuse is the failure this exists to prevent.

## 8. Tests

The scenarios are the tests; what tests *them*:

| Check | Proves |
|---|---|
| Each ● scenario fails when its guard is removed (a one-off check at review, noted in the pull request) | The scenario can fail: Caddy's host rule, the cookie attributes, the family revocation |
| `up.sh` run twice in a row | The stack starts from a used state, as a laptop's will |
| `make e2e` on a clean clone | One command reproduces CI |
| The baseline run on the current `main` | `baseline.json` is true before the nightly relies on it |

## 9. Slices

1. **The stack (clavia).** `test/e2e/` compose, env, `up.sh`/`down.sh`, `make e2e-*`, and a workflow that
   builds the image, brings the stack up, seeds it, and checks over HTTPS that discovery answers, the host
   separation holds and `/healthz` is closed. It also checks that `CLAVIA_ENV=development` changes nothing
   in handling (the code reads of §2, confirmed by running one flow in each mode). *Done when* the workflow
   is green on a pull request, a clean clone runs `make e2e-up` and gets the same, and the job's time is
   reported in the pull request.
2. **Behat and the first scenarios (clavia).** Behat, the contexts, the ● scenarios of "Through Caddy" and
   "Sign-in as a browser does it", wired into the workflow with JUnit and the logs on failure. *Done when*
   each ● scenario is seen to fail with its guard removed and the suite passes in CI.
3. **Mail scenarios (clavia).** Mailpit in the stack, the `Mail` context, the sign-up and reset scenarios.
   *Done when* the mails of the ● scenario are read from Mailpit in CI.
4. **`:edge` images.** Each repository publishes `:edge` from `main` (clavia in `image.yml`, the dashboard
   in a new step of its image workflow). *Done when* both tags exist on ghcr and a push to `main` moves them.
5. **The dashboard's workflow (clavia-dashboard#17, first part).** `.github/workflows/e2e.yml`: clavia's stack
   at `main` with the dashboard built from the pull request, serves it, runs the existing smoke suite and the
   sign-out then sign-in case, uploads traces and logs on failure. *Done when* a pull request to the dashboard
   runs `npm run e2e` against the real stack and fails when a section breaks (shown once). Needs slices 1 and 4.
6. **Dashboard scenarios (clavia-dashboard#17, second part).** The ● and the remaining scenarios of "The
   dashboard behind Clavia", in order: back-channel logout, step-up, narrow role, CSV export, then provisioning
   and webhooks (which need the receiver). *Done when* the list is in `e2e/` and green in CI. Several pull requests.
7. **Remaining clavia scenarios.** Device, introspection, revocation, throttling, headers and the rest of §5.
8. **Nightly conformance.** `conformance/run.sh`, `baseline.json`, `conformance.yml` with the issue on a
   regression. *Done when* a scheduled run reproduces `conformance/README.md`'s results against the baseline,
   and a deliberately broken baseline entry turns the run red.

Slices 1 and 4 can go in parallel; 2 and 3 follow 1; 5 follows 1 and 4; 6 follows 5; 7 follows 2; 8 follows 1.

## 10. Open questions

1. **Publish `:edge` images from `main`?** The alternative is each repository's workflow building the other's
   `main` (about double the minutes per job, no new published tag). *Recommendation: publish*, from `main`
   only: it is what the images are for, and CI stays fast.
2. **Which repository does a cross-repository break block?** If the dashboard's `main` and clavia's `main` are
   briefly incompatible (a contract change merged on one side first), both suites go red for an unrelated
   pull request. *Recommendation:* merge the server side first, as the contract copy already requires, and
   keep the checks non-required for the first two weeks (§2), so the first incompatibility is learned from
   rather than a blocker.
3. **Development mode or a production seed?** *Recommendation: development mode for now* (§2), since it
   changes nothing in request handling; a production-mode seed command is a later slice if a scenario ever
   needs something development mode hides.
4. **Conformance failure notice.** An issue opened or updated per regression needs `issues: write` on the
   scheduled workflow only. *Recommendation:* yes, one issue labelled `conformance`, so a red night is
   in the backlog, not only in the Actions tab.
5. **Required checks.** *Recommendation:* make `e2e` required in both repositories after two weeks without
   a flake, as a separate ruleset change by the maintainer.
