# OpenID Foundation conformance

Clavia is run against the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
(release `v5.1.36`): the **Config OP** plan (`oidcc-config-certification-test-plan`) and the
**Basic OP** plan (`oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`).

## Results (2026-11-21, Step 20)

| Plan | Modules | Conditions | Outcome |
|---|---|---|---|
| Config OP | 1 | 25 passed | Passed |
| Basic OP | 36 | 1637 passed, 1 failed, 6 warnings | 20 passed, 4 for review, 6 warnings, 4 skipped, 1 failed |

**The one failure is deliberate.** `oidcc-ensure-request-without-nonce-succeeds-for-code-flow`
sends an authorization request with neither PKCE nor a `nonce`. OAuth 2.1 §7.5.1 allows a
confidential client to omit PKCE only when the OpenID Connect `nonce` binds the code instead;
without either, nothing ties the code to the client's own request, and Clavia refuses it
(`invalid_request`). Certification would need that test passed, which would mean accepting
codes bound to nothing.

**For review** (the suite asks a person to look at a screenshot): `oidcc-prompt-login` and
`oidcc-max-age-1` (the login page is shown a second time), `oidcc-ensure-registered-redirect-uri`
and `oidcc-ensure-request-object-with-redirect-uri` (an error page, not a redirect, for an
unregistered redirect URI).

**Skipped** by the suite because discovery does not advertise them: the `address` and `phone`
scopes (and `oidcc-scope-all`), and request objects.

**Warnings**, none of them a requirement:

| Module | What the suite says | Why |
|---|---|---|
| `oidcc-userinfo-post-body` | The access token in a form body (RFC 6750 §2.2) is not accepted | RFC 6750 says that method SHOULD NOT be used unless the header cannot be; only the `Authorization` header is. |
| `oidcc-scope-profile` | Not every `profile` claim is returned | Clavia keeps `name`, `given_name`, `family_name`, `nickname`, `picture`, `locale`, `updated_at` — not `middle_name`, `preferred_username`, `profile`, `website`, `gender`, `birthdate`, `zoneinfo`. |
| `oidcc-scope-email`, `oidcc-ensure-other-scope-order-succeeds` | `email` is in the ID token, not only from userinfo | The ID token and userinfo carry the same claims (`IdentityClaims::of()`); see "Open questions" below. |
| `oidcc-ensure-request-with-acr-values-succeeds` | No `acr` claim | `acr_values_supported` is not advertised; `amr` says how the person signed in. |
| `oidcc-claims-essential` | `name` not returned for an essential `claims` request | The `claims` parameter is not supported (`claims_parameter_supported: false`). |

### Open questions

- Returning scope claims in the ID token is allowed (OIDC Core §5.4 only requires them from
  userinfo), but an ID token travels further — `id_token_hint`, logs — than a userinfo
  response. Whether the code flow's ID token should carry only `sub` and the protocol claims is
  a decision for the project, not this suite.

## Running it

The suite needs Java 17, Maven, Docker and Python 3. Everything below runs on one machine.

1. **Clavia**, served over HTTPS at `https://auth.{domain}` and `https://management.{domain}`
   (the `Caddyfile` does this), seeded with `clavia seed-dev`. The suite's browser signs in as
   the seeded user, so give it a profile (`PATCH /api/v1/users/{id}` with `name` and the rest).
2. **The suite**, built and started:

   ```sh
   git clone --depth 1 --branch release-v5.1.36 https://gitlab.com/openid/conformance-suite.git
   cd conformance-suite && mvn -B -DskipTests clean package
   docker network create oidf
   docker run -d --name oidf-mongo --network oidf --network-alias mongodb mongo:6.0.13
   docker run -d --name oidf-server --network oidf -p 8080:8080 \
     --add-host auth.{domain}:host-gateway --add-host suite.{domain}:host-gateway \
     -v "$PWD/target:/server" eclipse-temurin:17 java -jar /server/fapi-test-suite.jar \
     --fintechlabs.base_url=https://suite.{domain}:8443 --fintechlabs.devmode=true \
     --spring.data.mongodb.uri=mongodb://mongodb:27017/test_suite
   ```

   and put HTTPS in front of it at `https://suite.{domain}:8443` — a Caddy site with
   `reverse_proxy 127.0.0.1:8080` and the same certificate as Clavia's.
3. **The clients and the plan configuration**, from the machine client `seed-dev` printed:

   ```sh
   python3 conformance/provision.py --domain {domain} --suite https://suite.{domain}:8443 \
     --m2m-id … --m2m-secret … --email dev@{domain} --password devpassword > plan.json
   ```

   It registers three confidential clients relieved of PKCE (`require_pkce: false`) — the
   suite sends a `nonce` and never PKCE — and fills `oidcc-plan.json.dist`, which also tells the
   suite's browser how to sign in and which pages to photograph.
4. **The plans**:

   ```sh
   cd conformance-suite/scripts
   CONFORMANCE_SERVER=https://suite.{domain}:8443/ CONFORMANCE_SERVER_MTLS=https://suite.{domain}:8444/ \
   CONFORMANCE_DEV_MODE=1 python3 run-test-plan.py --no-parallel \
     "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" plan.json \
     oidcc-config-certification-test-plan plan.json
   ```
