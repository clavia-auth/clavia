#!/usr/bin/env python3
# This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
#
# @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
# @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
"""Register the OpenID Foundation conformance suite's clients and write its plan config.

The suite's OIDC plans need three confidential clients — two signing in with
`client_secret_basic`, one with `client_secret_post` — each relieved of PKCE
(`require_pkce: false`), because the suite sends a `nonce` and never PKCE. They are
created through the Management API with a machine client holding `create:clients`;
`clavia seed-dev` prints one.

Standard library only, so it runs next to the suite's own `run-test-plan.py`:

    python3 conformance/provision.py \
        --domain clavia.test \
        --suite https://suite.clavia.test:8443 \
        --m2m-id <id> --m2m-secret <secret> \
        --email dev@clavia.test --password devpassword \
        --ca certs/ca.pem > plan.json
"""

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ALIAS = "clavia"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--domain", required=True, help="CLAVIA_ROOT_DOMAIN of the server under test")
    parser.add_argument("--suite", required=True, help="The suite's base URL, e.g. https://suite.clavia.test:8443")
    parser.add_argument("--m2m-id", required=True, help="A machine client holding create:clients")
    parser.add_argument("--m2m-secret", required=True)
    parser.add_argument("--email", required=True, help="The account the suite's browser signs in as")
    parser.add_argument("--password", required=True)
    parser.add_argument("--ca", help="A CA bundle to trust, for a server with a local certificate")
    parser.add_argument("--profile", action="store_true",
                        help="Give the account a profile first: the suite asks for the profile scope's claims")
    args = parser.parse_args()

    context = ssl.create_default_context(cafile=args.ca)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
    auth = f"https://auth.{args.domain}"
    management = f"https://management.{args.domain}/api/v1/"
    suite = args.suite.rstrip("/")

    token = call(opener, f"{auth}/oauth2/token", {
        "Authorization": "Basic " + base64.b64encode(f"{args.m2m_id}:{args.m2m_secret}".encode()).decode(),
    }, urllib.parse.urlencode({"grant_type": "client_credentials", "audience": management}).encode(),
        "application/x-www-form-urlencoded")["access_token"]

    if args.profile:
        give_profile(opener, management, token, args.email)

    def client(name: str, method: str) -> dict:
        created = call(opener, management + "clients", {"Authorization": f"Bearer {token}"}, json.dumps({
            "name": name,
            "client_type": "confidential",
            "token_endpoint_auth_method": method,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "redirect_uris": [f"{suite}/test/a/{ALIAS}/callback"],
            "post_logout_redirect_uris": [f"{suite}/test/a/{ALIAS}/post_logout_redirect"],
            "require_pkce": False,
        }).encode(), "application/json")
        return {"client_id": created["client_id"], "client_secret": created["client_secret"]}

    template = (Path(__file__).parent / "oidcc-plan.json.dist").read_text()
    clients = {
        "client": client("OIDF conformance", "client_secret_basic"),
        "client2": client("OIDF conformance (second)", "client_secret_basic"),
        "client_secret_post": client("OIDF conformance (client_secret_post)", "client_secret_post"),
    }
    plan = json.loads(template.replace("{DOMAIN}", args.domain).replace("{EMAIL}", args.email)
                      .replace("{PASSWORD}", args.password))
    plan.update(clients)
    json.dump(plan, sys.stdout, indent=2)
    print()
    return 0


def give_profile(opener, management: str, token: str, email: str) -> None:
    """The account the suite signs in as, with the profile claims Clavia keeps (README, step 1)."""
    headers = {"Authorization": f"Bearer {token}"}
    found = call(opener, management + "users?" + urllib.parse.urlencode({"q": email}), headers, None, None, "GET")
    user = next((item for item in found["items"] if item["email"] == email), None)
    if user is None:
        sys.exit(f"No account {email}: run `clavia seed-dev` first.")
    call(opener, management + "users/" + urllib.parse.quote(user["id"]), headers, json.dumps({
        "name": "Ada Lovelace",
        "given_name": "Ada",
        "family_name": "Lovelace",
        "nickname": "ada",
        "locale": "en-GB",
    }).encode(), "application/json", "PATCH")


def call(opener, url: str, headers: dict, body: bytes | None, content_type: str | None,
         method: str = "POST") -> dict:
    extra = {} if content_type is None else {"Content-Type": content_type}
    request = urllib.request.Request(url, data=body, method=method, headers=headers | extra)
    try:
        with opener.open(request) as response:
            return json.load(response)
    except urllib.error.HTTPError as refused:
        sys.exit(f"{url} answered {refused.code}: {refused.read().decode(errors='replace')}")


if __name__ == "__main__":
    sys.exit(main())
