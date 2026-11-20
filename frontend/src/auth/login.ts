/**
 * Starting a sign-in: send the browser to the authorization server.
 *
 * The dashboard has no login page of its own. It is an OAuth2 client like any other,
 * and signing in happens where credentials are typed for every application — the
 * auth origin's login page, reached through `/oauth2/authorize`. This module is the
 * one place that request is built, so the API client (on a 401) and the router (on a
 * page that needs a session) start exactly the same flow.
 */

import { MANAGEMENT_SCOPES } from "../api/scopes";
import { config, endpoints } from "./config";
import { challengeFor, randomToken } from "./pkce";
import { writePending } from "./session";

let started = false;

/**
 * Stop any sign-in from starting on this page. Called by sign-out before it
 * navigates: dropping the session makes every guarded route want a new login, and a
 * second navigation started in the same tick would win over the logout's.
 */
export function suppressLogin(): void {
  started = true;
}

/**
 * Begin the authorization code flow and navigate away. Never resolves in the
 * normal case — the page is left. Idempotent within a page: React's StrictMode
 * runs effects twice and two flows in flight would leave the wrong `state` stored.
 */
export async function beginLogin(returnTo = "/"): Promise<void> {
  if (started) return;
  started = true;

  const state = randomToken();
  const verifier = randomToken(64);
  writePending({ state, verifier, returnTo });

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    // OIDC scopes for the identity shown in the header, plus every management
    // permission — the server narrows the token to what the signed-in user's
    // roles actually grant, at sign-in and again at every refresh.
    scope: ["openid", "email", "profile", ...MANAGEMENT_SCOPES].join(" "),
    audience: config.audience,
    state,
    nonce: randomToken(16),
    code_challenge: await challengeFor(verifier),
    code_challenge_method: "S256",
  });
  window.location.assign(`${endpoints.authorize}?${params}`);
}
