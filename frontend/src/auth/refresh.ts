/**
 * Renewing the access token with the refresh token, without a round trip through
 * the login page.
 *
 * The server rotates: every refresh spends the token presented and issues a new
 * one, and a token presented twice is treated as stolen — the whole session is
 * revoked. So this module guarantees the dashboard never presents the same token
 * twice: all callers share one in-flight refresh, and the new token is written to
 * storage before anyone is told the refresh succeeded.
 */

import { config, endpoints } from "./config";
import { clearSession, readSession, writeSession, type StoredSession } from "./session";

let inFlight: Promise<StoredSession | null> | null = null;

/**
 * Refresh the session, or return null when it cannot be refreshed — no refresh
 * token, or the server refused (expired, revoked, the account deactivated). Null
 * means "sign in again"; the stored session has already been cleared.
 */
export function refreshSession(): Promise<StoredSession | null> {
  if (!inFlight) {
    inFlight = doRefresh().finally(() => {
      inFlight = null;
    });
  }
  return inFlight;
}

async function doRefresh(): Promise<StoredSession | null> {
  const current = readSession();
  if (!current?.refreshToken) return null;

  const response = await fetch(endpoints.token, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: config.clientId,
      refresh_token: current.refreshToken,
    }),
  });
  const body = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    scope?: string;
  };
  if (!response.ok || !body.access_token) {
    clearSession();
    return null;
  }

  const next: StoredSession = {
    ...current,
    accessToken: body.access_token,
    refreshToken: body.refresh_token ?? current.refreshToken,
    expiresAt: Math.floor(Date.now() / 1000) + (body.expires_in ?? 3600),
    scope: body.scope ?? current.scope,
  };
  writeSession(next);
  return next;
}
