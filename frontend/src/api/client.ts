/**
 * The one way the dashboard talks to `/api/v1`.
 *
 * Same origin, so no CORS; bearer token from the tab's session, never a cookie.
 * An access token about to expire is refreshed before the call; a 401 is answered
 * with one refresh and one retry, because a token can be revoked before it
 * expires. When the refresh itself fails the only fix is a new sign-in, so the
 * local session ends and the browser goes to the login page.
 */

import { basePath } from "../auth/config";
import { beginLogin } from "../auth/login";
import { refreshSession } from "../auth/refresh";
import { clearSession, isExpired, readSession, type StoredSession } from "../auth/session";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code?: string,
  ) {
    super(message);
  }
}

interface ErrorBody {
  error?: string;
  error_description?: string;
  detail?: string | { msg: string; loc?: (string | number)[] }[];
}

function describe(status: number, body: ErrorBody | null): string {
  if (!body) return `The API answered ${status}.`;
  if (typeof body.detail === "string") return body.detail;
  if (Array.isArray(body.detail)) {
    // FastAPI validation errors: name the field so the form can show it.
    return body.detail
      .map((entry) => `${entry.loc?.slice(1).join(".") ?? "body"}: ${entry.msg}`)
      .join("; ");
  }
  return body.error_description ?? body.error ?? `The API answered ${status}.`;
}

function signInAgain(message: string): never {
  clearSession();
  // Straight to the authorization server, and back to this very page afterwards.
  // The router's paths are relative to the dashboard prefix, so strip it.
  const here = window.location.pathname.slice(basePath.length) + window.location.search;
  void beginLogin(here || "/");
  throw new ApiError(401, message);
}

/** The session to call with — refreshed first if its access token is (nearly) spent. */
async function usableSession(): Promise<StoredSession> {
  const session = readSession();
  if (!session) signInAgain("Not signed in.");
  if (!isExpired(session)) return session;
  return (await refreshSession()) ?? signInAgain("Your session has ended. Please sign in again.");
}

async function send(path: string, init: RequestInit, session: StoredSession): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${session.accessToken}`);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  return fetch(`/api/v1${path}`, { ...init, headers });
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response = await send(path, init, await usableSession());

  if (response.status === 401) {
    // Revoked, or expired between the check and the call. One refresh, one retry.
    const renewed = await refreshSession();
    if (!renewed) signInAgain("Your session has ended. Please sign in again.");
    response = await send(path, init, renewed);
    if (response.status === 401) signInAgain("Your session has ended. Please sign in again.");
  }
  if (response.status === 204) return undefined as T;

  const body = response.headers.get("content-type")?.includes("json")
    ? ((await response.json()) as unknown)
    : null;
  if (!response.ok) {
    const error = body as ErrorBody | null;
    throw new ApiError(response.status, describe(response.status, error), error?.error);
  }
  return body as T;
}

export const query = (params: object): string => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params) as [string, unknown][]) {
    if (value !== undefined && value !== "") search.set(key, String(value));
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
};
