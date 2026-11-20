/**
 * The signed-in state of this tab.
 *
 * Kept in `sessionStorage`: scoped to the tab, gone when it closes, not shared with
 * other origins — and, unlike a cookie, never attached to a request by the browser
 * on its own, which is the property the Management API's bearer-only rule depends
 * on. The trade-off is that a script running on this origin could read it; that is
 * exactly why the dashboard lives on `management.*`, apart from the login pages.
 */

export interface IdTokenClaims {
  sub: string;
  email?: string;
  name?: string;
  amr?: string[];
  exp: number;
}

export interface StoredSession {
  accessToken: string;
  idToken: string;
  /**
   * The current refresh token, if the client was issued one. Single-use: every
   * refresh replaces it (see `refresh.ts`), and presenting an old one revokes the
   * whole session on the server — which is why refreshes are funnelled through one
   * in-flight request rather than fired from wherever a 401 happens to land.
   */
  refreshToken?: string;
  /** POSIX seconds at which the access token stops working. */
  expiresAt: number;
  scope: string;
  claims: IdTokenClaims;
}

const SESSION_KEY = "clavia.session";
const PENDING_KEY = "clavia.pending";

export interface PendingLogin {
  state: string;
  verifier: string;
  /** Where the user was heading before being sent to sign in. */
  returnTo: string;
}

/**
 * The stored session, or null when there is nothing usable.
 *
 * An expired access token is still a session when a refresh token sits beside it —
 * the API client renews it before the next call. Without one, expiry is the end.
 */
export function readSession(): StoredSession | null {
  const raw = sessionStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    const session = JSON.parse(raw) as StoredSession;
    if (isExpired(session) && !session.refreshToken) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }
    return session;
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    return null;
  }
}

/** Whether the access token has expired, or is about to (a request takes time). */
export function isExpired(session: StoredSession, leewaySeconds = 30): boolean {
  return session.expiresAt <= Date.now() / 1000 + leewaySeconds;
}

export function writeSession(session: StoredSession): void {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  sessionStorage.removeItem(SESSION_KEY);
}

export function writePending(pending: PendingLogin): void {
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
}

export function takePending(): PendingLogin | null {
  const raw = sessionStorage.getItem(PENDING_KEY);
  sessionStorage.removeItem(PENDING_KEY);
  return raw ? (JSON.parse(raw) as PendingLogin) : null;
}

/**
 * The claims of an ID token, read without verifying the signature.
 *
 * Deliberate: the token arrived over TLS from the token endpoint this dashboard
 * chose to call, in direct response to a code it just redeemed with its own PKCE
 * verifier — the transport is the trust. It is used here only to show who is
 * signed in; every authorization decision is made by the API, against the access
 * token, on the server.
 */
export function decodeIdToken(idToken: string): IdTokenClaims {
  const payload = idToken.split(".")[1] ?? "";
  const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(json) as IdTokenClaims;
}
