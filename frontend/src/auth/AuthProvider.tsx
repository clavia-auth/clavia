import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useLocation } from "react-router";

import { config, endpoints } from "./config";
import { beginLogin, suppressLogin } from "./login";
import {
  clearSession,
  decodeIdToken,
  readSession,
  takePending,
  writeSession,
  type IdTokenClaims,
  type StoredSession,
} from "./session";

interface AuthContextValue {
  session: StoredSession | null;
  /** Send the browser to the authorization server. Never resolves — it navigates. */
  login: (returnTo?: string) => Promise<void>;
  /** Redeem the code on /callback. Returns where to go next. */
  completeLogin: (params: URLSearchParams) => Promise<string>;
  /** Forget the token here and end the session at the authorization server. */
  logout: () => void;
  /** Drop the local token without a round trip — used when the API says 401. */
  expire: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<StoredSession | null>(() => readSession());

  const login = useCallback((returnTo = "/") => beginLogin(returnTo), []);

  const completeLogin = useCallback(async (params: URLSearchParams): Promise<string> => {
    const pending = takePending();
    const error = params.get("error");
    if (error) {
      throw new Error(params.get("error_description") ?? `The authorization server said: ${error}`);
    }
    const code = params.get("code");
    const state = params.get("state");
    if (!pending || !code || !state || state !== pending.state) {
      throw new Error("This sign-in did not start in this tab. Please try again.");
    }

    const response = await fetch(endpoints.token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientId,
        redirect_uri: config.redirectUri,
        code,
        code_verifier: pending.verifier,
      }),
    });
    const body = (await response.json()) as {
      access_token?: string;
      refresh_token?: string;
      id_token?: string;
      expires_in?: number;
      scope?: string;
      error?: string;
      error_description?: string;
    };
    if (!response.ok || !body.access_token || !body.id_token) {
      throw new Error(body.error_description ?? body.error ?? "The token exchange failed.");
    }

    const next: StoredSession = {
      accessToken: body.access_token,
      idToken: body.id_token,
      // Present when this client is registered for the refresh_token grant; the
      // API client renews the access token with it instead of sending the
      // operator back here every hour.
      refreshToken: body.refresh_token,
      expiresAt: Math.floor(Date.now() / 1000) + (body.expires_in ?? 3600),
      scope: body.scope ?? "",
      claims: await withUserinfo(decodeIdToken(body.id_token), body.access_token),
    };
    writeSession(next);
    setSession(next);
    return pending.returnTo;
  }, []);

  const expire = useCallback(() => {
    clearSession();
    setSession(null);
  }, []);

  const logout = useCallback(() => {
    const idToken = session?.idToken;
    const refreshToken = session?.refreshToken;
    // Leave without starting a new sign-in: this page is about to be abandoned,
    // and a guarded route reacting to the dropped session would otherwise send the
    // browser back to the authorization server instead of to the logout.
    suppressLogin();
    expire();
    // The refresh token is handed back (RFC 7009), taking its whole chain with it, so
    // a copy left anywhere stops working now rather than when it runs out. A beacon,
    // because the page is being left: it is sent even as the navigation starts, and
    // a form-encoded body needs no preflight. Its answer does not matter.
    if (refreshToken) {
      const body = new URLSearchParams({
        token: refreshToken,
        token_type_hint: "refresh_token",
        client_id: config.clientId,
      });
      if (!navigator.sendBeacon(endpoints.revocation, body)) {
        void fetch(endpoints.revocation, { method: "POST", body, keepalive: true }).catch(() => undefined);
      }
    }
    //
    // RP-Initiated Logout: a top-level navigation, because that is the only request
    // the auth origin's SameSite=Lax session cookie travels with. The ID token
    // proves this browser is entitled to end that session.
    const params = new URLSearchParams({ post_logout_redirect_uri: config.postLogoutRedirectUri });
    if (idToken) params.set("id_token_hint", idToken);
    window.location.assign(`${endpoints.endSession}?${params}`);
  }, [expire, session]);

  const value = useMemo(
    () => ({ session, login, completeLogin, logout, expire }),
    [session, login, completeLogin, logout, expire],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}

/**
 * Wraps routes that need a signed-in user. Without one, the browser goes straight
 * to the authorization server — there is no dashboard login page to stop at — and
 * comes back to the page it was heading for.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const location = useLocation();
  const returnTo = location.pathname + location.search;

  useEffect(() => {
    if (!session) void beginLogin(returnTo);
  }, [session, returnTo]);

  if (!session) {
    return (
      <div className="grid min-h-screen place-items-center p-6">
        <p className="text-sm text-muted">Redirecting to sign in…</p>
      </div>
    );
  }
  return <>{children}</>;
}

/**
 * The ID token names the person by `sub` alone; their name and address are userinfo's
 * (OIDC Core §5.4). Asked once, at sign-in, and only for display: a userinfo that does
 * not answer, or answers for someone else (§5.3.2), leaves the claims as they were.
 */
async function withUserinfo(claims: IdTokenClaims, accessToken: string): Promise<IdTokenClaims> {
  try {
    const response = await fetch(endpoints.userinfo, { headers: { Authorization: `Bearer ${accessToken}` } });
    if (!response.ok) return claims;
    const userinfo = (await response.json()) as { sub?: string; email?: string; name?: string };
    if (userinfo.sub !== claims.sub) return claims;
    return { ...claims, email: userinfo.email, name: userinfo.name };
  } catch {
    return claims;
  }
}
