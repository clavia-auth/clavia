/**
 * Where this dashboard signs in, and as whom.
 *
 * Read from Vite's environment at build time. `clavia seed-dev` writes
 * `frontend/.env.local` with these for a development checkout; a deployment sets
 * them however it builds the bundle. Nothing here is a secret — the dashboard is a
 * public client and its id is visible to anyone who loads the page.
 */

function required(name: keyof ImportMetaEnv & string): string {
  const value = import.meta.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(
      `${name} is not set. Run \`clavia seed-dev\` to write frontend/.env.local, ` +
        `or set it in the build environment.`,
    );
  }
  return value;
}

/**
 * The path prefix this dashboard lives under — `/dashboard` — without a trailing
 * slash. Vite's `base` is the source of truth; everything that builds a URL on this
 * origin goes through here so the prefix is written exactly once on the frontend.
 */
export const basePath = import.meta.env.BASE_URL.replace(/\/$/, "");

/** An absolute path on this origin, under the dashboard's prefix. */
export function pathTo(route: string): string {
  return `${basePath}/${route.replace(/^\//, "")}`;
}

/** A URL on this origin, under the dashboard's prefix. */
export function urlTo(route: string): string {
  return `${window.location.origin}${pathTo(route)}`;
}

export const config = {
  /** The OAuth2/OIDC origin, e.g. https://auth.acme.com. */
  issuer: required("VITE_CLAVIA_ISSUER").replace(/\/$/, ""),
  /** This dashboard's client_id, registered by seed-dev. */
  clientId: required("VITE_CLAVIA_CLIENT_ID"),
  /** The Management API's identifier — the `aud` every token here must carry. */
  audience: required("VITE_CLAVIA_AUDIENCE"),
  /**
   * Where the authorization server sends the browser back. Same origin as this page,
   * and registered verbatim by `clavia seed-dev` — an exact match, so the prefix here
   * and there have to agree.
   */
  redirectUri: urlTo("callback"),
  /** Where sign-out lands: a page that says so, rather than straight back into a sign-in. */
  postLogoutRedirectUri: urlTo("signed-out"),
} as const;

export const endpoints = {
  authorize: `${config.issuer}/oauth2/authorize`,
  token: `${config.issuer}/oauth2/token`,
  revocation: `${config.issuer}/oauth2/revoke`,
  endSession: `${config.issuer}/oidc/logout`,
  userinfo: `${config.issuer}/oidc/userinfo`,
} as const;
