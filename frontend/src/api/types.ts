/**
 * Shapes of the Management API's responses — the schemas of
 * `docs/openapi/management-api.yaml`, which the server checks every response against.
 * A field appears here once the server sends it, never before.
 */

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

/** An error the Management API answers with (RFC 9457 problem details). */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail: string;
  /** What was wrong with the request, one entry per field or parameter. */
  errors?: { pointer?: string; parameter?: string; detail: string }[];
}

export interface User {
  id: string;
  /** The pool the account belongs to, or the external connection that created it. */
  connection: string;
  email: string;
  email_verified: boolean;
  is_active: boolean;
  has_password: boolean;
  /** A confirmed authenticator app: signing in asks for a second factor. */
  mfa_enrolled: boolean;
  name: string | null;
  given_name: string | null;
  family_name: string | null;
  nickname: string | null;
  picture: string | null;
  locale: string | null;
  created_at: string;
  updated_at: string;
}

export type ClientType = "public" | "confidential";

export type AuthMethod = "none" | "client_secret_basic" | "client_secret_post";

/** `refresh_token` only beside `authorization_code`: a refresh token is issued when a code is redeemed. */
export type GrantType = "authorization_code" | "client_credentials" | "refresh_token";

export type ResponseType = "code";

export interface Client {
  client_id: string;
  name: string;
  client_type: ClientType;
  token_endpoint_auth_method: AuthMethod;
  redirect_uris: string[];
  grant_types: GrantType[];
  response_types: ResponseType[];
  /** Where a sign-out the application starts at `/oidc/logout` may send the browser back. */
  post_logout_redirect_uris: string[];
  /**
   * Who runs it: the operator (first-party) or somebody else (third-party, id `tpc_…`).
   * Fixed at registration.
   */
  is_first_party: boolean;
  /**
   * The connections its users may sign in through, by name. Always empty for a
   * third-party application: it gets the domain connections.
   */
  connections: string[];
  created_at: string;
}

/** The create and rotate-secret responses — the only time `client_secret` appears. */
export interface ClientCreated extends Client {
  client_secret: string | null;
}

export interface Permission {
  value: string;
  description: string;
}

export interface ResourceServer {
  id: string;
  identifier: string;
  name: string;
  permissions: Permission[];
  is_system: boolean;
  /** RBAC: narrow a user's token to what their roles grant on this API. */
  enforce_policies: boolean;
  /** First-party applications skip the consent screen for this API's permissions. */
  allow_skipping_consent: boolean;
  created_at: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  created_at: string;
}

export interface RolePermission extends Permission {
  resource_server_id: string;
  resource_server_identifier: string;
}

export interface RoleDetail extends Role {
  permissions: RolePermission[];
}

/** What a user allowed one application to do on one API, acting as them. */
export interface UserConsent {
  client_id: string;
  client_name: string;
  is_first_party: boolean;
  /** The API's identifier; null for a request that named none. */
  audience: string | null;
  scopes: string[];
  granted_at: string;
  updated_at: string;
}

/** An effective permission of a user, and every role that grants it. */
export interface UserPermission extends RolePermission {
  roles: { id: string; name: string }[];
}

/**
 * `database` is a pool of accounts with passwords; `social` a provider the code
 * implements (Google, GitHub); `oidc` any OpenID Connect provider an operator registered.
 */
export type ConnectionStrategy = "database" | "social" | "oidc";

/** A way to sign in. */
export interface Connection {
  name: string;
  display_name: string;
  strategy: ConnectionStrategy;
  /** The global switch: off means off for every application. */
  is_enabled: boolean;
  /** Open to every third-party application, which gets no other kind. */
  is_domain_connection: boolean;
  /** Whether it could work were it switched on: credentials or provider settings are there. */
  configured: boolean;
  /** Switched on and configured: offered wherever an application enables it. */
  usable: boolean;
  /** OIDC connections only; the client secret is never sent back. */
  oidc_issuer: string | null;
  oidc_client_id: string | null;
  oidc_scope: string | null;
  created_at: string;
}

/** An account at an external provider, linked to a user. */
export interface Identity {
  connection: string;
  subject: string;
  /** The address the provider reported when it was linked. */
  email: string | null;
  linked_at: string;
}
