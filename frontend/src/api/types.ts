/** Shapes of the Management API's responses — see `clavia.api.schemas`. */

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}

export interface User {
  id: string;
  email: string;
  email_verified: boolean;
  is_active: boolean;
  has_password: boolean;
  mfa_enrolled: boolean;
  linked_providers: string[];
  /** The pool the account belongs to, or the external connection that created it. */
  connection: string;
  identities: Identity[];
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

export interface Client {
  client_id: string;
  name: string;
  client_type: ClientType;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  /** OIDC Back-Channel Logout: where a logout token is POSTed when a session ends. Null: never told. */
  backchannel_logout_uri: string | null;
  backchannel_logout_session_required: boolean;
  /** Who owns it: the operator (first-party) or somebody else. Fixed at creation. */
  is_first_party: boolean;
  /** Connection names this application may sign users in through (first-party only). */
  connections: string[];
  created_at: string;
}

export type ConnectionStrategy = "database" | "social" | "oidc" | "passwordless";

/** A way to sign in, and the switches on it. */
export interface Connection {
  name: string;
  display_name: string;
  strategy: ConnectionStrategy;
  is_enabled: boolean;
  /** Open to every application, third-party ones included. */
  is_domain_connection: boolean;
  /** The deployment has what it needs (a social provider's credentials, an OIDC provider's settings). */
  configured: boolean;
  /** Enabled and configured: what the login page actually offers. */
  usable: boolean;
  /** OIDC connections only; the secret is never returned. */
  oidc_issuer: string | null;
  oidc_client_id: string | null;
  oidc_scopes: string | null;
  created_at: string;
}

/** One external account linked to a user. */
export interface Identity {
  provider: string;
  subject: string;
  email: string | null;
  created_at: string;
}

/** What a user allowed one application to do on one API, acting as them. */
export interface UserConsent {
  client_id: string;
  client_name: string;
  is_first_party: boolean;
  audience: string | null;
  scopes: string[];
  granted_at: string;
  updated_at: string;
}

/** One browser session at auth.{domain}, named by its OIDC `sid`. */
export interface UserSession {
  sid: string;
  created_at: string;
  /** The absolute ceiling; idle expiry may end it sooner. */
  expires_at: string;
  amr: string[];
  connection: string;
  /** Applications that signed in through it — told by back-channel logout when it ends. */
  clients: { client_id: string; name: string }[];
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

/** An effective permission of a user, and every role that grants it. */
export interface UserPermission extends RolePermission {
  roles: { id: string; name: string }[];
}
