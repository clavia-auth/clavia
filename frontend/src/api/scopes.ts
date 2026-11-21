/**
 * The Management API's permissions, mirrored from `ManagementPermission` on the server.
 *
 * Mirrored rather than fetched because the dashboard has to name them *before* it
 * holds a token — they are what it asks for at sign-in. A scope added on the server
 * is added here too; the server ignores nothing and refuses anything it does not
 * define, so a mismatch surfaces as `invalid_scope` at the first login, not silently.
 */
export const ACTIONS = ["read", "create", "update", "delete"] as const;

/** Each resource with the verbs that exist for it. */
export const RESOURCE_ACTIONS = {
  users: ACTIONS,
  clients: ACTIONS,
  resource_servers: ACTIONS,
  roles: ACTIONS,
  connections: ACTIONS,
} as const satisfies Record<string, readonly (typeof ACTIONS)[number][]>;

export const RESOURCES = Object.keys(RESOURCE_ACTIONS) as (keyof typeof RESOURCE_ACTIONS)[];

export const MANAGEMENT_SCOPES = Object.entries(RESOURCE_ACTIONS).flatMap(([resource, actions]) =>
  actions.map((action) => `${action}:${resource}`),
);

export type ManagementScope = (typeof MANAGEMENT_SCOPES)[number];
