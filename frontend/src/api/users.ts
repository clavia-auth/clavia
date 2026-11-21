import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, query } from "./client";
import type { Identity, Page, Role, User, UserConsent, UserPermission } from "./types";

export interface UserListParams {
  page?: number;
  per_page?: number;
  q?: string;
}

export interface UserCreate {
  /** The pool it is created in; the default pool, `password`, when omitted. */
  connection?: string;
  email: string;
  password: string;
  email_verified?: boolean;
  is_active?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  nickname?: string;
  picture?: string;
  locale?: string;
}

export type UserUpdate = Partial<{
  email: string;
  password: string;
  email_verified: boolean;
  is_active: boolean;
  name: string | null;
  given_name: string | null;
  family_name: string | null;
  nickname: string | null;
  picture: string | null;
  locale: string | null;
}>;

const keys = {
  all: ["users"] as const,
  list: (params: UserListParams) => ["users", "list", params] as const,
  one: (id: string) => ["users", id] as const,
};

export function useUsers(params: UserListParams) {
  return useQuery({
    queryKey: keys.list(params),
    queryFn: () => api<Page<User>>(`/users${query(params)}`),
  });
}

export function useUser(id: string) {
  return useQuery({ queryKey: keys.one(id), queryFn: () => api<User>(`/users/${id}`) });
}

export function useCreateUser() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: UserCreate) => api<User>("/users", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useUpdateUser(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: UserUpdate) =>
      api<User>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: (user) => {
      client.setQueryData(keys.one(id), user);
      void client.invalidateQueries({ queryKey: keys.all });
    },
  });
}

export function useDeleteUser() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/users/${id}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useUserRoles(id: string) {
  return useQuery({ queryKey: [...keys.one(id), "roles"], queryFn: () => api<Role[]>(`/users/${id}/roles`) });
}

export function useUserPermissions(id: string) {
  return useQuery({
    queryKey: [...keys.one(id), "permissions"],
    queryFn: () => api<UserPermission[]>(`/users/${id}/permissions`),
  });
}

export function useSetUserRoles(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (roleIds: string[]) =>
      api<Role[]>(`/users/${id}/roles`, { method: "PUT", body: JSON.stringify({ role_ids: roleIds }) }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: keys.one(id) });
      void client.invalidateQueries({ queryKey: ["roles"] });
    },
  });
}

export function useResetUserMfa(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api<void>(`/users/${id}/mfa`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useUserConsents(id: string) {
  return useQuery({
    queryKey: [...keys.one(id), "consents"],
    queryFn: () => api<UserConsent[]>(`/users/${id}/consents`),
  });
}

/** Withdraw everything the user allowed one application; it has to ask again. */
export function useWithdrawUserConsent(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (clientId: string) =>
      api<void>(`/users/${id}/consents/${encodeURIComponent(clientId)}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: [...keys.one(id), "consents"] }),
  });
}

export function useUserIdentities(id: string) {
  return useQuery({
    queryKey: [...keys.one(id), "identities"],
    queryFn: () => api<Identity[]>(`/users/${id}/identities`),
  });
}

/** Detach every identity the user holds through one connection. Refused when it is the only way in. */
export function useUnlinkUserIdentity(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (connection: string) =>
      api<void>(`/users/${id}/identities/${encodeURIComponent(connection)}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: [...keys.one(id), "identities"] }),
  });
}
