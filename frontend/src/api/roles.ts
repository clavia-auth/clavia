import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, query } from "./client";
import type { Page, Role, RoleDetail, User } from "./types";

export interface RoleListParams {
  page?: number;
  per_page?: number;
  q?: string;
}

export interface PermissionRef {
  resource_server_id: string;
  value: string;
}

export interface RoleCreate {
  name: string;
  description: string;
  permissions: PermissionRef[];
}

export type RoleUpdate = Partial<RoleCreate>;

export const roleKeys = {
  all: ["roles"] as const,
  list: (params: RoleListParams) => ["roles", "list", params] as const,
  one: (id: string) => ["roles", id] as const,
  users: (id: string) => ["roles", id, "users"] as const,
};

export function useRoles(params: RoleListParams) {
  return useQuery({ queryKey: roleKeys.list(params), queryFn: () => api<Page<Role>>(`/roles${query(params)}`) });
}

/** Every role, for pickers. The list is small by nature — roles are coarse. */
export function useAllRoles() {
  return useQuery({
    queryKey: roleKeys.list({ per_page: 100 }),
    queryFn: () => api<Page<Role>>(`/roles${query({ per_page: 100 })}`),
    select: (page) => page.items,
  });
}

export function useRole(id: string) {
  return useQuery({ queryKey: roleKeys.one(id), queryFn: () => api<RoleDetail>(`/roles/${id}`) });
}

export function useRoleUsers(id: string, params: RoleListParams) {
  return useQuery({
    queryKey: [...roleKeys.users(id), params],
    queryFn: () => api<Page<User>>(`/roles/${id}/users${query(params)}`),
  });
}

export function useCreateRole() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: RoleCreate) => api<RoleDetail>("/roles", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => client.invalidateQueries({ queryKey: roleKeys.all }),
  });
}

export function useUpdateRole(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: RoleUpdate) => api<RoleDetail>(`/roles/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: (role) => {
      client.setQueryData(roleKeys.one(id), role);
      void client.invalidateQueries({ queryKey: roleKeys.all });
    },
  });
}

export function useDeleteRole() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/roles/${id}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: roleKeys.all }),
  });
}

export function useAssignRole(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (userIds: string[]) =>
      api<User[]>(`/roles/${id}/users`, { method: "POST", body: JSON.stringify({ user_ids: userIds }) }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: roleKeys.users(id) });
      void client.invalidateQueries({ queryKey: ["users"] });
    },
  });
}

export function useUnassignRole(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (userIds: string[]) =>
      api<User[]>(`/roles/${id}/users`, { method: "DELETE", body: JSON.stringify({ user_ids: userIds }) }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: roleKeys.users(id) });
      void client.invalidateQueries({ queryKey: ["users"] });
    },
  });
}
