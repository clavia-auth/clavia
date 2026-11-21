import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, query } from "./client";
import type { Page, Permission, ResourceServer } from "./types";

export interface ResourceServerListParams {
  page?: number;
  per_page?: number;
  q?: string;
}

export interface ResourceServerCreate {
  identifier: string;
  name: string;
  permissions: Permission[];
  enforce_policies?: boolean;
  allow_skipping_consent?: boolean;
}

export type ResourceServerUpdate = Partial<Omit<ResourceServerCreate, "identifier">>;

const keys = {
  all: ["resource-servers"] as const,
  list: (params: ResourceServerListParams) => ["resource-servers", "list", params] as const,
  one: (id: string) => ["resource-servers", id] as const,
};

export function useResourceServers(params: ResourceServerListParams) {
  return useQuery({
    queryKey: keys.list(params),
    queryFn: () => api<Page<ResourceServer>>(`/resource-servers${query(params)}`),
  });
}

export function useResourceServer(id: string) {
  return useQuery({
    queryKey: keys.one(id),
    queryFn: () => api<ResourceServer>(`/resource-servers/${id}`),
  });
}

export function useCreateResourceServer() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ResourceServerCreate) =>
      api<ResourceServer>("/resource-servers", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useUpdateResourceServer(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ResourceServerUpdate) =>
      api<ResourceServer>(`/resource-servers/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: (updated) => {
      client.setQueryData(keys.one(id), updated);
      void client.invalidateQueries({ queryKey: keys.all });
    },
  });
}

export function useDeleteResourceServer() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/resource-servers/${id}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}
