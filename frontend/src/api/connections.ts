import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./client";
import type { Connection, ConnectionStrategy } from "./types";

export interface ConnectionCreate {
  name: string;
  display_name: string;
  strategy: ConnectionStrategy;
  is_enabled?: boolean;
  is_domain_connection?: boolean;
  oidc_issuer?: string;
  oidc_client_id?: string;
  oidc_client_secret?: string;
  oidc_scopes?: string;
}

export type ConnectionUpdate = Partial<{
  display_name: string;
  is_enabled: boolean;
  is_domain_connection: boolean;
  oidc_issuer: string;
  oidc_client_id: string;
  oidc_client_secret: string;
  oidc_scopes: string;
}>;

const keys = { all: ["connections"] as const };

export function useConnections() {
  return useQuery({ queryKey: keys.all, queryFn: () => api<Connection[]>("/connections") });
}

export function useCreateConnection() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ConnectionCreate) =>
      api<Connection>("/connections", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useUpdateConnection() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ name, ...body }: ConnectionUpdate & { name: string }) =>
      api<Connection>(`/connections/${name}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useDeleteConnection() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api<void>(`/connections/${name}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}
