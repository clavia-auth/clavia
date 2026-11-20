import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, query } from "./client";
import type { Client, ClientCreated, ClientType, Page } from "./types";

export interface ClientListParams {
  page?: number;
  per_page?: number;
  q?: string;
}

export interface ClientCreate {
  name: string;
  client_type: ClientType;
  token_endpoint_auth_method: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  /** OIDC Back-Channel Logout URI (https); null or omitted means the application is not told. */
  backchannel_logout_uri?: string | null;
  backchannel_logout_session_required?: boolean;
  is_first_party?: boolean;
  /** Connection names; omitted means every connection (first-party only). */
  connections?: string[];
}

export type ClientUpdate = Partial<
  Omit<ClientCreate, "client_type" | "is_first_party" | "connections">
>;

const keys = {
  all: ["clients"] as const,
  list: (params: ClientListParams) => ["clients", "list", params] as const,
  one: (id: string) => ["clients", id] as const,
};

export function useClients(params: ClientListParams) {
  return useQuery({
    queryKey: keys.list(params),
    queryFn: () => api<Page<Client>>(`/clients${query(params)}`),
  });
}

export function useClient(id: string) {
  return useQuery({ queryKey: keys.one(id), queryFn: () => api<Client>(`/clients/${id}`) });
}

export function useCreateClient() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ClientCreate) =>
      api<ClientCreated>("/clients", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useUpdateClient(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: ClientUpdate) =>
      api<Client>(`/clients/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: (updated) => {
      client.setQueryData(keys.one(id), updated);
      void client.invalidateQueries({ queryKey: keys.all });
    },
  });
}

/** Replace the connections an application may sign users in through. */
export function useSetClientConnections(id: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (connections: string[]) =>
      api<string[]>(`/clients/${id}/connections`, {
        method: "PUT",
        body: JSON.stringify({ connections }),
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}

export function useRotateClientSecret(id: string) {
  return useMutation({
    mutationFn: () => api<ClientCreated>(`/clients/${id}/rotate-secret`, { method: "POST" }),
  });
}

export function useDeleteClient() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<void>(`/clients/${id}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.all }),
  });
}
