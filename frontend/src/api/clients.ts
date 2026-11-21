import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, query } from "./client";
import type { AuthMethod, Client, ClientCreated, ClientType, GrantType, Page, ResponseType } from "./types";

export interface ClientListParams {
  page?: number;
  per_page?: number;
  q?: string;
}

export interface ClientCreate {
  name: string;
  client_type: ClientType;
  token_endpoint_auth_method: AuthMethod;
  redirect_uris: string[];
  grant_types: GrantType[];
  response_types: ResponseType[];
  post_logout_redirect_uris?: string[];
}

/** The type is identity, not configuration: it is fixed at registration. */
export type ClientUpdate = Partial<Omit<ClientCreate, "client_type">>;

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
