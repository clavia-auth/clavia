import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate, useParams } from "react-router";
import { z } from "zod";

import {
  useClient,
  useDeleteClient,
  useRotateClientSecret,
  useSetClientConnections,
  useUpdateClient,
} from "../api/clients";
import { useConnections } from "../api/connections";
import type { Client } from "../api/types";
import { BackLink, ErrorNote, Field, KeyValue, PageHeader, SecretReveal, formatDate } from "../components/ui";

const GRANTS = [
  "authorization_code",
  "refresh_token",
  "client_credentials",
  "urn:ietf:params:oauth:grant-type:device_code",
] as const;
const AUTH_METHODS = ["none", "client_secret_basic", "client_secret_post"] as const;

const schema = z.object({
  name: z.string().max(120),
  redirect_uris: z.string(),
  grant_types: z.array(z.enum(GRANTS)),
  token_endpoint_auth_method: z.enum(AUTH_METHODS),
  backchannel_logout_uri: z.union([
    z.literal(""),
    z.url().refine((value) => value.startsWith("https://"), "Must be an https URL."),
  ]),
  backchannel_logout_session_required: z.boolean(),
});
type Form = z.infer<typeof schema>;

function toForm(client: Client): Form {
  return {
    name: client.name,
    redirect_uris: client.redirect_uris.join("\n"),
    grant_types: client.grant_types.filter((g): g is (typeof GRANTS)[number] => (GRANTS as readonly string[]).includes(g)),
    token_endpoint_auth_method: client.token_endpoint_auth_method as (typeof AUTH_METHODS)[number],
    backchannel_logout_uri: client.backchannel_logout_uri ?? "",
    backchannel_logout_session_required: client.backchannel_logout_session_required,
  };
}

export function ClientDetailPage() {
  const { clientId = "" } = useParams();
  const client = useClient(clientId);
  if (client.isPending) return <p className="text-sm text-muted">Loading…</p>;
  if (client.error) return <ErrorNote error={client.error} />;
  return <ClientDetail client={client.data} />;
}

function ClientDetail({ client }: { client: Client }) {
  const navigate = useNavigate();
  const update = useUpdateClient(client.client_id);
  const rotate = useRotateClientSecret(client.client_id);
  const remove = useDeleteClient();
  const [secret, setSecret] = useState<string | null>(null);
  const form = useForm<Form>({ resolver: zodResolver(schema), defaultValues: toForm(client) });
  useEffect(() => form.reset(toForm(client)), [client, form]);

  const submit = form.handleSubmit(async (values) => {
    await update.mutateAsync({
      name: values.name,
      redirect_uris: values.redirect_uris.split(/\s+/).filter(Boolean),
      grant_types: values.grant_types,
      response_types: values.grant_types.includes("authorization_code") ? ["code"] : [],
      token_endpoint_auth_method: values.token_endpoint_auth_method,
      backchannel_logout_uri: values.backchannel_logout_uri || null,
      backchannel_logout_session_required: values.backchannel_logout_session_required,
    });
  });

  return (
    <>
      <BackLink to="/clients">Applications</BackLink>
      <PageHeader
        title={client.name || "Unnamed application"}
        description={`Registered ${formatDate(client.created_at)}`}
        actions={
          <>
            {client.client_type === "confidential" && (
              <button
                type="button"
                className="btn-secondary"
                disabled={rotate.isPending}
                onClick={async () => {
                  if (confirm("Issue a new secret? The current one stops working immediately; tokens already issued are unaffected.")) {
                    const result = await rotate.mutateAsync();
                    setSecret(result.client_secret);
                  }
                }}
              >
                Rotate secret
              </button>
            )}
            <button
              type="button"
              className="btn-danger"
              disabled={remove.isPending}
              onClick={async () => {
                if (confirm(`Delete ${client.name || client.client_id}? Every code, token and grant it holds goes with it.`)) {
                  await remove.mutateAsync(client.client_id);
                  navigate("/clients");
                }
              }}
            >
              Delete
            </button>
          </>
        }
      />

      {secret && (
        <div className="mb-6">
          <SecretReveal label="New client secret" value={secret} />
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-[1fr_18rem]">
        <form onSubmit={submit} className="card space-y-4 p-6">
          <Field label="Name">
            <input className="input" {...form.register("name")} />
          </Field>
          <Field label="Redirect URIs" hint="One per line, absolute, matched exactly. Required for the authorization code grant.">
            <textarea className="input font-mono text-xs" rows={3} {...form.register("redirect_uris")} />
          </Field>
          <Field
            label="Back-channel logout URI"
            hint="Optional, https. When a session this application signed in through ends, a signed logout token is POSTed here (OIDC Back-Channel Logout 1.0). Private and loopback addresses are refused."
            error={form.formState.errors.backchannel_logout_uri?.message}
          >
            <input className="input font-mono text-xs" placeholder="https://app.example.com/oidc/backchannel-logout" {...form.register("backchannel_logout_uri")} />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" className="accent-accent" {...form.register("backchannel_logout_session_required")} />
            <span>
              Logout tokens must carry a <code className="font-mono text-xs">sid</code>
              <span className="text-muted"> — informational; this server always sends one.</span>
            </span>
          </label>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Grant types">
              <div className="space-y-1 pt-1 text-sm">
                {GRANTS.map((grant) => (
                  <label key={grant} className="flex items-center gap-2">
                    <input type="checkbox" value={grant} className="accent-accent" {...form.register("grant_types")} />
                    <code className="font-mono text-xs">{grant}</code>
                  </label>
                ))}
              </div>
            </Field>
            <Field label="Token endpoint auth" hint={client.client_type === "public" ? "A public client can only use none." : undefined}>
              <select className="input" {...form.register("token_endpoint_auth_method")}>
                {AUTH_METHODS.map((method) => (
                  <option key={method} value={method}>
                    {method}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <ErrorNote error={update.error} />
          <div className="flex items-center justify-end gap-3 pt-2">
            {update.isSuccess && !form.formState.isDirty && <span className="text-xs text-muted">Saved.</span>}
            <button type="submit" className="btn-primary" disabled={!form.formState.isDirty || update.isPending}>
              Save changes
            </button>
          </div>
        </form>

        <aside className="card p-6">
          <h2 className="mb-3 text-sm font-semibold">Identity</h2>
          <KeyValue
            items={[
              ["Client ID", <code className="font-mono text-xs">{client.client_id}</code>],
              ["Type", <span className={client.client_type === "confidential" ? "badge-ok" : "badge-muted"}>{client.client_type}</span>],
              [
                "Ownership",
                client.is_first_party ? (
                  <span className="badge-muted">First-party</span>
                ) : (
                  <span className="badge-gold">Third-party</span>
                ),
              ],
              ["Response types", client.response_types.join(", ") || "—"],
            ]}
          />
          <p className="mt-4 text-xs text-muted">
            Type and ownership are identity, not configuration: to change either, register a new application.
            {!client.is_first_party &&
              " A third-party application puts every scope to the user on the consent screen and can never reach the Management API."}
          </p>
          <p className="mt-3 text-xs text-muted">
            An application holds no permissions of its own. On a user's behalf it may request whatever the
            API named in <code className="font-mono">audience</code> defines, narrowed to the user's roles.
            Access as itself is granted from the shell — <code className="font-mono">clavia clients grant</code>.
          </p>
          <ErrorNote error={rotate.error ?? remove.error} />
        </aside>
      </div>

      <ConnectionsPanel client={client} />
    </>
  );
}

/** Which ways of signing in this application may use. */
function ConnectionsPanel({ client }: { client: Client }) {
  const all = useConnections();
  const set = useSetClientConnections(client.client_id);
  const enabled = new Set(client.connections);

  return (
    <section className="card mt-6 p-6">
      <h2 className="mb-1 text-sm font-semibold">Connections</h2>
      <p className="mb-3 text-xs text-muted">
        {client.is_first_party
          ? "The login page for this application offers only these. A session signed in through any other does not count for it. Takes effect at the next sign-in."
          : "A third-party application uses the domain-level connections and cannot choose its own. Open a connection to every application from the Connections page."}
      </p>
      <ErrorNote error={all.error ?? set.error} />
      <div className="grid gap-1 sm:grid-cols-2">
        {all.data?.map((connection) => {
          const applies = client.is_first_party ? enabled.has(connection.name) : connection.is_domain_connection;
          return (
            <label key={connection.name} className="flex items-start gap-2 rounded-md px-2 py-1 text-sm hover:bg-field">
              <input
                type="checkbox"
                className="mt-0.5 accent-accent"
                checked={applies}
                disabled={!client.is_first_party || set.isPending}
                onChange={(event) => {
                  const next = new Set(enabled);
                  if (event.target.checked) next.add(connection.name);
                  else next.delete(connection.name);
                  void set.mutateAsync([...next]);
                }}
              />
              <span>
                <span className="font-medium">{connection.display_name}</span>
                <span className="block text-xs text-muted">
                  {connection.name}
                  {!connection.usable && " · not usable until enabled and configured"}
                  {connection.is_domain_connection && " · domain-level"}
                </span>
              </span>
            </label>
          );
        })}
      </div>
    </section>
  );
}
