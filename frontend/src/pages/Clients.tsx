import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router";
import { z } from "zod";

import { useClients, useCreateClient } from "../api/clients";
import type { ClientCreated } from "../api/types";
import {
  Dialog,
  EmptyState,
  ErrorNote,
  Field,
  PageHeader,
  Pagination,
  SearchBox,
  SecretReveal,
  formatDate,
} from "../components/ui";

const schema = z.object({
  name: z.string().min(1, "Give the application a name.").max(120),
  kind: z.enum(["spa", "web", "m2m", "device"]),
  ownership: z.enum(["first", "third"]),
  redirect_uris: z.string(),
});
type Form = z.infer<typeof schema>;

/**
 * Three shapes cover what people actually register. Each maps to a coherent
 * registration the server will accept; the raw fields stay editable afterwards.
 */
const KINDS = {
  spa: {
    label: "Single-page or native app",
    hint: "Public client — no secret; PKCE is its proof. Authorization code flow with rotating refresh tokens.",
    client_type: "public",
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  },
  web: {
    label: "Server-side web app",
    hint: "Confidential client with a secret. Authorization code flow with rotating refresh tokens.",
    client_type: "confidential",
    token_endpoint_auth_method: "client_secret_basic",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  },
  m2m: {
    label: "Machine to machine",
    hint: "Confidential client, client credentials grant, no redirect. Grant it an API from the shell afterwards.",
    client_type: "confidential",
    token_endpoint_auth_method: "client_secret_basic",
    grant_types: ["client_credentials"],
    response_types: [],
  },
  device: {
    label: "Device or command-line tool",
    hint: "Public client with no browser of its own: it shows a code the user types at auth.{domain}/auth/device. Device authorization grant with rotating refresh tokens. First-party only.",
    client_type: "public",
    token_endpoint_auth_method: "none",
    grant_types: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    response_types: [],
  },
} as const;

export function ClientsPage() {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const clients = useClients({ q, page, per_page: 25 });

  return (
    <>
      <PageHeader
        title="Applications"
        description="OAuth2 clients registered with this server."
        actions={
          <button className="btn-primary" onClick={() => setCreating(true)} type="button">
            New application
          </button>
        }
      />
      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 border-b border-line px-4 py-3">
          <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search by name or client id" />
        </div>
        <ErrorNote error={clients.error} />
        {clients.data && clients.data.items.length === 0 ? (
          <EmptyState>{q ? "No applications match." : "No applications yet."}</EmptyState>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Type</th>
                <th className="px-4 py-2 font-medium">Grants</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {clients.data?.items.map((client) => (
                <tr key={client.client_id} className="hover:bg-field/60">
                  <td className="px-4 py-3">
                    <Link to={`/clients/${client.client_id}`} className="font-medium hover:underline">
                      {client.name || <span className="text-muted">Unnamed</span>}
                    </Link>
                    <div className="font-mono text-xs text-muted">{client.client_id}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={client.client_type === "confidential" ? "badge-ok" : "badge-muted"}>
                      {client.client_type}
                    </span>
                    {!client.is_first_party && <span className="badge-gold ml-2">Third-party</span>}
                  </td>
                  <td className="px-4 py-3 text-muted">{client.grant_types.join(", ") || "—"}</td>
                  <td className="px-4 py-3 text-muted">{formatDate(client.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {clients.data && (
          <Pagination page={clients.data.page} perPage={clients.data.per_page} total={clients.data.total} onPage={setPage} />
        )}
      </div>
      <CreateClientDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

function CreateClientDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const create = useCreateClient();
  const [created, setCreated] = useState<ClientCreated | null>(null);
  const form = useForm<Form>({
    resolver: zodResolver(schema),
    defaultValues: { kind: "spa", ownership: "first", redirect_uris: "", name: "" },
  });
  const kind = KINDS[form.watch("kind")];

  const submit = form.handleSubmit(async (values) => {
    const preset = KINDS[values.kind];
    const result = await create.mutateAsync({
      name: values.name,
      client_type: preset.client_type,
      token_endpoint_auth_method: preset.token_endpoint_auth_method,
      grant_types: [...preset.grant_types],
      response_types: [...preset.response_types],
      redirect_uris: values.redirect_uris.split(/\s+/).filter(Boolean),
      is_first_party: values.ownership === "first",
    });
    if (result.client_secret) {
      setCreated(result); // show the secret once, before leaving the dialog
    } else {
      close();
      navigate(`/clients/${result.client_id}`);
    }
  });

  function close() {
    form.reset();
    setCreated(null);
    onClose();
  }

  return (
    <Dialog open={open} onClose={close} title={created ? "Application created" : "New application"}>
      {created ? (
        <div className="space-y-4">
          <p className="text-sm">
            <span className="font-medium">{created.name}</span> is registered as{" "}
            <code className="font-mono text-xs">{created.client_id}</code>.
          </p>
          <SecretReveal label="Client secret" value={created.client_secret ?? ""} />
          <div className="flex justify-end pt-2">
            <button
              type="button"
              className="btn-primary"
              onClick={() => {
                const id = created.client_id;
                close();
                navigate(`/clients/${id}`);
              }}
            >
              Done
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <Field label="Name" error={form.formState.errors.name?.message}>
            <input className="input" {...form.register("name")} />
          </Field>
          <Field label="Kind" hint={kind.hint}>
            <select className="input" {...form.register("kind")}>
              {Object.entries(KINDS).map(([value, preset]) => (
                <option key={value} value={value}>
                  {preset.label}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="Ownership"
            hint={
              form.watch("ownership") === "first"
                ? "Yours: users are not asked for consent unless an API insists. Cannot be changed later."
                : "Somebody else's: every scope goes through the consent screen, the id is prefixed tpc_, and it can never reach the Management API. Cannot be changed later."
            }
          >
            <select className="input" {...form.register("ownership")}>
              <option value="first">First-party — run by this organisation</option>
              <option value="third">Third-party — run by a partner or external developer</option>
            </select>
          </Field>
          {form.watch("kind") !== "m2m" && form.watch("kind") !== "device" && (
            <Field label="Redirect URIs" hint="One per line. Matched exactly at the authorization endpoint." error={form.formState.errors.redirect_uris?.message}>
              <textarea className="input font-mono text-xs" rows={3} placeholder="https://app.example.com/callback" {...form.register("redirect_uris")} />
            </Field>
          )}
          <ErrorNote error={create.error} />
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" className="btn-secondary" onClick={close}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={create.isPending}>
              Register
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
