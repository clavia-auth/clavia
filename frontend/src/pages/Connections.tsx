import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import {
  useConnections,
  useCreateConnection,
  useDeleteConnection,
  useUpdateConnection,
} from "../api/connections";
import type { Connection } from "../api/types";
import { Dialog, ErrorNote, Field, PageHeader } from "../components/ui";

export function ConnectionsPage() {
  const connections = useConnections();
  const update = useUpdateConnection();
  const remove = useDeleteConnection();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Connection | null>(null);

  return (
    <>
      <PageHeader
        title="Connections"
        description="The ways users can sign in. Each application enables the ones it may use; a domain-level connection is open to every application, third-party ones included."
        actions={
          <button className="btn-primary" onClick={() => setCreating(true)} type="button">
            New connection
          </button>
        }
      />
      <div className="card overflow-hidden">
        <ErrorNote error={connections.error ?? update.error ?? remove.error} />
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase tracking-wide text-muted">
            <tr>
              <th className="px-4 py-2 font-medium">Connection</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 font-medium">Enabled</th>
              <th className="px-4 py-2 font-medium">Domain-level</th>
              <th className="px-4 py-2 font-medium" />
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {connections.data?.map((connection) => (
              <ConnectionRow
                key={connection.name}
                connection={connection}
                busy={update.isPending || remove.isPending}
                onChange={(patch) => void update.mutateAsync({ name: connection.name, ...patch })}
                onEdit={() => setEditing(connection)}
                onDelete={() => {
                  if (confirm(`Delete the connection ${connection.display_name}? Refused while users or identities depend on it.`)) {
                    void remove.mutateAsync(connection.name);
                  }
                }}
              />
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-4 text-xs text-muted">
        A <strong>database</strong> connection is a pool of users with passwords; several may exist, and the same email
        may live in two as two accounts. An <strong>OIDC</strong> connection is any OpenID Connect provider, discovered from
        its issuer URL when it is registered. The <strong>social</strong> and <strong>passwordless</strong> (email code or
        link) connections are built in; social ones take their credentials from the server's configuration, the
        passwordless one needs an email backend there.
      </p>
      <ConnectionDialog open={creating} onClose={() => setCreating(false)} />
      <ConnectionDialog open={editing !== null} existing={editing ?? undefined} onClose={() => setEditing(null)} />
    </>
  );
}

function ConnectionRow({
  connection,
  busy,
  onChange,
  onEdit,
  onDelete,
}: {
  connection: Connection;
  busy: boolean;
  onChange: (patch: { is_enabled?: boolean; is_domain_connection?: boolean }) => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  return (
    <tr className="hover:bg-field/60">
      <td className="px-4 py-3">
        <div className="font-medium">{connection.display_name}</div>
        <div className="font-mono text-xs text-muted">
          {connection.name} · {connection.strategy}
          {connection.oidc_issuer && ` · ${connection.oidc_issuer}`}
        </div>
      </td>
      <td className="px-4 py-3">
        {connection.usable ? (
          <span className="badge-ok">Usable</span>
        ) : !connection.is_enabled ? (
          <span className="badge-muted">Off</span>
        ) : (
          <span className="badge-gold" title="The provider's settings or credentials are missing.">
            Not configured
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        <input
          type="checkbox"
          className="accent-accent"
          checked={connection.is_enabled}
          disabled={busy}
          onChange={(event) => onChange({ is_enabled: event.target.checked })}
          aria-label={`Enable ${connection.display_name}`}
        />
      </td>
      <td className="px-4 py-3">
        <input
          type="checkbox"
          className="accent-accent"
          checked={connection.is_domain_connection}
          disabled={busy}
          onChange={(event) => onChange({ is_domain_connection: event.target.checked })}
          aria-label={`Open ${connection.display_name} to every application`}
        />
      </td>
      <td className="px-4 py-3 text-right whitespace-nowrap">
        <button type="button" className="btn-secondary" onClick={onEdit}>
          Edit
        </button>
        {connection.strategy !== "social" && connection.strategy !== "passwordless" && (
          <button type="button" className="btn-danger ml-2" disabled={busy} onClick={onDelete}>
            Delete
          </button>
        )}
      </td>
    </tr>
  );
}

const schema = z.object({
  name: z
    .string()
    .regex(/^[a-z0-9][a-z0-9-]{1,62}$/, "Lower-case letters, digits and hyphens; 2–63 characters."),
  display_name: z.string().min(1, "Give it a name people will see.").max(120),
  strategy: z.enum(["database", "oidc"]),
  oidc_issuer: z.string(),
  oidc_client_id: z.string(),
  oidc_client_secret: z.string(),
  oidc_scopes: z.string(),
});
type Form = z.infer<typeof schema>;

function toForm(existing?: Connection): Form {
  return {
    name: existing?.name ?? "",
    display_name: existing?.display_name ?? "",
    strategy: existing?.strategy === "oidc" ? "oidc" : "database",
    oidc_issuer: existing?.oidc_issuer ?? "",
    oidc_client_id: existing?.oidc_client_id ?? "",
    oidc_client_secret: "",
    oidc_scopes: existing?.oidc_scopes ?? "openid profile email",
  };
}

/** Create a pool or an OIDC provider — or edit an existing connection's settings. */
function ConnectionDialog({ open, existing, onClose }: { open: boolean; existing?: Connection; onClose: () => void }) {
  const create = useCreateConnection();
  const update = useUpdateConnection();
  const form = useForm<Form>({ resolver: zodResolver(schema), defaultValues: toForm(existing) });
  useEffect(() => form.reset(toForm(existing)), [existing, form]);
  const strategy = form.watch("strategy");
  const isOidc = existing ? existing.strategy === "oidc" : strategy === "oidc";

  const submit = form.handleSubmit(async (values) => {
    if (existing) {
      const body: Record<string, string> = { display_name: values.display_name };
      if (existing.strategy === "oidc") {
        body.oidc_issuer = values.oidc_issuer;
        body.oidc_client_id = values.oidc_client_id;
        body.oidc_scopes = values.oidc_scopes;
        if (values.oidc_client_secret) body.oidc_client_secret = values.oidc_client_secret;
      }
      await update.mutateAsync({ name: existing.name, ...body });
    } else {
      await create.mutateAsync({
        name: values.name,
        display_name: values.display_name,
        strategy: values.strategy,
        ...(values.strategy === "oidc"
          ? {
              oidc_issuer: values.oidc_issuer,
              oidc_client_id: values.oidc_client_id,
              oidc_client_secret: values.oidc_client_secret,
              oidc_scopes: values.oidc_scopes,
            }
          : {}),
      });
    }
    form.reset(toForm());
    onClose();
  });

  return (
    <Dialog open={open} onClose={onClose} title={existing ? `Edit ${existing.display_name}` : "New connection"}>
      <form onSubmit={submit} className="space-y-4">
        {!existing && (
          <Field label="Kind">
            <select className="input" {...form.register("strategy")}>
              <option value="database">Database — a pool of users with passwords</option>
              <option value="oidc">OpenID Connect provider</option>
            </select>
          </Field>
        )}
        <Field
          label="Name"
          hint={existing ? "Permanent." : "Permanent; part of the callback URL for an OIDC provider. Lower-case letters, digits, hyphens."}
          error={form.formState.errors.name?.message}
        >
          <input className="input font-mono text-xs" disabled={Boolean(existing)} {...form.register("name")} />
        </Field>
        <Field label="Display name" hint="What users see on the login page." error={form.formState.errors.display_name?.message}>
          <input className="input" {...form.register("display_name")} />
        </Field>
        {isOidc && (
          <>
            <Field label="Issuer URL" hint="Exactly as the provider's discovery document names it, e.g. https://login.example.com. Discovery runs when you save.">
              <input className="input font-mono text-xs" placeholder="https://" {...form.register("oidc_issuer")} />
            </Field>
            <Field label="Client ID">
              <input className="input font-mono text-xs" {...form.register("oidc_client_id")} />
            </Field>
            <Field label="Client secret" hint={existing ? "Leave empty to keep the current secret. Never shown again." : "Stored encrypted; never shown again."}>
              <input className="input font-mono text-xs" type="password" autoComplete="new-password" {...form.register("oidc_client_secret")} />
            </Field>
            <Field label="Scopes" hint="Space-separated. openid is required; email and profile bring the claims Clavia links accounts with.">
              <input className="input font-mono text-xs" {...form.register("oidc_scopes")} />
            </Field>
            {!existing && (
              <p className="text-xs text-muted">
                Register this callback URL at the provider:{" "}
                <code className="font-mono">{`${import.meta.env.VITE_CLAVIA_ISSUER}/auth/social/${form.watch("name") || "<name>"}/callback`}</code>
              </p>
            )}
          </>
        )}
        <ErrorNote error={create.error ?? update.error} />
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={create.isPending || update.isPending}>
            {existing ? "Save" : "Create"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
