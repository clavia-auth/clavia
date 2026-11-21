import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { useConnections, useCreateConnection, useDeleteConnection, useUpdateConnection } from "../api/connections";
import type { Connection } from "../api/types";
import { config } from "../auth/config";
import { Dialog, ErrorNote, Field, PageHeader } from "../components/ui";

/** The default pool and the social providers are the code's: switched, never deleted. */
const isBuiltIn = (connection: Connection): boolean =>
  connection.strategy === "social" || connection.name === "password";

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
        description="The ways people sign in. A first-party application enables the ones it may use; a third-party one gets the domain connections."
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
              <th className="px-4 py-2 font-medium">On</th>
              <th className="px-4 py-2 font-medium">Third parties</th>
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
                  if (
                    confirm(
                      `Delete the connection ${connection.display_name}? Refused while accounts or identities depend on it.`,
                    )
                  ) {
                    void remove.mutateAsync(connection.name);
                  }
                }}
              />
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-4 text-xs text-muted">
        A <strong>database</strong> connection is a pool of accounts with passwords; there may be several, and the same
        address in two of them is two accounts. An <strong>OIDC</strong> connection is any OpenID Connect provider,
        discovered from its issuer when it is saved. The <strong>social</strong> connections are built in and take their
        credentials from the server's configuration. Switching one off takes effect at the next sign-in.
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
        ) : !connection.configured ? (
          <span className="badge-gold" title="The deployment has no credentials for it, or its secret cannot be read.">
            Not configured
          </span>
        ) : (
          <span className="badge-muted">Off</span>
        )}
      </td>
      <td className="px-4 py-3">
        <input
          type="checkbox"
          className="accent-accent"
          checked={connection.is_enabled}
          disabled={busy}
          onChange={(event) => onChange({ is_enabled: event.target.checked })}
          aria-label={`Switch ${connection.display_name} on`}
        />
      </td>
      <td className="px-4 py-3">
        <input
          type="checkbox"
          className="accent-accent"
          checked={connection.is_domain_connection}
          disabled={busy}
          onChange={(event) => onChange({ is_domain_connection: event.target.checked })}
          aria-label={`Open ${connection.display_name} to every third-party application`}
        />
      </td>
      <td className="px-4 py-3 text-right whitespace-nowrap">
        <button type="button" className="btn-secondary" onClick={onEdit}>
          Edit
        </button>
        {!isBuiltIn(connection) && (
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
    .regex(/^[a-z][a-z0-9-]{0,31}$/, "Lower-case letters, digits and dashes, starting with a letter; at most 32."),
  display_name: z.string().trim().min(1, "Give it a name people will see.").max(120),
  strategy: z.enum(["database", "oidc"]),
  oidc_issuer: z.string(),
  oidc_client_id: z.string(),
  oidc_client_secret: z.string(),
  oidc_scope: z.string(),
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
    oidc_scope: existing?.oidc_scope ?? "openid profile email",
  };
}

/** Create a pool or an OIDC provider — or change an existing connection's label and provider settings. */
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
        // Only what changed: any OIDC setting sent runs discovery again.
        if (values.oidc_issuer !== existing.oidc_issuer) body.oidc_issuer = values.oidc_issuer;
        if (values.oidc_client_id !== existing.oidc_client_id) body.oidc_client_id = values.oidc_client_id;
        if (values.oidc_scope !== existing.oidc_scope) body.oidc_scope = values.oidc_scope;
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
              oidc_scope: values.oidc_scope,
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
              <option value="database">Database — a pool of accounts with passwords</option>
              <option value="oidc">OpenID Connect provider</option>
            </select>
          </Field>
        )}
        <Field
          label="Name"
          hint={
            existing
              ? "Permanent."
              : "Permanent: accounts and sessions record it, and an OIDC provider's callback URL contains it."
          }
          error={form.formState.errors.name?.message}
        >
          <input className="input font-mono text-xs" disabled={Boolean(existing)} {...form.register("name")} />
        </Field>
        <Field
          label="Display name"
          hint="What people see on the login page."
          error={form.formState.errors.display_name?.message}
        >
          <input className="input" {...form.register("display_name")} />
        </Field>
        {isOidc && (
          <>
            <Field
              label="Issuer"
              hint="Exactly as the provider's discovery document names it, e.g. https://login.example.com. Discovery runs when you save."
            >
              <input className="input font-mono text-xs" placeholder="https://" {...form.register("oidc_issuer")} />
            </Field>
            <Field label="Client ID">
              <input className="input font-mono text-xs" {...form.register("oidc_client_id")} />
            </Field>
            <Field
              label="Client secret"
              hint={existing ? "Leave empty to keep the current one. Never shown again." : "Stored encrypted; never shown again."}
            >
              <input
                className="input font-mono text-xs"
                type="password"
                autoComplete="new-password"
                {...form.register("oidc_client_secret")}
              />
            </Field>
            <Field
              label="Scope"
              hint="Space-separated, including openid; email brings the verified address accounts are linked by."
            >
              <input className="input font-mono text-xs" {...form.register("oidc_scope")} />
            </Field>
            {!existing && (
              <p className="text-xs text-muted">
                Register this callback URL at the provider:{" "}
                <code className="font-mono">{`${config.issuer}/auth/social/${form.watch("name") || "<name>"}/callback`}</code>
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
