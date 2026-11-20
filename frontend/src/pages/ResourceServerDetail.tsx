import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { useNavigate, useParams } from "react-router";
import { z } from "zod";

import { useDeleteResourceServer, useResourceServer, useUpdateResourceServer } from "../api/resourceServers";
import type { ResourceServer } from "../api/types";
import { BackLink, ErrorNote, Field, KeyValue, PageHeader, formatDate } from "../components/ui";
import { parsePermissions } from "./ResourceServers";

const schema = z.object({ name: z.string().max(120), permissions: z.string() });
type Form = z.infer<typeof schema>;

function toForm(api: ResourceServer): Form {
  return {
    name: api.name,
    permissions: api.permissions.map((p) => (p.description ? `${p.value}  ${p.description}` : p.value)).join("\n"),
  };
}

export function ResourceServerDetailPage() {
  const { resourceServerId = "" } = useParams();
  const api = useResourceServer(resourceServerId);
  if (api.isPending) return <p className="text-sm text-muted">Loading…</p>;
  if (api.error) return <ErrorNote error={api.error} />;
  return <ResourceServerDetail api={api.data} />;
}

function ResourceServerDetail({ api }: { api: ResourceServer }) {
  const navigate = useNavigate();
  const update = useUpdateResourceServer(api.id);
  const remove = useDeleteResourceServer();
  const form = useForm<Form>({ resolver: zodResolver(schema), defaultValues: toForm(api) });
  useEffect(() => form.reset(toForm(api)), [api, form]);

  const submit = form.handleSubmit(async (values) => {
    const body: { name?: string; permissions?: { value: string; description: string }[] } = {};
    if (form.formState.dirtyFields.name) body.name = values.name;
    if (form.formState.dirtyFields.permissions) body.permissions = parsePermissions(values.permissions);
    await update.mutateAsync(body);
  });

  return (
    <>
      <BackLink to="/apis">APIs</BackLink>
      <PageHeader
        title={api.name || api.identifier}
        description={`Registered ${formatDate(api.created_at)}`}
        actions={
          !api.is_system && (
            <button
              type="button"
              className="btn-danger"
              disabled={remove.isPending}
              onClick={async () => {
                if (confirm(`Delete ${api.name || api.identifier}? Every client grant on it goes with it, and tokens naming it stop being accepted.`)) {
                  await remove.mutateAsync(api.id);
                  navigate("/apis");
                }
              }}
            >
              Delete
            </button>
          )
        }
      />

      <div className="grid gap-6 md:grid-cols-[1fr_18rem]">
        <form onSubmit={submit} className="card space-y-4 p-6">
          <Field label="Name">
            <input className="input" {...form.register("name")} />
          </Field>
          <Field
            label="Permissions"
            hint={
              api.is_system
                ? "Defined by the server's own routes; edit them by upgrading Clavia."
                : "One per line: the value, then an optional description. Removing one takes effect on the next token."
            }
          >
            <textarea className="input font-mono text-xs" rows={Math.max(6, api.permissions.length + 1)} readOnly={api.is_system} {...form.register("permissions")} />
          </Field>
          <ErrorNote error={update.error} />
          <div className="flex items-center justify-end gap-3 pt-2">
            {update.isSuccess && !form.formState.isDirty && <span className="text-xs text-muted">Saved.</span>}
            <button type="submit" className="btn-primary" disabled={!form.formState.isDirty || update.isPending}>
              Save changes
            </button>
          </div>
        </form>

        <aside className="space-y-6">
          <section className="card p-6">
            <h2 className="mb-3 text-sm font-semibold">Audience</h2>
            <KeyValue
              items={[
                ["Identifier", <code className="font-mono text-xs">{api.identifier}</code>],
                ["ID", <code className="font-mono text-xs">{api.id}</code>],
                ["System", api.is_system ? <span className="badge-gold">Yes</span> : "No"],
              ]}
            />
            <p className="mt-4 text-xs text-muted">
              The identifier is the <code className="font-mono">aud</code> of every token issued for this API and cannot be changed.
              {api.is_system && " A system API cannot be deleted: the server itself depends on it."}
            </p>
            <ErrorNote error={remove.error} />
          </section>

          <section className="card p-6">
            <h2 className="mb-1 text-sm font-semibold">Role-based access control</h2>
            <label className="mt-3 flex items-start gap-3 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 accent-accent"
                checked={api.enforce_policies}
                disabled={api.is_system || update.isPending}
                onChange={(event) => void update.mutateAsync({ enforce_policies: event.target.checked })}
              />
              <span>
                <span className="font-medium">Enforce roles</span>
                <span className="block text-xs text-muted">
                  {api.is_system
                    ? "Always on for a system API: what an operator may do has to depend on who they are."
                    : "When on, a user's token for this API carries only the permissions their roles grant, and a user holding none is refused. Machine clients are governed by their grants either way."}
                </span>
              </span>
            </label>
          </section>

          <section className="card p-6">
            <h2 className="mb-1 text-sm font-semibold">Consent</h2>
            <label className="mt-3 flex items-start gap-3 text-sm">
              <input
                type="checkbox"
                className="mt-0.5 accent-accent"
                checked={api.allow_skipping_consent}
                disabled={update.isPending}
                onChange={(event) => void update.mutateAsync({ allow_skipping_consent: event.target.checked })}
              />
              <span>
                <span className="font-medium">Allow first-party applications to skip consent</span>
                <span className="block text-xs text-muted">
                  When on, your own applications are not shown the consent screen for this API's permissions — signing in is the consent.
                  Third-party applications always ask, whatever this says.
                </span>
              </span>
            </label>
          </section>
        </aside>
      </div>
    </>
  );
}
