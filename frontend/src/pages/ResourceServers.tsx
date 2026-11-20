import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router";
import { z } from "zod";

import { useCreateResourceServer, useResourceServers } from "../api/resourceServers";
import {
  Dialog,
  EmptyState,
  ErrorNote,
  Field,
  PageHeader,
  Pagination,
  SearchBox,
  formatDate,
} from "../components/ui";

const schema = z.object({
  identifier: z.url("An absolute URI, e.g. https://invoices.example.com/api/").max(255),
  name: z.string().max(120),
  permissions: z.string(),
});
type Form = z.infer<typeof schema>;

/** "value  description" per line → permission objects; the value is the first token. */
export function parsePermissions(text: string) {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [value, ...rest] = line.split(/\s+/);
      return { value, description: rest.join(" ") };
    });
}

export function ResourceServersPage() {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const apis = useResourceServers({ q, page, per_page: 25 });

  return (
    <>
      <PageHeader
        title="APIs"
        description="Resource servers tokens can be issued for, and the permissions each defines."
        actions={
          <button className="btn-primary" onClick={() => setCreating(true)} type="button">
            New API
          </button>
        }
      />
      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 border-b border-line px-4 py-3">
          <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search by identifier or name" />
        </div>
        <ErrorNote error={apis.error} />
        {apis.data && apis.data.items.length === 0 ? (
          <EmptyState>{q ? "No APIs match." : "No APIs yet."}</EmptyState>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">API</th>
                <th className="px-4 py-2 font-medium">Permissions</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {apis.data?.items.map((api) => (
                <tr key={api.id} className="hover:bg-field/60">
                  <td className="px-4 py-3">
                    <Link to={`/apis/${api.id}`} className="font-medium hover:underline">
                      {api.name || <span className="text-muted">Unnamed</span>}
                    </Link>
                    {api.is_system && <span className="badge-gold ml-2">System</span>}
                    <div className="font-mono text-xs text-muted">{api.identifier}</div>
                  </td>
                  <td className="px-4 py-3 text-muted">{api.permissions.length}</td>
                  <td className="px-4 py-3 text-muted">{formatDate(api.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {apis.data && <Pagination page={apis.data.page} perPage={apis.data.per_page} total={apis.data.total} onPage={setPage} />}
      </div>
      <CreateApiDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

function CreateApiDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const create = useCreateResourceServer();
  const form = useForm<Form>({ resolver: zodResolver(schema), defaultValues: { identifier: "", name: "", permissions: "" } });

  const submit = form.handleSubmit(async (values) => {
    const api = await create.mutateAsync({
      identifier: values.identifier,
      name: values.name,
      permissions: parsePermissions(values.permissions),
    });
    form.reset();
    onClose();
    navigate(`/apis/${api.id}`);
  });

  return (
    <Dialog open={open} onClose={onClose} title="New API">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Identifier" hint="The audience clients name and tokens carry. A URI you own; it is never fetched." error={form.formState.errors.identifier?.message}>
          <input className="input font-mono text-xs" placeholder="https://invoices.example.com/api/" {...form.register("identifier")} />
        </Field>
        <Field label="Name">
          <input className="input" {...form.register("name")} />
        </Field>
        <Field label="Permissions" hint="One per line: the value, then an optional description.">
          <textarea className="input font-mono text-xs" rows={4} placeholder={"invoices:read  Read invoices\ninvoices:write Create and edit invoices"} {...form.register("permissions")} />
        </Field>
        <ErrorNote error={create.error} />
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={create.isPending}>
            Register
          </button>
        </div>
      </form>
    </Dialog>
  );
}
