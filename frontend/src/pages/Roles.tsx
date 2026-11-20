import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router";
import { z } from "zod";

import { useCreateRole, useRoles } from "../api/roles";
import { Dialog, EmptyState, ErrorNote, Field, PageHeader, Pagination, SearchBox, formatDate } from "../components/ui";

const schema = z.object({
  name: z.string().min(1, "Give the role a name.").max(64),
  description: z.string().max(500),
});
type Form = z.infer<typeof schema>;

export function RolesPage() {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const roles = useRoles({ q, page, per_page: 25 });

  return (
    <>
      <PageHeader
        title="Roles"
        description="Named sets of permissions, assigned to users. On an API with RBAC on, a user's token carries only what their roles grant."
        actions={
          <button className="btn-primary" onClick={() => setCreating(true)} type="button">
            New role
          </button>
        }
      />
      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 border-b border-line px-4 py-3">
          <SearchBox value={q} onChange={(v) => { setQ(v); setPage(1); }} placeholder="Search by name or description" />
        </div>
        <ErrorNote error={roles.error} />
        {roles.data && roles.data.items.length === 0 ? (
          <EmptyState>{q ? "No roles match." : "No roles yet."}</EmptyState>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Role</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {roles.data?.items.map((role) => (
                <tr key={role.id} className="hover:bg-field/60">
                  <td className="px-4 py-3">
                    <Link to={`/roles/${role.id}`} className="font-medium hover:underline">
                      {role.name}
                    </Link>
                    {role.description && <div className="text-xs text-muted">{role.description}</div>}
                  </td>
                  <td className="px-4 py-3 text-muted">{formatDate(role.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {roles.data && <Pagination page={roles.data.page} perPage={roles.data.per_page} total={roles.data.total} onPage={setPage} />}
      </div>
      <CreateRoleDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

function CreateRoleDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const create = useCreateRole();
  const form = useForm<Form>({ resolver: zodResolver(schema), defaultValues: { name: "", description: "" } });

  const submit = form.handleSubmit(async (values) => {
    const role = await create.mutateAsync({ ...values, permissions: [] });
    form.reset();
    onClose();
    navigate(`/roles/${role.id}`);
  });

  return (
    <Dialog open={open} onClose={onClose} title="New role">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name" error={form.formState.errors.name?.message}>
          <input className="input" placeholder="Support" {...form.register("name")} />
        </Field>
        <Field label="Description" hint="Permissions are chosen on the next screen.">
          <input className="input" placeholder="Read-only access for the help desk" {...form.register("description")} />
        </Field>
        <ErrorNote error={create.error} />
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={create.isPending}>
            Create
          </button>
        </div>
      </form>
    </Dialog>
  );
}
