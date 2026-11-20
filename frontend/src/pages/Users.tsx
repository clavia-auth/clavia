import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router";
import { z } from "zod";

import { useConnections } from "../api/connections";
import { useCreateUser, useUsers } from "../api/users";
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

const createSchema = z.object({
  email: z.email("Enter a valid email address."),
  password: z.string().min(8, "At least 8 characters."),
  name: z.string().max(200).optional(),
  connection: z.string().min(1, "Pick the pool the account belongs to."),
});
type CreateForm = z.infer<typeof createSchema>;

export function UsersPage() {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const users = useUsers({ q, page, per_page: 25 });

  return (
    <>
      <PageHeader
        title="Users"
        description="The people who sign in through this server."
        actions={
          <button className="btn-primary" onClick={() => setCreating(true)} type="button">
            New user
          </button>
        }
      />
      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 border-b border-line px-4 py-3">
          <SearchBox
            value={q}
            onChange={(value) => {
              setQ(value);
              setPage(1);
            }}
            placeholder="Search by email"
          />
        </div>
        <ErrorNote error={users.error} />
        {users.data && users.data.items.length === 0 ? (
          <EmptyState>{q ? "No users match." : "No users yet."}</EmptyState>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Email</th>
                <th className="px-4 py-2 font-medium">Connection</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Sign-in</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {users.data?.items.map((user) => (
                <tr key={user.id} className="hover:bg-field/60">
                  <td className="px-4 py-3">
                    <Link to={`/users/${user.id}`} className="font-medium hover:underline">
                      {user.email}
                    </Link>
                    {user.name && <div className="text-xs text-muted">{user.name}</div>}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted">{user.connection}</td>
                  <td className="px-4 py-3">
                    {user.is_active ? <span className="badge-ok">Active</span> : <span className="badge-muted">Disabled</span>}
                  </td>
                  <td className="px-4 py-3 space-x-1">
                    {user.has_password && <span className="badge-muted">Password</span>}
                    {user.linked_providers.map((p) => (
                      <span key={p} className="badge-muted capitalize">
                        {p}
                      </span>
                    ))}
                    {user.mfa_enrolled && <span className="badge-gold">MFA</span>}
                  </td>
                  <td className="px-4 py-3 text-muted">{formatDate(user.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {users.data && (
          <Pagination page={users.data.page} perPage={users.data.per_page} total={users.data.total} onPage={setPage} />
        )}
      </div>
      <CreateUserDialog open={creating} onClose={() => setCreating(false)} />
    </>
  );
}

function CreateUserDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const create = useCreateUser();
  const connections = useConnections();
  const pools = connections.data?.filter((c) => c.strategy === "database") ?? [];
  const form = useForm<CreateForm>({
    resolver: zodResolver(createSchema),
    defaultValues: { connection: "password" },
  });

  const submit = form.handleSubmit(async (values) => {
    const user = await create.mutateAsync({ ...values, name: values.name || null });
    form.reset();
    onClose();
    navigate(`/users/${user.id}`);
  });

  return (
    <Dialog open={open} onClose={onClose} title="New user">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Email" error={form.formState.errors.email?.message}>
          <input className="input" type="email" autoComplete="off" {...form.register("email")} />
        </Field>
        <Field
          label="Connection"
          hint="The pool the account belongs to. Cannot be changed later; the same email may exist in another pool as a different account."
          error={form.formState.errors.connection?.message}
        >
          <select className="input" {...form.register("connection")}>
            {pools.map((pool) => (
              <option key={pool.name} value={pool.name}>
                {pool.display_name} ({pool.name})
              </option>
            ))}
          </select>
        </Field>
        <Field label="Password" hint="At least 8 characters. The user can change it later." error={form.formState.errors.password?.message}>
          <input className="input" type="password" autoComplete="new-password" {...form.register("password")} />
        </Field>
        <Field label="Name (optional)" error={form.formState.errors.name?.message}>
          <input className="input" type="text" {...form.register("name")} />
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
