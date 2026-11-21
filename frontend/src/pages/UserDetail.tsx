import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate, useParams } from "react-router";
import { z } from "zod";

import { useAllRoles } from "../api/roles";
import {
  useDeleteUser,
  useResetUserMfa,
  useSetUserRoles,
  useUpdateUser,
  useUser,
  useUserConsents,
  useUserPermissions,
  useUserRoles,
  useWithdrawUserConsent,
} from "../api/users";
import type { User } from "../api/types";
import { BackLink, ErrorNote, Field, KeyValue, PageHeader, formatDate } from "../components/ui";

const schema = z.object({
  email: z.email("Enter a valid email address."),
  name: z.string().max(255),
  given_name: z.string().max(255),
  family_name: z.string().max(255),
  email_verified: z.boolean(),
  is_active: z.boolean(),
  password: z.union([z.literal(""), z.string().min(8, "At least 8 characters.")]),
});
type Form = z.infer<typeof schema>;

function toForm(user: User): Form {
  return {
    email: user.email,
    name: user.name ?? "",
    given_name: user.given_name ?? "",
    family_name: user.family_name ?? "",
    email_verified: user.email_verified,
    is_active: user.is_active,
    password: "",
  };
}

export function UserDetailPage() {
  const { userId = "" } = useParams();
  const user = useUser(userId);
  if (user.isPending) return <p className="text-sm text-muted">Loading…</p>;
  if (user.error) return <ErrorNote error={user.error} />;
  return <UserDetail user={user.data} />;
}

function UserDetail({ user }: { user: User }) {
  const navigate = useNavigate();
  const update = useUpdateUser(user.id);
  const remove = useDeleteUser();
  const resetMfa = useResetUserMfa(user.id);
  const form = useForm<Form>({ resolver: zodResolver(schema), defaultValues: toForm(user) });
  useEffect(() => form.reset(toForm(user)), [user, form]);

  const submit = form.handleSubmit(async (values) => {
    // Only what changed goes over the wire: a PATCH says "leave the rest alone".
    const dirty = form.formState.dirtyFields;
    const body: Record<string, unknown> = {};
    for (const key of Object.keys(dirty) as (keyof Form)[]) {
      const value = values[key];
      body[key] = typeof value === "string" && value === "" && key !== "email" ? null : value;
    }
    if (!body.password) delete body.password;
    await update.mutateAsync(body);
  });

  return (
    <>
      <BackLink to="/users">Users</BackLink>
      <PageHeader
        title={user.email}
        description={`Created ${formatDate(user.created_at)} · updated ${formatDate(user.updated_at)}`}
        actions={
          <>
            {user.mfa_enrolled && (
              <button
                type="button"
                className="btn-secondary"
                disabled={resetMfa.isPending}
                onClick={() => {
                  if (confirm("Remove this user's second factor and recovery codes? They will sign in with their password alone until they enroll again.")) {
                    void resetMfa.mutateAsync();
                  }
                }}
              >
                Reset MFA
              </button>
            )}
            <button
              type="button"
              className="btn-danger"
              disabled={remove.isPending}
              onClick={async () => {
                if (confirm(`Delete ${user.email}? Every token issued to them is revoked with the account.`)) {
                  await remove.mutateAsync(user.id);
                  navigate("/users");
                }
              }}
            >
              Delete
            </button>
          </>
        }
      />

      <div className="grid gap-6 md:grid-cols-[1fr_18rem]">
        <form onSubmit={submit} className="card space-y-4 p-6">
          <Field label="Email" error={form.formState.errors.email?.message}>
            <input className="input" type="email" {...form.register("email")} />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Given name">
              <input className="input" {...form.register("given_name")} />
            </Field>
            <Field label="Family name">
              <input className="input" {...form.register("family_name")} />
            </Field>
          </div>
          <Field label="Display name">
            <input className="input" {...form.register("name")} />
          </Field>
          <Field label="New password" hint="Leave empty to keep the current one." error={form.formState.errors.password?.message}>
            <input className="input" type="password" autoComplete="new-password" {...form.register("password")} />
          </Field>
          <div className="flex flex-wrap gap-6 pt-1 text-sm">
            <label className="flex items-center gap-2">
              <input type="checkbox" className="accent-accent" {...form.register("is_active")} /> Active
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" className="accent-accent" {...form.register("email_verified")} /> Email verified
            </label>
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
          <h2 className="mb-3 text-sm font-semibold">Sign-in</h2>
          <KeyValue
            items={[
              ["Password", user.has_password ? "Set" : "None (Google or GitHub only)"],
              ["Second factor", user.mfa_enrolled ? <span className="badge-gold">Enrolled</span> : "Off"],
              ["Subject", <code className="font-mono text-xs">{user.id}</code>],
            ]}
          />
          <ErrorNote error={resetMfa.error ?? remove.error} />
        </aside>
      </div>

      <RolesPanel user={user} />
      <ConsentsPanel user={user} />
    </>
  );
}

/** Applications the user allowed to act as them, and the way to take that back. */
function ConsentsPanel({ user }: { user: User }) {
  const consents = useUserConsents(user.id);
  const withdraw = useWithdrawUserConsent(user.id);

  return (
    <section className="card mt-6 p-6">
      <h2 className="mb-1 text-sm font-semibold">Authorized applications</h2>
      <p className="mb-3 text-xs text-muted">
        What this user agreed to on the consent screen. First-party applications that skipped it are not listed.
        Withdrawing makes the application ask again; tokens it already holds run to their expiry.
      </p>
      <ErrorNote error={consents.error ?? withdraw.error} />
      {consents.data?.length === 0 && <p className="text-sm text-muted">None.</p>}
      <ul className="divide-y divide-line">
        {consents.data?.map((consent) => (
          <li key={`${consent.client_id}:${consent.audience ?? ""}`} className="flex items-start justify-between gap-4 py-3 text-sm">
            <div>
              <Link to={`/clients/${consent.client_id}`} className="font-medium hover:underline">
                {consent.client_name || consent.client_id}
              </Link>
              <span className={`ml-2 ${consent.is_first_party ? "badge-muted" : "badge-gold"}`}>
                {consent.is_first_party ? "First-party" : "Third-party"}
              </span>
              <div className="mt-1 font-mono text-xs text-muted">{consent.scopes.join(" ")}</div>
              <div className="text-xs text-muted">
                {consent.audience ?? "Sign-in only"} · granted {formatDate(consent.granted_at)}
              </div>
            </div>
            <button
              type="button"
              className="btn-secondary"
              disabled={withdraw.isPending}
              onClick={() => {
                if (confirm(`Withdraw what ${user.email} allowed ${consent.client_name || consent.client_id}, on every API?`)) {
                  void withdraw.mutateAsync(consent.client_id);
                }
              }}
            >
              Withdraw
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Which roles the user holds, and what they add up to. */
function RolesPanel({ user }: { user: User }) {
  const all = useAllRoles();
  const held = useUserRoles(user.id);
  const permissions = useUserPermissions(user.id);
  const setRoles = useSetUserRoles(user.id);
  const heldIds = new Set(held.data?.map((r) => r.id));

  return (
    <div className="mt-6 grid gap-6 md:grid-cols-[1fr_20rem]">
      <section className="card p-6">
        <h2 className="mb-1 text-sm font-semibold">Roles</h2>
        <p className="mb-3 text-xs text-muted">
          Changes take effect on the user's next token. Needs <code className="font-mono">update:roles</code>.
        </p>
        <ErrorNote error={all.error ?? held.error ?? setRoles.error} />
        {all.data?.length === 0 && (
          <p className="text-sm text-muted">
            No roles exist yet. <Link to="/roles" className="text-accent hover:underline">Create one.</Link>
          </p>
        )}
        <div className="grid gap-1 sm:grid-cols-2">
          {all.data?.map((role) => (
            <label key={role.id} className="flex items-start gap-2 rounded-md px-2 py-1 text-sm hover:bg-field">
              <input
                type="checkbox"
                className="mt-0.5 accent-accent"
                checked={heldIds.has(role.id)}
                disabled={setRoles.isPending}
                onChange={(event) => {
                  const next = new Set(heldIds);
                  if (event.target.checked) next.add(role.id);
                  else next.delete(role.id);
                  void setRoles.mutateAsync([...next]);
                }}
              />
              <span>
                <Link to={`/roles/${role.id}`} className="font-medium hover:underline">
                  {role.name}
                </Link>
                {role.description && <span className="block text-xs text-muted">{role.description}</span>}
              </span>
            </label>
          ))}
        </div>
      </section>

      <aside className="card p-6">
        <h2 className="mb-1 text-sm font-semibold">Effective permissions</h2>
        <p className="mb-3 text-xs text-muted">Everything the roles above add up to, and which role grants each.</p>
        <ErrorNote error={permissions.error} />
        {permissions.data?.length === 0 && <p className="text-sm text-muted">None.</p>}
        <ul className="space-y-2 text-sm">
          {permissions.data?.map((permission) => (
            <li key={`${permission.resource_server_id}:${permission.value}`}>
              <code className="font-mono text-xs">{permission.value}</code>
              <div className="text-xs text-muted">
                {permission.resource_server_identifier} · via {permission.roles.map((r) => r.name).join(", ")}
              </div>
            </li>
          ))}
        </ul>
      </aside>
    </div>
  );
}
