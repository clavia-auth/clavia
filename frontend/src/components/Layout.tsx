import { NavLink, Outlet } from "react-router";

import { useAuth } from "../auth/AuthProvider";
import { pathTo } from "../auth/config";
import { ThemeToggle } from "./ThemeToggle";

const NAV = [
  { to: "/users", label: "Users" },
  { to: "/clients", label: "Applications" },
  { to: "/apis", label: "APIs" },
  { to: "/roles", label: "Roles" },
  { to: "/connections", label: "Connections" },
] as const;

export function Layout() {
  const { session, logout } = useAuth();
  const who = session?.claims.name ?? session?.claims.email ?? session?.claims.sub;
  const mfa = session?.claims.amr?.includes("mfa");

  return (
    <div className="min-h-screen md:grid md:grid-cols-[15rem_1fr]">
      <aside className="flex flex-col border-b border-line bg-card/70 backdrop-blur md:border-r md:border-b-0">
        <div className="flex items-center gap-3 px-5 py-5">
          <img src={pathTo("clavia-icon.svg")} alt="" className="h-9 w-9 rounded-lg" />
          <div>
            <div className="font-semibold leading-tight">Clavia</div>
            <div className="text-xs text-muted">Management</div>
          </div>
        </div>
        <nav className="flex gap-1 px-3 pb-3 md:flex-col md:pb-0">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `rounded-lg px-3 py-2 text-sm font-medium ${
                  isActive ? "bg-accent text-on-accent" : "text-ink hover:bg-field"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto hidden border-t border-line px-5 py-4 text-xs md:block">
          <ThemeToggle className="mb-4" />
          <div className="truncate font-medium" title={who}>
            {who}
          </div>
          <div className="mt-1 flex items-center gap-2 text-muted">
            <span>Signed in{mfa ? " · MFA" : ""}</span>
            <button type="button" onClick={logout} className="ml-auto text-accent hover:underline">
              Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className="mx-auto w-full max-w-5xl px-5 py-8">
        <Outlet />
      </main>
    </div>
  );
}
