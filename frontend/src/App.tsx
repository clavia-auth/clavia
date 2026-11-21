import { Navigate, Route, Routes } from "react-router";

import { RequireAuth } from "./auth/AuthProvider";
import { Layout } from "./components/Layout";
import { CallbackPage } from "./pages/Callback";
import { ClientDetailPage } from "./pages/ClientDetail";
import { ClientsPage } from "./pages/Clients";
import { ResourceServerDetailPage } from "./pages/ResourceServerDetail";
import { ResourceServersPage } from "./pages/ResourceServers";
import { RoleDetailPage } from "./pages/RoleDetail";
import { RolesPage } from "./pages/Roles";
import { SignedOutPage } from "./pages/SignedOut";
import { UserDetailPage } from "./pages/UserDetail";
import { UsersPage } from "./pages/Users";

export function App() {
  return (
    <Routes>
      {/* No login page: a page that needs a session sends the browser to the
          authorization server, where sign-in happens for every application. */}
      <Route path="/signed-out" element={<SignedOutPage />} />
      <Route path="/callback" element={<CallbackPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/users" replace />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/users/:userId" element={<UserDetailPage />} />
        <Route path="/clients" element={<ClientsPage />} />
        <Route path="/clients/:clientId" element={<ClientDetailPage />} />
        <Route path="/apis" element={<ResourceServersPage />} />
        <Route path="/apis/:resourceServerId" element={<ResourceServerDetailPage />} />
        <Route path="/roles" element={<RolesPage />} />
        <Route path="/roles/:roleId" element={<RoleDetailPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/users" replace />} />
    </Routes>
  );
}
