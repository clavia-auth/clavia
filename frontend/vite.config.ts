import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The dashboard is served by Caddy at https://management.{domain}/dashboard/, which
// proxies that prefix to this dev server on :5174 and /api/v1 to the backend. Vite
// refuses Host headers it does not know, so the management host (written to
// .env.local by `clavia seed-dev`) and the name Caddy uses for the upstream are
// allowed explicitly. HMR has to reach the browser back through Caddy's TLS, hence
// wss on 443.
//
// `base` is the one place the prefix is written on the frontend side: the router,
// the OAuth2 redirect URI and every asset URL derive it from import.meta.env.BASE_URL.
// The server side registers the matching redirect URI in `clavia seed-dev`
// (DASHBOARD_PATH) and Caddy routes the same prefix — change all three together.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const managementHost = env.VITE_CLAVIA_MANAGEMENT_HOST;

  return {
    base: "/dashboard/",
    plugins: [react(), tailwindcss()],
    server: {
      host: "127.0.0.1",
      port: 5174,
      strictPort: true,
      allowedHosts: managementHost
        ? [managementHost, "host.docker.internal"]
        : ["host.docker.internal"],
      hmr: managementHost
        ? { protocol: "wss", host: managementHost, clientPort: 443 }
        : undefined,
    },
    preview: { host: "127.0.0.1", port: 5174, strictPort: true },
  };
});
