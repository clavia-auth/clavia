import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router";

import "./index.css";
import { App } from "./App";
import { AuthProvider } from "./auth/AuthProvider";
import { basePath } from "./auth/config";
import { applyTheme } from "./theme";

// Before the first render, so a pinned theme never flashes the system one.
applyTheme();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Management data changes when an operator changes it; polling would only
      // burn tokens. Refetch on focus is enough to catch a colleague's edits.
      staleTime: 30_000,
      retry: (count, error) => !(error instanceof Response && error.status < 500) && count < 2,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {/* Every route in App is relative to the prefix Vite serves the bundle under. */}
    <BrowserRouter basename={basePath}>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </QueryClientProvider>
    </BrowserRouter>
  </StrictMode>,
);
