import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";

import { useAuth } from "../auth/AuthProvider";
import { beginLogin } from "../auth/login";
import { ErrorNote } from "../components/ui";

/** Where the authorization server sends the browser back with a code. */
export function CallbackPage() {
  const { completeLogin } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<unknown>(null);
  // React StrictMode runs effects twice in development; a code is single-use, so
  // the exchange must not be.
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    completeLogin(new URLSearchParams(window.location.search))
      .then((returnTo) => navigate(returnTo, { replace: true }))
      .catch(setError);
  }, [completeLogin, navigate]);

  return (
    <div className="grid min-h-screen place-items-center p-6">
      <div className="card w-full max-w-sm p-8">
        {error ? (
          <>
            <ErrorNote error={error} />
            <button type="button" className="btn-primary mt-4 w-full" onClick={() => void beginLogin("/")}>
              Try again
            </button>
          </>
        ) : (
          <p className="text-center text-sm text-muted">Signing you in…</p>
        )}
      </div>
    </div>
  );
}
