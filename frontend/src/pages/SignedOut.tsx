import { pathTo } from "../auth/config";
import { beginLogin } from "../auth/login";
import { ThemeToggle } from "../components/ThemeToggle";

/**
 * Where sign-out lands. A page rather than an immediate new sign-in: the person
 * just asked to leave, and bouncing them straight back into a login form would
 * make "sign out" look like it had not worked.
 */
export function SignedOutPage() {
  return (
    <div className="grid min-h-screen grid-rows-[1fr_auto] place-items-center gap-6 p-6">
      <div className="card w-full max-w-sm p-8 text-center">
        <img src={pathTo("clavia-icon.svg")} alt="" className="mx-auto mb-4 h-12 w-12 rounded-xl" />
        <h1 className="text-xl font-semibold">Signed out</h1>
        <p className="mt-1 mb-6 text-sm text-muted">Your session has ended, here and at the authorization server.</p>
        <button className="btn-primary w-full" onClick={() => void beginLogin("/")} type="button">
          Sign in again
        </button>
        <p className="mt-6 text-xs text-muted">
          Secured by <span className="font-bold text-gold">Clavia</span>
        </p>
      </div>
      <ThemeToggle />
    </div>
  );
}
