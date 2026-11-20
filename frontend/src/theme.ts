/**
 * Colour scheme: follow the system, or pin light or dark.
 *
 * The stylesheet expresses every colour as a `light-dark()` pair resolved by
 * `color-scheme`, so pinning a theme is one attribute on `<html>` — the same
 * mechanism the login page uses, with a cookie there and `localStorage` here.
 */

import { useCallback, useSyncExternalStore } from "react";

export type Theme = "auto" | "light" | "dark";
export const THEMES: readonly Theme[] = ["auto", "light", "dark"];

const STORAGE_KEY = "clavia.theme";
const listeners = new Set<() => void>();

function read(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === "light" || stored === "dark" ? stored : "auto";
  } catch {
    return "auto";
  }
}

/** Stamp the choice on the document. Called once at startup and on every change. */
export function applyTheme(theme: Theme = read()): void {
  if (theme === "auto") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
}

function write(theme: Theme): void {
  try {
    if (theme === "auto") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Storage unavailable (private mode, blocked): the choice still applies to
    // this page for as long as it is open.
  }
  applyTheme(theme);
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // Another tab changing the preference should change this one too.
  const onStorage = (event: StorageEvent) => {
    if (event.key === STORAGE_KEY) {
      applyTheme();
      listener();
    }
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

export function useTheme(): [Theme, (theme: Theme) => void] {
  const theme = useSyncExternalStore(subscribe, read, () => "auto" as Theme);
  const setTheme = useCallback((next: Theme) => write(next), []);
  return [theme, setTheme];
}
