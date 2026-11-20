import { THEMES, useTheme, type Theme } from "../theme";

const LABELS: Record<Theme, string> = { auto: "Auto", light: "Light", dark: "Dark" };

/** The same pill the login page shows: Auto · Light · Dark. */
export function ThemeToggle({ className = "" }: { className?: string }) {
  const [theme, setTheme] = useTheme();
  return (
    <div
      role="group"
      aria-label="Colour scheme"
      className={`inline-flex gap-0.5 rounded-full border border-line bg-card p-[3px] ${className}`}
    >
      {THEMES.map((option) => (
        <button
          key={option}
          type="button"
          aria-pressed={theme === option}
          onClick={() => setTheme(option)}
          className={`rounded-full px-3 py-1 text-xs font-semibold transition-colors ${
            theme === option ? "bg-accent text-on-accent" : "text-muted hover:text-ink"
          }`}
        >
          {LABELS[option]}
        </button>
      ))}
    </div>
  );
}
