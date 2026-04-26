// Date / time formatting helpers shared across pages.
//
// Both formatters here used to live as private helpers in their
// respective pages (`formatWhen` in app/findings/page.tsx,
// `formatAge` in app/pods/page.tsx). Pulling them up into one
// module keeps the UI's date conventions consistent and gives new
// pages an obvious place to look before reinventing their own.

// Render an ISO-8601 timestamp as a deterministic UTC string of
// the form "YYYY-MM-DD HH:mm UTC".
//
// Deterministic on purpose — the SPA prerenders at CI time, so a
// locale-derived format would diff between the build host and the
// browser. The fixed UTC layout also matches the JSON-log
// timestamps siphon-api emits, which makes copy-paste into a log
// search work without reformatting.
export function formatTimestampUtc(iso: string): string {
  const d = new Date(iso);
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(
    d.getUTCDate(),
  )} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

// Render an ISO-8601 timestamp as a coarse relative age — "12s",
// "4m", "3h", "2d". `null` / unparseable input returns "—" so the
// caller can drop it into a column without a `?? "—"` everywhere.
//
// Granularity caps at days; anything older than ~48 h falls into
// the day bucket. Pods that old usually warrant a different UX
// (see Forensics) so a precise "37d" string isn't useful here.
export function formatRelativeAge(iso: string | null): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours}h`;
  const days = Math.round(hours / 24);
  return `${days}d`;
}
