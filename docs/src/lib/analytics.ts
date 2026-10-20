export const TRACKED_PATHS = {
  site: "/site",
  documentation: "/documentation",
} as const;

export type TrackedPath = (typeof TRACKED_PATHS)[keyof typeof TRACKED_PATHS];

const DISABLED = new Set(["1", "true", "yes", "on"]);

export function analyticsEnabled(input: { production: boolean; disabled?: string }): boolean {
  if (DISABLED.has((input.disabled ?? "").trim().toLowerCase())) return false;
  return input.production;
}

export function assertTrackedPath(path: string): TrackedPath {
  if (path === TRACKED_PATHS.site || path === TRACKED_PATHS.documentation) return path;
  throw new Error(`Vercel Analytics only runs on ${TRACKED_PATHS.site} and ${TRACKED_PATHS.documentation}.`);
}

/** Report a visit under one stable path, without the query string. */
export function pageUrl(current: string, path: TrackedPath, base = "https://example.com"): string {
  const url = new URL(current, base);
  url.pathname = path;
  url.search = "";
  url.hash = "";
  return url.toString();
}
