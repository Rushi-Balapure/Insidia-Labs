import { GITHUB_REPO } from "../content/install";

let pending: Promise<number | null> | null = null;

/** Star count at build time. Null when GitHub cannot be reached, so the nav omits the number. */
export function githubStars(): Promise<number | null> {
  if (pending) return pending;
  pending = fetch(`https://api.github.com/repos/${GITHUB_REPO}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "insidia-site",
    },
    signal: AbortSignal.timeout(4000),
  })
    .then(async (response) => {
      if (!response.ok) return null;
      const data = (await response.json()) as { stargazers_count?: unknown };
      return typeof data.stargazers_count === "number" ? data.stargazers_count : null;
    })
    .catch(() => null);
  return pending;
}
