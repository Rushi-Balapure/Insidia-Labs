export const GITHUB_REPO = "Rushi-Balapure/Insidia-Labs";
export const GITHUB_URL = `https://github.com/${GITHUB_REPO}`;

const git = `git+https://github.com/${GITHUB_REPO}#subdirectory=core`;

export const installCommands = {
  uv: `uv tool install "${git}"`,
  pipx: `pipx install "${git}"`,
} as const;

export type Installer = keyof typeof installCommands;

/** Shorten the GitHub host so the command fits the hero. Copy still uses the full line. */
export function truncatedInstall(command: string): string {
  return command.replace(`https://github.com/${GITHUB_REPO.split("/")[0]}`, "https://github.com/…");
}
