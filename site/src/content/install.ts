export const GITHUB_REPO = "Rushi-Balapure/Insidia-Labs";
export const GITHUB_URL = `https://github.com/${GITHUB_REPO}`;

const git = `git+https://github.com/${GITHUB_REPO}#subdirectory=core`;

export const installCommands = {
  uv: `uv tool install "${git}"`,
  pipx: `pipx install "${git}"`,
} as const;

export type Installer = keyof typeof installCommands;
