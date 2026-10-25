export const GITHUB_REPO = "Rushi-Balapure/Insidia-Labs";
export const GITHUB_URL = `https://github.com/${GITHUB_REPO}`;

// Must equal the version in core/pyproject.toml; lead.test.ts checks it.
export const CLI_VERSION = "1.0.0";
export const RELEASE_URL = `${GITHUB_URL}/releases/tag/v${CLI_VERSION}`;

const git = `git+https://github.com/${GITHUB_REPO}@v${CLI_VERSION}#subdirectory=core`;

export const installCommands = {
  uv: `uv tool install "${git}"`,
  pipx: `pipx install "${git}"`,
} as const;

export type Installer = keyof typeof installCommands;
