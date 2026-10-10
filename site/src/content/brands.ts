export type Brand = {
  name: string;
  file: string;
  /** svg marks take the text color. img marks keep the artwork. */
  kind: "svg" | "img";
  font: string;
  /** The file already draws the name, so the row does not repeat it. */
  wordmark?: boolean;
  /** Backing plate so a light or dark mark stays visible in both themes. */
  plate?: "light" | "dark";
};

const sans = "ui-sans-serif, system-ui, sans-serif";
const mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";

export const stackBrands: Brand[] = [
  { name: "Claude Code", file: "claude.svg", kind: "svg", font: `"Anthropic Sans", "Avenir Next", "Segoe UI", ${sans}` },
  { name: "Cursor", file: "cursor.png", kind: "img", font: `"Cursor Gothic", ${sans}`, plate: "dark" },
  { name: "Codex", file: "openai.svg", kind: "svg", font: `"OpenAI Sans", "Söhne", "Helvetica Neue", Arial, ${sans}` },
  { name: "GitHub Actions", file: "githubactions.svg", kind: "svg", font: `"Mona Sans", ${sans}` },
  { name: "OpenAI", file: "openai.svg", kind: "svg", font: `"OpenAI Sans", "Söhne", "Helvetica Neue", Arial, ${sans}` },
  { name: "Anthropic", file: "anthropic.svg", kind: "svg", font: `"Anthropic Sans", "Avenir Next", "Segoe UI", ${sans}` },
  { name: "Gemini", file: "googlegemini.svg", kind: "svg", font: `"Google Sans", "Helvetica Neue", Arial, ${sans}` },
  { name: "Ollama", file: "ollama.svg", kind: "svg", font: `"Helvetica Neue", Arial, ${sans}` },
  { name: "vLLM", file: "vllm.png", kind: "img", font: `"Helvetica Neue", Arial, ${sans}`, wordmark: true, plate: "dark" },
];

export const engineBrands: Brand[] = [
  { name: "garak", file: "garak.svg", kind: "img", font: `"NVIDIA Sans", Futura, "Trebuchet MS", ${sans}`, wordmark: true, plate: "light" },
  { name: "promptfoo", file: "promptfoo.svg", kind: "img", font: `Inter, ${sans}` },
  { name: "PyRIT", file: "pyrit.svg", kind: "svg", font: `"Segoe UI", ${sans}` },
  { name: "DeepTeam", file: "deepteam.svg", kind: "img", font: `Inter, ${sans}` },
  { name: "ZAP", file: "zap.svg", kind: "svg", font: `"Segoe UI", ${sans}` },
  { name: "Nuclei", file: "nuclei.svg", kind: "svg", font: `"Segoe UI", ${sans}` },
  { name: "Trivy", file: "trivy.svg", kind: "svg", font: `"Segoe UI", ${sans}` },
  { name: "gitleaks", file: "gitleaks.svg", kind: "svg", font: mono },
];
