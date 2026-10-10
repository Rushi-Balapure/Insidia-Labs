import { useId, useState, type KeyboardEvent } from "react";
import { installCommands, truncatedInstall, type Installer } from "../content/install";

const order: Installer[] = ["uv", "pipx"];

export default function InstallLine() {
  const [which, setWhich] = useState<Installer>("uv");
  const [copied, setCopied] = useState(false);
  const base = useId();
  const command = installCommands[which];

  async function copy() {
    let copiedOk = false;
    try {
      await navigator.clipboard.writeText(command);
      copiedOk = true;
    } catch {
      const area = document.createElement("textarea");
      area.value = command;
      area.setAttribute("readonly", "true");
      area.style.position = "fixed";
      area.style.left = "-9999px";
      document.body.append(area);
      area.select();
      copiedOk = document.execCommand("copy");
      area.remove();
    }
    if (!copiedOk) return;
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  function onTabsKey(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
    event.preventDefault();
    const current = order.indexOf(which);
    const next = order[(current + (event.key === "ArrowRight" ? 1 : -1) + order.length) % order.length];
    setWhich(next);
    setCopied(false);
    document.getElementById(`${base}-${next}`)?.focus();
  }

  return (
    <div className="install">
      <div className="seg" role="tablist" aria-label="Install command" onKeyDown={onTabsKey}>
        {order.map((name) => (
          <button
            key={name}
            id={`${base}-${name}`}
            type="button"
            role="tab"
            className={which === name ? "on" : undefined}
            aria-selected={which === name}
            tabIndex={which === name ? 0 : -1}
            onClick={() => {
              setWhich(name);
              setCopied(false);
            }}
          >
            {name}
          </button>
        ))}
      </div>
      <div className="install-row">
        <pre className="install-box" tabIndex={0}>
          <code>$ {truncatedInstall(command)}</code>
        </pre>
        <button className="btn" type="button" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="visually-hidden" aria-live="polite">
        {copied ? "Install command copied." : ""}
      </p>
      <p className="install-note">Runs on your machine · No account</p>
    </div>
  );
}
