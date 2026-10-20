import { useId, useLayoutEffect, useRef, useState, type KeyboardEvent } from "react";
import { installCommands, type Installer } from "../content/install";

const order: Installer[] = ["uv", "pipx"];

export default function InstallLine() {
  const [which, setWhich] = useState<Installer>("uv");
  const [copied, setCopied] = useState(false);
  const [slider, setSlider] = useState<{ x: number; w: number } | null>(null);
  const tabsRef = useRef<HTMLDivElement>(null);
  const base = useId();
  const command = installCommands[which];

  useLayoutEffect(() => {
    const list = tabsRef.current;
    if (!list) return;
    const measure = () => {
      const active = list.querySelector<HTMLElement>('[aria-selected="true"]');
      if (!active) return;
      const next = { x: active.offsetLeft, w: active.offsetWidth };
      setSlider((current) => (current && current.x === next.x && current.w === next.w ? current : next));
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(list);
    return () => observer.disconnect();
  }, [which]);

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
      <div className={slider ? "seg has-slider" : "seg"} role="tablist" aria-label="Install command" onKeyDown={onTabsKey} ref={tabsRef}>
        {slider ? (
          <span className="seg-slider" aria-hidden="true" style={{ width: slider.w, transform: `translateX(${slider.x}px)` }} />
        ) : null}
        {order.map((name) => (
          <button
            key={name}
            id={`${base}-${name}`}
            type="button"
            role="tab"
            className={which === name ? "on" : undefined}
            aria-selected={which === name}
            aria-controls={`${base}-command`}
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
      <div className="install-row" id={`${base}-command`} role="tabpanel" aria-labelledby={`${base}-${which}`}>
        <div className="install-swap">
          {order.map((name) => {
            const shown = which === name;
            return (
              <pre key={name} className={shown ? "install-box is-shown" : "install-box"} aria-hidden={shown ? undefined : true} inert={shown ? undefined : true} tabIndex={shown ? 0 : -1}>
                <code>{installCommands[name]}</code>
              </pre>
            );
          })}
        </div>
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
