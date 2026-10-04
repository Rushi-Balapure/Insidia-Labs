import { animate, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { springs } from "../design/tokens";

const STOPS = ["target", "engine", "injection", "tool", "exploit", "findings"] as const;

export default function DataFlowHero() {
  const reduce = useReducedMotion();
  const root = useRef<HTMLDivElement>(null);
  const packet = useRef<HTMLDivElement>(null);
  const [paused, setPaused] = useState(false);
  const [hot, setHot] = useState<string>("target");
  const [badge, setBadge] = useState(Boolean(reduce));

  useEffect(() => {
    if (reduce) {
      setBadge(true);
      setHot("exploit");
      return;
    }
    const rootEl = root.current;
    const packetEl = packet.current;
    if (!rootEl || !packetEl || paused) return;

    let stop = false;
    const center = (id: string) => {
      const node = rootEl.querySelector<HTMLElement>(`[data-node="${id}"]`);
      const box = rootEl.getBoundingClientRect();
      const nodeBox = node?.getBoundingClientRect();
      if (!nodeBox) return { x: 0, y: 0 };
      return {
        x: nodeBox.left - box.left + nodeBox.width / 2,
        y: nodeBox.top - box.top,
      };
    };

    const run = async () => {
      while (!stop) {
        setBadge(false);
        for (const id of STOPS) {
          if (stop) return;
          const point = center(id);
          setHot(id);
          await animate(packetEl, { x: point.x, y: point.y, opacity: 1 }, springs.move);
          if (id === "exploit") setBadge(true);
        }
        await animate(packetEl, { opacity: 0.35 }, { duration: 0.35 });
      }
    };
    void run();
    return () => {
      stop = true;
    };
  }, [paused, reduce]);

  return (
    <div className="flow" ref={root} aria-labelledby="flow-title">
      <p id="flow-title" className="kicker">
        Where a test goes
      </p>
      <div className="flow-grid">
        <Node id="target" hot={hot} title="Target" detail="Chat, agent, or app" />
        <Node id="engine" hot={hot} title="Insidia Labs Engine" detail="One run, both layers" />
        <Node id="findings" hot={hot} title="Findings" detail="Path you can reproduce" />
        <Node id="injection" hot={hot} title="Prompt injection" detail="Hidden instruction" />
        <Node id="tool" hot={hot} title="Tool call" detail="The agent acts" />
        <div className="flow-node" data-node="exploit" data-hot={hot === "exploit" ? "true" : "false"}>
          <strong>Backend exploit</strong>
          <span style={{ opacity: badge ? 1 : 0.4 }}>
            {badge ? "Critical · confirmed" : "Waiting for proof"}
          </span>
        </div>
      </div>
      <div ref={packet} className="packet" aria-hidden="true" />
      <div className="flow-actions">
        <button type="button" className="btn ghost" aria-pressed={paused || Boolean(reduce)} disabled={Boolean(reduce)} onClick={() => setPaused((value) => !value)}>
          {reduce ? "Motion reduced" : paused ? "Play path" : "Pause path"}
        </button>
      </div>
      <p className="mock-note">
        A diagram of a test that already ran. This page has no prompt box, and nothing you type here is sent to a target.
      </p>
    </div>
  );
}

function Node({ id, hot, title, detail }: { id: string; hot: string; title: string; detail: string }) {
  return (
    <div className="flow-node" data-node={id} data-hot={hot === id ? "true" : "false"}>
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}
