import { useEffect, useState } from "react";
import { typeScale } from "./design/tokens";

type Health = "checking" | "reachable" | "unreachable";

export function App() {
  const [health, setHealth] = useState<Health>("checking");

  useEffect(() => {
    const controller = new AbortController();
    fetch("/healthz", { signal: controller.signal })
      .then((response) => {
        setHealth(response.ok ? "reachable" : "unreachable");
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setHealth("unreachable");
        }
      });
    return () => controller.abort();
  }, []);

  const label =
    health === "checking"
      ? "Checking the engine"
      : health === "reachable"
        ? "Engine reachable"
        : "Engine unreachable";

  return (
    <main>
      <header className="bar" style={typeScale.title}>
        Insidia
      </header>
      <p className="status" role="status" style={{ padding: "1.5rem" }}>
        {label}
      </p>
    </main>
  );
}
