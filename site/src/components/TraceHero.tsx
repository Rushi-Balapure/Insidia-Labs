import sample from "../content/sample-run.json";

type Row = {
  symbol: string;
  family: string;
  result: string;
  engine: string;
  seconds: string;
};

type Panel = {
  findingId: string;
  figure: string;
  banner: string;
  tone: string;
  header: string;
  targets: { name: string; rows: Row[] }[];
  rootCause?: { title: string; lines: string[] };
};

const panels = sample as {
  representative: boolean;
  note: string;
  blocked: Panel;
  clear: Panel;
};

export function tracePanel(which: "blocked" | "clear"): Panel {
  return panels[which];
}

export default function TraceHero({
  which,
  live = false,
}: {
  which: "blocked" | "clear";
  live?: boolean;
}) {
  const panel = tracePanel(which);
  let index = 0;
  const rowCount = panel.targets.reduce((sum, target) => sum + target.rows.length, 0);

  return (
    <figure className={live ? "trace is-live" : "trace"} aria-label={`${panel.findingId}, ${panel.banner}`}>
      <figcaption className="trace-top">
        <span>
          FINDING {panel.findingId} · {panel.figure}
        </span>
        <span className={`trace-banner ${panel.tone}`}>{panel.banner}</span>
      </figcaption>
      <p className="trace-meta">
        <span className="rep">Representative</span>
        <span>{panel.header}</span>
      </p>
      <div className="trace-scroll">
        {panel.targets.map((target) => (
          <div key={target.name}>
            <p className="trace-target">{target.name}</p>
            {target.rows.map((row) => {
              const delay = index * 140;
              index += 1;
              return (
                <p
                  key={`${target.name}-${row.family}`}
                  className={`trace-row ${row.result === "FAIL" ? "is-fail" : "is-pass"}`}
                  style={live ? { animationDelay: `${delay}ms` } : undefined}
                >
                  <span>{row.symbol}</span>
                  <span>{row.family}</span>
                  <span className="trace-bits">
                    <span>{row.result}</span>
                    <span>{row.engine}</span>
                    <span>{row.seconds}</span>
                  </span>
                </p>
              );
            })}
          </div>
        ))}
      </div>
      {panel.rootCause ? (
        <div className="trace-cause" style={live ? { animationDelay: `${rowCount * 140 + 80}ms` } : undefined}>
          <p>{panel.rootCause.title}</p>
          {panel.rootCause.lines.map((line) => (
            <p key={line}>{line}</p>
          ))}
        </div>
      ) : null}
      <p className="trace-foot">{panels.note}</p>
    </figure>
  );
}
