"""Self-contained styles embedded in generated scan reports."""

REPORT_CSS = """
:root {
  --crit: #8E1B3E;
  --high: #D43F3A;
  --med: #EE8A33;
  --low: #F2C230;
  --info: #3F8FD2;
  --pass: #2E8B57;
  --ink: #101028;
  --bg: #F6F6FB;
  --card: #fff;
  --line: #DADAE8;
  --muted: #5A5A80;
}
* { box-sizing: border-box; }
body {
  font: 16px/1.5 system-ui, sans-serif;
  margin: 0;
  color: var(--ink);
  background: var(--bg);
}
header {
  display: flex;
  gap: 1rem;
  align-items: center;
  padding: 1.2rem 2rem;
  color: #fff;
  background: #101028;
}
header svg { width: 48px; height: 48px; }
header h1 { margin: 0; font-size: 1.4rem; font-weight: 600; }
.brand { margin: 0; color: #B2B2D1; font-size: 0.85rem; }
nav {
  background: #fff;
  border-bottom: 1px solid var(--line);
  padding: 0.5rem 2rem;
  position: sticky;
  top: 0;
}
nav a {
  margin-right: 1.1rem;
  color: var(--ink);
  text-decoration: none;
  font-weight: 600;
}
main { padding: 1rem 2rem 3rem; max-width: 1100px; margin: auto; }
h2 {
  margin: 2rem 0 0.6rem;
  font-size: 1.15rem;
  border-bottom: 2px solid #101028;
  padding-bottom: 0.2rem;
}
.status {
  margin: 0 0 1rem;
  padding: 1rem 1.25rem;
  background: var(--card);
  border-left: 4px solid var(--high);
  border-radius: 8px;
}
.status.pass { border-left-color: var(--pass); }
.verdict-strip { display: flex; flex-wrap: wrap; gap: 1rem 2rem; margin: 1rem 0; }
.verdict-strip dt { font-size: 0.8rem; color: var(--muted); }
.verdict-strip dd { margin: 0.3rem 0 0; }
.note, .muted { color: var(--muted); }
.framework-group { margin: 0.75rem 0; border: 1px solid var(--line);
  border-radius: 8px; padding: 0.7rem; }
.framework-group > summary { cursor: pointer; font-weight: 650; }
.framework-items td:first-child { white-space: nowrap; font-family: ui-monospace, monospace;
  font-size: 0.85rem; }
.bar-track { display: flex; width: 100%; height: 0.8rem; overflow: hidden;
  border-radius: 999px; background: var(--line); }
.segment { display: block; height: 100%; flex-shrink: 0; }
.segment-pass { background: var(--pass); }
.segment-fail { background: var(--high); }
.segment-nt { background: #D9A21B; }
.segment-info, .segment-tested { background: var(--info); }
.framework-scores td:last-child { min-width: 150px; text-align: left; }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 0.75rem; margin: 1.25rem 0 0.5rem; }
.metric { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 1rem; border-top: 3px solid var(--info); }
.metric dt { font-size: 0.8rem; color: var(--muted); }
.metric dd { margin: 0.3rem 0 0; font-size: 1.8rem; font-weight: 700;
  font-variant-numeric: tabular-nums; }
.metric-passed { border-top-color: var(--pass); }
.metric-failed { border-top-color: var(--high); }
.metric-untested { border-top-color: var(--low); }
.tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.6rem; margin: 1rem 0; }
.tile { color: #fff; border-radius: 8px; padding: 0.7rem; text-align: center; }
.tile b { display: block; font-size: 2rem; line-height: 1.1; }
.tile span { font-size: 0.75rem; letter-spacing: 0.06em; }
.t-critical { background: var(--crit); }
.t-high { background: var(--high); }
.t-medium { background: var(--med); }
.t-low { background: var(--low); color: #222; }
.t-info { background: var(--info); }
table { border-collapse: collapse; width: 100%; background: var(--card); margin: 0.4rem 0; }
th, td {
  text-align: left;
  border-bottom: 1px solid var(--line);
  padding: 0.5rem 0.65rem;
  vertical-align: top;
}
th { color: var(--muted); font-weight: 600; }
thead th { background: #ECECF5; color: var(--ink); }
tbody tr:nth-child(even) { background: #F8F8FC; }
.framework-scores td:first-child { font-weight: 650; }
.number, .framework-scores th:not(:first-child) { text-align: right;
  font-variant-numeric: tabular-nums; }
.count-fail { color: #A12830; }
.count-pass { color: #21653F; }
.count-nt { color: #765300; }
code { font-family: ui-monospace, monospace; word-break: break-all; }
.sev, .res {
  display: inline-block;
  padding: 0.05rem 0.45rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 700;
}
.sev-critical, .bar-critical { background: var(--crit); color: #fff; }
.sev-high, .bar-high { background: var(--high); color: #fff; }
.sev-medium, .bar-medium { background: var(--med); color: #fff; }
.sev-low, .bar-low { background: var(--low); color: #222; }
.sev-info, .bar-info { background: var(--info); color: #fff; }
.res-fail { background: var(--high); color: #fff; }
.res-pass { background: var(--pass); color: #fff; }
.res-low { background: var(--low); color: #222; }
.res-info { background: var(--info); color: #fff; }
.res-nt { background: #FFF0BD; color: #624500; }
.res::before { margin-right: 0.35em; }
.res-pass::before { content: "✓"; }
.res-fail::before { content: "✕"; }
.res-nt::before { content: "—"; }
.res-low::before { content: "!"; }
.res-info::before { content: "i"; }
details.finding {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 8px;
  margin: 0.6rem 0;
  overflow: hidden;
}
summary.bar {
  cursor: pointer;
  font-weight: 700;
  padding: 0.55rem 0.8rem;
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  align-items: baseline;
}
.pid { font-family: ui-monospace, monospace; }
.right { margin-left: auto; font-size: 0.85rem; }
.by-target { position: relative; margin: 0.2rem 0 0.8rem; }
.by-target input {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: 0;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
}
.by-target label {
  display: inline-block;
  margin: 0 0.4rem 0.4rem 0;
  padding: 0.15rem 0.7rem;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--card);
  cursor: pointer;
  font-weight: 600;
}
.by-target input:checked + label {
  background: #101028;
  color: #fff;
  border-color: #101028;
}
.by-target input:focus-visible + label {
  outline: 2px solid var(--info);
  outline-offset: 2px;
}
ul.locations { margin: 0.7rem 1rem 0.2rem; padding-left: 1.2rem; }
ul.locations li { margin: 0.2rem 0; }
.body { padding: 0.2rem 1rem 1rem; }
pre {
  white-space: pre-wrap;
  word-break: break-word;
  background: #F1F1F7;
  padding: 0.6rem;
  border-radius: 6px;
}
footer {
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--line);
  color: var(--muted);
}
@media (prefers-color-scheme: dark) {
  body { color: #F6F6FB; background: #101028; }
  nav, .status, table, details.finding, .by-target label { background: #181839; color: #F6F6FB; }
  .by-target label { border-color: #2E2E56; }
  .by-target input:checked + label {
    background: var(--info);
    color: #fff;
    border-color: var(--info);
  }
  nav a, h2 { color: #F6F6FB; }
  h2, header { border-color: #2E2E56; }
  .note, .muted, th, footer { color: #B2B2D1; }
  th, td, footer { border-bottom-color: #2E2E56; }
  pre { background: #101028; color: #F6F6FB; }
  .res-nt { background: #594512; color: #FFE5A0; }
}
@media (max-width:700px) {
  header, nav, main { padding-left: 1rem; padding-right: 1rem; }
  .tiles { gap: 0.3rem; }
  .tile { padding: 0.35rem 0.15rem; }
  .tile b { font-size: 1.3rem; }
  .tile span { font-size: 0.6rem; letter-spacing: 0; }
  table thead { display: none; }
  table tr {
    display: block;
    border-bottom: 2px solid var(--line);
    padding: 0.3rem 0;
  }
  table td, table.scan th {
    display: flex;
    gap: 0.6rem;
    border: 0;
    padding: 0.2rem 0.4rem;
    max-width: 100%;
  }
  table td[data-l]::before {
    content: attr(data-l);
    flex: 0 0 6.2rem;
    font-weight: 600;
    color: var(--muted);
  }
  .right { margin-left: 0; width: 100%; }
  pre, code, td { overflow-wrap: anywhere; }
  body { overflow-x: hidden; }
}
@media (max-width:390px) {
  nav {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem 1.1rem;
    max-width: 100%;
    overflow-x: auto;
  }
  nav a { margin-right: 0; white-space: nowrap; }
  table td[data-l], table.scan th, table.scan td {
    flex-direction: column;
    align-items: stretch;
    min-width: 0;
    max-width: 100%;
  }
  table td[data-l]::before { flex: none; }
}
@media print {
  nav { display: none; }
  .by-target input, .by-target label { display: none; }
  .by-target .finding { display: block !important; }
  .by-target .loc { display: list-item !important; }
  details, details.finding { break-inside: avoid; }
  details > summary { list-style: none; }
  details > *:not(summary) { display: block !important; }
}
"""
