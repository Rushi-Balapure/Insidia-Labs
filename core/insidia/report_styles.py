"""Self-contained styles embedded in generated scan reports."""

REPORT_CSS = """
:root {
  --crit: #8E1B3E;
  --high: #B52D35;
  --med: #A34D00;
  --low: #F2C230;
  --info: #23669C;
  --pass: #21683E;
  --ink: #101028;
  --bg: #F6F6FB;
  --card: #fff;
  --line: #DADAE8;
  --muted: #5A5A80;
  --focus: #0066CC;
  --plot-pass: #21683E;
  --plot-fail: #B52D35;
  --plot-nt: #AA7900;
  --plot-info: #23669C;
  --plot-critical: #8E1B3E;
  --plot-medium: #A34D00;
  --plot-low: #927000;
}
* { box-sizing: border-box; }
html { scroll-padding-top: 7rem; }
a { color: var(--info); }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 3px; }
.skip-link { position: absolute; top: -100px; left: 1rem; padding: 0.6rem 1rem;
  background: var(--card); color: var(--ink); z-index: 10; }
.skip-link:focus { top: 0.5rem; }
.header-inner > div { min-width: 0; }
.report-logo { display: block; flex: 0 0 260px; line-height: 0; }
.report-logo svg { display: block; width: 260px; max-width: 100%; height: auto; }
.report-logo-light { display: none; }
.report-heading { flex: 1; }
nav { z-index: 5; }
.header-inner, .report-nav-inner { width: 100%; max-width: 1200px; margin: auto; }
.report-nav-inner { display: flex; flex-wrap: wrap; gap: 0.35rem 1rem;
  padding: 0.5rem 2rem; }
nav a { padding: 0.35rem 0; }
summary { min-height: 2rem; }
.report-page[hidden] { display: none; }
nav a[aria-current="page"] { color: var(--focus); border-bottom-color: var(--focus); }
h3 { font-size: 1rem; margin: 1.4rem 0 0.4rem; }
body {
  font: 16px/1.5 system-ui, sans-serif;
  margin: 0;
  color: var(--ink);
  background: var(--bg);
}
header { color: #fff; background: #101028; }
.header-inner { display: flex; gap: 1rem; align-items: center; padding: 1.2rem 2rem; }
header h1 { margin: 0; font-size: 1.4rem; font-weight: 600; }
.report-identity { display: flex; flex-wrap: wrap; gap: 0.5rem 1.5rem;
  margin: 0.75rem 0 0; font-size: 0.75rem; }
.report-identity dt { color: #B2B2D1; }
.report-identity dd { margin: 0.15rem 0 0; overflow-wrap: anywhere; }
nav {
  background: #fff;
  border-bottom: 1px solid var(--line);
  position: sticky;
  top: 0;
}
nav a {
  border-bottom: 3px solid transparent;
  color: var(--ink);
  text-decoration: none;
  font-weight: 600;
}
nav a:hover { text-decoration: underline; }
main { width: 100%; padding: 1rem 2rem 3rem; max-width: 1200px; margin: auto; }
h2 {
  margin: 2rem 0 0.6rem;
  font-size: 1.35rem;
  border-bottom: 1px solid var(--line);
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
.summary-detail { margin: 1rem 0; }
.summary-detail > summary { cursor: pointer; color: var(--muted); }
.note, .muted { color: var(--muted); }
.coverage-reason summary { cursor: pointer; color: #765300; font-weight: 600; }
.coverage-reason p { margin: 0.5rem 0; }
.coverage-filter { border: 0; padding: 0; margin: 1rem 0; min-width: 0; }
.coverage-filter legend { font-size: 0.85rem; color: var(--muted); margin-bottom: 0.5rem; }
.coverage-filter > input { position: absolute; width: 1px; height: 1px; opacity: 0; }
.coverage-filter > label { display: inline-block; cursor: pointer; margin: 0 0.3rem 0.5rem 0;
  padding: 0.35rem 0.7rem; border: 1px solid var(--line); border-radius: 999px;
  background: var(--card); font-size: 0.85rem; }
.coverage-filter > input:checked + label { background: var(--ink); color: var(--card); }
.coverage-filter > input:focus-visible + label { outline: 3px solid var(--focus);
  outline-offset: 2px; }
.filter-empty { display: none; padding: 1rem; background: var(--card); }
.framework-group { margin: 0.75rem 0; border: 1px solid var(--line);
  border-radius: 8px; padding: 0.7rem; }
.framework-group > summary { cursor: pointer; font-weight: 650; }
.framework-items td:first-child { white-space: nowrap; font-family: ui-monospace, monospace;
  font-size: 0.85rem; }
.charts-grid { display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr));
  gap: 1rem; margin: 1rem 0; }
.chart { margin: 0; background: var(--card); padding: 1.25rem;
  border: 1px solid var(--line); border-radius: 10px; min-width: 0; }
.chart figcaption { font-size: 1rem; font-weight: 700; margin-bottom: 1rem; }
.outcome-total { margin: 1.5rem 0; color: var(--muted); }
.outcome-total strong { display: block; color: var(--ink); font-size: 2.5rem;
  font-variant-numeric: tabular-nums; }
.chart-outcomes .bar-track { height: 1.5rem; }
.chart-total { font-size: 0.95rem; font-weight: 650; margin: 0.5rem 0; }
.chart-legend { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem;
  margin: 0.75rem 0 0; padding: 0; list-style: none; font-size: 0.8rem; }
.chart-legend li { display: flex; align-items: center; gap: 0.4rem; }
.legend-dot { display: inline-block; width: 0.65rem; height: 0.65rem; border-radius: 50%; }
.donut-wrap { position: relative; width: 170px; margin: auto; }
.donut-wrap svg { width: 100%; height: auto; display: block; }
.donut-wrap circle { fill: none; stroke-width: 13; }
.donut-track { stroke: var(--plot-nt); }
.chart-empty .donut-track { stroke: var(--line); }
.donut-tested { stroke: var(--plot-info); }
.donut-label { position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center; }
.donut-label strong { font-size: 2rem; font-variant-numeric: tabular-nums; }
.donut-label span { font-size: 0.8rem; color: var(--muted); }
.bar-track { display: flex; width: 100%; height: 0.8rem; overflow: hidden;
  border-radius: 999px; background: var(--line); }
.segment { display: block; height: 100%; flex-shrink: 0; }
.segment-pass { background: var(--plot-pass); }
.segment-fail { background: var(--plot-fail); }
.segment-nt { background: var(--plot-nt); }
.segment-info, .segment-tested { background: var(--plot-info); }
.severity-row { display: grid; grid-template-columns: 5.5rem 1fr 2rem;
  align-items: center; gap: 1rem; margin: 0.8rem 0; font-size: 0.85rem; }
.severity-row strong { text-align: right; font-variant-numeric: tabular-nums; }
.segment-critical { background: var(--plot-critical); }
.segment-high { background: var(--plot-fail); }
.segment-medium { background: var(--plot-medium); }
.segment-low { background: var(--plot-low); }
.chart-severity { margin-bottom: 1rem; }
.framework-chart-row { display: grid; grid-template-columns: minmax(180px, 1fr) 2fr;
  gap: 0.4rem 1.5rem; margin: 1rem 0; align-items: center; }
.framework-chart-row strong { font-size: 0.9rem; }
.framework-chart-row small, .framework-chart-row p { grid-column: 2; margin: 0; font-size: 0.8rem; }
.framework-chart-row small { display: block; margin-top: 0.25rem; }
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
.sev-critical { background: var(--crit); color: #fff; }
.bar-critical { border-left: 5px solid var(--crit); }
.sev-high { background: var(--high); color: #fff; }
.bar-high { border-left: 5px solid var(--high); }
.sev-medium { background: var(--med); color: #fff; }
.bar-medium { border-left: 5px solid var(--med); }
.sev-low { background: var(--low); color: #222; }
.bar-low { border-left: 5px solid var(--low); }
.sev-info { background: var(--info); color: #fff; }
.bar-info { border-left: 5px solid var(--info); }
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
.empty-findings { background: var(--card); border: 1px solid var(--line);
  border-left: 4px solid var(--info); border-radius: 8px; padding: 1.25rem; }
.empty-findings p { color: var(--muted); margin: 0.5rem 0; }
.empty-findings a { color: var(--info); font-weight: 600; }
.finding dl { margin: 0; padding: 1rem 1.25rem; }
.finding dt { font-size: 0.78rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.04em; color: var(--muted); margin-top: 1rem; }
.finding dt:first-child { margin-top: 0; }
.finding dd { margin: 0.3rem 0 0; overflow-wrap: anywhere; }
.finding-engine { font-size: 0.8rem; font-weight: 500; }
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
  outline: 2px solid var(--focus);
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
  :root { --ink: #F6F6FB; --bg: #101028; --card: #181839; --line: #393958;
    --muted: #B8B8D1; --focus: #9BCFFF;
    --plot-pass: #66C790; --plot-fail: #F07580; --plot-nt: #EAC454;
    --plot-info: #76BDF0; --plot-critical: #E5749D;
    --plot-medium: #E7A56F; --plot-low: #E1D06C; }
  thead th { background: #252545; color: var(--ink); }
  tbody tr:nth-child(even) { background: #202040; }
  .count-fail { color: #FFB4BA; }
  .count-pass { color: #97E3B3; }
  .count-nt, .coverage-reason summary { color: #FFE5A0; }
  a, .empty-findings a { color: #9BCFFF; }
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
  .header-inner { flex-direction: column; align-items: flex-start; }
  .report-logo { flex-basis: auto; width: 260px; max-width: 100%; }
  html { scroll-padding-top: 1rem; }
  nav { position: static; }
  .header-inner, .report-nav-inner, main { padding-left: 1rem; padding-right: 1rem; }
  .framework-chart-row { grid-template-columns: 1fr; gap: 0.4rem; }
  .framework-chart-row small, .framework-chart-row p { grid-column: 1; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .verdict-strip { flex-direction: column; gap: 0.6rem; }
  .framework-items td:first-child { white-space: normal; }
  .framework-scores td:last-child { min-width: 0; }
  .framework-scores td:last-child .stacked-bar { flex: 1; min-width: 0; }
  .number { text-align: left; }
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
  .report-nav-inner { gap: 0.35rem 1rem; }
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
  .report-page[hidden] { display: block !important; }
  header { background: #fff; color: #101028; }
  .header-inner { padding: 0 0 1rem; }
  .report-logo-dark { display: none; }
  .report-logo-light { display: block; }
  .report-identity dt { color: #454573; }
  :root { --ink: #101028; --bg: #fff; --card: #fff; --line: #DADAE8;
    --muted: #454573; color-scheme: light;
    --plot-pass: #21683E; --plot-fail: #B52D35; --plot-nt: #AA7900;
    --plot-info: #23669C; --plot-critical: #8E1B3E;
    --plot-medium: #A34D00; --plot-low: #927000; }
  body, main { background: #fff; color: #101028; padding: 0; }
  a, .count-fail, .count-pass, .count-nt { color: #101028; }
  thead th { background: #ECECF5; color: #101028; }
  tbody tr:nth-child(even) { background: #F8F8FC; }
  nav { display: none; }
  .skip-link, .coverage-filter > input, .coverage-filter > label,
  .coverage-filter > legend, .filter-empty { display: none !important; }
  .coverage-filter .coverage-row { display: table-row !important; }
  table { display: table; }
  thead { display: table-header-group !important; }
  tbody { display: table-row-group; }
  table tr { display: table-row; }
  table td, table th, table.scan th { display: table-cell; }
  table td::before { display: none; }
  details::details-content { content-visibility: visible !important; display: block !important; }
  .segment, .sev, .res { print-color-adjust: exact; }
  .framework-group, .finding { background: #fff !important; color: #101028; }
  .finding dt, .coverage-reason summary { color: #454573; }
  .by-target input, .by-target label { display: none; }
  .by-target .finding { display: block !important; }
  .by-target .loc { display: list-item !important; }
  details, details.finding { break-inside: avoid; }
  details > summary { list-style: none; }
  details > *:not(summary) { display: block !important; }
}
"""
