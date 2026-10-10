(() => {
  // Lays out `insidia scan` / `insidia rerun` output in the same order ScanView prints it.
  function scanOutput(term, S, { at, command, rowGap, targetGap = 0.4, allPass = false, tail }) {
    let t = term.cmd(command, at);
    term.out(S.scan.header, t, "dim");
    t += 0.3;
    let failLine = null;
    for (const target of S.scan.targets) {
      term.blank(t);
      term.out(target.name, t + 0.1, "bold");
      t += targetGap;
      for (const row of target.rows) {
        const shown = allPass ? ["pass", row[1], row[2], row[3]] : row;
        const line = term.row(shown, t);
        if (shown[0] === "fail") {
          failLine = line;
          term.highlight(line, t + 0.3);
        }
        t += rowGap;
      }
    }
    term.blank(t);
    term.out(S.scan.write, t + 0.1, "dim");
    t += 0.6;
    term.out(tail.totals, t, "dim");
    t += 0.4;
    term.out(tail.verdict, t, tail.exit_code === 0 ? "ok-pass" : "ok-fail");
    return { end: t + 0.4, failLine };
  }

  const HEADLINE = { before: "Your AI agent is your ", accent: "newest attack surface." };

  window.SHARED = { scanOutput, HEADLINE };
})();
