window.VIDEOS.howto = (S) => {
  const { h, p, show, place, makeVideo } = window.V;
  const { Terminal, CodePane, browser, reportFinding, reportHeader, findingCard, endCard, speedBadge } = window.C;
  const { scanOutput, HEADLINE } = window.SHARED;
  const v = makeVideo(60);

  // 0:00 The finding first
  v.scene(0, 5.4, (root) => {
    const kicker = place(h("div", { class: "abs kicker", text: "Fig. 1 — an injection, traced" }), 410, 250);
    root.append(kicker);
    const card = findingCard(root, S, { x: 410, y: 310, w: 1100 });
    return (t) => {
      show(kicker, p(t, 0.2, 0.6));
      show(card, p(t, 0.4, 0.7), 30);
    };
  });
  v.cap(0.3, 5.0, "A real finding in a sample support bot.");

  // 0:05 Install
  v.scene(5, 7.4, (root) => {
    const term = new Terminal(root, { x: 160, y: 330, w: 1600, h: 260 });
    let t = term.cmd(S.install.command, 0.5);
    S.install.output.forEach((line, i) => term.out(line, t + 0.3 + i * 0.5));
    return (t) => {
      show(term.el, p(t, 0, 0.5));
      term.update(t);
    };
  });
  v.cap(5.4, 12.0, "Install the CLI. It runs on your machine. No account.");

  // 0:12 init and the scope file
  v.scene(12, 10.4, (root) => {
    const term = new Terminal(root, { x: 100, y: 200, w: 820, h: 300 });
    const t = term.cmd("insidia init", 0.4);
    S.init.output.forEach((line, i) => term.out(line, t + i * 0.4));
    const pane = new CodePane(root, { x: 980, y: 150, w: 840, h: 680, title: "insidia.yaml", lines: S.init.config });
    pane.outline(3, 5, 4.0, 6.6);
    pane.outline(6, 13, 6.8);
    return (t) => {
      show(term.el, p(t, 0, 0.5));
      term.update(t);
      show(pane.el, p(t, 1.9, 0.6), 30);
      pane.update(t);
    };
  });
  v.cap(12.4, 22.0, "One file sets the targets and the hosts it may touch.");

  // 0:22 doctor
  v.scene(22, 5.4, (root) => {
    const term = new Terminal(root, { x: 260, y: 230, w: 1400, h: 380 });
    const t = term.cmd("insidia doctor", 0.3);
    S.doctor.output.forEach((line, i) => term.out(line, t + i * 0.45, i === 0 ? "dim" : "out"));
    return (t) => {
      show(term.el, p(t, 0, 0.4));
      term.update(t);
    };
  });
  v.cap(22.4, 27.0, "Doctor checks that everything is ready.");

  // 0:27 scan
  v.scene(27, 13.4, (root) => {
    const term = new Terminal(root, { x: 160, y: 120, w: 1600, h: 820 });
    const badge = speedBadge(root);
    scanOutput(term, S, { at: 0.3, command: S.scan.command, rowGap: 0.85, tail: S.scan });
    return (t) => {
      show(term.el, p(t, 0, 0.4));
      term.update(t);
      badge.style.opacity = Math.min(p(t, 1.5, 0.3), 1 - p(t, 11, 0.3));
    };
  });
  v.cap(27.4, 33.5, "One scan covers the AI side and the app side.");
  v.cap(33.5, 40.0, "Every row names its engine. One check failed.");

  // 0:40 report
  v.scene(40, 10.4, (root) => {
    const b = browser(root, { x: 210, y: 110, w: 1500, h: 830, url: S.report.path });
    const head = reportHeader(S);
    const finding = reportFinding(S);
    b.page.append(head, finding.el);
    return (t) => {
      show(b.el, p(t, 0, 0.5), 40);
      show(head, p(t, 0.5, 0.5));
      show(finding.el, p(t, 1.4, 0.5));
      finding.blocks.forEach((el, i) => show(el, p(t, 2.6 + i * 1.3, 0.5)));
    };
  });
  v.cap(40.4, 50.0, "See the attack, the reply, and the fix.");

  // 0:50 fix and rerun
  v.scene(50, 7, (root) => {
    const pane = new CodePane(root, { x: 160, y: 110, w: 1600, h: 310, title: S.fix_diff.file, lines: S.fix_diff.lines, kind: "diff" });
    const term = new Terminal(root, { x: 160, y: 460, w: 1600, h: 470 });
    const badge = speedBadge(root);
    const { end } = scanOutput(term, S, { at: 1.1, command: S.rerun.command, rowGap: 0.13, targetGap: 0.12, allPass: true, tail: S.rerun });
    return (t) => {
      show(pane.el, p(t, 0, 0.5));
      show(term.el, p(t, 0.7, 0.5));
      term.update(t);
      badge.style.opacity = Math.min(p(t, 1.6, 0.3), 1 - p(t, end - 0.6, 0.3));
    };
  });
  v.cap(50.4, 56.6, "Fix the code. Rerun with the same config. It passes.");

  // 0:57 end card
  v.scene(56.6, 3.4, (root) => endCard(root, S, HEADLINE));
  v.cap(56.8, 60, "Your AI agent is your newest attack surface.", { hidden: true });

  return v;
};
