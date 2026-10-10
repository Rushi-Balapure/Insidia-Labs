window.VIDEOS.film = (S) => {
  const { h, p, show, place, esc, makeVideo } = window.V;
  const { Terminal, CodePane, browser, reportFinding, reportHeader, frameworkTable, chat, bubble, endCard, speedBadge, canaryHtml } = window.C;
  const { scanOutput, HEADLINE } = window.SHARED;
  const f = S.finding;
  const v = makeVideo(185);
  const NS = "http://www.w3.org/2000/svg";

  function svgLayer(root) {
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("width", "1920");
    svg.setAttribute("height", "1080");
    svg.style.position = "absolute";
    svg.style.inset = "0";
    svg.innerHTML = `<defs></defs>`;
    root.append(svg);
    let n = 0;
    return function arrow(x1, y1, x2, y2, { color = "#b2b2d1", dashed = false, width = 3 } = {}) {
      const id = `m${Math.random().toString(36).slice(2)}${n++}`;
      const len = Math.hypot(x2 - x1, y2 - y1);
      const angle = Math.atan2(y2 - y1, x2 - x1);
      const head = [
        [x2, y2],
        [x2 - 18 * Math.cos(angle - 0.45), y2 - 18 * Math.sin(angle - 0.45)],
        [x2 - 18 * Math.cos(angle + 0.45), y2 - 18 * Math.sin(angle + 0.45)],
      ].map((pt) => pt.join(",")).join(" ");
      const g = document.createElementNS(NS, "g");
      g.innerHTML =
        `<mask id="${id}" maskUnits="userSpaceOnUse" x="0" y="0" width="1920" height="1080"><line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#fff" stroke-width="${width + 6}" stroke-dasharray="${len}" stroke-dashoffset="${len}"/></mask>` +
        `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${width}" stroke-linecap="round" ${dashed ? 'stroke-dasharray="14 12"' : ""} mask="url(#${id})"/>` +
        `<polygon points="${head}" fill="${color}" opacity="0"/>`;
      svg.append(g);
      const reveal = g.querySelector("mask line");
      const tip = g.querySelector("polygon");
      return (prog) => {
        reveal.setAttribute("stroke-dashoffset", String(len * (1 - prog)));
        tip.setAttribute("opacity", prog > 0.92 ? String((prog - 0.92) / 0.08) : "0");
      };
    };
  }

  const chapters = [
    [0, "The bug that doesn't crash"],
    [20, "Two layers to test"],
    [50, "What Insidia does"],
    [75, "Scope"],
    [95, "Scan"],
    [120, "Report"],
    [145, "Fix and rerun"],
    [160, "CI and your coding agent"],
    [175, "End"],
  ];
  chapters.slice(0, -1).forEach(([start, label]) => v.chapter(start, label));

  // 0:00 The bug that doesn't crash
  v.scene(0, 20, (root) => {
    const c = chat(root, { x: 360, y: 110, w: 1200, h: 760, title: "support-bot · chat" });
    const ask = bubble(c.body, "user", `<div class="attach">PDF · ${esc(f.upload)}</div><br>${esc(f.question)}`);
    const answer = bubble(c.body, "bot", esc(f.answer));
    const leak = bubble(c.body, "bot", canaryHtml(f.leak, f.canary));

    const paper = place(h("div", { class: "abs", style: { background: "#fbfbfe", borderRadius: "14px", boxShadow: "0 30px 80px rgba(0,0,0,.5)", padding: "56px 64px", color: "#101028" } }), 560, 100, 800, 800);
    const bar = (w, mt = 18, c = "#dcdcea") => `<div style="height:16px;width:${w}%;background:${c};border-radius:8px;margin-top:${mt}px"></div>`;
    paper.innerHTML =
      `<div style="font-size:34px;font-weight:600">Invoice #4471</div>` +
      `<div style="font-size:20px;color:#454573;margin-top:8px">Acme Supplies · due 14 November</div>` +
      bar(90, 40) + bar(76) + bar(84) + bar(60) +
      `<div class="hidden-line" style="margin-top:36px;padding:14px 18px;border-radius:10px;font-family:var(--mono);font-size:22px;color:#fbfbfe;background:transparent">${esc(f.hidden_line)}</div>` +
      bar(88, 36) + bar(70) + bar(40);
    const hidden = paper.querySelector(".hidden-line");
    const tag = place(h("div", { class: "abs badge", text: "Hidden text, revealed" }), 1390, 470);
    root.append(paper, tag);

    return (t) => {
      const chatOut = 1 - p(t, 10.4, 0.6);
      c.el.style.opacity = Math.min(p(t, 0, 0.5), chatOut);
      show(ask, p(t, 1.0, 0.4));
      show(answer, p(t, 3.4, 0.4));
      show(leak, p(t, 6.0, 0.4));
      show(paper, p(t, 11.0, 0.7), 40);
      const r = p(t, 13.5, 0.8);
      hidden.style.background = `rgba(227, 61, 134, ${0.16 * r})`;
      hidden.style.color = r > 0 ? `rgb(${251 - (251 - 160) * r}, ${251 - (251 - 20) * r}, ${254 - (254 - 80) * r})` : "#fbfbfe";
      hidden.style.outline = r > 0.5 ? "3px solid #e33d86" : "none";
      show(tag, p(t, 14.2, 0.5));
    };
  });
  v.cap(0.5, 6.0, "This support bot answered the question.");
  v.cap(6.0, 11.0, "It also printed part of its own system prompt.");
  v.cap(11.0, 19.6, "The instruction was hidden in the PDF. Nothing crashed.");

  // 0:20 Two layers to test
  v.scene(20, 30, (root) => {
    const label = h("div", { class: "badge label-illustrative", text: "Illustrative" });
    const sources = ["Uploads", "Web pages", "Tool results"].map((text, i) =>
      place(h("div", { class: "abs chip", text, style: { fontFamily: "var(--font)" } }), 110, 330 + i * 130),
    );
    const ai = place(h("div", { class: "box", html: `<h3>AI layer</h3><div class="item">Prompt</div><div class="item">Retrieved documents</div><div class="item">Tools</div>` }), 520, 290, 480, 380);
    const app = place(h("div", { class: "box", html: `<h3>App layer</h3><div class="item">API</div><div class="item">Database</div><div class="item">Auth</div>` }), 1300, 290, 480, 380);
    ai.style.borderColor = "rgba(237, 123, 57, 0.6)";
    app.style.borderColor = "rgba(227, 61, 134, 0.55)";
    root.append(label, ...sources, ai, app);
    const arrow = svgLayer(root);
    const inputs = sources.map((_, i) => arrow(300, 356 + i * 130, 510, 480, { color: "#ed7b39" }));
    const cross = arrow(1010, 480, 1290, 480, { color: "#e33d86", dashed: true, width: 4 });
    const crossLabel = place(h("div", { class: "abs", text: "model calls your API", style: { color: "#f7c4da", fontSize: "22px", fontWeight: 600 } }), 1040, 420);
    root.append(crossLabel);
    return (t) => {
      show(label, p(t, 0.3, 0.5));
      show(ai, p(t, 0.6, 0.6), 30);
      show(app, p(t, 1.2, 0.6), 30);
      sources.forEach((el, i) => show(el, p(t, 7.6 + i * 0.4, 0.4)));
      inputs.forEach((draw, i) => draw(p(t, 8.2 + i * 0.4, 0.8)));
      cross(p(t, 21.8, 1.2));
      show(crossLabel, p(t, 22.8, 0.5));
    };
  });
  v.cap(20.5, 27.5, "An AI app is still an app, with a new kind of input.");
  v.cap(27.5, 34.5, "Anything the model reads can carry an instruction.");
  v.cap(34.5, 41.5, "AI checks and app checks usually run in different tools, on different days.");
  v.cap(41.5, 49.6, "The risky path can start on one side and end on the other.");

  // 0:50 What Insidia does
  v.scene(50, 25, (root) => {
    const chips = S.engines.map((name) => h("span", { class: "chip", text: name, style: { fontFamily: "var(--font)", fontSize: "26px", padding: "12px 26px" } }));
    const row = place(h("div", { class: "abs", style: { display: "flex", gap: "18px", justifyContent: "center" } }, chips), 0, 230, 1920);
    const plus = h("span", { class: "chip", text: "+ Insidia checks", style: { fontFamily: "var(--font)", fontSize: "26px", padding: "12px 26px", background: "rgba(237,123,57,.2)", color: "#ffd2b5" } });
    row.append(plus);
    const boxes = [
      ["insidia.yaml", "your targets and scope"],
      ["insidia scan", "AI and app checks, one run"],
      ["report.html", "+ JSON · SARIF · exit code"],
    ].map(([title, sub], i) =>
      place(h("div", { class: "box", style: { textAlign: "center" }, html: `<h3 class="mono" style="margin-bottom:10px">${esc(title)}</h3><div style="color:#b2b2d1;font-size:22px">${esc(sub)}</div>` }), 200 + i * 560, 470, 440, 150),
    );
    root.append(row, ...boxes);
    const arrow = svgLayer(root);
    const links = [arrow(650, 545, 750, 545), arrow(1210, 545, 1310, 545)];
    const term = new Terminal(root, { x: 410, y: 690, w: 1100, h: 196, title: "insidia scan" });
    const rows = S.scan.targets[0].rows.slice(0, 2);
    rows.forEach((r, i) => term.row(r, 16.6 + i * 0.5));
    const engineGlow = place(h("div", { class: "outline" }), 0, 0);
    term.el.append(engineGlow);
    Object.assign(engineGlow.style, { left: "712px", top: "72px", width: "142px", height: "92px" });
    return (t) => {
      chips.concat(plus).forEach((el, i) => show(el, p(t, 0.6 + i * 0.35, 0.5)));
      boxes.forEach((el, i) => show(el, p(t, 8.2 + i * 1.6, 0.6), 30));
      links.forEach((draw, i) => draw(p(t, 9.0 + i * 1.6, 0.7)));
      show(term.el, p(t, 16.2, 0.5));
      term.update(t);
      engineGlow.style.opacity = p(t, 18.2, 0.4);
    };
  });
  v.cap(50.5, 58.0, "Insidia tests both layers in one run, on your machine.");
  v.cap(58.0, 66.0, "It runs engines like garak, promptfoo, Nuclei, and ZAP, plus its own checks.");
  v.cap(66.0, 74.6, "Every result names the engine that produced it.");

  // 1:15 Scope
  v.scene(75, 20, (root) => {
    const term = new Terminal(root, { x: 90, y: 170, w: 910, h: 460 });
    const t0 = term.cmd("insidia init", 0.3);
    S.init.output.forEach((line, i) => term.out(line, t0 + i * 0.4));
    const t1 = term.cmd("insidia scan", 7.4);
    S.scope_refusal.output.forEach((line) => term.out(line, t1 + 0.3, "err"));
    const pane = new CodePane(root, { x: 1050, y: 120, w: 780, h: 760, title: "insidia.yaml", lines: S.init.config });
    const added = pane.add(S.scope_refusal.added, "yaml", 4.4);
    added.typeAt = 4.4;
    added.removeAt = 11.6;
    pane.code.insertBefore(added.el, pane.rows[6].el);
    added.el.style.background = "rgba(227, 61, 134, 0.12)";
    pane.outline(3, 5, 1.6, 4.2);
    pane.outline(10, 10, 13.2);
    return (t) => {
      show(term.el, p(t, 0, 0.5));
      term.update(t);
      show(pane.el, p(t, 1.0, 0.6), 30);
      pane.update(t);
    };
  });
  v.cap(75.5, 82.0, "Insidia only touches hosts you list.");
  v.cap(82.0, 88.0, "Anything beyond localhost needs authorized: true, set by you.");
  v.cap(88.0, 94.6, "A planted canary proves a leak. No guessing.");

  // 1:35 Scan
  v.scene(95, 25, (root) => {
    const term = new Terminal(root, { x: 160, y: 120, w: 1600, h: 820 });
    const badge = speedBadge(root);
    scanOutput(term, S, { at: 0.4, command: S.scan.command, rowGap: 0.75, tail: S.scan });
    const zoom = place(h("div", { class: "card" }), 260, 330, 1400);
    const row = S.scan.targets[0].rows.find((r) => r[0] === "fail");
    const parts = [
      ["✘ " + row[1], "check", "#fff"],
      ["FAIL", "result", "#e33d86"],
      [row[2], "engine", "#b2b2d1"],
      [row[3], "time", "#b2b2d1"],
    ];
    zoom.innerHTML = `<div style="display:flex;gap:56px;align-items:flex-end;justify-content:center">${parts
      .map(([text, lab, color]) => `<div style="text-align:center"><div class="mono" style="font-size:40px;color:${color};font-weight:700">${esc(text)}</div><div class="kicker" style="margin-top:16px;color:#ed7b39">${lab}</div></div>`)
      .join("")}</div>`;
    const legend = place(h("div", { class: "abs", style: { display: "flex", gap: "22px", justifyContent: "center" } }), 0, 600, 1920);
    [["✔", "pass", "#4ade80"], ["✘", "FAIL", "#e33d86"], ["–", "skipped", "#f6c13f"], ["?", "incomplete", "#f6c13f"]].forEach(([s, lab, color]) =>
      legend.append(h("span", { class: "chip", html: `<span style="color:${color}">${s}</span> ${lab}` })),
    );
    root.append(zoom, legend);
    return (t) => {
      term.el.style.opacity = p(t, 0, 0.4) * (1 - 0.9 * p(t, 11.6, 0.5));
      term.update(t);
      badge.style.opacity = Math.min(p(t, 1.4, 0.3), 1 - p(t, 11.2, 0.3));
      show(zoom, Math.min(p(t, 12.0, 0.6), 1 - p(t, 23.8, 0.4)), 30);
      show(legend, p(t, 17.6, 0.6));
    };
  });
  v.cap(95.5, 107.0, "L1 is the baseline. Fast enough for every pull request.");
  v.cap(107.0, 112.5, "Each row: the check, the result, the engine, the time.");
  v.cap(112.5, 119.6, "A check that couldn't run is marked incomplete, never passed.");

  // 2:00 Report
  v.scene(120, 25, (root) => {
    const b = browser(root, { x: 210, y: 100, w: 1500, h: 840, url: S.report.path });
    const head = reportHeader(S);
    const table = frameworkTable(S);
    const finding = reportFinding(S);
    b.page.append(head, table, finding.el);
    const col = h("div", { class: "outline" });
    b.view.append(col);
    return (t) => {
      show(b.el, p(t, 0, 0.5), 40);
      show(head, p(t, 0.5, 0.5));
      show(table, p(t, 1.4, 0.5));
      show(finding.el, p(t, 2.4, 0.5));
      const range = Math.max(0, b.page.scrollHeight - b.view.clientHeight);
      const down = p(t, 8.0, 1.4) * (1 - p(t, 16.0, 1.2));
      b.page.style.transform = `translateY(${-range * down}px)`;
      finding.blocks.forEach((el, i) => show(el, i < 2 ? p(t, 9.6 + i * 1.6, 0.5) : p(t, 2.4, 0.5)));
      const th = table.querySelectorAll("th")[3];
      if (th) {
        const top = table.offsetTop - range * down;
        Object.assign(col.style, { left: `${56 + th.offsetLeft - 6}px`, top: `${top - 6}px`, width: `${th.offsetWidth + 12}px`, height: `${table.offsetHeight + 12}px` });
      }
      col.style.opacity = p(t, 17.6, 0.4);
    };
  });
  v.cap(120.5, 128.0, "One HTML file. Opens offline.");
  v.cap(128.0, 136.0, "The attack, the reply, and the proof.");
  v.cap(136.0, 144.6, "It also lists what wasn't tested.");

  // 2:25 Fix and rerun
  v.scene(145, 15, (root) => {
    const pane = new CodePane(root, { x: 160, y: 110, w: 1600, h: 310, title: S.fix_diff.file, lines: [S.fix_diff.lines[0]], kind: "diff" });
    S.fix_diff.lines.slice(1).forEach((line, i) => (pane.add(line, "diff", 1.0 + i * 0.7).at = 1.0 + i * 0.7));
    const term = new Terminal(root, { x: 160, y: 460, w: 1600, h: 470 });
    const badge = speedBadge(root);
    const { end } = scanOutput(term, S, { at: 6.4, command: S.rerun.command, rowGap: 0.3, targetGap: 0.25, allPass: true, tail: S.rerun });
    return (t) => {
      show(pane.el, p(t, 0, 0.5));
      pane.update(t);
      show(term.el, p(t, 5.8, 0.5));
      term.update(t);
      badge.style.opacity = Math.min(p(t, 7.2, 0.3), 1 - p(t, end - 0.8, 0.3));
    };
  });
  v.cap(145.5, 151.0, "Treat uploads as data, not instructions.");
  v.cap(151.0, 159.6, "Rerun checks again with the same config. Now it passes.");

  // 2:40 CI and your coding agent
  v.scene(160, 15, (root) => {
    const pane = new CodePane(root, { x: 80, y: 130, w: 900, h: 470, title: S.ci.file, lines: S.ci.lines });
    pane.code.style.fontSize = "22px";
    const check = place(h("div", { class: "card", style: { padding: "26px 32px" }, html: `<div class="kicker">Pull request · checks</div><div style="margin-top:14px;font-size:24px;display:flex;gap:14px;align-items:center"><span style="color:#e33d86;font-size:30px">✘</span>${esc(S.ci.check)}</div><div style="margin-top:10px;color:#b2b2d1;font-size:20px">Merging is blocked</div>` }), 80, 640, 900);
    root.append(check);
    const c = chat(root, { x: 1020, y: 130, w: 820, h: 690, title: "Coding agent" });
    const ask = bubble(c.body, "user", esc(S.agent.prompt));
    const reply = bubble(c.body, "bot", esc(S.agent.reply));
    const yes = bubble(c.body, "user", esc(S.agent.confirm));
    return (t) => {
      show(pane.el, p(t, 0, 0.5));
      show(check, p(t, 3.2, 0.5), 24);
      show(c.el, p(t, 6.8, 0.5), 30);
      show(ask, p(t, 7.6, 0.4));
      show(reply, p(t, 9.4, 0.4));
      show(yes, p(t, 12.0, 0.4));
    };
  });
  v.cap(160.5, 167.5, "In CI, a failed policy blocks the merge.");
  v.cap(167.5, 174.6, "Or hand it to your coding agent. You confirm the hosts.");

  // 2:55 End
  v.scene(175, 10, (root) => endCard(root, S, HEADLINE));
  v.cap(175.3, 185, "Your AI agent is your newest attack surface.", { hidden: true });

  return v;
};
