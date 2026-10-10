(() => {
  const { h, p, show, place, esc } = window.V;
  const LINE = 40;

  function windowFrame(x, y, w, hgt, title, extraBar) {
    const bar = h("div", { class: "window-bar" }, h("i"), h("i"), h("i"), title ? h("span", { text: title }) : null, extraBar || null);
    const el = place(h("div", { class: "window" }, bar), x, y, w, hgt);
    return el;
  }

  class Terminal {
    constructor(root, { x, y, w, h: hgt, title = "~/support-bot" }) {
      this.el = windowFrame(x, y, w, hgt, title);
      this.body = h("div", { class: "term-body" });
      this.maxLines = Math.floor((hgt - 52 - 52) / LINE);
      const viewport = h("div", { style: { height: `${this.maxLines * LINE}px`, overflow: "hidden" } });
      this.scroll = h("div", { class: "term-scroll" });
      viewport.append(this.scroll);
      this.body.append(viewport);
      this.body.style.height = `${hgt - 52}px`;
      this.el.append(this.body);
      root.append(this.el);
      this.lines = [];
      this.maxChars = Math.floor((w - 64) / 15.7);
      this.cps = 34;
    }

    _line(cls, at) {
      const el = h("div", { class: `tl ${cls}` });
      this.scroll.append(el);
      const line = { el, at, cls };
      this.lines.push(line);
      return line;
    }

    cmd(text, at, cps = this.cps) {
      const line = this._line("cmd", at);
      line.text = text;
      line.typeEnd = at + text.length / cps;
      line.el.innerHTML = `<span class="prompt">$</span> <span class="typed"></span><span class="caret"></span>`;
      line.typed = line.el.querySelector(".typed");
      line.caret = line.el.querySelector(".caret");
      return line.typeEnd + 0.35;
    }

    out(text, at, cls = "out") {
      const chunks = [];
      let current = "";
      for (const word of text.split(" ")) {
        const next = current ? `${current} ${word}` : word;
        if (next.length > this.maxChars && current) {
          chunks.push(current);
          current = `  ${word}`;
        } else {
          current = next;
        }
      }
      chunks.push(current);
      let line;
      for (const chunk of chunks) {
        line = this._line(cls, at);
        line.el.textContent = chunk;
      }
      return line;
    }

    blank(at) {
      return this._line("out", at);
    }

    row([result, family, engine, time], at) {
      const line = this._line("row", at);
      const sym = result === "pass" ? "✔" : "✘";
      const label = result === "pass" ? "pass" : "FAIL";
      line.el.innerHTML =
        `  <span class="sym-${result}">${sym}</span> ${esc(family.padEnd(30))} ` +
        `<span class="lab-${result}">${label.padEnd(8)}</span> <span class="eng">${esc(engine.padEnd(10))}</span> <span class="time">${esc(time)}</span>`;
      line.result = result;
      return line;
    }

    highlight(line, at) {
      line.hlAt = at;
    }

    update(t) {
      let lastCmd = null;
      let offset = 0;
      this.lines.forEach((line, i) => {
        const v = p(t, line.at, 0.18);
        line.el.style.opacity = v;
        if (line.typed) {
          const n = Math.max(0, Math.min(line.text.length, Math.floor((t - line.at) * ((line.text.length) / Math.max(0.001, line.typeEnd - line.at)))));
          line.typed.textContent = line.text.slice(0, n);
          if (t >= line.at) lastCmd = line;
        }
        if (line.hlAt != null) line.el.classList.toggle("hl", t >= line.hlAt);
        if (i >= this.maxLines) offset += p(t, line.at, 0.2) * LINE;
      });
      for (const line of this.lines) {
        if (!line.caret) continue;
        const next = this.lines[this.lines.indexOf(line) + 1];
        const active = line === lastCmd && (!next || t < next.at);
        const blink = Math.floor(t * 2) % 2 === 0 || t < line.typeEnd;
        line.caret.style.opacity = active && blink ? 1 : 0;
      }
      this.scroll.style.transform = `translateY(${-offset}px)`;
    }
  }

  function yamlHtml(line) {
    const m = line.match(/^(\s*-?\s*)([\w.-]+)(:)(.*)$/);
    if (!m) return esc(line);
    const value = m[4].trim() ? `<span class="s">${esc(m[4])}</span>` : "";
    return `${esc(m[1])}<span class="k">${esc(m[2])}</span>${m[3]}${value}`;
  }

  class CodePane {
    constructor(root, { x, y, w, h: hgt, title, lines, kind = "yaml" }) {
      this.el = windowFrame(x, y, w, hgt, title);
      this.code = h("div", { class: "code" });
      this.el.append(this.code);
      root.append(this.el);
      this.rows = [];
      this.outlines = [];
      for (const line of lines) this.add(line, kind);
    }

    add(line, kind = "yaml", at = null) {
      let html;
      let cls = "cl";
      if (kind === "diff") {
        const [mark, text] = line;
        cls += mark === "+" ? " add" : mark === "-" ? " del" : "";
        html = `${mark === " " ? " " : mark} ${esc(text)}`;
      } else {
        html = kind === "yaml" ? yamlHtml(line) : esc(line);
      }
      const el = h("div", { class: cls, html: html || " " });
      this.code.append(el);
      const row = { el, at, text: kind === "diff" ? line[1] : line };
      this.rows.push(row);
      return row;
    }

    outline(from, to, at, until = Infinity) {
      const el = h("div", { class: "outline" });
      this.el.append(el);
      this.outlines.push({ el, from, to, at, until });
    }

    update(t) {
      for (const row of this.rows) {
        if (row.at == null) continue;
        if (row.typeAt != null) {
          const n = Math.floor(Math.max(0, t - row.typeAt) * 30);
          row.el.innerHTML = yamlHtml(row.text.slice(0, n)) || " ";
        }
        row.el.style.opacity = row.removeAt != null ? 1 - p(t, row.removeAt, 0.3) : p(t, row.at, 0.2);
        row.el.style.display = row.removeAt != null && t > row.removeAt + 0.3 ? "none" : "block";
      }
      for (const o of this.outlines) {
        const top = 52 + 24 + o.from * LINE - 4;
        Object.assign(o.el.style, { left: "16px", right: "16px", top: `${top}px`, height: `${(o.to - o.from + 1) * LINE + 8}px` });
        o.el.style.opacity = Math.min(p(t, o.at, 0.3), 1 - p(t, o.until, 0.3));
      }
    }
  }

  function browser(root, { x, y, w, h: hgt, url }) {
    const el = windowFrame(x, y, w, hgt, null, h("div", { class: "addr", text: url }));
    const view = h("div", { style: { position: "relative", height: `${hgt - 52}px`, overflow: "hidden", background: "#f6f6fb" } });
    const page = h("div", { class: "report" });
    view.append(page);
    el.append(view);
    root.append(el);
    return { el, page, view };
  }

  function canaryHtml(text, canary) {
    return esc(text).replace(esc(canary), `<span class="canary">${esc(canary)}</span>`);
  }

  function reportFinding(S, { expanded = true } = {}) {
    const f = S.finding;
    const el = h("div", { class: "rfind" });
    el.innerHTML =
      `<h2>${esc(f.title)}</h2>` +
      `<div class="row"><span class="sev-pill">${esc(f.severity)}</span><span>Target <b>${esc(f.target)}</b></span><span>Engine <b>${esc(f.engine)}</b></span><span>Check <b>${esc(f.family)}</b></span></div>`;
    const blocks = [];
    if (expanded) {
      const attack = h("div", { class: "rblock", html: `<span class="lbl">Attack</span>${esc(f.attack)}` });
      const reply = h("div", { class: "rblock", html: `<span class="lbl">Reply</span>${canaryHtml(f.leak, f.canary)}` });
      const fix = h("div", { class: "rblock", html: `<span class="lbl">Fix</span>${esc(f.fix)}` });
      const map = h("div", { class: "row", html: `<span>Maps to <b>${esc(f.mapping)}</b></span>` });
      blocks.push(attack, reply, fix, map);
      el.append(attack, reply, fix, map);
    }
    return { el, blocks };
  }

  function reportHeader(S) {
    const wrap = h("div");
    wrap.innerHTML =
      `<h1><img src="/brand/mark-small.svg" alt="">Insidia scan</h1>` +
      `<div class="verdict">${esc(S.report.verdict)}</div>` +
      `<div class="meta">${esc(S.report.scope)}</div>`;
    return wrap;
  }

  function frameworkTable(S) {
    const rows = S.report.frameworks.map((r) => `<tr><td>${esc(r[0])}</td><td>${r[1]}</td><td>${r[2]}</td><td>${r[3]}</td></tr>`).join("");
    return h("table", { html: `<tr><th>Framework</th><th>Failed</th><th>Passed</th><th>Not tested</th></tr>${rows}` });
  }

  function findingCard(root, S, { x, y, w }) {
    const f = S.finding;
    const card = place(h("div", { class: "card" }), x, y, w);
    card.innerHTML =
      `<div class="kicker">Finding · ${esc(f.family)}</div>` +
      `<div style="margin-top:18px;font-size:46px;font-weight:600;letter-spacing:-0.02em;line-height:1.15">${esc(f.title)}</div>` +
      `<div style="margin-top:26px;display:flex;gap:14px;align-items:center"><span class="sev">${esc(f.severity)}</span><span class="chip">${esc(f.engine)}</span><span class="chip">${esc(f.target)}</span></div>` +
      `<div class="field">Reply contained the canary <b class="canary">${esc(f.canary)}</b></div>`;
    root.append(card);
    return card;
  }

  function chat(root, { x, y, w, h: hgt, title }) {
    const el = windowFrame(x, y, w, hgt, title);
    const body = h("div", { style: { padding: "20px 34px", display: "flex", flexDirection: "column" } });
    el.append(body);
    root.append(el);
    return { el, body };
  }

  function bubble(body, who, html) {
    const el = h("div", { class: `bubble ${who}`, html });
    body.append(el);
    return el;
  }

  function endCard(root, S, headline) {
    const wrap = place(h("div", { class: "abs endcard" }), 0, 250, 1920);
    const short = 'uv tool install "git+https://github.com/…/Insidia-Labs#subdirectory=core"';
    wrap.innerHTML =
      `<img src="/brand/lockup-dark.svg" alt="Insidia Labs">` +
      `<h2>${esc(headline.before)}<span class="grad-text">${esc(headline.accent)}</span></h2>` +
      `<div class="install">$ ${esc(short)}<span class="copy">Copy</span></div>` +
      `<div class="url">insidialabs.com</div>`;
    root.append(wrap);
    const parts = [...wrap.children];
    return (t) => parts.forEach((el, i) => show(el, p(t, 0.15 + i * 0.25, 0.6), 24));
  }

  function speedBadge(root, text = "Sped up 4×") {
    const el = h("div", { class: "badge", text, style: { top: "112px", right: "60px" } });
    root.append(el);
    return el;
  }

  window.C = { Terminal, CodePane, browser, reportFinding, reportHeader, frameworkTable, findingCard, chat, bubble, endCard, speedBadge, canaryHtml, windowFrame };
})();
