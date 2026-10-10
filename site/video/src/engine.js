// Deterministic timeline: every frame is a pure function of t, so the renderer can seek to any frame.
(() => {
  const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
  const ease = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
  const p = (t, start, dur = 0.5) => ease(clamp((t - start) / dur));
  const window01 = (t, start, end, fade = 0.35) => Math.min(p(t, start, fade), 1 - p(t, end - fade, fade));

  function h(tag, attrs = {}, ...kids) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "class") el.className = value;
      else if (key === "style") Object.assign(el.style, value);
      else if (key === "html") el.innerHTML = value;
      else if (key === "text") el.textContent = value;
      else el.setAttribute(key, value);
    }
    for (const kid of kids.flat()) {
      if (kid == null) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  function show(el, v, dy = 18) {
    el.style.opacity = v;
    const base = el.dataset.base || "";
    el.style.transform = `${base} translateY(${(1 - v) * dy}px)`;
  }

  function place(el, x, y, w, hgt) {
    Object.assign(el.style, { left: `${x}px`, top: `${y}px` });
    if (w != null) el.style.width = `${w}px`;
    if (hgt != null) el.style.height = `${hgt}px`;
    return el;
  }

  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

  function makeVideo(duration) {
    const scenes = [];
    const captions = [];
    const chapters = [];
    return {
      duration,
      scenes,
      captions,
      chapters,
      scene(start, dur, build) {
        const root = h("div", { class: "scene" });
        const update = build(root) || (() => {});
        scenes.push({ start, dur, root, update });
      },
      cap(start, end, text, { hidden = false } = {}) {
        captions.push({ start, end, text, hidden });
      },
      chapter(start, label) {
        chapters.push({ start, label });
      },
    };
  }

  function mount(video, stage, session) {
    for (const s of video.scenes) stage.append(s.root);
    const caption = h("div", { id: "caption" });
    const chapter = h("div", { id: "chapter" });
    stage.append(caption, chapter);
    if (session.placeholder) stage.append(h("div", { id: "watermark", text: "Draft · placeholder data" }));

    return function seek(t) {
      for (const s of video.scenes) {
        const local = t - s.start;
        const visible = local >= 0 && local <= s.dur;
        if (!visible) {
          s.root.style.opacity = 0;
          s.root.style.display = "none";
          continue;
        }
        s.root.style.display = "block";
        const fadeIn = s.start === 0 ? 1 : p(local, 0, 0.45);
        const fadeOut = s.start + s.dur >= video.duration ? 1 : 1 - p(local, s.dur - 0.45, 0.45);
        s.root.style.opacity = Math.min(fadeIn, fadeOut);
        s.update(local);
      }
      const cue = video.captions.find((c) => !c.hidden && t >= c.start && t < c.end);
      if (cue) {
        caption.textContent = cue.text;
        caption.style.opacity = window01(t, cue.start, cue.end, 0.25);
      } else {
        caption.style.opacity = 0;
      }
      const chapters = video.chapters.filter((c) => t >= c.start);
      const current = chapters[chapters.length - 1];
      if (current) {
        const index = video.chapters.indexOf(current) + 1;
        chapter.innerHTML = `<b>${String(index).padStart(2, "0")}</b>${esc(current.label)}`;
        chapter.style.opacity = p(t, current.start, 0.4);
      } else {
        chapter.style.opacity = 0;
      }
    };
  }

  window.V = { clamp, ease, p, window01, h, show, place, esc, makeVideo, mount };
  window.VIDEOS = {};
})();
