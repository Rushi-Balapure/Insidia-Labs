// Renders the site videos: serves src/, seeks every frame in headless Chromium, pipes JPEG frames to ffmpeg.
// Usage: node render.mjs howto film   |   node render.mjs --preview
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFile, mkdir, writeFile, rm } from "node:fs/promises";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = dirname(fileURLToPath(import.meta.url));
const roots = {
  "/fonts/": join(here, "..", "public", "fonts"),
  "/brand/": join(here, "..", "public", "brand"),
  "/": join(here, "src"),
};
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".ttf": "font/ttf" };
const FPS = 30;
// Set CHROMIUM_PATH to reuse an already-downloaded browser instead of `npx playwright install chromium`.
const launchOptions = process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {};
const args = process.argv.slice(2);
const preview = args.includes("--preview");
const names = args.filter((a) => !a.startsWith("--"));
const publish = args.includes("--publish");

function serve() {
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const prefix = Object.keys(roots).find((key) => path.startsWith(key));
    const relative = normalize(path.slice(prefix.length)).replace(/^(\.\.[/\\])+/, "");
    const file = join(roots[prefix], relative || "stage.html");
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": types[extname(file)] || "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end();
    }
  });
  return new Promise((resolve) => server.listen(preview ? 4321 : 0, "127.0.0.1", () => resolve(server)));
}

function run(cmd, argv, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, argv, { stdio: [input ? "pipe" : "ignore", "ignore", "pipe"] });
    let err = "";
    child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} exited ${code}\n${err.slice(-2000)}`))));
    if (input) input(child.stdin);
  });
}

const stamp = (t) => {
  const ms = Math.round(t * 1000);
  const hh = String(Math.floor(ms / 3600000)).padStart(2, "0");
  const mm = String(Math.floor((ms % 3600000) / 60000)).padStart(2, "0");
  const ss = String(Math.floor((ms % 60000) / 1000)).padStart(2, "0");
  return `${hh}:${mm}:${ss}.${String(ms % 1000).padStart(3, "0")}`;
};

function vtt(cues) {
  return `WEBVTT\n\n${cues.map((c, i) => `${i + 1}\n${stamp(c.start)} --> ${stamp(c.end)}\n${c.text}\n`).join("\n")}`;
}

function transcript(name, meta) {
  const lines = [`# Transcript: ${name}`, ""];
  if (meta.chapters.length) {
    for (const ch of meta.chapters) {
      lines.push(`## ${stamp(ch.start).slice(3, 8)} ${ch.label}`, "");
      const next = meta.chapters[meta.chapters.indexOf(ch) + 1];
      const end = next ? next.start : meta.duration;
      for (const c of meta.captions.filter((c) => c.start >= ch.start && c.start < end)) lines.push(c.text);
      lines.push("");
    }
  } else {
    for (const c of meta.captions) lines.push(c.text);
  }
  return `${lines.join("\n").trim()}\n`;
}

// A soft pad generated from sine partials with slow, independent swells. No sample, no licence to track.
function music(file, duration) {
  const notes = [110, 164.81, 220, 261.63, 329.63, 392];
  const voices = notes
    .map((f, i) => `(0.5+0.5*sin(2*PI*t/${(9 + i * 3.7).toFixed(1)}+${i}))*sin(2*PI*${f}*t)`)
    .join("+");
  const expr = `0.055*(${voices})`;
  return run("ffmpeg", [
    "-y", "-f", "lavfi", "-i", `aevalsrc=${expr}:s=48000:d=${duration}`,
    "-af", `lowpass=f=1400,aecho=0.8:0.7:60|140:0.25|0.18,afade=t=in:d=2.5,afade=t=out:st=${duration - 3}:d=3,volume=2.4`,
    "-ac", "2", "-c:a", "pcm_s16le", file,
  ]);
}

async function render(browser, base, name) {
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  await page.goto(`${base}/stage.html?v=${name}`);
  await page.evaluate(() => window.stageReady);
  const meta = await page.evaluate(() => window.meta);
  if (publish && meta.placeholder) throw new Error("session.json is placeholder data; refusing to publish");

  const out = publish ? join(here, "..", "public", "video") : join(here, "out");
  const work = join(here, "out", `.work-${name}`);
  await mkdir(out, { recursive: true });
  await mkdir(work, { recursive: true });
  const master = join(work, "master.mp4");
  const audio = join(work, "music.wav");
  const frames = Math.round(meta.duration * FPS);
  const started = Date.now();

  await run("ffmpeg", ["-y", "-f", "image2pipe", "-framerate", String(FPS), "-c:v", "mjpeg", "-i", "-", "-c:v", "libx264", "-preset", "medium", "-crf", "14", "-pix_fmt", "yuv420p", master], async (stdin) => {
    for (let i = 0; i < frames; i++) {
      await page.evaluate((t) => window.seek(t), i / FPS);
      const shot = await page.screenshot({ type: "jpeg", quality: 95 });
      if (!stdin.write(shot)) await new Promise((r) => stdin.once("drain", r));
      if (i % (FPS * 5) === 0) process.stdout.write(`\r${name}: frame ${i}/${frames}`);
    }
    stdin.end();
  });
  process.stdout.write(`\r${name}: ${frames} frames in ${Math.round((Date.now() - started) / 1000)}s\n`);

  await music(audio, meta.duration);
  await run("ffmpeg", ["-y", "-i", master, "-i", audio, "-c:v", "libx264", "-preset", "slow", "-crf", "22", "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-c:a", "aac", "-b:a", "128k", "-shortest", join(out, `${name}.mp4`)]);
  await run("ffmpeg", ["-y", "-i", master, "-i", audio, "-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "36", "-row-mt", "1", "-deadline", "good", "-cpu-used", "4", "-c:a", "libopus", "-b:a", "96k", "-shortest", join(out, `${name}.webm`)]);

  const posterAt = name === "howto" ? 3 : 2;
  await page.evaluate((t) => window.seek(t), posterAt);
  await page.screenshot({ type: "jpeg", quality: 88, path: join(out, `${name}.jpg`) });

  await writeFile(join(out, `${name}.vtt`), vtt(meta.captions));
  if (meta.chapters.length) await writeFile(join(out, `${name}-chapters.vtt`), vtt(meta.chapters.map((c, i, all) => ({ start: c.start, end: all[i + 1]?.start ?? meta.duration, text: c.label }))));
  await writeFile(join(out, `${name}-transcript.md`), transcript(name, meta));
  await rm(work, { recursive: true, force: true });
  await page.close();
  console.log(`${name}: wrote ${out}/${name}.{mp4,webm,jpg,vtt}`);
}

const server = await serve();
const base = `http://127.0.0.1:${server.address().port}`;
const snap = args.find((a) => a.startsWith("--snap="));
if (preview) {
  console.log(`Preview: ${base}/stage.html?v=howto&preview  (or v=film). Space pauses; drag the bar to scrub.`);
} else if (snap) {
  const browser = await chromium.launch(launchOptions);
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
  await mkdir(join(here, "out", "snaps"), { recursive: true });
  for (const name of names) {
    await page.goto(`${base}/stage.html?v=${name}`);
    await page.evaluate(() => window.stageReady);
    for (const t of snap.slice(7).split(",").map(Number)) {
      await page.evaluate((x) => window.seek(x), t);
      await page.screenshot({ type: "jpeg", quality: 80, path: join(here, "out", "snaps", `${name}-${t}.jpg`) });
    }
  }
  await browser.close();
  server.close();
} else {
  const browser = await chromium.launch(launchOptions);
  try {
    for (const name of names.length ? names : ["howto", "film"]) await render(browser, base, name);
  } finally {
    await browser.close();
    server.close();
  }
}
