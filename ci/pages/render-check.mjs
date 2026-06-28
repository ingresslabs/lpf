#!/usr/bin/env node
// End-to-end render check for the GitHub Pages landing page.
//
// Serves docs/ over HTTP, loads docs/index.html in headless Chrome, lets the
// Mermaid module run, then asserts that every diagram produced an <svg> with no
// Mermaid parse/render errors. Exits non-zero on any failure.
//
// Usage: node ci/pages/render-check.mjs
// Env:   CHROME_BIN  override the Chrome/Chromium binary path.

import { createServer } from "node:http";
import { readFile, mkdtemp, writeFile, access } from "node:fs/promises";
import { constants as FS } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const docsDir = path.join(repoRoot, "docs");

const EXPECTED_DIAGRAMS = ["dg-consolidate", "dg-pipeline", "dg-apply", "dg-packet", "dg-ebpf"];

// accDescr text that Mermaid renders into <desc> on each diagram's SVG. After
// mermaid.run() the original source is replaced, so finding this text proves the
// accessible description actually rendered.
const ACC_DESCR = {
  "dg-consolidate": "are unified into a single lpf policy file",
  "dg-pipeline": "policy file flows through check",
  "dg-apply": "states flow from Checked",
  "dg-packet": "packet matched against rules",
  "dg-ebpf": "packets arrive at the NIC",
};

const ERROR_MARKERS = [
  'data-mermaid="error"',
  'aria-roledescription="error"',
  "Syntax error in text",
];
const VIRTUAL_TIME_BUDGET_MS = 25000;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

async function findChrome() {
  const candidates = [
    process.env.CHROME_BIN,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      await access(candidate, FS.X_OK);
      return candidate;
    } catch {
      /* keep looking */
    }
  }
  throw new Error("No Chrome/Chromium binary found. Set CHROME_BIN.");
}

function startServer() {
  const server = createServer(async (req, res) => {
    try {
      const urlPath = decodeURIComponent((req.url || "/").split("?")[0]);
      const rel = urlPath === "/" ? "/index.html" : urlPath;
      const filePath = path.join(docsDir, path.normalize(rel));
      if (!filePath.startsWith(docsDir)) {
        res.writeHead(403).end("forbidden");
        return;
      }
      const body = await readFile(filePath);
      res.writeHead(200, { "content-type": MIME[path.extname(filePath)] || "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

function runChrome(chrome, url) {
  return new Promise(async (resolve, reject) => {
    const profile = await mkdtemp(path.join(tmpdir(), "lpf-pages-"));
    const args = [
      "--headless=new",
      "--disable-gpu",
      "--no-sandbox",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--hide-scrollbars",
      `--user-data-dir=${profile}`,
      "--run-all-compositor-stages-before-draw",
      `--virtual-time-budget=${VIRTUAL_TIME_BUDGET_MS}`,
      "--dump-dom",
      url,
    ];
    const child = spawn(chrome, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), VIRTUAL_TIME_BUDGET_MS + 20000);
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", reject);
    child.on("close", (code) => {
      clearTimeout(timer);
      if (!out.trim()) reject(new Error(`Chrome produced no DOM (exit ${code}). stderr:\n${err.slice(-2000)}`));
      else resolve(out);
    });
  });
}

function sliceForId(dom, id) {
  const idx = dom.indexOf(`id="${id}"`);
  if (idx === -1) return null;
  return dom.slice(idx, idx + 6000);
}

async function main() {
  const failures = [];
  const checks = [];
  const ok = (name) => checks.push(`  ok   ${name}`);
  const fail = (name, detail) => {
    checks.push(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
    failures.push(name);
  };

  const chrome = await findChrome();
  const { server, port } = await startServer();
  const url = `http://127.0.0.1:${port}/index.html`;
  let dom = "";
  try {
    dom = await runChrome(chrome, url);
  } finally {
    server.close();
  }

  const dumpPath = path.join(await mkdtemp(path.join(tmpdir(), "lpf-pages-dom-")), "dom.html");
  await writeFile(dumpPath, dom);

  // ---- static source checks ----
  const src = await readFile(path.join(docsDir, "index.html"), "utf-8");
  const srcCheck = (name, test) => { if (test) ok(`source: ${name}`); else fail(`source: ${name}`); };

  srcCheck("skip link", src.includes('class="skip-link"'));
  srcCheck("main id", src.includes('<main id="main">'));
  srcCheck("og:title", src.includes('<meta property="og:title"'));
  srcCheck("og:description", src.includes('<meta property="og:description"'));
  srcCheck("twitter:card", src.includes('<meta name="twitter:card"'));
  srcCheck("JSON-LD", src.includes('"@type": "SoftwareApplication"'));

  // Regression guard: base .diagram-grid must appear before @media (max-width)
  const diagIdx = src.indexOf("\n    .diagram-grid {");
  const mqIdx = src.indexOf("@media (max-width: 760px)");
  srcCheck(".diagram-grid before @media (760px)", diagIdx > -1 && mqIdx > -1 && diagIdx < mqIdx);

  // ---- DOM checks ----
  dom.includes("PF-style firewall policy engine") ? ok("page content intact") : fail("page content intact");
  dom.includes('id="flow"') ? ok("flow section present") : fail("flow section present");
  dom.includes('id="main"') ? ok("main landmark present") : fail("main landmark present");

  dom.includes('data-mermaid="ready"')
    ? ok("mermaid runtime reached ready state")
    : fail("mermaid runtime reached ready state", "missing data-mermaid=ready");

  for (const marker of ERROR_MARKERS) {
    if (dom.includes(marker)) fail("no mermaid error markers", `found '${marker}'`);
  }
  if (!ERROR_MARKERS.some((m) => dom.includes(m))) ok("no mermaid error markers");

  const processed = (dom.match(/<div class="mermaid"[^>]*data-processed="true"/g) || []).length;
  if (processed !== EXPECTED_DIAGRAMS.length) {
    fail("exact mermaid block count", `processed=${processed}, expected=${EXPECTED_DIAGRAMS.length}`);
  } else {
    ok(`${processed} mermaid blocks processed`);
  }

  for (const id of EXPECTED_DIAGRAMS) {
    const slice = sliceForId(dom, id);
    if (!slice) {
      fail(`diagram ${id} present`, "id not found");
    } else if (!slice.includes("<svg")) {
      fail(`diagram ${id} rendered svg`, "no <svg> after container");
    } else {
      const role = (slice.match(/aria-roledescription="([^"]+)"/) || [])[1] || "?";
      const descOk = ACC_DESCR[id] ? dom.includes(ACC_DESCR[id]) : null;
      let status = `diagram ${id} rendered (${role})`;
      if (descOk !== null) status += descOk ? " + accDescr" : " — accDescr missing";
      descOk === false ? fail(status) : ok(status);
    }
  }

  console.log(`\nlanding-page render check  (chrome: ${path.basename(chrome)})`);
  console.log(`url: ${url}`);
  console.log(checks.join("\n"));

  if (failures.length) {
    console.error(`\nFAILED (${failures.length}). DOM dumped to: ${dumpPath}`);
    process.exit(1);
  }
  console.log(`\nPASS — ${EXPECTED_DIAGRAMS.length} diagrams rendered, 0 errors.`);
}

main().catch((e) => {
  console.error("render-check crashed:", e.message);
  process.exit(2);
});
