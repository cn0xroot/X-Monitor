// Visits every dashboard tab in a real headless Chrome and fails on any page exception or console error.
// Needs a running daemon and Chrome. Usage: node scripts/ui_smoke.mjs <base-url> <token> [chrome-path]
import { spawn } from "node:child_process";

const [, , BASE, TOKEN, CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"] = process.argv;
if (!BASE || !TOKEN) { console.error("usage: node scripts/ui_smoke.mjs <base-url> <token> [chrome-path]"); process.exit(2); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PORT = 9350 + Math.floor(Math.random() * 40);
const chrome = spawn(CHROME, ["--headless=new", `--remote-debugging-port=${PORT}`, "--user-data-dir=/tmp/xmon-smoke-" + Date.now(),
  "--no-first-run", "--disable-gpu", "about:blank"], { stdio: "ignore" });
const done = (code) => { try { chrome.kill(); } catch {} process.exit(code); };
setTimeout(() => { console.error("smoke test timed out"); done(1); }, 90000);

async function waitFor(fn, ms = 15000) { const t0 = Date.now(); while (Date.now() - t0 < ms) { try { const v = await fn(); if (v) return v; } catch {} await sleep(200); } throw new Error("timeout"); }
const targets = await waitFor(async () => (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).filter((t) => t.type === "page"));
const ws = new WebSocket(targets[0].webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const problems = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { const p = pending.get(d.id); pending.delete(d.id); d.error ? p.rej(new Error(d.error.message)) : p.res(d.result); return; }
  if (d.method === "Runtime.exceptionThrown") problems.push("exception: " + (d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text));
  if (d.method === "Runtime.consoleAPICalled" && d.params.type === "error") problems.push("console.error: " + d.params.args.map((a) => a.value ?? a.description).join(" "));
};
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); setTimeout(() => rej(new Error("cdp timeout: " + method)), method === "Page.navigate" ? 30000 : 10000); });
const ev = async (e) => { const r = await send("Runtime.evaluate", { expression: e, returnByValue: true, awaitPromise: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || "eval failed"); return r.result.value; };

await send("Page.enable"); await send("Runtime.enable");
// the first navigation of a fresh headless Chrome is occasionally slow: retry instead of failing the run
for (let attempt = 1; ; attempt++) {
  try { await send("Page.navigate", { url: `${BASE}/?token=${TOKEN}` }); break; }
  catch (e) { if (attempt >= 3) throw e; await sleep(1000); }
}
await sleep(3000);
for (const lang of ["zh", "en"]) {
  await ev(`setLang('${lang}')`);
  for (const tab of ["overview", "approvals", "events", "timeline", "sessions", "status", "coverage"]) {
    try { await ev(`(async()=>{ tab('${tab}'); await new Promise(r=>setTimeout(r,900)); })()`); }
    catch (e) { problems.push(`tab ${tab} (${lang}): ${e.message}`); }
  }
  for (const th of ["brand", "dark", "nord"]) { try { await ev(`setTheme('${th}')`); } catch (e) { problems.push(`theme ${th}: ${e.message}`); } }
}
const cards = await ev(`document.querySelectorAll('#detCards .dcard').length + '|' + document.querySelectorAll('#secCards .card').length`);
console.log("detected cards | security cards:", cards);
const uniq = [...new Set(problems)];
console.log(uniq.length ? "FAIL\n  " + uniq.join("\n  ") : "UI smoke test passed: 7 tabs x 2 languages x 3 themes, no page errors");
done(uniq.length ? 1 : 0);
