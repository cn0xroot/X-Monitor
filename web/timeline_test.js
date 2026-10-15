"use strict";
// node web/timeline_test.js — 无框架，失败 exit(1)
const fs = require("fs");
const path = require("path");
const vm = require("vm");

let failed = 0, passed = 0;
function ok(cond, msg) { if (cond) passed++; else { failed++; console.error("FAIL: " + msg); } }
function eq(a, b, msg) { ok(JSON.stringify(a) === JSON.stringify(b), `${msg} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`); }
function noThrow(fn, msg) { try { fn(); passed++; } catch (e) { failed++; console.error("FAIL: " + msg + " threw " + (e && e.stack || e)); } }

// ---- stub DOM ----
function ctx2d() {
  const base = { measureText: (s) => ({ width: String(s).length * 6 }) };
  return new Proxy(base, { get: (t, k) => (k in t ? t[k] : () => undefined), set: (t, k, v) => { t[k] = v; return true; } });
}
class El {
  constructor(tag) {
    this.tag = tag; this.children = []; this.style = {}; this.attrs = {}; this.listeners = {}; this.dataset = {};
    this.width = 300; this.height = 150; this._ih = ""; this.hidden = false; this.parentElement = null;
    const cls = new Set();
    this.classList = { add: (...c) => c.forEach((x) => cls.add(x)), remove: (...c) => c.forEach((x) => cls.delete(x)), contains: (c) => cls.has(c) };
    this.rect = { left: 0, top: 0, width: 800, height: 600 };
    this.className = "";
  }
  set innerHTML(v) { this._ih = v; if (v === "") this.children = []; }
  get innerHTML() { return this._ih; }
  appendChild(c) { c.parentElement = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  remove() { if (this.parentElement) this.parentElement.removeChild(this); }
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter((x) => x !== f); }
  getBoundingClientRect() { return this.rect; }
  getContext() { return (this._ctx = this._ctx || ctx2d()); }
  closest() { return null; }
  disconnect() {}
}
const sandbox = {
  console, Date, Math, JSON, Set, Map, String, Number, Array, Object, Promise, Proxy,
  getComputedStyle: () => ({ getPropertyValue: () => "" }),
  document: {
    documentElement: { lang: "zh-CN" },
    head: new El("head"),
    createElement: (t) => new El(t),
    createElementNS: (ns, t) => new El(t),
    getElementById: () => null,
  },
};
sandbox.window = sandbox;
sandbox.addEventListener = () => {};
sandbox.removeEventListener = () => {};
sandbox.devicePixelRatio = 2;
sandbox.innerWidth = 1200;
vm.createContext(sandbox);
const file = path.join(__dirname, "timeline.js");
const src = fs.readFileSync(file, "utf8");
vm.runInContext(src, sandbox, { filename: file });
const X = sandbox.XTimeline;
ok(X && X.SessionTimeline && X.FlowView && X.i18n && X._test, "XTimeline exposes API");
const T = X._test;

// ---- i18n ----
const zk = Object.keys(X.i18n.zh).sort(), ek = Object.keys(X.i18n.en).sort();
eq(zk, ek, "zh/en key sets identical");
ok(zk.every((k) => k.startsWith("tl.")), "all keys start with tl.");
ok(Object.values(X.i18n.zh).every((v) => v) && Object.values(X.i18n.en).every((v) => v), "no empty strings");
const lits = new Set((src.match(/["'`](tl\.[A-Za-z0-9_.]+)["'`]/g) || []).map((s) => s.slice(1, -1)));
for (const k of lits) if (!k.endsWith(".")) ok(k in X.i18n.zh, "literal key defined: " + k);
for (const s of ["ok", "approved", "blocked", "denied", "warn", "observed"]) ok("tl.status." + s in X.i18n.zh, "status key " + s);
for (const s of ["critical", "high", "medium", "low", "info"]) ok("tl.risk." + s in X.i18n.zh, "risk key " + s);
for (const s of ["op", "observe", "alert", "group"]) ok("tl.type." + s in X.i18n.zh, "type key " + s);
for (const k of zk) {
  const ph = (s) => (s.match(/\{\w+\}/g) || []).sort().join();
  ok(ph(X.i18n.zh[k]) === ph(X.i18n.en[k]), "placeholders match: " + k);
}
eq(T.fallbackT("tl.tt.events", { n: 3 }), "3 个事件", "fallbackT zh");
sandbox.document.documentElement.lang = "en";
eq(T.fallbackT("tl.tt.events", { n: 3 }), "3 events", "fallbackT en");
sandbox.document.documentElement.lang = "zh";

// ---- worstRisk / labels ----
eq(T.worstRisk({ nHigh: 1, nMedium: 5 }), "high", "high wins");
eq(T.worstRisk({ nHigh: 0, nMedium: 1, nLow: 9 }), "medium", "medium");
eq(T.worstRisk({ nLow: 1, nInfo: 5 }), "low", "low");
eq(T.worstRisk({ nInfo: 5 }), "info", "info");
eq(T.worstRisk({}), "info", "empty bucket info");
eq(T.worstRisk({ nCritical: 1 }), "high", "critical -> high");
eq(T.laneName({ label: "p", agent: "a", sessionId: "zs_abcdef123" }), "p", "label");
eq(T.laneName({ label: "", agent: "claude-code", sessionId: "zs_abcdef123" }), "claude-code", "agent fallback");
eq(T.laneName({ sessionId: "zs_abcdef123" }), "zs_abcde", "id fallback");
eq(T.laneFlag({ blockedCount: 1, bypassCount: 1 }), " ■", "blocked flag");
eq(T.laneFlag({ blockedCount: 0, bypassCount: 2 }), " ⚠", "bypass flag");
eq(T.laneFlag({}), "", "no flag");

// ---- ticks ----
const MIN = 60000, HOUR = 3600000, DAY = 24 * HOUR;
eq(T.tickStepFor(HOUR), 10 * MIN, "step 1h");
eq(T.tickStepFor(6 * HOUR), HOUR, "step 6h");
eq(T.tickStepFor(DAY), 3 * HOUR, "step 24h");
eq(T.tickStepFor(7 * DAY), DAY, "step 7d");
for (const [start, step] of [[1760000000000, 3 * HOUR], [1760000123456, HOUR], [1760000123456, 10 * MIN], [1760000123456, DAY]]) {
  const t0 = T.firstTick(start, step);
  const d = new Date(t0);
  ok(t0 >= start && t0 - start < step + HOUR, `firstTick within step (${step})`);
  if (step === 3 * HOUR) ok(d.getHours() % 3 === 0 && d.getMinutes() === 0 && d.getSeconds() === 0, "3h tick aligned to local hour%3");
  if (step === HOUR) ok(d.getMinutes() === 0, "1h tick on the hour");
  if (step === 10 * MIN) ok(d.getMinutes() % 10 === 0 && d.getSeconds() === 0, "10m tick aligned");
  if (step === DAY) ok(d.getHours() === 0 && d.getMinutes() === 0, "day tick at local midnight");
}
eq(T.tickLabel(new Date(2026, 0, 5, 0, 0, 0).getTime(), 3 * HOUR), "1/5", "midnight label has date");
eq(T.tickLabel(new Date(2026, 0, 5, 3, 0, 0).getTime(), 3 * HOUR), "03:00", "hm label");

// ---- 数据构造 ----
function makeData(nBuckets, lanes, rangeMinutes, bucketMs) {
  const now = 1760000000000;
  const aligned = Math.floor(now / bucketMs) * bucketMs;
  const bc = Math.round((rangeMinutes * 60000) / bucketMs);
  const L = [];
  for (let l = 0; l < lanes; l++) {
    const buckets = [];
    for (let i = 0; i < nBuckets; i++) {
      const idx = (i * 7 + l * 3) % bc;
      if (buckets.some((b) => b.startMs === aligned - idx * bucketMs)) continue;
      buckets.push({ startMs: aligned - idx * bucketMs, n: 1 + (i % 9), nHigh: i % 5 === 0 ? 1 : 0, nMedium: i % 3 === 0 ? 1 : 0, nLow: 1, nInfo: 0, nBlocked: i % 4 === 0 ? 1 : 0 });
    }
    L.push({ sessionId: "zs_lane" + l, label: "lane" + l, agent: "claude-code", cwd: "/x", managed: true, eventCount: 10, blockedCount: l % 2, bypassCount: 0, firstTs: 0, lastTs: 0, buckets });
  }
  return { rangeMinutes, bucketMs, now, lanes: L };
}

// ---- 命中测试 / 绘制公式对称性 ----
for (const [cssW, rangeMin, bms, nb] of [[1000, 1440, 900000, 96], [733.3, 60, 60000, 60], [1234, 10080, 3600000, 168], [260, 1440, 900000, 40], [201, 360, 300000, 70]]) {
  const data = makeData(nb, 4, rangeMin, bms);
  const g = T.geometry(data, cssW);
  let checked = 0;
  data.lanes.forEach((lane, li) => {
    const laneMax = lane.buckets.reduce((m, b) => Math.max(m, b.n), 1);
    for (const b of lane.buckets) {
      const r = T.barRect(g, b, laneMax, li);
      ok(r !== null, "bucket inside window");
      if (!r) continue;
      const cx = r.bx + g.bucketW / 2;
      const cy = T.consts.AXIS_HEIGHT + li * T.consts.LANE_HEIGHT + T.consts.LANE_HEIGHT / 2;
      const hit = T.hitTest(data, cssW, cx, cy);
      ok(hit && hit.lane === lane && hit.bucket === b, `symmetry cssW=${cssW} lane=${li} start=${b.startMs}`);
      const h2 = T.hitTest(data, cssW, r.bx + 0.01, cy), h3 = T.hitTest(data, cssW, r.bx + g.bucketW - 0.01, cy);
      ok(h2 && h2.bucket === b && h3 && h3.bucket === b, "edges hit same bucket");
      checked++;
    }
  });
  ok(checked > 0, "checked some buckets");
}
{
  const data = makeData(5, 2, 1440, 900000);
  eq(T.hitTest(data, 1000, 50, 5), null, "axis row -> null");
  eq(T.hitTest(data, 1000, 50, 22 + 2 * 30 + 1), null, "below lanes -> null");
  const lblHit = T.hitTest(data, 1000, 50, 30);
  ok(lblHit && lblHit.bucket === null && lblHit.laneIndex === 0, "label area -> lane, bucket null");
  eq(T.hitTest(null, 1000, 5, 5), null, "null data");
  ok(T.hitTest(data, 1000, 1500, 30).bucket === null, "beyond plot -> no bucket");
}

// ---- SessionTimeline render ----
function mkCanvas(width) {
  const parent = new El("div"); parent.rect = { left: 0, top: 0, width, height: 400 };
  const c = new El("canvas"); parent.appendChild(c);
  c.rect = { left: 0, top: 0, width, height: 400 };
  return c;
}
{
  const canvas = mkCanvas(900), tip = new El("div");
  let tl;
  noThrow(() => { tl = new X.SessionTimeline(canvas, tip); }, "construct SessionTimeline");
  noThrow(() => tl.render(), "render with null data");
  noThrow(() => tl.setData({ rangeMinutes: 1440, bucketMs: 900000, now: 1760000000000, lanes: [] }), "empty lanes");
  noThrow(() => tl.setData(makeData(1, 1, 1440, 900000)), "single bucket");
  noThrow(() => tl.setData(makeData(96, 50, 1440, 900000)), "many buckets");
  noThrow(() => tl.setData(makeData(168, 3, 10080, 3600000)), "7d");
  noThrow(() => tl.setData({ lanes: [{ sessionId: "unattributed", buckets: [] }] }), "sparse fields");
  noThrow(() => tl.setData(null), "null data");
  tl.setData(makeData(10, 2, 1440, 900000));
  const w0 = canvas.width;
  ok(w0 === 1800, "HiDPI canvas width = css*dpr (" + w0 + ")");
  canvas.parentElement.rect = { left: 0, top: 0, width: 0, height: 0 };
  tl._resize();
  ok(canvas.width === w0 && canvas.width > 1, "hidden (width 0) keeps canvas size");
  canvas.parentElement.rect = { left: 0, top: 0, width: 900, height: 400 };
  tl._resize();
  const data = tl.data, lane = data.lanes[1], b = lane.buckets[0];
  const g = T.geometry(data, tl._cssWidth());
  const r = T.barRect(g, b, 1, 1);
  const ev = { clientX: r.bx + g.bucketW / 2, clientY: 22 + 30 + 15 };
  let got = null;
  tl.onLaneClick = (id, range) => (got = { id, range });
  tl._onClick(ev);
  ok(got && got.id === lane.sessionId && got.range && got.range.startMs === b.startMs && got.range.endMs === b.startMs + 900000, "click -> lane + range");
  tl._onClick({ clientX: 10, clientY: 22 + 15 });
  ok(got.range === null, "click label -> range null");
  noThrow(() => tl._onMouseMove(ev), "tooltip fallback");
  ok(tip.hidden === false && tip.innerHTML.includes("个事件"), "fallback tooltip uses t() (zh)");
  tl.t = (k, p) => X.i18n.en[k].replace(/\{(\w+)\}/g, (m, n) => p[n]);
  tl._onMouseMove(ev);
  ok(tip.innerHTML.includes("events"), "custom t used");
  tl.tooltipHtml = (l, bk, ms) => `X${l.sessionId}|${bk && bk.n}|${ms}`;
  tl._onMouseMove(ev);
  ok(tip.innerHTML.startsWith("X" + lane.sessionId), "custom tooltipHtml used");
  tl._onMouseMove({ clientX: 10, clientY: 3 });
  ok(tip.hidden === true, "tooltip hidden off lanes");
  noThrow(() => tl.destroy(), "destroy");
}

// ---- Flow 布局 ----
function node(i, o) {
  return Object.assign({ id: "ev_" + i, type: "op", layer: "L4", tool: "Bash", class: "exec.shell", title: "", summary: "cmd " + i, startTs: 1759999000000 + i * 1000, endTs: 0, risk: "low", decision: "allow", status: "ok", rule: "", branch: false, count: 1, eventIds: ["ev_" + i] }, o || {});
}
const flowEmpty = { sessionId: "zs_1", agent: "a", cwd: "", eventCount: 0, truncated: false, turns: [] };
{
  const L = T.layoutFlow(flowEmpty);
  eq(L.nodes.length, 0, "empty layout nodes");
  ok(L.worldW > 0 && L.worldH > 0, "empty layout has size");
  eq(T.layoutFlow(null).nodes.length, 0, "null flow layout");
}
const kinds = [
  node(1), node(2, { status: "approved" }), node(3, { status: "blocked", risk: "high", decision: "block", rule: "dangerous_delete" }), node(4, { status: "denied" }),
  node(5, { status: "warn", risk: "critical" }), node(6, { type: "observe", status: "observed", layer: "L2", tool: "" }),
  node(7, { type: "alert", status: "warn" }), node(8, { type: "group", count: 12, status: "observed", eventIds: ["a", "b"] }),
  node(9, { branch: true, class: "agent.spawn", tool: "Task" }), node(10, { branch: true, tool: "Task" }), node(11, { title: "<b>x</b>", summary: "<script>" }),
];
const flowMixed = { sessionId: "zs_1", truncated: true, turns: [{ index: 1, startTs: 1759999000000, endTs: 1759999900000, nodes: kinds }, { index: 2, startTs: 0, endTs: 0, nodes: [] }, { index: 3, startTs: 1759999950000, endTs: 0, nodes: [node(20)] }] };
{
  const L = T.layoutFlow(flowMixed);
  eq(L.nodes.length, 3 + 11 + 1, "mixed layout node count");
  const main = L.nodes.filter((n) => n.kind === "node" && !n.data.branch);
  ok(main.every((n) => n.x === -150), "main column centered");
  const br = L.nodes.filter((n) => n.data && n.data.branch);
  eq(br.length, 2, "two branch nodes");
  ok(br[1].py >= br[0].py + 84, "branches stack without overlap");
  ok(br.every((n) => n.x > 150), "branch to the right");
  const ys = L.nodes.filter((n) => !(n.data && n.data.branch)).map((n) => n.py);
  ok(ys.every((y, i) => i === 0 || y > ys[i - 1]), "main nodes y strictly increasing");
  ok(L.nodes.every((n) => n.px >= 0 && n.py >= 0 && n.px + n.w <= L.worldW && n.py + n.h <= L.worldH), "all nodes inside world");
  eq(L.edges.length, L.nodes.length - 1, "edges = nodes-1");
  ok(L.edges.every((e) => /^M[\d.\-]+,[\d.\-]+ C/.test(T.edgePath(L, e))), "edge paths well-formed");
  const hits = T.rangeHits(flowMixed, 1759999003000, 1759999005000);
  eq([...hits.keys].length, 2, "rangeHits count [3s,5s)");
  eq(hits.firstKey, "n0_2", "rangeHits first");
  eq(T.rangeHits(flowMixed, 1, 2).firstKey, null, "rangeHits none");
}
{
  const v = T.zoomView({ x: 10, y: 20, k: 1 }, 100, 100, 2);
  eq(v.k, 2, "zoom k");
  eq([(100 - v.x) / v.k, (100 - v.y) / v.k], [90, 80], "zoom keeps anchor point");
  eq(T.zoomView({ x: 0, y: 0, k: 2.5 }, 0, 0, 5).k, 2.5, "zoom clamped max");
  eq(T.zoomView({ x: 0, y: 0, k: 0.1 }, 0, 0, 0.1).k, 0.1, "zoom clamped min");
  const f = T.fitView(1000, 2000, 500, 500);
  ok(Math.abs(f.k - 0.25) < 1e-9 && Math.abs(f.x - 125) < 1e-9, "fitView");
  const big = { sessionId: "zs_big", turns: [{ index: 1, startTs: 1, endTs: 2, nodes: Array.from({ length: 600 }, (_, i) => node(i, { branch: i % 50 === 49 })) }] };
  const L = T.layoutFlow(big);
  eq(L.nodes.length, 601, "600 nodes layout");
  const vis = T.visibleNodes(L, T.visibleRect({ x: 0, y: 0, k: 1 }, 800, 600, T.consts.CULL_MARGIN));
  ok(vis.length > 0 && vis.length < 40, "culling keeps few cards: " + vis.length);
}

// ---- FlowView ----
function mkFlow() {
  const c = new El("div"); c.rect = { left: 0, top: 0, width: 900, height: 600 };
  return c;
}
{
  const calls = [];
  const t = (k, p) => { calls.push(k); return (X.i18n.en[k] || k).replace(/\{(\w+)\}/g, (m, n) => (p && p[n] !== undefined ? p[n] : m)); };
  const c = mkFlow();
  let fv;
  noThrow(() => { fv = new X.FlowView(c, { t, onNodeClick: () => {} }); }, "construct FlowView");
  noThrow(() => fv.setData(flowEmpty), "setData empty turns");
  ok(fv.emptyEl.hidden === false && fv.emptyEl.textContent === "No operations recorded for this session", "empty state text via t");
  noThrow(() => fv.setData(flowMixed), "setData mixed");
  ok(fv.note.hidden === false, "truncated note shown");
  noThrow(() => fv.fit(), "fit");
  noThrow(() => fv.highlightRange(1759999003000, 1759999005000), "highlightRange");
  ok(fv.highlight.size === 2, "highlight set");
  noThrow(() => fv.highlightRange(null), "highlight clear");
  ok(fv.highlight.size === 0, "highlight cleared");
  const big = { sessionId: "zs_big", turns: [{ index: 1, startTs: 1, endTs: 2, nodes: Array.from({ length: 600 }, (_, i) => node(i, { status: ["ok", "approved", "blocked", "denied", "warn", "observed"][i % 6], type: ["op", "observe", "alert", "group"][i % 4], branch: i % 40 === 39 })) }] };
  noThrow(() => fv.setData(big), "setData 600 nodes");
  ok(fv.live.size > 0 && fv.live.size < 60, "DOM cards culled: " + fv.live.size);
  noThrow(() => fv._zoomAt(400, 300, 0.2), "zoom out");
  noThrow(() => fv._applyView(), "applyView");
  ok(fv.live.size >= 1, "cards after zoom");
  const key = [...fv.live.keys()].find((k) => k.startsWith("n"));
  const el = fv.live.get(key);
  let clicked = null;
  fv.onNodeClick = (n) => (clicked = n);
  el.closest = (sel) => (sel === ".xtl-card" ? el : null);
  fv._click(el);
  ok(clicked && fv.detail.hidden === false && fv.detail.innerHTML.includes("Event IDs"), "click opens detail");
  fv._closeDetail();
  ok(fv.detail.hidden === true, "detail closed");
  fv.setData(Object.assign({}, flowMixed, { sessionId: "zs_x" }));
  const html = [...fv.live.values()].map((e) => e.innerHTML).join("");
  ok(html.length > 0 && !html.includes("<script>") && !html.includes("<b>x</b>"), "card html escapes content");
  ok(fv._cardHtml(fv.byKey.get("n0_1")).includes("xtl-tag") && fv._cardHtml(fv.byKey.get("n0_1")).includes("Approved"), "approved tag rendered");
  const c2 = mkFlow(); c2.rect = { left: 0, top: 0, width: 0, height: 0 };
  const fv2 = new X.FlowView(c2, { t });
  noThrow(() => fv2.setData(flowMixed), "setData in hidden container");
  noThrow(() => fv2.fit(), "fit in hidden container");
  c2.rect = { left: 0, top: 0, width: 900, height: 600 };
  noThrow(() => fv2._handleResize(), "resize after becoming visible");
  ok(!fv2._pendingInit, "pending init resolved");
  noThrow(() => fv.destroy(), "destroy");
  for (const k of new Set(calls)) ok(k in X.i18n.en || /^tl\.(status|risk|type|decision)\./.test(k), "t key known: " + k);
}

console.log(`${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
