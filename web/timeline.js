"use strict";
// Adapted from CC-Monitor (https://github.com/cn0xroot/cc-monitor, MIT License) — session-timeline.js / session-flow.js
//
// X-Monitor 操作时间线模块（自包含，零依赖，不发网络请求，不用 localStorage）。
// 只暴露 window.XTimeline = { SessionTimeline, FlowView, i18n, _test }。
//
// 与原版的差异：
//  * 数据来源不同：泳道图吃 /api/timeline，流程图吃 /api/session-flow（字段见各 setData 注释），
//    不再依赖原版的 prompt / matchedRule / summaryHtml 等字段。
//  * 泳道名称用 lane.label（空则 agent，再空则 sessionId 前 8 位），风险色读本项目 CSS 变量
//    (--high/--medium/--low/--info)，critical 与 high 同色并计入 nHigh。
//  * 文案全部走 t()：SessionTimeline.prototype.t（可外部赋值）/ FlowView 的 opts.t；
//    本文件自带 i18n.zh / i18n.en 字典（key 一律 tl. 开头）。
//  * 流程图：滚轮 = 以鼠标为中心缩放（原版是平移，Ctrl 才缩放）；节点类型换成 op/observe/alert/group，
//    status 换成 ok/approved/blocked/denied/warn/observed；group 卡不可展开（接口只给条数）；
//    去掉了原版的"按轮折叠"；点击卡片在视口内弹出详情面板，而不是外部回调的唯一出口。
//  * 性能：卡片是 DOM，节点 >几百时只渲染视口附近（外扩 300px）的卡片，平移/缩放时增量增删；
//    SVG 连线是单层 path，几千条仍然很便宜，所以不做裁剪。
//  * 自带样式：FlowView 首次构造时向 <head> 注入一个 <style id="xtl-style">（不需要改 index.html）。
(function () {
  // ======================================================================
  // i18n
  // ======================================================================
  const i18n = {
    zh: {
      "tl.tt.events": "{n} 个事件",
      "tl.tt.blocked": "{n} 个被拦截",
      "tl.tt.total": "该会话共 {n} 个事件",
      "tl.tt.bypass": "疑似绕过 {n} 次",
      "tl.tt.risks": "高 {h} · 中 {m} · 低 {l} · 信息 {i}",
      "tl.tt.hint": "点击查看",
      "tl.risk.critical": "严重",
      "tl.risk.high": "高",
      "tl.risk.medium": "中",
      "tl.risk.low": "低",
      "tl.risk.info": "信息",
      "tl.lane.unnamed": "未命名会话",
      "tl.flow.turn": "第 {n} 轮",
      "tl.flow.ops": "{n} 个操作",
      "tl.flow.group": "{n} 条同类观测",
      "tl.flow.empty": "该会话暂无操作记录",
      "tl.flow.truncated": "事件过多，仅显示部分",
      "tl.flow.zoomIn": "放大",
      "tl.flow.zoomOut": "缩小",
      "tl.flow.fit": "适应窗口",
      "tl.flow.minimap": "小地图",
      "tl.flow.branch": "子 Agent",
      "tl.flow.blockedN": "拦截 {n}",
      "tl.flow.approvedTag": "已批准",
      "tl.flow.noTime": "时间未知",
      "tl.status.ok": "成功",
      "tl.status.approved": "已批准",
      "tl.status.blocked": "已拦截",
      "tl.status.denied": "已拒绝",
      "tl.status.warn": "警告",
      "tl.status.observed": "观测",
      "tl.type.op": "工具调用",
      "tl.type.observe": "系统观测",
      "tl.type.alert": "告警",
      "tl.type.group": "观测合集",
      "tl.decision.allow": "放行",
      "tl.decision.block": "拦截",
      "tl.decision.confirm": "需确认",
      "tl.decision.approve": "已批准",
      "tl.decision.deny": "已拒绝",
      "tl.detail.title": "节点详情",
      "tl.detail.close": "关闭",
      "tl.detail.summary": "摘要",
      "tl.detail.rule": "命中规则",
      "tl.detail.decision": "决策",
      "tl.detail.layer": "层",
      "tl.detail.class": "分类",
      "tl.detail.tool": "工具",
      "tl.detail.risk": "风险",
      "tl.detail.status": "状态",
      "tl.detail.time": "时间",
      "tl.detail.count": "条数",
      "tl.detail.events": "事件 ID",
      "tl.detail.none": "无",
      "tl.detail.moreIds": "…等共 {n} 个",
    },
    en: {
      "tl.tt.events": "{n} events",
      "tl.tt.blocked": "{n} blocked",
      "tl.tt.total": "{n} events in this session",
      "tl.tt.bypass": "{n} suspected bypasses",
      "tl.tt.risks": "high {h} · medium {m} · low {l} · info {i}",
      "tl.tt.hint": "Click to inspect",
      "tl.risk.critical": "Critical",
      "tl.risk.high": "High",
      "tl.risk.medium": "Medium",
      "tl.risk.low": "Low",
      "tl.risk.info": "Info",
      "tl.lane.unnamed": "Unnamed session",
      "tl.flow.turn": "Turn {n}",
      "tl.flow.ops": "{n} operations",
      "tl.flow.group": "{n} similar observations",
      "tl.flow.empty": "No operations recorded for this session",
      "tl.flow.truncated": "Too many events, showing a subset",
      "tl.flow.zoomIn": "Zoom in",
      "tl.flow.zoomOut": "Zoom out",
      "tl.flow.fit": "Fit to window",
      "tl.flow.minimap": "Minimap",
      "tl.flow.branch": "Sub-agent",
      "tl.flow.blockedN": "blocked {n}",
      "tl.flow.approvedTag": "Approved",
      "tl.flow.noTime": "time unknown",
      "tl.status.ok": "OK",
      "tl.status.approved": "Approved",
      "tl.status.blocked": "Blocked",
      "tl.status.denied": "Denied",
      "tl.status.warn": "Warning",
      "tl.status.observed": "Observed",
      "tl.type.op": "Tool call",
      "tl.type.observe": "System observation",
      "tl.type.alert": "Alert",
      "tl.type.group": "Observation group",
      "tl.decision.allow": "Allowed",
      "tl.decision.block": "Blocked",
      "tl.decision.confirm": "Needs confirmation",
      "tl.decision.approve": "Approved",
      "tl.decision.deny": "Denied",
      "tl.detail.title": "Node details",
      "tl.detail.close": "Close",
      "tl.detail.summary": "Summary",
      "tl.detail.rule": "Matched rule",
      "tl.detail.decision": "Decision",
      "tl.detail.layer": "Layer",
      "tl.detail.class": "Class",
      "tl.detail.tool": "Tool",
      "tl.detail.risk": "Risk",
      "tl.detail.status": "Status",
      "tl.detail.time": "Time",
      "tl.detail.count": "Count",
      "tl.detail.events": "Event IDs",
      "tl.detail.none": "none",
      "tl.detail.moreIds": "… {n} in total",
    },
  };

  // ======================================================================
  // 通用小工具
  // ======================================================================
  const MIN = 60 * 1000;
  const HOUR = 60 * MIN;
  const DAY = 24 * HOUR;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function pad2(n) {
    return String(n).padStart(2, "0");
  }
  function fmt(str, params) {
    if (!params) return str;
    return String(str).replace(/\{(\w+)\}/g, (m, k) => (params[k] === undefined ? m : params[k]));
  }
  // 内部兜底翻译：按 <html lang> 取字典（zh* → zh，其它 → en）
  function fallbackT(key, params) {
    let lang = "zh";
    try {
      lang = String((document.documentElement && document.documentElement.lang) || "zh").toLowerCase();
    } catch (e) {}
    const dict = lang.indexOf("zh") === 0 || !lang ? i18n.zh : i18n.en;
    const s = dict[key] !== undefined ? dict[key] : i18n.en[key] !== undefined ? i18n.en[key] : key;
    return fmt(s, params);
  }
  // 取翻译；外部 t 对未知 key 通常原样返回 key，这时用 fallback（可为 null）
  function tr(t, key, fallback, params) {
    const s = t(key, params);
    if (s === key || s == null || s === "") return fallback;
    return s;
  }
  function readVar(name, fallback) {
    try {
      const v = getComputedStyle(document.documentElement).getPropertyValue(name);
      const s = v ? String(v).trim() : "";
      return s || fallback;
    } catch (e) {
      return fallback;
    }
  }
  function themeColors() {
    const high = readVar("--high", "#f85149");
    return {
      critical: readVar("--critical", high),
      high,
      medium: readVar("--medium", "#d29922"),
      low: readVar("--low", "#3fb950"),
      info: readVar("--info", "#6b7686"),
      accent: readVar("--accent", "#4c8dff"),
      border: readVar("--border", "#2a3140"),
      fg: readVar("--fg", "#e6edf3"),
      muted: readVar("--muted", "#8b98a9"),
      panel: readVar("--panel", "#161b22"),
      panel2: readVar("--panel2", "#1c2230"),
      bg: readVar("--bg", "#0e1116"),
      allow: readVar("--allow", "#3fb950"),
      block: readVar("--block", "#f85149"),
      confirm: readVar("--confirm", "#d29922"),
    };
  }

  // ======================================================================
  // 泳道图：纯函数
  // ======================================================================
  const LANE_HEIGHT = 30;
  const LABEL_WIDTH = 200;
  const AXIS_HEIGHT = 22;
  const DEFAULT_BUCKET_MS = 15 * MIN;

  function tickStepFor(rangeMs) {
    if (rangeMs <= HOUR) return 10 * MIN;
    if (rangeMs <= 6 * HOUR) return HOUR;
    if (rangeMs <= DAY) return 3 * HOUR;
    return DAY;
  }

  // 刻度按本地时间对齐（整点 / 整 3 小时 / 零点），不是按 epoch 取整（非整点时区会错位）。
  function firstTick(startMs, stepMs) {
    const d = new Date(startMs);
    if (stepMs >= DAY) {
      d.setHours(0, 0, 0, 0);
    } else if (stepMs >= HOUR) {
      d.setMinutes(0, 0, 0);
      d.setHours(d.getHours() - (d.getHours() % (stepMs / HOUR)));
    } else {
      d.setSeconds(0, 0);
      d.setMinutes(d.getMinutes() - (d.getMinutes() % (stepMs / MIN)));
    }
    let t = d.getTime();
    while (t < startMs) t += stepMs;
    return t;
  }

  function tickLabel(ms, stepMs) {
    const d = new Date(ms);
    if (stepMs >= DAY) return `${d.getMonth() + 1}/${d.getDate()}`;
    const hm = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
    return d.getHours() === 0 && d.getMinutes() === 0 ? `${d.getMonth() + 1}/${d.getDate()}` : hm;
  }

  // 桶内最差风险。critical 与 high 同色（接口把 critical 计入 nHigh；若同时给了 nCritical 也认）。
  function worstRisk(b) {
    if ((b.nHigh || 0) > 0 || (b.nCritical || 0) > 0) return "high";
    if ((b.nMedium || 0) > 0) return "medium";
    if ((b.nLow || 0) > 0) return "low";
    return "info";
  }

  function laneName(lane, t) {
    const id = String(lane.sessionId || "");
    return lane.label || lane.agent || id.slice(0, 8) || (t ? t("tl.lane.unnamed") : "");
  }
  function laneFlag(lane) {
    return lane.blockedCount > 0 ? " ■" : lane.bypassCount > 0 ? " ⚠" : "";
  }

  // 共享几何：绘制与命中测试都用它，保证两边公式一致。
  function geometry(data, cssW) {
    const bucketMs = data.bucketMs > 0 ? data.bucketMs : DEFAULT_BUCKET_MS;
    const rangeMinutes = data.rangeMinutes > 0 ? data.rangeMinutes : 1440;
    const bucketCount = Math.max(1, Math.round((rangeMinutes * MIN) / bucketMs));
    const plotX0 = LABEL_WIDTH;
    const plotW = Math.max(1, cssW - LABEL_WIDTH);
    const bucketW = plotW / bucketCount;
    const now = data.now > 0 ? data.now : Date.now();
    const alignedNow = Math.floor(now / bucketMs) * bucketMs;
    return { bucketMs, bucketCount, plotX0, plotW, bucketW, alignedNow };
  }
  // 桶离"当前桶"几个桶（0 = 当前桶）
  function bucketIndexFromNow(g, b) {
    return Math.round((g.alignedNow - b.startMs) / g.bucketMs);
  }
  // 绘制：桶左边缘 x；窗口外返回 null
  function bucketX(g, b) {
    const i = bucketIndexFromNow(g, b);
    if (i < 0 || i >= g.bucketCount) return null;
    return g.plotX0 + (g.bucketCount - 1 - i) * g.bucketW;
  }
  // 命中：x → 离现在几个桶；超出绘图区返回 null
  function indexFromNowAtX(g, x) {
    const slot = Math.floor((x - g.plotX0) / g.bucketW);
    if (slot < 0 || slot >= g.bucketCount) return null;
    return g.bucketCount - 1 - slot;
  }
  function laneIndexAtY(data, y) {
    const li = Math.floor((y - AXIS_HEIGHT) / LANE_HEIGHT);
    if (li < 0 || li >= data.lanes.length) return -1;
    return li;
  }
  // 纯命中测试：返回 {laneIndex, lane, bucket} 或 null
  function hitTest(data, cssW, x, y) {
    if (!data || !data.lanes) return null;
    const li = laneIndexAtY(data, y);
    if (li < 0) return null;
    const lane = data.lanes[li];
    if (x < LABEL_WIDTH) return { laneIndex: li, lane, bucket: null };
    const g = geometry(data, cssW);
    const idx = indexFromNowAtX(g, x);
    let bucket = null;
    if (idx !== null) {
      const bs = lane.buckets || [];
      for (let i = 0; i < bs.length; i++) {
        if (bucketIndexFromNow(g, bs[i]) === idx) {
          bucket = bs[i];
          break;
        }
      }
    }
    return { laneIndex: li, lane, bucket };
  }
  // 柱子矩形（绘制用，测试也可校验）
  function barRect(g, b, laneMaxN, laneIndex) {
    const bx = bucketX(g, b);
    if (bx === null) return null;
    const y0 = AXIS_HEIGHT + laneIndex * LANE_HEIGHT;
    const heightFrac = Math.max(0.14, Math.min(1, b.n / Math.max(1, laneMaxN)));
    const barH = Math.max(3, heightFrac * (LANE_HEIGHT - 6));
    return { bx, x: bx + 1, y: y0 + LANE_HEIGHT - 3 - barH, w: Math.max(1, g.bucketW - 2), h: barH };
  }

  function truncateText(ctx, text, maxWidth) {
    if (!(ctx.measureText(text).width > maxWidth)) return text;
    let s = text;
    while (s.length > 1 && ctx.measureText(s + "…").width > maxWidth) s = s.slice(0, -1);
    return s + "…";
  }

  // ======================================================================
  // SessionTimeline
  // ======================================================================
  class SessionTimeline {
    constructor(canvas, tooltipEl) {
      this.canvas = canvas;
      this.tooltipEl = tooltipEl;
      this.ctx = canvas.getContext("2d");
      this.data = null; // /api/timeline 响应
      this.onLaneClick = null; // (laneSessionId, {startMs,endMs}|null) => void
      this.tooltipHtml = null; // (lane, bucket|null, bucketMs) => html，可选
      this.dpr = 1;
      this._cssW = 0;
      this._onResize = () => this._resize();
      this._onMove = (ev) => this._onMouseMove(ev);
      this._onLeave = () => this._hideTooltip();
      this._onClickEv = (ev) => this._onClick(ev);
      window.addEventListener("resize", this._onResize);
      canvas.addEventListener("mousemove", this._onMove);
      canvas.addEventListener("mouseleave", this._onLeave);
      canvas.addEventListener("click", this._onClickEv);
      // 容器从 display:none 变可见时 window 不会触发 resize，用 ResizeObserver 补一刀（有则用）。
      this._ro = null;
      try {
        if (typeof ResizeObserver !== "undefined" && canvas.parentElement) {
          this._ro = new ResizeObserver(() => this._resize());
          this._ro.observe(canvas.parentElement);
        }
      } catch (e) {
        this._ro = null;
      }
      this._resize();
    }

    _t(key, params) {
      return (this.t || fallbackT)(key, params);
    }

    setData(data) {
      this.data = data && Array.isArray(data.lanes) ? data : data ? Object.assign({}, data, { lanes: [] }) : null;
      this._resize();
    }

    destroy() {
      window.removeEventListener("resize", this._onResize);
      this.canvas.removeEventListener("mousemove", this._onMove);
      this.canvas.removeEventListener("mouseleave", this._onLeave);
      this.canvas.removeEventListener("click", this._onClickEv);
      if (this._ro) this._ro.disconnect();
      this._hideTooltip();
    }

    _resize() {
      const dpr = Math.min((typeof window !== "undefined" && window.devicePixelRatio) || 1, 2);
      const laneCount = this.data ? this.data.lanes.length : 0;
      const host = this.canvas.parentElement || this.canvas;
      const rect = host.getBoundingClientRect();
      // 页面隐藏（display:none）时量出来宽度是 0：此时若照样改 canvas.width，位图会缩成 1px 再被 CSS
      // 拉伸，切回来看到的是一片空图（原版踩过的坑）。隐藏时直接跳过，等下次可见时再量。
      if (!rect || !(rect.width > 0)) return;
      const cssHeight = AXIS_HEIGHT + Math.max(1, laneCount) * LANE_HEIGHT;
      this.canvas.style.height = cssHeight + "px";
      const w = Math.max(1, Math.round(rect.width * dpr));
      const h = Math.max(1, Math.round(cssHeight * dpr));
      if (this.canvas.width !== w || this.canvas.height !== h) {
        this.canvas.width = w;
        this.canvas.height = h;
      }
      this.dpr = dpr;
      this._cssW = rect.width; // 绘制与命中测试共用同一个宽度，避免 round(w*dpr)/dpr 带来的偏差
      this.render();
    }

    _cssWidth() {
      return this._cssW || this.canvas.width / (this.dpr || 1);
    }

    // 命中测试公式与 render() 共用 geometry()/bucketIndexFromNow()，保证对称。
    _hitTest(ev) {
      const box = this.canvas.getBoundingClientRect();
      return hitTest(this.data, this._cssWidth(), ev.clientX - box.left, ev.clientY - box.top);
    }

    _onMouseMove(ev) {
      const hit = this._hitTest(ev);
      if (!hit) return this._hideTooltip();
      this._showTooltip(ev, hit);
    }

    _onClick(ev) {
      const hit = this._hitTest(ev);
      if (!hit || !this.onLaneClick) return;
      const bms = geometry(this.data, 1).bucketMs;
      const range = hit.bucket ? { startMs: hit.bucket.startMs, endMs: hit.bucket.startMs + bms } : null;
      this.onLaneClick(hit.lane.sessionId, range);
    }

    _defaultTooltip(lane, bucket) {
      const parts = [`<div class="tt-title">${esc(laneName(lane, (k, p) => this._t(k, p)))}</div>`];
      if (bucket) {
        const extra = bucket.nBlocked ? ", " + this._t("tl.tt.blocked", { n: bucket.nBlocked }) : "";
        parts.push(`<div>${esc(this._t("tl.tt.events", { n: bucket.n }) + extra)}</div>`);
        parts.push(`<div>${esc(this._t("tl.tt.risks", { h: bucket.nHigh || 0, m: bucket.nMedium || 0, l: bucket.nLow || 0, i: bucket.nInfo || 0 }))}</div>`);
      } else {
        parts.push(`<div>${esc(this._t("tl.tt.total", { n: lane.eventCount || 0 }))}</div>`);
        if (lane.bypassCount) parts.push(`<div>${esc(this._t("tl.tt.bypass", { n: lane.bypassCount }))}</div>`);
      }
      return parts.join("");
    }

    _showTooltip(ev, hit) {
      const el = this.tooltipEl;
      if (!el) return;
      const { lane, bucket } = hit;
      const bms = geometry(this.data, 1).bucketMs;
      el.innerHTML = this.tooltipHtml ? this.tooltipHtml(lane, bucket, bms) : this._defaultTooltip(lane, bucket);
      el.hidden = false;
      const left = Math.min(ev.clientX + 14, (window.innerWidth || 1024) - 260);
      el.style.left = Math.max(4, left) + "px";
      el.style.top = ev.clientY + 14 + "px";
    }

    _hideTooltip() {
      if (this.tooltipEl) this.tooltipEl.hidden = true;
    }

    render() {
      const ctx = this.ctx;
      if (!ctx) return;
      const dpr = this.dpr || 1;
      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const cssW = this._cssWidth();
      const cssH = this.canvas.height / dpr;
      ctx.clearRect(0, 0, cssW, cssH);
      if (!this.data || !this.data.lanes || !this.data.lanes.length) {
        ctx.restore();
        return;
      }
      const C = themeColors();
      const riskFill = { high: C.high, medium: C.medium, low: C.low, info: C.info };
      const g = geometry(this.data, cssW);
      const lanes = this.data.lanes;

      ctx.font = "11px -apple-system, system-ui, sans-serif";
      ctx.textBaseline = "middle";

      // 时间轴：时间 → x 与柱子用同一坐标系（窗口右端 = 当前桶的结束时刻）
      const rangeMs = g.bucketCount * g.bucketMs;
      const windowStart = g.alignedNow + g.bucketMs - rangeMs;
      const xOf = (ms) => g.plotX0 + ((ms - windowStart) / rangeMs) * g.plotW;
      const stepMs = tickStepFor(rangeMs);
      ctx.fillStyle = C.muted;
      ctx.textAlign = "center";
      for (let tMs = firstTick(windowStart, stepMs); tMs <= windowStart + rangeMs; tMs += stepMs) {
        const x = Math.round(xOf(tMs)) + 0.5;
        ctx.strokeStyle = C.border;
        ctx.globalAlpha = 0.6;
        ctx.beginPath();
        ctx.moveTo(x, AXIS_HEIGHT - 4);
        ctx.lineTo(x, cssH);
        ctx.stroke();
        ctx.globalAlpha = 1;
        const label = tickLabel(tMs, stepMs);
        const halfW = ctx.measureText(label).width / 2;
        if (!(x - halfW < g.plotX0) && !(x + halfW > cssW)) ctx.fillText(label, x, AXIS_HEIGHT / 2);
      }
      ctx.textAlign = "left";
      ctx.strokeStyle = C.border;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, AXIS_HEIGHT - 0.5);
      ctx.lineTo(cssW, AXIS_HEIGHT - 0.5);
      ctx.moveTo(g.plotX0 - 0.5, 0);
      ctx.lineTo(g.plotX0 - 0.5, cssH);
      ctx.stroke();

      const t = (k, p) => this._t(k, p);
      lanes.forEach((lane, laneIndex) => {
        const y0 = AXIS_HEIGHT + laneIndex * LANE_HEIGHT;
        const name = laneName(lane, t);
        const idPart = String(lane.sessionId || "").slice(0, 8);
        const main = truncateText(ctx, name + laneFlag(lane), LABEL_WIDTH - 80);
        ctx.fillStyle = C.fg;
        ctx.fillText(main, 6, y0 + LANE_HEIGHT / 2);
        if (idPart && idPart !== name) {
          ctx.fillStyle = C.muted;
          ctx.fillText(" · " + idPart, 6 + (ctx.measureText(main).width || 0), y0 + LANE_HEIGHT / 2);
        }

        ctx.strokeStyle = C.border;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, y0 + LANE_HEIGHT - 0.5);
        ctx.lineTo(cssW, y0 + LANE_HEIGHT - 0.5);
        ctx.stroke();

        const buckets = lane.buckets || [];
        const laneMaxN = buckets.reduce((m, b) => Math.max(m, b.n), 1);
        for (const b of buckets) {
          const r = barRect(g, b, laneMaxN, laneIndex);
          if (!r) continue; // 窗口外的桶（防御性跳过）
          ctx.fillStyle = riskFill[worstRisk(b)];
          ctx.fillRect(r.x, r.y, r.w, r.h);
          if (b.nBlocked > 0) {
            ctx.strokeStyle = C.block;
            ctx.lineWidth = 1.5;
            ctx.strokeRect(r.bx + 0.5, y0 + 1.5, Math.max(1, g.bucketW - 1), LANE_HEIGHT - 3);
          }
        }
      });
      ctx.restore();
    }
  }
  SessionTimeline.prototype.t = null;

  // ======================================================================
  // 流程图：纯函数（布局）
  // ======================================================================
  const CARD_W = 300;
  const CARD_H = 84;
  const TURN_W = 380;
  const TURN_H = 64;
  const GAP_Y = 26;
  const TURN_GAP = 44;
  const BRANCH_X = CARD_W / 2 + 60; // 旁支卡片左边缘（相对主干中线）
  const MIN_K = 0.1;
  const MAX_K = 2.5;
  const PAD = 60;
  const CULL_MARGIN = 300;

  const STATUS_ICON = { ok: "✓", approved: "✓", blocked: "⛔", denied: "✗", warn: "!", observed: "◉" };
  const BAD_STATUS = { blocked: 1, denied: 1 };

  // 布局：返回 {nodes, edges, bbox}；nodes[i] = {key, kind:'turn'|'node', x, y, w, h, data, turn}，
  // x/y 是以主干中线为 0 的世界坐标；edges[i] = {from, to}（nodes 下标）+ branch + status。
  function layoutFlow(flow) {
    const nodes = [];
    const edges = [];
    let y = 0;
    let branchBottom = -Infinity;
    let prevMain = -1;
    const turns = flow && Array.isArray(flow.turns) ? flow.turns : [];
    turns.forEach((turn, ti) => {
      const ti0 = nodes.length;
      nodes.push({ key: "t" + ti, kind: "turn", x: -TURN_W / 2, y, w: TURN_W, h: TURN_H, data: turn, turn });
      if (prevMain >= 0) edges.push({ from: prevMain, to: ti0, branch: false, status: "turn" });
      prevMain = ti0;
      y += TURN_H + GAP_Y;
      (turn.nodes || []).forEach((n, ni) => {
        const idx = nodes.length;
        const key = "n" + ti + "_" + ni;
        if (n.branch) {
          // 旁支放在"下一格"高度，从上一张主干卡右侧弯过去；连续派生时在旁支列里往下叠
          const by = Math.max(y, branchBottom + GAP_Y / 2);
          nodes.push({ key, kind: "node", x: BRANCH_X, y: by, w: CARD_W, h: CARD_H, data: n, turn });
          edges.push({ from: prevMain, to: idx, branch: true, status: n.status });
          branchBottom = by + CARD_H;
        } else {
          nodes.push({ key, kind: "node", x: -CARD_W / 2, y, w: CARD_W, h: CARD_H, data: n, turn });
          edges.push({ from: prevMain, to: idx, branch: false, status: n.status });
          prevMain = idx;
          y += CARD_H + GAP_Y;
        }
      });
      y = Math.max(y, branchBottom + GAP_Y) + TURN_GAP - GAP_Y;
    });
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of nodes) {
      x0 = Math.min(x0, n.x);
      y0 = Math.min(y0, n.y);
      x1 = Math.max(x1, n.x + n.w);
      y1 = Math.max(y1, n.y + n.h);
    }
    if (!nodes.length) { x0 = 0; y0 = 0; x1 = 1; y1 = 1; }
    // 偏移到 stage 坐标（加 PAD、去掉 bbox 原点）
    const ox = -x0 + PAD;
    const oy = -y0 + PAD;
    for (const n of nodes) { n.px = n.x + ox; n.py = n.y + oy; }
    return { nodes, edges, bbox: { x0, y0, x1, y1 }, worldW: x1 - x0 + PAD * 2, worldH: y1 - y0 + PAD * 2 };
  }

  // 边的 SVG path（stage 坐标）
  function edgePath(layout, e) {
    const a = layout.nodes[e.from];
    const b = layout.nodes[e.to];
    if (e.branch) {
      const sx = a.px + a.w, sy = a.py + a.h / 2;
      const tx = b.px + b.w / 2, ty = b.py;
      return `M${sx},${sy} C${sx + 60},${sy} ${tx},${ty - 50} ${tx},${ty}`;
    }
    const sx = a.px + a.w / 2, sy = a.py + a.h;
    const tx = b.px + b.w / 2, ty = b.py;
    const my = (sy + ty) / 2;
    return `M${sx},${sy} C${sx},${my} ${tx},${my} ${tx},${ty}`;
  }

  // 视口（屏幕像素 vw×vh，变换 view）对应的世界矩形，外扩 margin
  function visibleRect(view, vw, vh, margin) {
    return { x0: -view.x / view.k - margin, y0: -view.y / view.k - margin, x1: (-view.x + vw) / view.k + margin, y1: (-view.y + vh) / view.k + margin };
  }
  function visibleNodes(layout, rect) {
    const out = [];
    for (const n of layout.nodes) {
      if (n.px + n.w < rect.x0 || n.px > rect.x1 || n.py + n.h < rect.y0 || n.py > rect.y1) continue;
      out.push(n);
    }
    return out;
  }
  function clampK(k) {
    return Math.min(MAX_K, Math.max(MIN_K, k));
  }
  function fitView(worldW, worldH, vw, vh) {
    const k = clampK(Math.min(vw / worldW, vh / worldH));
    return { k, x: (vw - worldW * k) / 2, y: (vh - worldH * k) / 2 };
  }
  // 在 (sx,sy) 处按 factor 缩放，保持该点下的世界坐标不动
  function zoomView(view, sx, sy, factor) {
    const k = clampK(view.k * factor);
    const f = k / view.k;
    return { k, x: sx - (sx - view.x) * f, y: sy - (sy - view.y) * f };
  }
  // 时间范围内第一个节点的 key（按 startTs ∈ [s, e)）；同时返回命中集合
  function rangeHits(flow, startMs, endMs) {
    const ids = new Set();
    let firstKey = null;
    ((flow && flow.turns) || []).forEach((turn, ti) => {
      (turn.nodes || []).forEach((n, ni) => {
        const s = Number(n.startTs) || 0;
        if (s <= 0 || s < startMs || s >= endMs) return;
        const key = "n" + ti + "_" + ni;
        ids.add(key);
        if (firstKey === null) firstKey = key;
      });
    });
    return { keys: ids, firstKey };
  }

  function hms(ts) {
    const v = Number(ts);
    if (!(v > 0)) return "";
    const d = new Date(v);
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }
  function fullTime(ts) {
    const v = Number(ts);
    if (!(v > 0)) return "";
    const d = new Date(v);
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${hms(v)}`;
  }
  function turnSpan(turn) {
    const s = hms(turn.startTs);
    const e = hms(turn.endTs);
    if (s && e && e !== s) return s + " – " + e;
    return s || e || "";
  }
  function toolCategory(tool) {
    if (tool === "Read" || tool === "Glob" || tool === "Grep" || tool === "LS") return "read";
    if (tool === "Write" || tool === "Edit" || tool === "MultiEdit" || tool === "NotebookEdit") return "write";
    if (tool === "Bash") return "bash";
    if (tool === "Agent" || tool === "Task") return "agent";
    if (tool === "WebFetch" || tool === "WebSearch") return "web";
    return "other";
  }
  const CAT_GLYPH = { read: "R", write: "W", bash: "$", agent: "A", web: "@", other: "•", observe: "◉", alert: "!", group: "≡" };
  function nodeCategory(n) {
    if (n.type === "observe") return "observe";
    if (n.type === "alert") return "alert";
    if (n.type === "group") return "group";
    return toolCategory(n.tool);
  }
  function normRisk(r) {
    return r === "critical" ? "high" : r || "";
  }

  // ======================================================================
  // 样式（FlowView 首次构造时注入）
  // ======================================================================
  const STYLE_ID = "xtl-style";
  const CSS = `
.xtl-flow{position:relative;overflow:hidden;touch-action:none;cursor:grab;background:var(--bg,#0e1116);color:var(--fg,#e6edf3);font-size:0.8571rem;user-select:none;min-height:240px}
.xtl-flow.xtl-dragging{cursor:grabbing}
.xtl-stage{position:absolute;left:0;top:0;transform-origin:0 0}
.xtl-edges{position:absolute;left:0;top:0;overflow:visible;pointer-events:none}
.xtl-cards{position:absolute;left:0;top:0}
.xtl-edge{fill:none;stroke:var(--muted,#8b98a9);stroke-width:1.5;opacity:.7}
.xtl-edge-branch{stroke-dasharray:6 5}
.xtl-edge-bad{stroke:var(--block,#f85149);opacity:.9}
.xtl-edge-turn{stroke-dasharray:2 4;opacity:.4}
.xtl-arrow{fill:var(--muted,#8b98a9)}
.xtl-arrow-bad{fill:var(--block,#f85149)}
.xtl-card{position:absolute;box-sizing:border-box;background:var(--panel2,#1c2230);border:1px solid var(--border,#2a3140);border-left:4px solid var(--info,#6b7686);border-radius:8px;padding:6px 10px;overflow:hidden;cursor:pointer;line-height:1.35}
.xtl-card:hover{border-color:var(--accent,#4c8dff)}
.xtl-card.xtl-branch{border-style:dashed;border-left-style:solid}
.xtl-card.xtl-st-ok{border-left-color:var(--allow,#3fb950)}
.xtl-card.xtl-st-approved{border-left-color:var(--confirm,#d29922)}
.xtl-card.xtl-st-blocked,.xtl-card.xtl-st-denied{border-left-color:var(--block,#f85149);background:color-mix(in srgb,var(--block,#f85149) 10%,var(--panel2,#1c2230))}
.xtl-card.xtl-st-warn{border-left-color:var(--medium,#d29922)}
.xtl-card.xtl-st-observed{border-left-color:var(--info,#6b7686)}
.xtl-card.xtl-hl{box-shadow:0 0 0 2px var(--accent,#4c8dff),0 0 14px var(--accent,#4c8dff)}
.xtl-card.xtl-sel{border-color:var(--accent,#4c8dff);box-shadow:0 0 0 1px var(--accent,#4c8dff)}
.xtl-card.xtl-turn{background:var(--panel,#161b22);border-left-color:var(--accent,#4c8dff);cursor:default;display:flex;flex-direction:column;justify-content:center}
.xtl-head{display:flex;align-items:center;gap:6px;color:var(--muted,#8b98a9);white-space:nowrap}
.xtl-head .xtl-time{margin-left:auto}
.xtl-turn-no{font-weight:600;color:var(--fg,#e6edf3);font-size:0.9286rem}
.xtl-statusi{font-weight:600}
.xtl-st-ok .xtl-statusi{color:var(--allow,#3fb950)}
.xtl-st-approved .xtl-statusi{color:var(--confirm,#d29922)}
.xtl-st-blocked .xtl-statusi,.xtl-st-denied .xtl-statusi{color:var(--block,#f85149)}
.xtl-st-warn .xtl-statusi{color:var(--medium,#d29922)}
.xtl-tag{font-size:0.7143rem;padding:0 5px;border-radius:8px;border:1px solid var(--confirm,#d29922);color:var(--confirm,#d29922)}
.xtl-risk{font-size:0.7143rem;padding:0 5px;border-radius:8px;color:#fff}
.xtl-risk-high{background:var(--high,#f85149)}
.xtl-risk-medium{background:var(--medium,#d29922)}
.xtl-risk-low{background:var(--low,#3fb950)}
.xtl-risk-info{background:var(--info,#6b7686)}
.xtl-title{display:flex;align-items:center;gap:6px;margin-top:3px;font-weight:600;white-space:nowrap}
.xtl-title-text{overflow:hidden;text-overflow:ellipsis}
.xtl-icon{flex:none;width:18px;height:18px;line-height:18px;text-align:center;border-radius:4px;background:var(--border,#2a3140);font-size:0.7857rem}
.xtl-rule{margin-left:auto;flex:none;max-width:45%;overflow:hidden;text-overflow:ellipsis;font-weight:400;font-size:0.7143rem;color:var(--confirm,#d29922);border:1px solid var(--border,#2a3140);border-radius:4px;padding:0 4px}
.xtl-sub{margin-top:3px;color:var(--muted,#8b98a9);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:0.7857rem;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;word-break:break-all}
.xtl-chip{margin-right:8px;color:var(--muted,#8b98a9)}
.xtl-chip-bad{color:var(--block,#f85149)}
.xtl-ctl{position:absolute;right:10px;bottom:10px;display:flex;flex-direction:column;gap:4px;z-index:3}
.xtl-ctl button{width:28px;height:28px;border-radius:6px;border:1px solid var(--border,#2a3140);background:var(--panel,#161b22);color:var(--fg,#e6edf3);cursor:pointer;font-size:1rem;line-height:1}
.xtl-ctl button:hover{border-color:var(--accent,#4c8dff)}
.xtl-mini{position:absolute;left:10px;bottom:10px;width:170px;height:150px;border:1px solid var(--border,#2a3140);border-radius:6px;background:var(--panel,#161b22);opacity:.92;z-index:3;cursor:pointer}
.xtl-empty,.xtl-note{position:absolute;left:0;right:0;text-align:center;color:var(--muted,#8b98a9);z-index:2;pointer-events:none}
.xtl-empty{top:40%}
.xtl-note{top:8px}
.xtl-detail{position:absolute;right:10px;top:10px;width:min(360px,calc(100% - 20px));max-height:calc(100% - 20px);overflow:auto;background:var(--panel,#161b22);border:1px solid var(--border,#2a3140);border-radius:8px;padding:10px 12px;z-index:4;cursor:default;user-select:text;box-shadow:0 6px 24px rgba(0,0,0,.35)}
.xtl-detail h4{margin:0 0 8px;font-size:0.9286rem;display:flex;align-items:center}
.xtl-detail h4 button{margin-left:auto;background:none;border:0;color:var(--muted,#8b98a9);cursor:pointer;font-size:1.1429rem}
.xtl-detail dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:4px 10px}
.xtl-detail dt{color:var(--muted,#8b98a9)}
.xtl-detail dd{margin:0;word-break:break-all;white-space:pre-wrap}
`;
  function injectStyle() {
    try {
      if (document.getElementById && document.getElementById(STYLE_ID)) return;
      const st = document.createElement("style");
      st.id = STYLE_ID;
      st.textContent = CSS;
      (document.head || document.documentElement).appendChild(st);
    } catch (e) {}
  }

  // ======================================================================
  // FlowView
  // ======================================================================
  class FlowView {
    constructor(container, opts) {
      opts = opts || {};
      this.container = container;
      this.t = opts.t || fallbackT;
      this.onNodeClick = opts.onNodeClick || null;
      this.flow = null;
      this.layout = layoutFlow(null);
      this.view = { x: 0, y: 0, k: 1 };
      this.highlight = new Set(); // node keys
      this.selectedKey = null;
      this.live = new Map(); // key -> element（当前已渲染的卡片）
      this.byKey = new Map();
      this._pendingInit = false;
      this._miniMetrics = null;
      this._disposers = [];

      injectStyle();
      const vp = container;
      vp.classList.add("xtl-flow");
      this.vp = vp;
      vp.innerHTML = "";
      this.stage = document.createElement("div");
      this.stage.className = "xtl-stage";
      this.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      this.svg.setAttribute("class", "xtl-edges");
      this.cards = document.createElement("div");
      this.cards.className = "xtl-cards";
      this.stage.appendChild(this.svg);
      this.stage.appendChild(this.cards);
      vp.appendChild(this.stage);

      this.note = document.createElement("div");
      this.note.className = "xtl-note";
      this.note.hidden = true;
      vp.appendChild(this.note);
      this.emptyEl = document.createElement("div");
      this.emptyEl.className = "xtl-empty";
      this.emptyEl.hidden = true;
      vp.appendChild(this.emptyEl);

      this.mini = document.createElement("canvas");
      this.mini.className = "xtl-mini";
      this.mini.title = this._tt("tl.flow.minimap");
      vp.appendChild(this.mini);

      const ctl = document.createElement("div");
      ctl.className = "xtl-ctl";
      ctl.innerHTML =
        `<button type="button" data-z="in" title="${esc(this._tt("tl.flow.zoomIn"))}">+</button>` +
        `<button type="button" data-z="out" title="${esc(this._tt("tl.flow.zoomOut"))}">−</button>` +
        `<button type="button" data-z="fit" title="${esc(this._tt("tl.flow.fit"))}">⛶</button>`;
      this._onCtl = (ev) => {
        const b = ev.target && ev.target.closest ? ev.target.closest("button") : null;
        if (!b) return;
        const sz = this._vpSize();
        if (b.dataset.z === "in") this._zoomAt(sz.w / 2, sz.h / 2, 1.25);
        else if (b.dataset.z === "out") this._zoomAt(sz.w / 2, sz.h / 2, 0.8);
        else this.fit();
      };
      ctl.addEventListener("click", this._onCtl);
      vp.appendChild(ctl);
      this.ctl = ctl;

      this.detail = document.createElement("div");
      this.detail.className = "xtl-detail";
      this.detail.hidden = true;
      this.detail.addEventListener("pointerdown", (ev) => ev.stopPropagation && ev.stopPropagation());
      this.detail.addEventListener("wheel", (ev) => ev.stopPropagation && ev.stopPropagation());
      this.detail.addEventListener("click", (ev) => {
        if (ev.target && ev.target.closest && ev.target.closest("[data-close]")) this._closeDetail();
      });
      vp.appendChild(this.detail);

      this._bindPointer();
      this._bindMinimap();
      this._onResize = () => this._handleResize();
      this._listen(window, "resize", this._onResize);
      this._ro = null;
      try {
        if (typeof ResizeObserver !== "undefined") {
          this._ro = new ResizeObserver(() => this._handleResize());
          this._ro.observe(vp);
        }
      } catch (e) {
        this._ro = null;
      }
    }

    _tt(key, params) {
      return this.t(key, params);
    }
    _listen(target, type, fn, o) {
      target.addEventListener(type, fn, o);
      this._disposers.push(() => target.removeEventListener(type, fn, o));
    }
    _vpSize() {
      const r = this.vp.getBoundingClientRect();
      return { w: (r && r.width) || 0, h: (r && r.height) || 0 };
    }

    // ---------- 数据 ----------
    // flow: /api/session-flow 的响应
    setData(flow) {
      const sameSession = this.flow && flow && this.flow.sessionId === flow.sessionId;
      this.flow = flow || { turns: [] };
      if (!Array.isArray(this.flow.turns)) this.flow = Object.assign({}, this.flow, { turns: [] });
      if (!sameSession) {
        this.highlight.clear();
        this.selectedKey = null;
        this._closeDetail();
      }
      this.layout = layoutFlow(this.flow);
      this.byKey = new Map(this.layout.nodes.map((n) => [n.key, n]));
      this._buildEdges();
      this.stage.style.width = this.layout.worldW + "px";
      this.stage.style.height = this.layout.worldH + "px";
      this.svg.setAttribute("width", this.layout.worldW);
      this.svg.setAttribute("height", this.layout.worldH);
      // 重建卡片（数据变了，文案/状态可能变）
      this.live.clear();
      this.cards.innerHTML = "";
      const hasNodes = this.layout.nodes.length > 0;
      this.emptyEl.hidden = hasNodes;
      this.emptyEl.textContent = hasNodes ? "" : this._tt("tl.flow.empty");
      this.note.hidden = !this.flow.truncated;
      this.note.textContent = this.flow.truncated ? this._tt("tl.flow.truncated") : "";
      if (!sameSession) this._initView();
      else this._applyView();
    }

    _buildEdges() {
      const L = this.layout;
      const paths = L.edges.map((e) => {
        const bad = BAD_STATUS[e.status] ? 1 : 0;
        const cls = ["xtl-edge", e.branch ? "xtl-edge-branch" : "", bad ? "xtl-edge-bad" : "", e.status === "turn" ? "xtl-edge-turn" : ""].filter(Boolean).join(" ");
        return `<path class="${cls}" d="${edgePath(L, e)}" marker-end="url(#xtl-arrow${bad ? "-bad" : ""})"/>`;
      });
      this.svg.innerHTML =
        `<defs><marker id="xtl-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8 z" class="xtl-arrow"/></marker>` +
        `<marker id="xtl-arrow-bad" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8 z" class="xtl-arrow-bad"/></marker></defs>` +
        paths.join("");
    }

    // ---------- 卡片 ----------
    _nodeTitle(d) {
      if (d.type === "group") return this._tt("tl.flow.group", { n: d.count || 0 });
      const base = d.title || d.tool || d.class || this._typeLabel(d.type);
      return base;
    }
    _typeLabel(type) {
      return tr(this.t, "tl.type." + type, type || "");
    }

    _cardHtml(n) {
      const T = (k, p) => this._tt(k, p);
      const d = n.data;
      if (n.kind === "turn") {
        const idx = d.index != null ? d.index : "";
        const nodes = d.nodes || [];
        const blocked = nodes.filter((x) => x.status === "blocked" || x.status === "denied").length;
        const span = turnSpan(d);
        return (
          `<div class="xtl-head"><span class="xtl-turn-no">${esc(T("tl.flow.turn", { n: idx }))}</span><span class="xtl-time">${esc(span)}</span></div>` +
          `<div class="xtl-head"><span class="xtl-chip">${esc(T("tl.flow.ops", { n: nodes.length }))}</span>` +
          (blocked ? `<span class="xtl-chip xtl-chip-bad">${STATUS_ICON.blocked} ${esc(T("tl.flow.blockedN", { n: blocked }))}</span>` : "") +
          `</div>`
        );
      }
      const status = d.status || "observed";
      const statusText = tr(this.t, "tl.status." + status, status);
      const risk = normRisk(d.risk);
      const riskLabel = risk ? tr(this.t, "tl.risk." + (d.risk === "critical" ? "critical" : risk), d.risk) : "";
      const cat = nodeCategory(d);
      const time = hms(d.startTs);
      const sub = d.type === "group" ? [d.layer, d.class].filter(Boolean).join(" · ") : d.summary || [d.layer, d.class].filter(Boolean).join(" · ");
      return (
        `<div class="xtl-head"><span class="xtl-statusi">${esc(STATUS_ICON[status] || "")} ${esc(statusText)}</span>` +
        (status === "approved" ? `<span class="xtl-tag">${esc(T("tl.flow.approvedTag"))}</span>` : "") +
        (d.branch ? `<span class="xtl-tag" style="border-color:var(--border,#2a3140);color:var(--muted,#8b98a9)">${esc(T("tl.flow.branch"))}</span>` : "") +
        (risk ? `<span class="xtl-risk xtl-risk-${esc(risk)}">${esc(riskLabel)}</span>` : "") +
        `<span class="xtl-time">${esc(time)}</span></div>` +
        `<div class="xtl-title"><span class="xtl-icon">${esc(CAT_GLYPH[cat] || "")}</span><span class="xtl-title-text">${esc(this._nodeTitle(d))}</span>` +
        (d.layer && d.type !== "group" ? `<span class="xtl-tag" style="border-color:var(--border,#2a3140);color:var(--muted,#8b98a9)">${esc(d.layer)}</span>` : "") +
        (d.rule ? `<span class="xtl-rule" title="${esc(d.rule)}">${esc(d.rule)}</span>` : "") +
        `</div>` +
        `<div class="xtl-sub">${esc(sub)}</div>`
      );
    }

    _makeCard(n) {
      const el = document.createElement("div");
      const cls = ["xtl-card", n.kind === "turn" ? "xtl-turn" : "xtl-node"];
      if (n.kind === "node") {
        cls.push("xtl-st-" + (n.data.status || "observed"));
        if (n.data.branch) cls.push("xtl-branch");
        if (this.highlight.has(n.key)) cls.push("xtl-hl");
        if (this.selectedKey === n.key) cls.push("xtl-sel");
      }
      el.className = cls.join(" ");
      el.setAttribute("data-key", n.key);
      el.style.left = n.px + "px";
      el.style.top = n.py + "px";
      el.style.width = n.w + "px";
      el.style.height = n.h + "px";
      el.innerHTML = this._cardHtml(n);
      return el;
    }

    // 只保留视口附近的卡片：节点很多（>500）时 DOM 数量保持在几十张。
    _syncCards() {
      const sz = this._vpSize();
      const w = sz.w || 800; // 容器隐藏（宽 0）时按一个默认视口渲染，避免可见后空白
      const h = sz.h || 600;
      const rect = visibleRect(this.view, w, h, CULL_MARGIN);
      const want = visibleNodes(this.layout, rect);
      const wantKeys = new Set(want.map((n) => n.key));
      for (const [key, el] of this.live) {
        if (!wantKeys.has(key)) {
          if (el.remove) el.remove();
          else this.cards.removeChild(el);
          this.live.delete(key);
        }
      }
      for (const n of want) {
        if (this.live.has(n.key)) continue;
        const el = this._makeCard(n);
        this.cards.appendChild(el);
        this.live.set(n.key, el);
      }
    }

    // ---------- 视图 ----------
    _applyView() {
      const { x, y, k } = this.view;
      this.stage.style.transform = `translate(${x}px, ${y}px) scale(${k})`;
      this._syncCards();
      this._drawMinimap();
    }
    _zoomAt(sx, sy, factor) {
      this.view = zoomView(this.view, sx, sy, factor);
      this._applyView();
    }
    fit() {
      const sz = this._vpSize();
      if (!(sz.w > 0) || !(sz.h > 0)) {
        this._pendingInit = true;
        return;
      }
      this.view = fitView(this.layout.worldW, this.layout.worldH, sz.w, sz.h);
      this._applyView();
    }
    _centerOn(wx, wy, ax, ay) {
      const sz = this._vpSize();
      this.view.x = sz.w * (ax == null ? 0.5 : ax) - wx * this.view.k;
      this.view.y = sz.h * (ay == null ? 0.5 : ay) - wy * this.view.k;
      this._applyView();
    }
    // 初始视图：整张图放得下且不过小就适应窗口；否则 k=1 并定位到最后一轮（最新操作在下方）。
    _initView() {
      const sz = this._vpSize();
      if (!(sz.w > 0) || !(sz.h > 0)) {
        this._pendingInit = true;
        this._applyView();
        return;
      }
      this._pendingInit = false;
      const f = fitView(this.layout.worldW, this.layout.worldH, sz.w, sz.h);
      if (f.k >= 0.6 || !this.layout.nodes.length) {
        this.view = f.k > 1 ? { k: 1, x: (sz.w - this.layout.worldW) / 2, y: 20 } : f;
        this._applyView();
        return;
      }
      this.view.k = 1;
      const turns = this.layout.nodes.filter((n) => n.kind === "turn");
      const target = turns.length ? turns[turns.length - 1] : this.layout.nodes[this.layout.nodes.length - 1];
      this._centerOn(this.layout.nodes.length ? -this.layout.bbox.x0 + PAD : 0, target.py, 0.5, 0.12);
    }
    _handleResize() {
      const sz = this._vpSize();
      if (!(sz.w > 0)) return;
      if (this._pendingInit) this._initView();
      else this._applyView();
    }

    // 外部联动：高亮并滚动到时间范围内第一个节点；null 清除
    highlightRange(startMs, endMs) {
      if (startMs == null || endMs == null) {
        this.highlight.clear();
        this._refreshClasses();
        return false;
      }
      const hits = rangeHits(this.flow, startMs, endMs);
      this.highlight = hits.keys;
      this._refreshClasses();
      const n = hits.firstKey ? this.byKey.get(hits.firstKey) : null;
      if (n) {
        this.view.k = 1;
        this._centerOn(n.px + n.w / 2, n.py, 0.5, 0.25);
      }
      return !!n;
    }
    _refreshClasses() {
      for (const [key, el] of this.live) {
        const n = this.byKey.get(key);
        if (!n || n.kind !== "node") continue;
        const cls = ["xtl-card", "xtl-node", "xtl-st-" + (n.data.status || "observed")];
        if (n.data.branch) cls.push("xtl-branch");
        if (this.highlight.has(key)) cls.push("xtl-hl");
        if (this.selectedKey === key) cls.push("xtl-sel");
        el.className = cls.join(" ");
      }
      this._drawMinimap();
    }

    // ---------- 交互 ----------
    _bindPointer() {
      let drag = null;
      const vp = this.vp;
      this._listen(vp, "pointerdown", (ev) => {
        if (ev.button !== 0 || (ev.target.closest && ev.target.closest(".xtl-ctl, .xtl-mini, .xtl-detail"))) return;
        drag = { sx: ev.clientX, sy: ev.clientY, vx: this.view.x, vy: this.view.y, moved: false, target: ev.target };
      });
      this._listen(window, "pointermove", (ev) => {
        if (!drag) return;
        const dx = ev.clientX - drag.sx;
        const dy = ev.clientY - drag.sy;
        if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 5) return;
        if (!drag.moved) vp.classList.add("xtl-dragging");
        drag.moved = true;
        this.view.x = drag.vx + dx;
        this.view.y = drag.vy + dy;
        this._applyView();
      });
      this._listen(window, "pointerup", () => {
        if (!drag) return;
        const d = drag;
        drag = null;
        vp.classList.remove("xtl-dragging");
        if (!d.moved) this._click(d.target);
      });
      // 滚轮 = 以鼠标为中心缩放
      this._listen(
        vp,
        "wheel",
        (ev) => {
          ev.preventDefault();
          const r = vp.getBoundingClientRect();
          this._zoomAt(ev.clientX - r.left, ev.clientY - r.top, Math.exp(-ev.deltaY * 0.0015));
        },
        { passive: false }
      );
    }

    _click(target) {
      const card = target && target.closest ? target.closest(".xtl-card") : null;
      if (!card) return;
      const n = this.byKey.get(card.getAttribute("data-key"));
      if (!n || n.kind !== "node") return;
      this.selectedKey = n.key;
      this._refreshClasses();
      this._showDetail(n.data);
      if (this.onNodeClick) this.onNodeClick(n.data);
    }

    _closeDetail() {
      this.detail.hidden = true;
      this.detail.innerHTML = "";
      this.selectedKey = null;
      if (this.live) this._refreshClasses();
    }

    _showDetail(d) {
      const T = (k, p) => this._tt(k, p);
      const none = T("tl.detail.none");
      const row = (labelKey, val) => `<dt>${esc(T(labelKey))}</dt><dd>${val === "" || val == null ? esc(none) : esc(val)}</dd>`;
      const ids = d.eventIds && d.eventIds.length ? d.eventIds : d.id ? [d.id] : [];
      const shown = ids.slice(0, 20).join("\n") + (ids.length > 20 ? "\n" + T("tl.detail.moreIds", { n: ids.length }) : "");
      const status = d.status || "observed";
      const time = fullTime(d.startTs) + (Number(d.endTs) > 0 && d.endTs !== d.startTs ? " → " + fullTime(d.endTs) : "");
      const decision = d.decision ? tr(this.t, "tl.decision." + d.decision, d.decision) : "";
      const risk = d.risk ? tr(this.t, "tl.risk." + d.risk, d.risk) : "";
      this.detail.innerHTML =
        `<h4>${esc(T("tl.detail.title"))} · ${esc(this._typeLabel(d.type))}<button type="button" data-close="1" title="${esc(T("tl.detail.close"))}">×</button></h4><dl>` +
        row("tl.detail.status", (STATUS_ICON[status] || "") + " " + tr(this.t, "tl.status." + status, status)) +
        row("tl.detail.tool", d.tool || d.title || "") +
        row("tl.detail.layer", d.layer) +
        row("tl.detail.class", d.class) +
        row("tl.detail.risk", risk) +
        row("tl.detail.decision", decision) +
        row("tl.detail.rule", d.rule) +
        (d.type === "group" ? row("tl.detail.count", d.count) : "") +
        row("tl.detail.time", time || T("tl.flow.noTime")) +
        row("tl.detail.summary", d.summary) +
        row("tl.detail.events", shown) +
        `</dl>`;
      this.detail.hidden = false;
    }

    // ---------- 小地图 ----------
    _bindMinimap() {
      let down = false;
      const go = (ev) => {
        const r = this.mini.getBoundingClientRect();
        const m = this._miniMetrics;
        if (!m) return;
        this._centerOn((ev.clientX - r.left - m.ox) / m.s, (ev.clientY - r.top - m.oy) / m.s, 0.5, 0.5);
      };
      this._listen(this.mini, "pointerdown", (ev) => {
        down = true;
        go(ev);
        if (ev.stopPropagation) ev.stopPropagation();
      });
      this._listen(window, "pointermove", (ev) => down && go(ev));
      this._listen(window, "pointerup", () => (down = false));
    }

    _drawMinimap() {
      const c = this.mini;
      const cssW = 170;
      const cssH = 150;
      const dpr = Math.min((typeof window !== "undefined" && window.devicePixelRatio) || 1, 2);
      if (c.width !== cssW * dpr) {
        c.width = cssW * dpr;
        c.height = cssH * dpr;
      }
      const ctx = c.getContext("2d");
      if (!ctx) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, cssW, cssH);
      const L = this.layout;
      if (!L || !L.nodes.length) return;
      const s = Math.min((cssW - 10) / L.worldW, (cssH - 10) / L.worldH);
      const ox = (cssW - L.worldW * s) / 2;
      const oy = (cssH - L.worldH * s) / 2;
      this._miniMetrics = { s, ox, oy };
      const C = themeColors();
      const col = { ok: C.allow, approved: C.confirm, blocked: C.block, denied: C.block, warn: C.medium, observed: C.info, turn: C.accent };
      for (const n of L.nodes) {
        const st = n.kind === "turn" ? "turn" : n.data.status;
        ctx.fillStyle = col[st] || C.muted;
        ctx.globalAlpha = n.kind === "turn" ? 0.9 : this.highlight.has(n.key) ? 1 : 0.65;
        ctx.fillRect(ox + n.px * s, oy + n.py * s, Math.max(1.5, n.w * s), Math.max(1.5, n.h * s));
      }
      ctx.globalAlpha = 1;
      const sz = this._vpSize();
      ctx.strokeStyle = C.fg;
      ctx.lineWidth = 1;
      ctx.strokeRect(ox + (-this.view.x / this.view.k) * s, oy + (-this.view.y / this.view.k) * s, (sz.w / this.view.k) * s, (sz.h / this.view.k) * s);
    }

    destroy() {
      for (const d of this._disposers) d();
      this._disposers = [];
      if (this.ctl) this.ctl.removeEventListener("click", this._onCtl);
      if (this._ro) this._ro.disconnect();
      this.live.clear();
      this.vp.innerHTML = "";
      this.vp.classList.remove("xtl-flow", "xtl-dragging");
    }
  }

  window.XTimeline = {
    SessionTimeline,
    FlowView,
    i18n,
    _test: {
      worstRisk, tickStepFor, firstTick, tickLabel, geometry, bucketIndexFromNow, bucketX, indexFromNowAtX,
      laneIndexAtY, hitTest, barRect, laneName, laneFlag, layoutFlow, edgePath, visibleRect, visibleNodes,
      fitView, zoomView, rangeHits, fallbackT, tr, hms, normRisk,
      consts: { LANE_HEIGHT, LABEL_WIDTH, AXIS_HEIGHT, CARD_W, CARD_H, MIN_K, MAX_K, CULL_MARGIN },
    },
  };
})();
