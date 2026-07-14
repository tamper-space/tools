(function () {
  const ROW_H = 20;
  const OVERSCAN = 8;
  const CAT_CLASS = ["c-null", "", "c-ws", "c-ctrl", "c-high"];
  const EMPTY = new Uint8Array(0);
  const STR_CAP = 2000;

  const $ = (id) => document.getElementById(id);
  const els = {};
  ["open", "file", "fname", "goto", "find", "findPrev", "findNext", "findCase",
   "replace", "replaceOne", "replaceAll", "findInfo", "bpr", "enc", "color", "bookmark",
   "undo", "redo", "export", "exportWrap", "exportMenu", "exrows", "stats", "header",
   "tabbar", "body", "viewport", "sizer", "rows", "empty", "itable", "endian", "selinfo", "bmList",
   "strMin", "strScan", "strCount", "strList", "pos", "dirty", "mode", "diffBtn",
   "diff", "diffA", "diffB", "diffInfo", "diffPrev", "diffNext", "diffExit", "diffAName",
   "diffBName", "diffAvp", "diffAsizer", "diffArows", "diffBvp", "diffBsizer", "diffBrows",
  ].forEach((k) => (els[k] = $(k)));

  // Global/session state (view settings + open tabs). Per-file state lives in s.
  const g = {
    bpr: 16, enc: "ascii", colorOn: true, findCase: false, insert: false,
    dragging: false, exScope: "whole", tabs: [], active: -1, embedded: false,
    diff: { on: false, a: 0, b: 1, pos: -1 },
  };

  function newState(buf, name) {
    return {
      buf, name: name || "", size: buf ? buf.length : 0, cats: null, entropy: 0,
      cursor: 0, nibble: 0, pane: "hex", anchor: null,
      undo: [], redo: [], modified: false,
      matches: [], matchIdx: -1, matchLen: 0, lastFind: null,
      bookmarks: [], bmSeq: 0,
    };
  }
  let s = newState(null, "");

  const CP437 = (
    ".☺☻♥♦♣♠•◘○◙♂♀♪♫☼" +
    "►◄↕‼¶§▬↨↑↓→←∟↔▲▼" +
    " !\"#$%&'()*+,-./" +
    "0123456789:;<=>?" +
    "@ABCDEFGHIJKLMNO" +
    "PQRSTUVWXYZ[\\]^_" +
    "`abcdefghijklmno" +
    "pqrstuvwxyz{|}~⌂" +
    "ÇüéâäàåçêëèïîìÄÅ" +
    "ÉæÆôöòûùÿÖÜ¢£¥₧ƒ" +
    "áíóúñÑªº¿⌐¬½¼¡«»" +
    "░▒▓│┤╡╢╖╕╣║╗╝╜╛┐" +
    "└┴┬├─┼╞╟╚╔╩╦╠═╬╧" +
    "╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀" +
    "αßΓπΣσµτΦΘΩδ∞φε∩" +
    "≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ "
  );
  const BM_COLORS = [6, 9, 4, 2, 11, 0, 7, 10];

  function charFor(b) {
    if (g.enc === "cp437") return CP437[b];
    if (g.enc === "latin1") return (b >= 0x20 && b <= 0x7e) || b >= 0xa0 ? String.fromCharCode(b) : ".";
    return b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
  }

  window.init = function () {
    els.open.onclick = () => { if (!g.embedded) els.file.click(); };
    els.file.onchange = (e) => e.target.files[0] && load(e.target.files[0]);
    els.empty.addEventListener("click", () => { if (!g.embedded) els.file.click(); });
    els.tabbar.addEventListener("click", (e) => {
      if (e.target.closest(".tabadd")) return els.file.click();
      const cl = e.target.closest(".tabclose");
      if (cl) return closeTab(+cl.dataset.close);
      const tab = e.target.closest(".tab");
      if (tab) switchTab(+tab.dataset.i);
    });
    els.viewport.addEventListener("dragover", (e) => e.preventDefault());
    els.viewport.addEventListener("drop", (e) => {
      e.preventDefault();
      if (!g.embedded && e.dataTransfer.files[0]) load(e.dataTransfer.files[0]);
    });
    els.viewport.addEventListener("scroll", scheduleRender);
    els.viewport.addEventListener("keydown", onKey);
    els.rows.addEventListener("mousedown", onMouseDown);
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", () => { g.dragging = false; });

    els.bpr.onchange = () => { g.bpr = +els.bpr.value; updateHeader(); render(); };
    els.enc.onchange = () => { g.enc = els.enc.value; render(); };
    els.color.onchange = () => { g.colorOn = els.color.checked; render(); };
    els.bookmark.onclick = addBookmark;
    els.bmList.addEventListener("click", onBmClick);
    els.bmList.addEventListener("dblclick", onBmRename);
    els.endian.onchange = updateInspector;
    els.undo.onclick = undo;
    els.redo.onclick = redo;
    buildExportMenu();
    els.export.onclick = (e) => { e.stopPropagation(); toggleExport(); };
    els.exrows.addEventListener("click", onExport);
    els.exportMenu.querySelector(".exscope").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-scope]");
      if (b && !b.disabled) setScope(b.dataset.scope);
    });
    document.addEventListener("click", (e) => { if (!els.exportWrap.contains(e.target)) closeExport(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeExport(); });
    els.goto.onkeydown = (e) => { if (e.key === "Enter") doGoto(); };
    els.find.onkeydown = (e) => {
      if (e.key !== "Enter") return;
      if (e.shiftKey) stepMatch(-1);
      else if (els.find.value !== s.lastFind) doFind();
      else stepMatch(1);
    };
    els.findNext.onclick = () => (els.find.value !== s.lastFind ? doFind() : stepMatch(1));
    els.findPrev.onclick = () => stepMatch(-1);
    els.findCase.onclick = () => {
      g.findCase = !g.findCase;
      els.findCase.setAttribute("aria-pressed", String(g.findCase));
      s.lastFind = null;
    };
    els.replaceOne.onclick = replaceOne;
    els.replaceAll.onclick = replaceAll;
    els.diffBtn.onclick = enterDiff;
    els.diffExit.onclick = exitDiff;
    els.diffPrev.onclick = () => jumpDiff(-1);
    els.diffNext.onclick = () => jumpDiff(1);
    els.diffA.onchange = () => { g.diff.a = +els.diffA.value; refreshDiff(); };
    els.diffB.onchange = () => { g.diff.b = +els.diffB.value; refreshDiff(); };
    els.diffAvp.addEventListener("scroll", () => onDiffScroll(els.diffAvp, els.diffBvp));
    els.diffBvp.addEventListener("scroll", () => onDiffScroll(els.diffBvp, els.diffAvp));
    els.diffBtn.disabled = true;
    els.strScan.onclick = scanStrings;
    els.strList.addEventListener("click", (e) => {
      const it = e.target.closest(".stritem");
      if (!it) return;
      const off = +it.dataset.o, len = +it.dataset.l;
      s.anchor = off; moveTo(Math.min(s.size - 1, off + len - 1), true);
    });
    window.addEventListener("resize", scheduleRender);
    // Platform protocol (see docs/WORKSPACES.md): the tool is a lens over a byte
    // buffer. The shell sends/receives raw bytes; view state stays separate.
    window.addEventListener("message", onPlatformMessage);
    postToParent({ type: "tamper:ready", tool: "hex", accepts: ["bytes"] });
  };

  function toast(msg) {
    let t = document.getElementById("toast");
    if (!t) { t = document.createElement("div"); t.id = "toast"; document.body.appendChild(t); }
    t.textContent = msg; t.classList.add("show");
    clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 2600);
  }
  function postToParent(msg, transfer) {
    if (window.parent && window.parent !== window) window.parent.postMessage(msg, location.origin, transfer || []);
  }
  function currentView() {
    return { v: 2, bpr: g.bpr, enc: g.enc, color: g.colorOn, cursor: s.cursor, bookmarks: s.bookmarks, bmSeq: s.bmSeq };
  }
  function onPlatformMessage(e) {
    if (e.origin !== location.origin) return;
    const m = e.data || {};
    if (m.type === "tamper:load") loadArtifact(m);
    else if (m.type === "tamper:getState") replyState();
  }
  function replyState() {
    const ab = s.buf ? s.buf.slice().buffer : new ArrayBuffer(0);
    postToParent({ type: "tamper:state", name: s.name || "", bytes: ab, view: currentView() }, [ab]);
  }
  function applyView(view) {
    if (!view) return;
    if (view.bpr) { g.bpr = view.bpr; els.bpr.value = String(view.bpr); }
    if (view.enc) { g.enc = view.enc; els.enc.value = view.enc; }
    if (typeof view.color === "boolean") { g.colorOn = view.color; els.color.checked = view.color; }
  }
  // loadArtifact renders a byte buffer the shell hands over (tamper:load). In
  // embedded mode the shell owns the file list, so we keep a single buffer.
  function loadArtifact(m) {
    if (m.embedded) setEmbedded(true);
    const art = m.artifact || {};
    const st = newState(new Uint8Array(art.bytes || new ArrayBuffer(0)), art.name || "untitled");
    const a = tamperHex.analyze(st.buf);
    st.cats = a.categories; st.entropy = a.entropy;
    applyView(m.view);
    if (m.view) {
      st.cursor = Math.min(m.view.cursor || 0, Math.max(0, st.size - 1));
      st.bookmarks = m.view.bookmarks || []; st.bmSeq = m.view.bmSeq || 0;
    }
    if (g.embedded) { g.tabs = [st]; g.active = 0; } else { g.tabs.push(st); g.active = g.tabs.length - 1; }
    s = st;
    renderTabs(); syncTab();
  }
  function setEmbedded(on) {
    if (g.embedded === on) return;
    g.embedded = on;
    document.body.classList.toggle("embedded", on);
    if (on) els.empty.textContent = "Select or add a file in the sidebar.";
  }

  function load(file) {
    const r = new FileReader();
    r.onload = () => {
      const st = newState(new Uint8Array(r.result), file.name);
      const a = tamperHex.analyze(st.buf);
      st.cats = a.categories; st.entropy = a.entropy;
      g.tabs.push(st);
      g.active = g.tabs.length - 1;
      s = st;
      els.file.value = "";
      els.viewport.focus();
      renderTabs(); syncTab();
    };
    r.readAsArrayBuffer(file);
  }

  // ---- tabs ----
  function renderTabs() {
    els.diffBtn.disabled = g.tabs.length < 2;
    if (!g.tabs.length) { els.tabbar.classList.add("hidden"); els.tabbar.innerHTML = ""; return; }
    els.tabbar.classList.remove("hidden");
    els.tabbar.innerHTML = g.tabs.map((t, i) =>
      `<div class="tab${i === g.active ? " active" : ""}" data-i="${i}" title="${escText(t.name)}"><span class="tabname">${escText(t.name || "untitled")}${t.modified ? " •" : ""}</span><span class="tabclose" data-close="${i}" title="Close">×</span></div>`
    ).join("") + `<button class="tabadd" title="Open file">+</button>`;
  }
  function switchTab(i) {
    if (i < 0 || i >= g.tabs.length || i === g.active) return;
    if (g.diff.on) exitDiff();
    g.active = i; s = g.tabs[i];
    renderTabs(); syncTab();
  }
  function closeTab(i) {
    if (g.diff.on) exitDiff();
    g.tabs.splice(i, 1);
    if (!g.tabs.length) { g.active = -1; s = newState(null, ""); }
    else { g.active = Math.min(i, g.tabs.length - 1); s = g.tabs[g.active]; }
    renderTabs(); syncTab();
  }
  function syncTab() {
    els.fname.textContent = s.buf ? s.name : "no file";
    els.find.value = ""; els.replace.value = ""; s.lastFind = null;
    els.findInfo.textContent = "";
    els.strCount.textContent = ""; els.strList.innerHTML = "";
    updateHeader(); render(); updateAll();
  }

  // ---- diff (two-pane, positional) ----
  function enterDiff() {
    if (g.tabs.length < 2) return;
    g.diff.on = true;
    g.diff.a = g.active >= 0 ? g.active : 0;
    g.diff.b = g.diff.a === 0 ? 1 : 0;
    g.diff.pos = -1;
    populateDiffSelects();
    els.body.classList.add("hidden");
    els.diff.classList.remove("hidden");
    refreshDiff();
  }
  function exitDiff() {
    g.diff.on = false;
    els.diff.classList.add("hidden");
    els.body.classList.remove("hidden");
    render();
  }
  function populateDiffSelects() {
    const opts = g.tabs.map((t, i) => `<option value="${i}">${escText(t.name || "untitled")}</option>`).join("");
    els.diffA.innerHTML = opts; els.diffB.innerHTML = opts;
    els.diffA.value = String(g.diff.a); els.diffB.value = String(g.diff.b);
  }
  function refreshDiff() {
    g.diff.pos = -1;
    const [a, b] = [g.tabs[g.diff.a], g.tabs[g.diff.b]];
    const n = Math.max(a.size, b.size);
    let d = 0;
    for (let i = 0; i < n; i++) {
      if (i >= a.size || i >= b.size || a.buf[i] !== b.buf[i]) d++;
    }
    els.diffInfo.textContent = d ? `${d} differing bytes` : "identical";
    renderDiffPanes();
  }
  let diffRaf = false;
  function scheduleDiffRender() {
    if (diffRaf) return;
    diffRaf = true;
    requestAnimationFrame(() => { diffRaf = false; renderDiffPanes(); });
  }
  let diffSync = false;
  function onDiffScroll(src, dst) {
    if (diffSync) return;
    diffSync = true;
    dst.scrollTop = src.scrollTop;
    diffSync = false;
    scheduleDiffRender();
  }
  function renderDiffPanes() {
    const a = g.tabs[g.diff.a], b = g.tabs[g.diff.b];
    els.diffAName.textContent = a.name || "untitled";
    els.diffBName.textContent = b.name || "untitled";
    const total = Math.ceil(Math.max(a.size, b.size, 1) / g.bpr);
    paintDiff(a, b, els.diffAvp, els.diffArows, els.diffAsizer, total);
    paintDiff(b, a, els.diffBvp, els.diffBrows, els.diffBsizer, total);
  }
  function paintDiff(self, other, vp, rowsEl, sizerEl, total) {
    sizerEl.style.height = total * ROW_H + "px";
    const first = Math.max(0, Math.floor(vp.scrollTop / ROW_H) - OVERSCAN);
    const count = Math.ceil(vp.clientHeight / ROW_H) + OVERSCAN * 2;
    const last = Math.min(total, first + count);
    rowsEl.style.top = first * ROW_H + "px";
    let html = "";
    for (let r = first; r < last; r++) {
      const base = r * g.bpr;
      let hex = "", asc = "";
      for (let i = 0; i < g.bpr; i++) {
        const idx = base + i;
        const sep = i < g.bpr - 1 ? (i % 8 === 7 ? "  " : " ") : "";
        if (idx >= self.size) {
          if (idx < other.size) { hex += `<span class="cell dcell">··</span>` + sep; asc += `<span class="cell dcell"> </span>`; }
          else hex += "  " + sep;
          continue;
        }
        const bb = self.buf[idx];
        const diff = idx >= other.size || self.buf[idx] !== other.buf[idx];
        const cls = "cell" + (diff ? " dcell" : (g.colorOn && CAT_CLASS[self.cats[idx]] ? " " + CAT_CLASS[self.cats[idx]] : ""));
        hex += `<span class="${cls}">${hx(bb)}</span>` + sep;
        asc += `<span class="${cls}">${esc(charFor(bb))}</span>`;
      }
      html += `<div class="row"><span class="off">${base.toString(16).padStart(8, "0")}</span><span class="hex">${hex}</span><span class="asc">${asc}</span></div>`;
    }
    rowsEl.innerHTML = html;
  }
  function jumpDiff(dir) {
    const a = g.tabs[g.diff.a], b = g.tabs[g.diff.b];
    const n = Math.max(a.size, b.size);
    if (!n) return;
    let i = g.diff.pos;
    for (let k = 0; k < n; k++) {
      i += dir;
      if (i < 0) i = n - 1;
      if (i >= n) i = 0;
      if (i >= a.size || i >= b.size || a.buf[i] !== b.buf[i]) { g.diff.pos = i; scrollDiffTo(i); return; }
    }
  }
  function scrollDiffTo(off) {
    const top = Math.max(0, Math.floor(off / g.bpr) * ROW_H - els.diffAvp.clientHeight / 2);
    diffSync = true;
    els.diffAvp.scrollTop = top; els.diffBvp.scrollTop = top;
    diffSync = false;
    renderDiffPanes();
  }

  // ---- rendering (windowed) ----
  let rafPending = false;
  function scheduleRender() {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(() => { rafPending = false; renderRows(); });
  }
  function render() { renderRows(); }

  function updateHeader() {
    if (!s.buf) { els.header.classList.add("hidden"); els.header.innerHTML = ""; return; }
    els.header.classList.remove("hidden");
    let hex = "";
    for (let i = 0; i < g.bpr; i++) {
      const sep = i < g.bpr - 1 ? (i % 8 === 7 ? "  " : " ") : "";
      hex += i.toString(16).padStart(2, "0") + sep;
    }
    els.header.innerHTML = `<span class="off">offset</span><span class="hex">${hex}</span><span class="asc">text</span>`;
  }

  function selRange() {
    if (s.anchor == null) return null;
    return [Math.min(s.anchor, s.cursor), Math.max(s.anchor, s.cursor)];
  }
  function inMatch(idx) {
    const m = s.matches;
    if (!m.length || s.matchLen <= 0) return false;
    let lo = 0, hi = m.length - 1, res = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (m[mid] <= idx) { res = m[mid]; lo = mid + 1; } else hi = mid - 1;
    }
    return res >= 0 && idx < res + s.matchLen;
  }

  function renderRows() {
    if (!s.buf || s.size === 0) {
      els.empty.style.display = "flex";
      els.header.classList.add("hidden");
      els.rows.innerHTML = "";
      els.sizer.style.height = "0px";
      return;
    }
    els.empty.style.display = "none";
    const total = Math.ceil(s.size / g.bpr);
    els.sizer.style.height = total * ROW_H + "px";
    const st = els.viewport.scrollTop;
    const first = Math.max(0, Math.floor(st / ROW_H) - OVERSCAN);
    const count = Math.ceil(els.viewport.clientHeight / ROW_H) + OVERSCAN * 2;
    const last = Math.min(total, first + count);
    els.rows.style.top = first * ROW_H + "px";

    const sr = selRange();
    let html = "";
    for (let r = first; r < last; r++) {
      const base = r * g.bpr;
      let hex = "", asc = "";
      for (let i = 0; i < g.bpr; i++) {
        const idx = base + i;
        const sep = i < g.bpr - 1 ? (i % 8 === 7 ? "  " : " ") : "";
        if (idx >= s.size) { hex += "  " + sep; continue; }
        const b = s.buf[idx];
        const cls = cellClass(idx, sr);
        const bm = bmColorAt(idx);
        const st = bm >= 0 ? ` style="box-shadow:inset 0 -2px 0 var(--swatch-${bm})"` : "";
        hex += `<span class="${cls}" data-o="${idx}" data-p="h"${st}>${hx(b)}</span>` + sep;
        asc += `<span class="${cls}" data-o="${idx}" data-p="a"${st}>${esc(charFor(b))}</span>`;
      }
      const active = Math.floor(s.cursor / g.bpr) === r ? " active" : "";
      html += `<div class="row${active}"><span class="off">${base.toString(16).padStart(8, "0")}</span><span class="hex">${hex}</span><span class="asc">${asc}</span></div>`;
    }
    els.rows.innerHTML = html;
  }

  function cellClass(idx, sr) {
    let c = "cell";
    if (g.colorOn && CAT_CLASS[s.cats[idx]]) c += " " + CAT_CLASS[s.cats[idx]];
    const inSel = sr && idx >= sr[0] && idx <= sr[1];
    if (inMatch(idx) && !inSel) c += " match";
    if (inSel) c += " sel";
    if (idx === s.cursor) c += " cur";
    return c;
  }

  const HD = "0123456789abcdef";
  function hx(b) { return HD[b >> 4] + HD[b & 15]; }
  function esc(c) { return c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === "&" ? "&amp;" : c; }
  function jsCat(b) {
    if (b === 0) return 0;
    if (b === 32 || b === 9 || b === 10 || b === 13 || b === 11 || b === 12) return 2;
    if (b >= 0x21 && b <= 0x7e) return 1;
    if (b >= 0x80) return 4;
    return 3;
  }

  // ---- cursor / selection ----
  function moveTo(off, extend) {
    off = Math.max(0, Math.min(s.size - 1, off));
    if (extend) { if (s.anchor == null) s.anchor = s.cursor; }
    else s.anchor = null;
    s.cursor = off; s.nibble = 0;
    ensureVisible(off);
    render(); updateInspector(); updateStatus(); updateSel();
  }
  function ensureVisible(idx) {
    const row = Math.floor(idx / g.bpr), top = row * ROW_H, vp = els.viewport;
    if (top < vp.scrollTop) vp.scrollTop = top;
    else if (top + ROW_H > vp.scrollTop + vp.clientHeight) vp.scrollTop = top + ROW_H - vp.clientHeight;
  }
  function visRows() { return Math.max(1, Math.floor(els.viewport.clientHeight / ROW_H) - 1); }

  function onMouseDown(e) {
    const cell = e.target.closest(".cell");
    if (!cell) return;
    const idx = +cell.dataset.o;
    s.pane = cell.dataset.p === "a" ? "ascii" : "hex";
    g.dragging = true;
    s.anchor = idx; s.cursor = idx; s.nibble = 0;
    render(); updateInspector(); updateStatus(); updateSel();
  }
  function onMouseMove(e) {
    if (!g.dragging) return;
    const cell = e.target.closest && e.target.closest(".cell");
    if (!cell) return;
    const idx = +cell.dataset.o;
    if (idx === s.cursor) return;
    s.cursor = idx;
    render(); updateInspector(); updateStatus(); updateSel();
  }

  // ---- editing (overwrite + insert/delete) ----
  function spliceBuf(off, removeLen, ins) {
    off = Math.max(0, Math.min(off, s.size));
    removeLen = Math.max(0, Math.min(removeLen, s.size - off));
    const removed = s.buf.slice(off, off + removeLen);
    const nb = new Uint8Array(s.size - removeLen + ins.length);
    nb.set(s.buf.subarray(0, off), 0);
    nb.set(ins, off);
    nb.set(s.buf.subarray(off + removeLen), off + ins.length);
    const nc = new Uint8Array(nb.length);
    nc.set(s.cats.subarray(0, off), 0);
    for (let i = 0; i < ins.length; i++) nc[off + i] = jsCat(ins[i]);
    nc.set(s.cats.subarray(off + removeLen), off + ins.length);
    s.buf = nb; s.cats = nc; s.size = nb.length;
    return removed;
  }
  function clearMatches() { s.matches = []; s.matchIdx = -1; s.matchLen = 0; els.findInfo.textContent = ""; }
  function applyEdit(off, removeLen, insArr) {
    const ins = insArr instanceof Uint8Array ? insArr : Uint8Array.from(insArr);
    const removed = spliceBuf(off, removeLen, ins);
    s.undo.push({ off, removed, inserted: ins });
    s.redo = [];
    const wasMod = s.modified;
    s.modified = true;
    if (!wasMod) renderTabs();
    clearMatches();
    updateButtons(); scheduleReanalyze();
  }
  function setByte(idx, val) { applyEdit(idx, 1, [val]); }
  function undo() {
    const e = s.undo.pop();
    if (!e) return;
    spliceBuf(e.off, e.inserted.length, e.removed);
    s.redo.push(e); s.modified = true; clearMatches();
    updateButtons(); moveTo(e.off, false);
  }
  function redo() {
    const e = s.redo.pop();
    if (!e) return;
    spliceBuf(e.off, e.removed.length, e.inserted);
    s.undo.push(e); s.modified = true; clearMatches();
    updateButtons(); moveTo(e.off + e.inserted.length - (e.inserted.length ? 1 : 0), false);
  }

  function onKey(e) {
    if (!s.buf) return;
    const k = e.key;
    if ((e.ctrlKey || e.metaKey) && !e.altKey) {
      if (k === "z" || k === "Z") { e.preventDefault(); e.shiftKey ? redo() : undo(); return; }
      if (k === "y") { e.preventDefault(); redo(); return; }
      if (k === "a") { e.preventDefault(); s.anchor = 0; moveTo(s.size - 1, true); return; }
      if (k === "f") { e.preventDefault(); els.find.focus(); return; }
      if (k === "g") { e.preventDefault(); els.goto.focus(); return; }
      if (k === "c") { e.preventDefault(); copyText(tamperHex.encode(selBytes(), "hex")); return; }
      return;
    }
    switch (k) {
      case "ArrowLeft": e.preventDefault(); return moveTo(s.cursor - 1, e.shiftKey);
      case "ArrowRight": e.preventDefault(); return moveTo(s.cursor + 1, e.shiftKey);
      case "ArrowUp": e.preventDefault(); return moveTo(s.cursor - g.bpr, e.shiftKey);
      case "ArrowDown": e.preventDefault(); return moveTo(s.cursor + g.bpr, e.shiftKey);
      case "Home": e.preventDefault(); return moveTo(s.cursor - (s.cursor % g.bpr), e.shiftKey);
      case "End": e.preventDefault(); return moveTo(s.cursor - (s.cursor % g.bpr) + g.bpr - 1, e.shiftKey);
      case "PageUp": e.preventDefault(); return moveTo(s.cursor - g.bpr * visRows(), e.shiftKey);
      case "PageDown": e.preventDefault(); return moveTo(s.cursor + g.bpr * visRows(), e.shiftKey);
      case "Tab": e.preventDefault(); s.pane = s.pane === "hex" ? "ascii" : "hex"; s.nibble = 0; return render();
      case "Insert": e.preventDefault(); g.insert = !g.insert; return updateMode();
      case "Delete": e.preventDefault(); if (s.size > 0) { applyEdit(s.cursor, 1, EMPTY); moveTo(Math.min(s.cursor, s.size - 1), false); } return;
      case "Backspace": e.preventDefault(); if (s.cursor > 0) { applyEdit(s.cursor - 1, 1, EMPTY); moveTo(s.cursor - 1, false); } return;
    }
    if (s.pane === "hex" && /^[0-9a-fA-F]$/.test(k)) {
      e.preventDefault();
      const d = parseInt(k, 16);
      if (g.insert && s.nibble === 0) { applyEdit(s.cursor, 0, [d << 4]); s.nibble = 1; render(); return; }
      if (s.size === 0) return;
      if (s.nibble === 0) { setByte(s.cursor, (d << 4) | (s.buf[s.cursor] & 0x0f)); s.nibble = 1; render(); }
      else { setByte(s.cursor, (s.buf[s.cursor] & 0xf0) | d); s.nibble = 0; moveTo(s.cursor + 1, false); }
    } else if (s.pane === "ascii" && k.length === 1 && k.charCodeAt(0) >= 0x20 && k.charCodeAt(0) <= 0x7e) {
      e.preventDefault();
      const code = k.charCodeAt(0);
      if (g.insert) applyEdit(s.cursor, 0, [code]);
      else if (s.size > 0) setByte(s.cursor, code);
      else applyEdit(s.cursor, 0, [code]);
      moveTo(s.cursor + 1, false);
    }
  }

  // ---- inspector ----
  function updateInspector() {
    if (!s.buf) { els.itable.innerHTML = ""; return; }
    const off = s.cursor, avail = Math.min(16, s.size - off);
    const tmp = new Uint8Array(16);
    tmp.set(s.buf.subarray(off, off + avail));
    const dv = new DataView(tmp.buffer);
    const le = !els.endian.checked;
    const rows = [
      ["i8", avail >= 1 ? dv.getInt8(0) : null],
      ["u8", avail >= 1 ? dv.getUint8(0) : null],
      ["i16", avail >= 2 ? dv.getInt16(0, le) : null],
      ["u16", avail >= 2 ? dv.getUint16(0, le) : null],
      ["i32", avail >= 4 ? dv.getInt32(0, le) : null],
      ["u32", avail >= 4 ? dv.getUint32(0, le) : null],
      ["i64", avail >= 8 ? dv.getBigInt64(0, le).toString() : null],
      ["u64", avail >= 8 ? dv.getBigUint64(0, le).toString() : null],
      ["f32", avail >= 4 ? trimF(dv.getFloat32(0, le)) : null],
      ["f64", avail >= 8 ? trimF(dv.getFloat64(0, le)) : null],
      ["bits", avail >= 1 ? dv.getUint8(0).toString(2).padStart(8, "0") : null],
      ["uleb", uleb(tmp, avail)],
      ["sleb", sleb(tmp, avail)],
    ];
    els.itable.innerHTML = rows
      .map((r) => `<tr><td class="k">${r[0]}</td><td class="v">${r[1] == null ? "<span class='dim'>-</span>" : r[1]}</td></tr>`)
      .join("");
  }
  function trimF(n) { return Number.isFinite(n) ? String(+n.toPrecision(8)) : String(n); }
  function uleb(a, avail) {
    let r = 0n, sh = 0n;
    for (let i = 0; i < avail && i < 10; i++) {
      r |= BigInt(a[i] & 0x7f) << sh;
      if ((a[i] & 0x80) === 0) return r.toString();
      sh += 7n;
    }
    return null;
  }
  function sleb(a, avail) {
    let r = 0n, sh = 0n;
    for (let i = 0; i < avail && i < 10; i++) {
      const b = a[i];
      r |= BigInt(b & 0x7f) << sh;
      sh += 7n;
      if ((b & 0x80) === 0) {
        if (b & 0x40) r |= -1n << sh;
        return r.toString();
      }
    }
    return null;
  }

  // ---- find / replace / goto ----
  function parseNeedle(t) {
    if (!t) return null;
    if (t[0] === "/") return new TextEncoder().encode(t.slice(1));
    const h = t.replace(/\s+/g, "");
    if (!/^[0-9a-fA-F]+$/.test(h) || h.length % 2) return null;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function ciFor(text) { return g.findCase && text[0] === "/"; }
  function doFind() {
    s.lastFind = els.find.value;
    const needle = parseNeedle(els.find.value);
    if (!needle || !s.buf) { clearMatches(); els.findInfo.textContent = needle ? "" : "bad pattern"; render(); return; }
    s.matches = tamperHex.find(s.buf, needle, ciFor(els.find.value));
    s.matchLen = needle.length; s.matchIdx = -1;
    if (!s.matches.length) { els.findInfo.textContent = "0 matches"; render(); return; }
    stepMatch(1);
  }
  function stepMatch(dir) {
    if (!s.matches.length) return;
    s.matchIdx = (s.matchIdx + dir + s.matches.length) % s.matches.length;
    const o = s.matches[s.matchIdx];
    s.anchor = o; s.cursor = Math.min(s.size - 1, o + s.matchLen - 1); s.nibble = 0;
    els.findInfo.textContent = `${s.matchIdx + 1}/${s.matches.length}`;
    ensureVisible(o); render(); updateInspector(); updateStatus(); updateSel();
  }
  function replBytes() {
    return els.replace.value === "" ? EMPTY : parseNeedle(els.replace.value);
  }
  function replaceOne() {
    if (!s.buf) return;
    const repl = replBytes();
    if (repl === null) { els.findInfo.textContent = "bad replacement"; return; }
    if (s.matchIdx < 0) { doFind(); if (s.matchIdx < 0) return; }
    applyEdit(s.matches[s.matchIdx], s.matchLen, repl);
    doFind();
  }
  function replaceAll() {
    if (!s.buf) return;
    const needle = parseNeedle(els.find.value);
    const repl = replBytes();
    if (!needle) { els.findInfo.textContent = "bad pattern"; return; }
    if (repl === null) { els.findInfo.textContent = "bad replacement"; return; }
    const hits = tamperHex.find(s.buf, needle, ciFor(els.find.value));
    if (!hits.length) { els.findInfo.textContent = "0 matches"; return; }
    const parts = []; let prev = 0, total = 0;
    for (const h of hits) { parts.push(s.buf.subarray(prev, h), repl); prev = h + needle.length; }
    parts.push(s.buf.subarray(prev));
    for (const p of parts) total += p.length;
    const nb = new Uint8Array(total); let o = 0;
    for (const p of parts) { nb.set(p, o); o += p.length; }
    applyEdit(0, s.size, nb);
    els.findInfo.textContent = `replaced ${hits.length}`;
    moveTo(Math.min(s.cursor, s.size - 1), false);
  }
  function doGoto() {
    if (!s.buf) return;
    const t = els.goto.value.trim();
    const off = t.startsWith("0x") ? parseInt(t, 16) : parseInt(t, 10);
    if (Number.isNaN(off)) return;
    els.viewport.focus();
    moveTo(off, false);
  }

  // ---- strings ----
  function scanStrings() {
    if (!s.buf) return;
    const min = Math.max(1, parseInt(els.strMin.value, 10) || 4);
    const hits = tamperHex.strings(s.buf, min);
    els.strCount.textContent = `${hits.length} strings`;
    const n = Math.min(hits.length, STR_CAP);
    let html = "";
    for (let i = 0; i < n; i++) {
      const h = hits[i];
      const t = h.text.length > 72 ? h.text.slice(0, 72) + "..." : h.text;
      html += `<div class="stritem" data-o="${h.offset}" data-l="${h.text.length}"><span class="so">${h.offset.toString(16).padStart(8, "0")}</span> ${escText(t)}</div>`;
    }
    if (hits.length > STR_CAP) html += `<div class="dim strmore">showing first ${STR_CAP}</div>`;
    els.strList.innerHTML = html;
  }
  function escText(t) { return t.replace(/[<>&]/g, (c) => (c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&amp;")); }

  // ---- bookmarks ----
  function addBookmark() {
    if (!s.buf) return;
    const sr = selRange() || [s.cursor, s.cursor];
    s.bmSeq++;
    s.bookmarks.push({ start: sr[0], end: sr[1], name: "bookmark " + s.bmSeq, color: BM_COLORS[(s.bmSeq - 1) % BM_COLORS.length] });
    renderBookmarks(); render();
  }
  function removeBookmark(i) { s.bookmarks.splice(i, 1); renderBookmarks(); render(); }
  function bmColorAt(idx) {
    for (const b of s.bookmarks) if (idx >= b.start && idx <= b.end) return b.color;
    return -1;
  }
  function renderBookmarks() {
    if (!s.bookmarks.length) { els.bmList.className = "dim"; els.bmList.textContent = "none"; return; }
    els.bmList.className = "";
    els.bmList.innerHTML = s.bookmarks.map((b, i) =>
      `<div class="bmitem" data-i="${i}"><span class="bmdot" style="background:var(--swatch-${b.color})"></span><span class="bmname">${escText(b.name)}</span><span class="bmoff">0x${b.start.toString(16)}</span><span class="bmdel" data-del="${i}" title="Remove">×</span></div>`
    ).join("");
  }
  function onBmClick(e) {
    const del = e.target.closest(".bmdel");
    if (del) { removeBookmark(+del.dataset.del); return; }
    const it = e.target.closest(".bmitem");
    if (!it) return;
    const b = s.bookmarks[+it.dataset.i];
    s.anchor = b.start; moveTo(b.end, true);
  }
  function onBmRename(e) {
    const it = e.target.closest(".bmitem");
    if (!it) return;
    const b = s.bookmarks[+it.dataset.i];
    const n = prompt("Bookmark name", b.name);
    if (n != null) { b.name = n; renderBookmarks(); }
  }

  // ---- export ----
  function selBytes() {
    const sr = selRange();
    return sr ? s.buf.subarray(sr[0], sr[1] + 1) : s.buf;
  }
  const EXPORTS = [
    { id: "raw", label: "Raw bytes", ext: "bin", raw: true },
    { id: "hex", label: "Hex", ext: "hex.txt" },
    { id: "hexdump", label: "Hexdump", ext: "txt" },
    { id: "c", label: "C array", ext: "h" },
    { id: "rust", label: "Rust array", ext: "rs" },
    { id: "go", label: "Go slice", ext: "go" },
    { id: "python", label: "Python bytes", ext: "py" },
    { id: "base64", label: "Base64", ext: "b64.txt" },
    { id: "json", label: "JSON array", ext: "json" },
    { id: "intelhex", label: "Intel HEX", ext: "hex" },
  ];
  function buildExportMenu() {
    els.exrows.innerHTML = EXPORTS.map((e) =>
      `<div class="exrow"><span class="exlabel">${e.label}</span>` +
      (e.raw ? "<span></span>" : `<button class="exbtn" data-act="copy" data-id="${e.id}">Copy</button>`) +
      `<button class="exbtn" data-act="save" data-id="${e.id}">Save</button></div>`
    ).join("");
  }
  function toggleExport() { els.exportMenu.classList.contains("hidden") ? openExport() : closeExport(); }
  function openExport() {
    if (!s.buf) return;
    setScope(selRange() ? "sel" : "whole");
    els.exportMenu.classList.remove("hidden");
  }
  function closeExport() { els.exportMenu.classList.add("hidden"); }
  function setScope(scope) {
    const hasSel = !!selRange();
    g.exScope = scope === "sel" && hasSel ? "sel" : "whole";
    els.exportMenu.querySelectorAll(".exscope button").forEach((b) => {
      const sc = b.dataset.scope;
      b.disabled = sc === "sel" && !hasSel;
      b.classList.toggle("active", sc === g.exScope);
    });
  }
  function exBytes() {
    const sr = selRange();
    return g.exScope === "sel" && sr ? s.buf.subarray(sr[0], sr[1] + 1) : s.buf;
  }
  function exName(ex) {
    if (ex.raw && g.exScope === "whole") return s.name || "data.bin";
    const base = (s.name || "data").replace(/\.[^.]*$/, "");
    return `${base}${g.exScope === "sel" ? "-sel" : ""}.${ex.ext}`;
  }
  function onExport(e) {
    const btn = e.target.closest(".exbtn");
    if (!btn) return;
    const ex = EXPORTS.find((x) => x.id === btn.dataset.id);
    const bytes = exBytes();
    if (btn.dataset.act === "copy") copyText(tamperHex.encode(bytes, ex.id));
    else if (ex.raw) saveFile(bytes, exName(ex));
    else saveFile(tamperHex.encode(bytes, ex.id), exName(ex));
    closeExport();
  }
  function saveFile(content, name) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content]));
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }
  function copyText(t) {
    if (navigator.clipboard) navigator.clipboard.writeText(t).catch(() => fallbackCopy(t));
    else fallbackCopy(t);
  }
  function fallbackCopy(t) {
    const ta = document.createElement("textarea");
    ta.value = t; ta.style.position = "fixed"; ta.style.left = "-9999px";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e) {}
    ta.remove();
  }

  // ---- status ----
  let reAn = 0;
  function scheduleReanalyze() {
    clearTimeout(reAn);
    reAn = setTimeout(() => {
      if (!s.buf) return;
      const a = tamperHex.analyze(s.buf);
      s.cats = a.categories; s.entropy = a.entropy;
      updateStatus(); render();
    }, 250);
  }
  function updateButtons() {
    els.undo.disabled = !s.undo.length;
    els.redo.disabled = !s.redo.length;
  }
  function updateMode() { els.mode.textContent = g.insert ? "insert" : "overwrite"; }
  function updateStatus() {
    els.pos.textContent = `offset 0x${s.cursor.toString(16)} (${s.cursor})`;
    els.dirty.textContent = s.modified ? "modified" : "";
    els.stats.textContent = `${s.size} bytes · entropy ${s.entropy.toFixed(3)}`;
  }
  function updateSel() {
    const sr = selRange();
    els.selinfo.innerHTML = sr
      ? `start <b>0x${sr[0].toString(16)}</b><br>end <b>0x${sr[1].toString(16)}</b><br>length <b>${sr[1] - sr[0] + 1}</b>`
      : "none";
  }
  function updateAll() { updateButtons(); updateStatus(); updateMode(); updateInspector(); updateSel(); renderBookmarks(); }
})();
