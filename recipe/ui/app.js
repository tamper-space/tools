(function () {
  var $ = function (id) { return document.getElementById(id); };
  var manifest = [];              // [{id, name, category, params}]
  var recipe = [];               // [{id, args}]
  var inputBytes = new Uint8Array(0);
  var name = "untitled";
  var runTimer = 0;
  var collabOn = false;
  var lastValue = ""; // baseline for diffing input edits into CRDT ops
  var remoteCursors = {}; // uid -> {name, color, start, end}
  var mirror = null, cursorTimer = 0, lastCursorKey = "";
  var eng = null;     // ops/manifest engine instance
  var crdtEng = null; // per-collab-session CRDT instance (site id from the shell)

  window.init = function () {
    eng = window.tamperEngines.recipe.create();
    try { manifest = JSON.parse(eng.manifest()); } catch (e) { manifest = []; }
    renderOps();
    $("opsearch").addEventListener("input", renderOps);
    $("oplist").addEventListener("click", onOpClick);
    $("steps").addEventListener("click", onStepClick);
    $("steps").addEventListener("input", onParamInput);
    $("input").addEventListener("input", onInputEdit);
    mirror = $("input-mirror");
    var inp = $("input");
    inp.addEventListener("scroll", function () { if (mirror) mirror.scrollTop = inp.scrollTop; });
    inp.addEventListener("keyup", reportCursor);
    inp.addEventListener("pointerup", reportCursor);
    document.addEventListener("selectionchange", function () { if (document.activeElement === inp) reportCursor(); });
    $("copy").addEventListener("click", copyOutput);
    $("clear").addEventListener("click", clearRecipe);
    renderRecipe(); run();
    window.addEventListener("message", onMsg);
    post({ type: "tamper:ready", tool: "recipe", accepts: ["bytes"] });
  };

  // Latin-1 keeps arbitrary bytes lossless through the text areas.
  function b2s(u8) { var s = ""; for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return s; }
  function s2b(str) { var u = new Uint8Array(str.length); for (var i = 0; i < str.length; i++) u[i] = str.charCodeAt(i) & 0xff; return u; }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function opByID(id) { for (var i = 0; i < manifest.length; i++) if (manifest[i].id === id) return manifest[i]; return null; }

  function renderOps() {
    var q = ($("opsearch").value || "").toLowerCase();
    var cats = {}, orderCats = [];
    manifest.forEach(function (op) {
      if (q && op.name.toLowerCase().indexOf(q) < 0 && op.category.toLowerCase().indexOf(q) < 0) return;
      if (!cats[op.category]) { cats[op.category] = []; orderCats.push(op.category); }
      cats[op.category].push(op);
    });
    var html = orderCats.map(function (cat) {
      return '<div class="opcat">' + esc(cat) + "</div>" + cats[cat].map(function (op) {
        return '<button type="button" class="opitem" data-add="' + esc(op.id) + '">' + esc(op.name) + "</button>";
      }).join("");
    }).join("");
    $("oplist").innerHTML = html || '<div class="dim empty">No operations.</div>';
  }

  function onOpClick(e) {
    var b = e.target.closest("[data-add]");
    if (!b) return;
    var op = opByID(b.dataset.add);
    if (!op) return;
    var args = {};
    (op.params || []).forEach(function (p) { args[p.name] = p.default || ""; });
    recipe.push({ id: op.id, args: args });
    renderRecipe(); run();
  }

  function renderRecipe() {
    $("recipe-empty").style.display = recipe.length ? "none" : "block";
    $("steps").innerHTML = recipe.map(function (step, i) {
      var op = opByID(step.id) || { name: step.id, params: [] };
      var params = (op.params || []).map(function (p) {
        return '<label class="param">' + esc(p.label || p.name) +
          '<input data-step="' + i + '" data-param="' + esc(p.name) + '" value="' + esc(step.args[p.name] || "") + '"></label>';
      }).join("");
      return '<div class="step" data-i="' + i + '"><div class="stephead"><span class="stepname">' + esc(op.name) + "</span>" +
        '<span class="stepctl"><button data-up="' + i + '" title="Move up">↑</button><button data-down="' + i + '" title="Move down">↓</button><button data-del="' + i + '" title="Remove">×</button></span></div>' +
        (params ? '<div class="params">' + params + "</div>" : "") + "</div>";
    }).join("");
  }

  function onStepClick(e) {
    var t = e.target.closest("button");
    if (!t) return;
    if (t.dataset.del != null) recipe.splice(+t.dataset.del, 1);
    else if (t.dataset.up != null) { var i = +t.dataset.up; if (i > 0) recipe.splice(i - 1, 0, recipe.splice(i, 1)[0]); }
    else if (t.dataset.down != null) { var j = +t.dataset.down; if (j < recipe.length - 1) recipe.splice(j + 1, 0, recipe.splice(j, 1)[0]); }
    else return;
    renderRecipe(); run();
  }
  function onParamInput(e) {
    var inp = e.target.closest("input[data-step]");
    if (!inp) return;
    recipe[+inp.dataset.step].args[inp.dataset.param] = inp.value;
    run();
  }
  function clearRecipe() { recipe = []; renderRecipe(); run(); }

  function onInputEdit() {
    var v = $("input").value;
    if (collabOn) {
      var ops = diffToOps(lastValue, v);
      if (ops.length) post({ type: "tamper:ops", ops: ops });
    }
    lastValue = v;
    inputBytes = s2b(v);
    $("inlen").textContent = inputBytes.length + " bytes";
    renderCursors();
    clearTimeout(runTimer); runTimer = setTimeout(run, 150);
  }
  // diffToOps turns an input change into CRDT ops via a prefix/suffix diff:
  // delete the changed middle, insert the new middle.
  function diffToOps(oldS, newS) {
    var maxP = Math.min(oldS.length, newS.length), p = 0;
    while (p < maxP && oldS.charCodeAt(p) === newS.charCodeAt(p)) p++;
    var s = 0;
    while (s < maxP - p && oldS.charCodeAt(oldS.length - 1 - s) === newS.charCodeAt(newS.length - 1 - s)) s++;
    var ops = [], o, i;
    if (!crdtEng) return [];
    for (i = 0; i < oldS.length - p - s; i++) { o = crdtEng.del(p); if (o && o !== "null") ops.push(JSON.parse(o)); }
    var ins = newS.slice(p, newS.length - s);
    for (i = 0; i < ins.length; i++) { o = crdtEng.insert(p + i, ins.charCodeAt(i) & 0xff); if (o && o !== "null") ops.push(JSON.parse(o)); }
    return ops;
  }

  function run() {
    var cur = inputBytes, failAt = -1, errMsg = "";
    for (var i = 0; i < recipe.length; i++) {
      var res = eng.run(recipe[i].id, cur, recipe[i].args || {});
      if (res && res.error) { failAt = i; errMsg = res.error; break; }
      cur = res.output;
    }
    $("output").value = b2s(cur);
    var steps = $("steps").children;
    for (var k = 0; k < steps.length; k++) steps[k].classList.toggle("failed", k === failAt);
    $("output").classList.toggle("errored", failAt >= 0);
    $("outlen").textContent = failAt >= 0 ? "error: " + errMsg : cur.length + " bytes";
  }

  function copyOutput() {
    if (navigator.clipboard) navigator.clipboard.writeText($("output").value).catch(function () {});
  }

  // Platform protocol (tamper: v2): the recipe operates on the input artifact;
  // the recipe chain is this tool's view of it.
  function onMsg(e) {
    if (e.origin !== location.origin) return;
    var m = e.data || {};
    if (m.type === "tamper:load") loadArtifact(m);
    else if (m.type === "tamper:getState") reply();
    else if (m.type === "tamper:collab") onCollab(m);
    else if (m.type === "tamper:ops") onRemoteOps(m.ops);
    else if (m.type === "tamper:cursor") { remoteCursors[m.uid] = { name: m.name, color: m.color, start: m.start, end: m.end }; renderCursors(); }
    else if (m.type === "tamper:present") prunePresence(m.uids || []);
  }
  function loadArtifact(m) {
    var art = m.artifact || {};
    inputBytes = new Uint8Array(art.bytes || new ArrayBuffer(0));
    name = art.name || "untitled";
    $("input").value = b2s(inputBytes);
    lastValue = $("input").value;
    $("inlen").textContent = inputBytes.length + " bytes";
    if (m.view && Array.isArray(m.view.recipe)) recipe = m.view.recipe;
    renderRecipe(); run();
  }
  // Collaboration: the input becomes a shared CRDT document. The first participant
  // seeds it from the loaded bytes; others receive the op log and apply it.
  function onCollab(m) {
    collabOn = !!m.on;
    if (!collabOn) { remoteCursors = {}; renderCursors(); return; }
    if (crdtEng) crdtEng.dispose();
    crdtEng = window.tamperEngines.recipe.create({ site: m.site || 1 });
    if (m.seed) {
      var ops = JSON.parse(crdtEng.seed(inputBytes) || "[]");
      lastValue = $("input").value;
      if (ops.length) post({ type: "tamper:ops", ops: ops });
    }
  }
  function onRemoteOps(ops) {
    if (!collabOn || !crdtEng || !ops || !ops.length) return;
    crdtEng.loadOps(JSON.stringify(ops));
    var text = b2s(crdtEng.text());
    var el = $("input"), caret = el.selectionStart;
    el.value = text;
    el.selectionStart = el.selectionEnd = Math.min(caret, text.length);
    lastValue = text;
    inputBytes = s2b(text);
    $("inlen").textContent = inputBytes.length + " bytes";
    renderCursors();
    clearTimeout(runTimer); runTimer = setTimeout(run, 150);
  }
  function reply() {
    var ab = inputBytes.slice().buffer;
    post({ type: "tamper:state", name: name, bytes: ab, view: { v: 1, recipe: recipe } }, [ab]);
  }
  function post(msg, transfer) { if (window.parent && window.parent !== window) window.parent.postMessage(msg, location.origin, transfer || []); }

  // ---- remote cursors + selections ----
  function reportCursor() {
    if (!collabOn) return;
    var el = $("input");
    var key = el.selectionStart + ":" + el.selectionEnd;
    if (key === lastCursorKey) return;
    lastCursorKey = key;
    clearTimeout(cursorTimer);
    cursorTimer = setTimeout(function () { post({ type: "tamper:cursor", start: el.selectionStart, end: el.selectionEnd }); }, 60);
  }
  function prunePresence(uids) {
    var keep = {};
    uids.forEach(function (u) { keep[u] = 1; });
    for (var k in remoteCursors) if (!keep[k]) delete remoteCursors[k];
    renderCursors();
  }
  function clampPos(v, max) { v = v | 0; return v < 0 ? 0 : v > max ? max : v; }
  function selBg(color) { return "color-mix(in srgb, " + color + " 30%, transparent)"; }
  function caretHTML(c) { return '<span class="rc-caret" style="--rc:' + esc(c.color || "#888") + '"><span class="rc-label">' + esc(c.name || "?") + "</span></span>"; }
  // renderCursors paints remote carets + selections into the mirror, splitting the
  // text at cursor/selection boundaries so spans align to the text grid.
  function renderCursors() {
    if (!mirror) return;
    var text = $("input").value;
    var ids = Object.keys(remoteCursors);
    if (!ids.length) { mirror.innerHTML = ""; mirror.scrollTop = $("input").scrollTop; return; }
    var carets = {}, sels = [], bounds = {};
    bounds[0] = 1; bounds[text.length] = 1;
    ids.forEach(function (uid) {
      var c = remoteCursors[uid];
      var s = clampPos(c.start, text.length), e = clampPos(c.end, text.length);
      (carets[e] = carets[e] || []).push(c);
      bounds[e] = 1;
      if (s !== e) { var lo = Math.min(s, e), hi = Math.max(s, e); sels.push({ lo: lo, hi: hi, color: c.color }); bounds[lo] = 1; bounds[hi] = 1; }
    });
    var pts = Object.keys(bounds).map(Number).sort(function (a, b) { return a - b; });
    var html = "";
    for (var p = 0; p < pts.length; p++) {
      var pos = pts[p];
      if (carets[pos]) carets[pos].forEach(function (c) { html += caretHTML(c); });
      if (p < pts.length - 1) {
        var a = pos, b = pts[p + 1], seg = esc(text.slice(a, b)), col = null;
        for (var si = 0; si < sels.length; si++) if (a >= sels[si].lo && b <= sels[si].hi) { col = sels[si].color; break; }
        html += col ? '<span class="rc-sel" style="background:' + selBg(col) + '">' + seg + "</span>" : seg;
      }
    }
    mirror.innerHTML = html;
    mirror.scrollTop = $("input").scrollTop;
  }
})();
