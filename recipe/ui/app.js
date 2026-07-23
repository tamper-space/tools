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
    $("oplist").addEventListener("dragstart", onOpDragStart);
    $("oplist").addEventListener("dragend", onStepDragEnd);
    $("steps").addEventListener("click", onStepClick);
    $("steps").addEventListener("input", onParamInput);
    $("steps").addEventListener("change", onParamInput);
    $("steps").addEventListener("dragstart", onStepDragStart);
    $("steps").addEventListener("dragover", onStepDragOver);
    $("steps").addEventListener("drop", onStepDrop);
    $("steps").addEventListener("dragend", onStepDragEnd);
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

  // Pinned group: a default set of everyday ops, surfaced at the top so the 100+
  // catalog isn't a wall. Users pin/unpin any op; the set persists.
  var PINNED = "Pinned";
  var DEFAULT_PINS = ["magic", "from-base64", "to-base64", "from-hex", "to-hex", "url-decode", "url-encode", "from-charcode", "find-replace", "xor", "md5", "sha256", "gunzip", "jwt-decode"];
  var pins = (function () { try { var s = JSON.parse(localStorage.getItem("tn-recipe-pins")); if (Array.isArray(s)) return s; } catch (e) {} return DEFAULT_PINS.slice(); })();
  function savePins() { try { localStorage.setItem("tn-recipe-pins", JSON.stringify(pins)); } catch (e) {} }
  function togglePin(id) {
    var i = pins.indexOf(id);
    if (i >= 0) pins.splice(i, 1); else pins.push(id);
    savePins(); renderOps();
  }
  // Category open/closed state, persisted. Default: only Pinned open (categories
  // collapsed by default); a search overrides this to reveal all matches.
  var catOpen = (function () { try { return JSON.parse(localStorage.getItem("tn-recipe-cats")) || {}; } catch (e) { return {}; } })();
  function isOpen(cat) { return cat === PINNED ? catOpen[cat] !== false : catOpen[cat] === true; }
  function saveCats() { try { localStorage.setItem("tn-recipe-cats", JSON.stringify(catOpen)); } catch (e) {} }
  var ICON_CHEV_RIGHT = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>';
  var ICON_PIN = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5"/><path d="M9 10.8V4h6v6.8a2 2 0 0 0 .6 1.4l1.4 1.3H7l1.4-1.3a2 2 0 0 0 .6-1.4Z"/></svg>';

  function opItemHTML(op) {
    var d = op.description ? ' title="' + esc(op.description) + '"' : "";
    var on = pins.indexOf(op.id) >= 0 ? " on" : "";
    return '<div class="opitem" draggable="true" data-add="' + esc(op.id) + '"' + d + ">" +
      '<span class="opitem-name">' + esc(op.name) + "</span>" +
      '<button type="button" class="oppin' + on + '" data-pin="' + esc(op.id) + '" tabindex="-1" title="' + (on ? "Unpin" : "Pin") + '" aria-label="Pin operation">' + ICON_PIN + "</button>" +
      "</div>";
  }
  function opGroup(cat, ops, open) {
    var head = '<button type="button" class="opcat" data-cat="' + esc(cat) + '">' +
      '<span class="opcat-chev' + (open ? " open" : "") + '">' + ICON_CHEV_RIGHT + "</span>" +
      "<span>" + esc(cat) + '</span><span class="opcat-n">' + ops.length + "</span></button>";
    return open ? head + ops.map(opItemHTML).join("") : head;
  }

  function renderOps() {
    var q = ($("opsearch").value || "").toLowerCase();
    var searching = q.length > 0;
    var match = function (op) { return !q || op.name.toLowerCase().indexOf(q) >= 0 || op.category.toLowerCase().indexOf(q) >= 0; };
    var html = "";

    var pinnedOps = pins.map(opByID).filter(function (op) { return op && match(op); });
    if (pinnedOps.length) html += opGroup(PINNED, pinnedOps, searching || isOpen(PINNED));

    var cats = {};
    manifest.forEach(function (op) {
      if (!match(op)) return;
      (cats[op.category] = cats[op.category] || []).push(op);
    });
    Object.keys(cats).sort().forEach(function (cat) { html += opGroup(cat, cats[cat], searching || isOpen(cat)); });

    $("oplist").innerHTML = html || '<div class="dim empty">No operations.</div>';
  }

  function onOpClick(e) {
    var pin = e.target.closest("[data-pin]");
    if (pin) { togglePin(pin.dataset.pin); return; }
    var cat = e.target.closest("[data-cat]");
    if (cat) { var c = cat.dataset.cat; catOpen[c] = !isOpen(c); saveCats(); renderOps(); return; }
    var b = e.target.closest("[data-add]");
    if (!b) return;
    var op = opByID(b.dataset.add);
    if (!op) return;
    var args = {};
    (op.params || []).forEach(function (p) { args[p.name] = p.default || ""; });
    recipe.push({ id: op.id, args: args });
    renderRecipe(); run();
  }

  // paramControl renders a host-native control per param type (select dropdown,
  // boolean checkbox, number, or text) so the tool inherits the platform look.
  function paramControl(p, i, val) {
    var attrs = 'data-step="' + i + '" data-param="' + esc(p.name) + '"';
    if (p.type === "select") {
      return '<select ' + attrs + ">" + (p.options || []).map(function (o) {
        return '<option value="' + esc(o) + '"' + (String(val) === String(o) ? " selected" : "") + ">" + esc(o) + "</option>";
      }).join("") + "</select>";
    }
    if (p.type === "boolean") {
      return '<input type="checkbox" ' + attrs + (isTrue(val) ? " checked" : "") + ">";
    }
    if (p.type === "number") {
      // Custom stepper: native spin buttons don't theme in dark mode, so hide them
      // (CSS) and draw our own increment/decrement controls with crisp chevrons.
      return '<span class="numfield"><input type="number" ' + attrs + ' value="' + esc(val == null ? "" : val) + '">' +
        '<span class="numspin"><button type="button" class="numbtn" data-num="up" tabindex="-1" aria-label="Increase">' + ICON_CHEV_UP + "</button>" +
        '<button type="button" class="numbtn" data-num="down" tabindex="-1" aria-label="Decrease">' + ICON_CHEV_DOWN + "</button></span></span>";
    }
    return '<input ' + attrs + ' value="' + esc(val == null ? "" : val) + '">';
  }
  function isTrue(v) { v = String(v).toLowerCase(); return v === "true" || v === "1" || v === "yes" || v === "on"; }

  var ICON_X = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>';
  var ICON_CHEV_UP = '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m6 15 6-6 6 6"/></svg>';
  var ICON_CHEV_DOWN = '<svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>';
  var flowIDs = { fork: 1, merge: 1, register: 1, subsection: 1, label: 1, jump: 1, "conditional-jump": 1 };

  function renderRecipe() {
    $("recipe-empty").style.display = recipe.length ? "none" : "block";
    $("steps").innerHTML = recipe.map(function (step, i) {
      var op = opByID(step.id) || { name: step.id, params: [] };
      var params = (op.params || []).map(function (p) {
        return '<label class="param">' + esc(p.label || p.name) + paramControl(p, i, step.args[p.name]) + "</label>";
      }).join("");
      var cls = "step" + (step.disabled ? " off" : "") + (flowIDs[step.id] ? " flow" : "");
      var desc = op.description ? ' title="' + esc(op.description) + '"' : "";
      return '<div class="' + cls + '" data-i="' + i + '" draggable="true">' +
        '<div class="stephead">' +
          '<span class="draghandle" aria-hidden="true">⠇⠇</span>' +
          '<span class="stepnum">' + (i + 1) + "</span>" +
          '<span class="stepname"' + desc + ">" + esc(op.name) + "</span>" +
          '<button class="stepswitch" data-toggle="' + i + '" role="switch" aria-checked="' + (!step.disabled) + '" title="' + (step.disabled ? "Enable step" : "Disable step") + '"><span class="switch"></span></button>' +
          '<span class="stepctl"><button class="stepbtn" data-del="' + i + '" title="Remove step" aria-label="Remove step">' + ICON_X + "</button></span>" +
        "</div>" +
        (params ? '<div class="params">' + params + "</div>" : "") + "</div>";
    }).join("");
  }

  function onStepClick(e) {
    var num = e.target.closest("[data-num]");
    if (num) { stepNumber(num); return; }
    var t = e.target.closest("button");
    if (!t) return;
    if (t.dataset.del != null) recipe.splice(+t.dataset.del, 1);
    else if (t.dataset.toggle != null) { var s = recipe[+t.dataset.toggle]; s.disabled = !s.disabled; }
    else return;
    renderRecipe(); run();
  }
  // stepNumber adjusts a number param via the custom +/- buttons, respecting the
  // input's step/min/max, without a full re-render (keeps focus).
  function stepNumber(btn) {
    var input = btn.closest(".numfield").querySelector("input");
    var stepBy = parseFloat(input.step) || 1;
    var cur = parseFloat(input.value) || 0;
    var next = btn.dataset.num === "up" ? cur + stepBy : cur - stepBy;
    if (input.min !== "") next = Math.max(parseFloat(input.min), next);
    if (input.max !== "") next = Math.min(parseFloat(input.max), next);
    input.value = String(next);
    recipe[+input.dataset.step].args[input.dataset.param] = input.value;
    run();
  }

  // ---- drag: reorder steps, and add operations from the list ----
  var dragFrom = -1;  // step index being reordered
  var dragOp = null;  // operation id being dragged in from the list
  function onOpDragStart(e) {
    var b = e.target.closest("[data-add]");
    if (!b) return;
    dragOp = b.dataset.add; dragFrom = -1;
    e.dataTransfer.effectAllowed = "copy";
    try { e.dataTransfer.setData("text/plain", dragOp); } catch (_) {}
  }
  function onStepDragStart(e) {
    if (e.target.closest(".params")) { e.preventDefault(); return; } // let inputs select text
    var step = e.target.closest(".step");
    if (!step) return;
    dragFrom = +step.dataset.i; dragOp = null;
    step.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    try { e.dataTransfer.setData("text/plain", String(dragFrom)); } catch (_) {}
  }
  function clearDropMarks() {
    Array.prototype.forEach.call($("steps").querySelectorAll(".drop-before,.drop-after"), function (el) {
      el.classList.remove("drop-before", "drop-after");
    });
  }
  function dropTarget(e) {
    var step = e.target.closest(".step");
    if (!step) return null;
    var r = step.getBoundingClientRect();
    return { i: +step.dataset.i, after: e.clientY > r.top + r.height / 2, el: step };
  }
  function onStepDragOver(e) {
    if (dragFrom < 0 && !dragOp) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = dragOp ? "copy" : "move";
    if (dragOp) $("recipe").classList.add("drag-target");
    clearDropMarks();
    var t = dropTarget(e);
    if (t && t.i !== dragFrom) t.el.classList.add(t.after ? "drop-after" : "drop-before");
  }
  function onStepDrop(e) {
    if (dragFrom < 0 && !dragOp) return;
    e.preventDefault();
    $("recipe").classList.remove("drag-target");
    var t = dropTarget(e);
    var to = t ? (t.after ? t.i + 1 : t.i) : recipe.length;
    if (dragOp) {
      // Insert a new step from the operations list at the drop point.
      var op = opByID(dragOp), args = {};
      if (op) (op.params || []).forEach(function (p) { args[p.name] = p.default || ""; });
      recipe.splice(Math.max(0, Math.min(recipe.length, to)), 0, { id: dragOp, args: args });
    } else {
      if (dragFrom < to) to--; // the splice-out shifts everything after dragFrom left
      var item = recipe.splice(dragFrom, 1)[0];
      recipe.splice(Math.max(0, Math.min(recipe.length, to)), 0, item);
    }
    dragFrom = -1; dragOp = null;
    renderRecipe(); run();
  }
  function onStepDragEnd() {
    dragFrom = -1; dragOp = null;
    clearDropMarks();
    $("recipe").classList.remove("drag-target");
    var d = $("steps").querySelector(".dragging");
    if (d) d.classList.remove("dragging");
  }
  function onParamInput(e) {
    var el = e.target.closest("[data-param]");
    if (!el) return;
    var val = el.type === "checkbox" ? (el.checked ? "true" : "false") : el.value;
    recipe[+el.dataset.step].args[el.dataset.param] = val;
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

  // run executes the whole recipe through the engine interpreter (one call), so
  // flow-control steps (Fork/Merge/Register) work; the per-step error drives the
  // failed-step highlight.
  function run() {
    var res = eng.runRecipe(JSON.stringify(recipe.map(function (s) {
      return { id: s.id, args: s.args || {}, disabled: !!s.disabled };
    })), inputBytes);
    var out = res.output || new Uint8Array(0);
    $("output").value = b2s(out);
    var failAt = typeof res.failedAt === "number" ? res.failedAt : -1;
    var steps = $("steps").children;
    for (var k = 0; k < steps.length; k++) steps[k].classList.toggle("failed", k === failAt);
    $("output").classList.toggle("errored", failAt >= 0);
    $("outlen").textContent = failAt >= 0 ? "error: " + (res.error || "failed") : out.length + " bytes";
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
