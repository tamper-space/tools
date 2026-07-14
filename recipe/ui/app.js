(function () {
  var $ = function (id) { return document.getElementById(id); };
  var manifest = [];              // [{id, name, category, params}]
  var recipe = [];               // [{id, args}]
  var inputBytes = new Uint8Array(0);
  var name = "untitled";
  var runTimer = 0;

  window.init = function () {
    try { manifest = JSON.parse(tamperOps.manifest()); } catch (e) { manifest = []; }
    renderOps();
    $("opsearch").addEventListener("input", renderOps);
    $("oplist").addEventListener("click", onOpClick);
    $("steps").addEventListener("click", onStepClick);
    $("steps").addEventListener("input", onParamInput);
    $("input").addEventListener("input", onInputEdit);
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
    inputBytes = s2b($("input").value);
    $("inlen").textContent = inputBytes.length + " bytes";
    clearTimeout(runTimer); runTimer = setTimeout(run, 150);
  }

  function run() {
    var cur = inputBytes, failAt = -1, errMsg = "";
    for (var i = 0; i < recipe.length; i++) {
      var res = tamperOps.run(recipe[i].id, cur, recipe[i].args || {});
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
  }
  function loadArtifact(m) {
    var art = m.artifact || {};
    inputBytes = new Uint8Array(art.bytes || new ArrayBuffer(0));
    name = art.name || "untitled";
    $("input").value = b2s(inputBytes);
    $("inlen").textContent = inputBytes.length + " bytes";
    if (m.view && Array.isArray(m.view.recipe)) recipe = m.view.recipe;
    renderRecipe(); run();
  }
  function reply() {
    var ab = inputBytes.slice().buffer;
    post({ type: "tamper:state", name: name, bytes: ab, view: { v: 1, recipe: recipe } }, [ab]);
  }
  function post(msg, transfer) { if (window.parent && window.parent !== window) window.parent.postMessage(msg, location.origin, transfer || []); }
})();
