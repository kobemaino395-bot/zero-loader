/* zero-loader console — client logic */

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// ─── utilities ────────────────────────────────────────────────────────────

function getFilenameInputValue(id) {
  const inp = $("#" + id);
  if (!inp) return "";
  const ext = inp.nextElementSibling?.classList.contains("file-ext")
    ? inp.nextElementSibling.textContent : "";
  const name = inp.value.trim();
  return name ? name + ext : "";
}

function setFilenameInputValue(id, fullName) {
  const inp = $("#" + id);
  if (!inp) return;
  const extEl = inp.nextElementSibling?.classList.contains("file-ext")
    ? inp.nextElementSibling : null;
  const ext = extEl ? extEl.textContent : "";
  if (ext && fullName.endsWith(ext)) {
    inp.value = fullName.slice(0, -ext.length);
  } else {
    inp.value = fullName;
  }
}

function fmtSize(n) {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
function fmtTime(sec) {
  return new Date(sec * 1000).toLocaleString();
}
function fmtTimeShort(sec) {
  const d = new Date(sec * 1000);
  return d.toLocaleDateString([], {month:"short", day:"numeric"}) + " " +
         d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"});
}
function trunc(s, n = 20) {
  return s && s.length > n ? s.slice(0, n) + "…" : (s || "");
}
function writeConsole(el, line, { ok = null, reset = false } = {}) {
  if (reset) el.textContent = "";
  el.textContent += line;
  el.scrollTop = el.scrollHeight;
  el.classList.remove("ok", "bad");
  if (ok === true)  el.classList.add("ok");
  if (ok === false) el.classList.add("bad");
}

// ─── page switching ────────────────────────────────────────────────────────

const VALID_PAGES = new Set(["build","sideload","donut","arweave","pools","tor"]);

function navigateTo(target, pushState = true) {
  if (!VALID_PAGES.has(target)) target = "build";
  $$(".page-btn").forEach(b => b.classList.toggle("active", b.dataset.page === target));
  $$(".page").forEach(p => p.classList.toggle("active", p.id === `page-${target}`));
  if (pushState) history.pushState({ page: target }, "", `#${target}`);
  if (target === "donut")    refreshDonutJobs();
  if (target === "arweave")  { refreshWallets(); refreshEncryptDropdowns(); }
  if (target === "sideload") refreshSideloadAssets();
  if (target === "pools")    refreshPools();
  if (target === "tor")      { torRefresh(); torLoadLog(); }
  if (target === "build")    { refreshEncryptDropdowns(); refreshSideloadSelectors(); refreshEncryptHistory(); refreshBuildHistory(); refreshPayloadSelector(); }
}

$$(".page-btn").forEach(btn => {
  btn.addEventListener("click", () => navigateTo(btn.dataset.page));
});

// restore tab from hash on load / handle browser back-forward
window.addEventListener("popstate", e => {
  const page = (e.state && e.state.page) || location.hash.replace("#", "") || "build";
  navigateTo(page, false);
});

// initial load: read hash — called at boot after all declarations (see bottom of file)

// ─── inner tab switching (Build page) ─────────────────────────────────────

$$(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach(t => t.classList.toggle("active", t === btn));
    const target = btn.dataset.tab;
    $$(".panel").forEach(p => p.classList.toggle("active", p.id === `panel-${target}`));
    if (target === "encrypt") refreshEncryptHistory();
    if (target === "build")   refreshBuildHistory();
  });
});


// ─── artifacts ────────────────────────────────────────────────────────────

function refreshArtifacts() {
  const list = $("#artifact-list");
  list.innerHTML = "";
  if (!_buildHistory.length) {
    list.innerHTML = "<p class='empty-note'>No builds yet.</p>";
    return;
  }
  for (const j of _buildHistory.slice(0, 10)) {
    const li = document.createElement("li");
    li.className = "artifact";
    const dot    = j.ok ? "●" : "○";
    const dotCls = j.ok ? "dot-ok" : "dot-bad";
    const sz     = j.zip_size > 0 ? j.zip_size : (j.binary_size || 0);
    let dlLink = "";
    if (j.zip_size > 0)
      dlLink = `<a class="dl" href="/api/build/history/${j.id}/download/zip">↓ zip</a>`;
    else if (j.binary_size > 0)
      dlLink = `<a class="dl" href="/api/build/history/${j.id}/download/binary">↓ bin</a>`;
    li.innerHTML = `
      <div class="name">
        <span class="ji-dot ${dotCls}">${dot}</span>
        <span>${j.zip_name || j.binary_name || "—"}</span>
        ${dlLink}
      </div>
      <div class="meta">${j.mode} · ${fmtSize(sz)} · ${fmtTimeShort(j.created_at)}</div>`;
    list.appendChild(li);
  }
}
$("#btn-refresh-arts").addEventListener("click", () => { refreshBuildHistory(); });


// ─── custom dropdown (CDD) ───────────────────────────────────────────────────

let _cddValidIds = new Set();  // tracks valid donut job ids for profile restore

function _cddClose() {
  $$(".cdd.open").forEach(w => {
    w.classList.remove("open");
    w.querySelector(".cdd-list")?.classList.add("hidden");
  });
}
document.addEventListener("click", _cddClose);

function _cddSetDisplay(wrap, html) {
  const d = wrap.querySelector(".cdd-display");
  if (d) d.innerHTML = html;
}

function cddSetValue(wrapId, hiddenId, value) {
  const wrap   = $(`#${wrapId}`);
  const hidden = $(`#${hiddenId}`);
  if (!wrap || !hidden) return;
  hidden.value = value || "";
  const item = wrap.querySelector(`.cdd-item[data-value="${CSS.escape(value)}"]`);
  if (item) {
    _cddSetDisplay(wrap, item.innerHTML.replace(/<button[^>]*>.*?<\/button>/s, "").trim());
    wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.toggle("cdd-selected", i === item));
  } else {
    _cddSetDisplay(wrap, value ? `#${value.slice(0,6)}…` : "— select a Stub —");
    wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.remove("cdd-selected"));
  }
}

// ─── encrypt dropdowns ────────────────────────────────────────────────────
// Populates:  #enc-sc-job-wrap / #enc-sc-job  (shellcode from donut workspace)

async function refreshEncryptDropdowns() {
  // Donut jobs → custom shellcode dropdown
  try {
    const jobs = await fetch("/api/donut/jobs").then(r => r.json());
    const wrap = $("#enc-sc-job-wrap");
    const list = wrap.querySelector(".cdd-list");
    const prev = $("#enc-sc-job").value;
    list.innerHTML = "";
    _cddValidIds.clear();
    const ok = jobs.filter(j => j.ok);
    if (!ok.length) {
      _cddSetDisplay(wrap, "— no successful Stub jobs yet —");
      $("#enc-sc-job").value = "";
    } else {
      const ph = document.createElement("div");
      ph.className = "cdd-item cdd-placeholder";
      ph.textContent = "— select a Stub —";
      ph.addEventListener("click", () => { cddSetValue("enc-sc-job-wrap", "enc-sc-job", ""); _cddClose(); });
      list.appendChild(ph);

      for (const j of ok) {
        _cddValidIds.add(j.id);
        const item = document.createElement("div");
        item.className = "cdd-item";
        item.dataset.value = j.id;
        const labelHtml = j.label
          ? `<span class="cdd-label-badge">${j.label}</span>`
          : "";
        item.innerHTML = `
          <span class="cdd-item-id">#${j.id.slice(0,6)}</span>
          ${labelHtml}
          <span class="cdd-item-name">${j.original_name}</span>
          <span class="cdd-item-meta">${fmtSize(j.size_out)} · ${j.arch_label}</span>`;
        item.addEventListener("click", () => {
          cddSetValue("enc-sc-job-wrap", "enc-sc-job", j.id);
          _cddClose();
        });
        if (j.id === prev) item.classList.add("cdd-selected");
        list.appendChild(item);
      }
      if (!prev || !_cddValidIds.has(prev)) {
        _cddSetDisplay(wrap, "— select a Stub —");
        $("#enc-sc-job").value = "";
      } else {
        cddSetValue("enc-sc-job-wrap", "enc-sc-job", prev);
      }
    }

    const trigger = wrap.querySelector(".cdd-trigger");
    trigger.onclick = (e) => {
      e.stopPropagation();
      const isOpen = wrap.classList.contains("open");
      _cddClose();
      if (!isOpen) {
        wrap.classList.add("open");
        wrap.querySelector(".cdd-list").classList.remove("hidden");
      }
    };
  } catch (_) {}

  // Wallets → enc-wallet-wrap / enc-wallet-id
  try {
    const wallets = await fetch("/api/wallets").then(r => r.json());
    const wrap    = $("#enc-wallet-wrap");
    const hidden  = $("#enc-wallet-id");
    if (!wrap || !hidden) return;
    const list = wrap.querySelector(".cdd-list");
    const prev = hidden.value;
    list.innerHTML = "";

    const ph = document.createElement("div");
    ph.className = "cdd-item cdd-placeholder";
    ph.textContent = "— select a wallet —";
    ph.addEventListener("click", () => {
      hidden.value = "";
      _cddSetDisplay(wrap, "— select a wallet —");
      wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.remove("cdd-selected"));
      _cddClose();
    });
    list.appendChild(ph);

    if (!wallets.length) {
      _cddSetDisplay(wrap, "— no wallets yet (create one in the Arweave tab) —");
    } else {
      for (const w of wallets) {
        const item = document.createElement("div");
        item.className = "cdd-item" + (w.id === prev ? " cdd-selected" : "");
        item.dataset.value = w.id;
        item.innerHTML = `
          <span class="cdd-item-id">#${w.id.slice(0,6)}</span>
          <span class="cdd-label-badge">${w.name}</span>
          <span class="cdd-item-name">${w.address}</span>`;
        item.addEventListener("click", () => {
          hidden.value = w.id;
          _cddSetDisplay(wrap, item.innerHTML);
          wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.toggle("cdd-selected", i === item));
          _cddClose();
        });
        list.appendChild(item);
      }
      if (prev && wallets.find(w => w.id === prev)) {
        const sel = wrap.querySelector(`.cdd-item[data-value="${CSS.escape(prev)}"]`);
        if (sel) _cddSetDisplay(wrap, sel.innerHTML);
      } else {
        _cddSetDisplay(wrap, "— select a wallet —");
        hidden.value = "";
      }
    }

    const trigger = wrap.querySelector(".cdd-trigger");
    trigger.onclick = (e) => {
      e.stopPropagation();
      const isOpen = wrap.classList.contains("open");
      _cddClose();
      if (!isOpen) { wrap.classList.add("open"); list.classList.remove("hidden"); }
    };
  } catch (_) {}
}

// ─── encrypt ──────────────────────────────────────────────────────────────

$("#form-encrypt").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#out-encrypt");
  writeConsole(out, "> running Encrypt.py …\n", { reset: true });

  const fd = new FormData();

  const jobId = $("#enc-sc-job").value;
  if (jobId) fd.append("shellcode_job_id", jobId);

  const walletId = $("#enc-wallet-id").value;
  if (walletId) fd.append("wallet_id", walletId);

  try {
    const r = await fetch("/api/encrypt", { method: "POST", body: fd });
    const j = await r.json();
    if (j.stdout) writeConsole(out, j.stdout);
    if (j.stderr) writeConsole(out, j.stderr);
    writeConsole(out, `\n[exit ${j.code ?? (j.ok ? 0 : -1)}]\n`, { ok: j.ok });
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  refreshEncryptHistory();
  refreshPayloadSelector();
});


// ─── sideload workspace (DLL + EXE management) ────────────────────────────

let _dlls  = [];
let _exes  = [];
let _binds = [];

async function refreshSideloadAssets() {
  await Promise.all([refreshDlls(), refreshExes(), refreshBinds()]);
}

// ── DLLs ──────────────────────────────────────────────────────────────────

async function refreshDlls() {
  try { _dlls = await fetch("/api/dlls").then(r => r.json()); }
  catch (_) { _dlls = []; }
  renderDlls();
  refreshSideloadSelectors();
}

function renderDlls() {
  const list  = $("#dll-list");
  const empty = $("#dll-empty");
  list.querySelectorAll(".sl-asset-item").forEach(el => el.remove());
  if (!_dlls.length) { empty.style.display = ""; return; }
  empty.style.display = "none";
  for (const d of _dlls) {
    const el = document.createElement("div");
    el.className = "sl-asset-item";
    const selDllId = $("#sl-dll-sel")?.value;
    const active = selDllId === d.id ? " selected" : "";
    el.innerHTML = `
      <div class="sai-info${active}">
        <span class="sai-name">${d.name}</span>
        <span class="sai-meta">#${d.id} · ${fmtSize(d.size)} · ${fmtTimeShort(d.created_at)}</span>
      </div>
      <div class="sai-btns">
        <button class="btn-xs primary" data-select-dll="${d.id}" title="Select for build">Use</button>
        <button class="btn-xs btn-danger" data-del-dll="${d.id}" title="Delete">✕</button>
      </div>`;
    list.appendChild(el);
    el.querySelector(`[data-select-dll]`).addEventListener("click", () => selectDll(d.id));
    el.querySelector(`[data-del-dll]`).addEventListener("click", () => deleteDll(d.id));
  }
}

function selectDll(id) {
  const sel = $("#sl-dll-sel");
  if (sel) sel.value = id;
  renderDlls(); // refresh "active" highlight
}

async function deleteDll(id) {
  if (!confirm("Delete this DLL from workspace?")) return;
  await fetch(`/api/dlls/${id}`, { method: "DELETE" });
  refreshDlls();
}

$("#sl-dll-upload").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("dll", file);
  const btn = $("label[for=sl-dll-upload]");
  const orig = btn.textContent;
  btn.textContent = "Uploading…";
  try {
    const r = await fetch("/api/dlls", { method: "POST", body: fd });
    const j = await r.json();
    if (j.ok) { await refreshDlls(); selectDll(j.dll.id); }
    else alert("Upload failed: " + (j.stderr || "unknown error"));
  } catch (err) { alert("Upload error: " + err); }
  finally { btn.textContent = orig; e.target.value = ""; }
});

// ── EXEs ──────────────────────────────────────────────────────────────────

async function refreshExes() {
  try { _exes = await fetch("/api/exes").then(r => r.json()); }
  catch (_) { _exes = []; }
  renderExes();
  refreshSideloadSelectors();
}

function renderExes() {
  const list  = $("#exe-list");
  const empty = $("#exe-empty");
  list.querySelectorAll(".sl-asset-item").forEach(el => el.remove());
  if (!_exes.length) { empty.style.display = ""; return; }
  empty.style.display = "none";
  for (const x of _exes) {
    const el = document.createElement("div");
    el.className = "sl-asset-item";
    const selExeId = $("#sl-exe-sel")?.value;
    const active = selExeId === x.id ? " selected" : "";
    el.innerHTML = `
      <div class="sai-info${active}">
        <span class="sai-name">${x.name}</span>
        <span class="sai-meta">#${x.id} · ${fmtSize(x.size)} · ${fmtTimeShort(x.created_at)}</span>
      </div>
      <div class="sai-btns">
        <button class="btn-xs primary" data-select-exe="${x.id}" title="Select for build">Use</button>
        <button class="btn-xs btn-danger" data-del-exe="${x.id}" title="Delete">✕</button>
      </div>`;
    list.appendChild(el);
    el.querySelector(`[data-select-exe]`).addEventListener("click", () => selectExe(x.id));
    el.querySelector(`[data-del-exe]`).addEventListener("click", () => deleteExe(x.id));
  }
}

function selectExe(id) {
  const sel = $("#sl-exe-sel");
  if (sel) sel.value = id;
  renderExes();
}

async function deleteExe(id) {
  if (!confirm("Delete this EXE from workspace?")) return;
  await fetch(`/api/exes/${id}`, { method: "DELETE" });
  refreshExes();
}

$("#sl-exe-upload").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("exe", file);
  const btn = $("label[for=sl-exe-upload]");
  const orig = btn.textContent;
  btn.textContent = "Uploading…";
  try {
    const r = await fetch("/api/exes", { method: "POST", body: fd });
    const j = await r.json();
    if (j.ok) { await refreshExes(); selectExe(j.exe.id); }
    else alert("Upload failed: " + (j.stderr || "unknown error"));
  } catch (err) { alert("Upload error: " + err); }
  finally { btn.textContent = orig; e.target.value = ""; }
});

// ── Bind files ────────────────────────────────────────────────────────────

async function refreshBinds() {
  try { _binds = await fetch("/api/binds").then(r => r.json()); }
  catch (_) { _binds = []; }
  renderBinds();
  refreshSideloadSelectors();
}

function renderBinds() {
  const list  = $("#bind-list");
  const empty = $("#bind-empty");
  list.querySelectorAll(".sl-asset-item").forEach(el => el.remove());
  if (!_binds.length) { empty.style.display = ""; return; }
  empty.style.display = "none";
  for (const b of _binds) {
    const el = document.createElement("div");
    el.className = "sl-asset-item";
    const selBindId = $("#sl-bind-sel")?.value;
    const active = selBindId === b.id ? " selected" : "";
    el.innerHTML = `
      <div class="sai-info${active}">
        <span class="sai-name">${b.name}</span>
        <span class="sai-meta">#${b.id} · ${fmtSize(b.size)} · ${fmtTimeShort(b.created_at)}</span>
      </div>
      <div class="sai-btns">
        <a class="btn-xs" href="/api/binds/${b.id}/download" title="Download">↓</a>
        <button class="btn-xs primary" data-select-bind="${b.id}" title="Select for build">Use</button>
        <button class="btn-xs btn-danger" data-del-bind="${b.id}" title="Delete">✕</button>
      </div>`;
    list.appendChild(el);
    el.querySelector(`[data-select-bind]`).addEventListener("click", () => selectBind(b.id));
    el.querySelector(`[data-del-bind]`).addEventListener("click", () => deleteBind(b.id));
  }
}

function selectBind(id) {
  const sel = $("#sl-bind-sel");
  if (sel) sel.value = id;
  syncBindRenameExt();
  renderBinds();
}

async function deleteBind(id) {
  if (!confirm("Delete this bind file from workspace?")) return;
  await fetch(`/api/binds/${id}`, { method: "DELETE" });
  refreshBinds();
}

$("#sl-bind-upload").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("bind", file);
  const btn = $("label[for=sl-bind-upload]");
  const orig = btn.textContent;
  btn.textContent = "Uploading…";
  try {
    const r = await fetch("/api/binds", { method: "POST", body: fd });
    const j = await r.json();
    if (j.ok) { await refreshBinds(); selectBind(j.bind.id); }
    else alert("Upload failed: " + (j.stderr || "unknown error"));
  } catch (err) { alert("Upload error: " + err); }
  finally { btn.textContent = orig; e.target.value = ""; }
});

// ── sideload dropdowns (in Build tab) ────────────────────────────────────

function refreshSideloadSelectors() {
  const dllSel  = $("#sl-dll-sel");
  const exeSel  = $("#sl-exe-sel");
  const bindSel = $("#sl-bind-sel");
  if (!dllSel || !exeSel) return;

  const prevDll  = dllSel.value;
  const prevExe  = exeSel.value;
  const prevBind = bindSel ? bindSel.value : "";

  dllSel.innerHTML = _dlls.length
    ? `<option value="">— select DLL —</option>` + _dlls.map(d =>
        `<option value="${d.id}">${d.name}  (#${d.id} · ${fmtSize(d.size)})</option>`).join("")
    : `<option value="">— no DLLs in workspace yet —</option>`;
  if (prevDll && [...dllSel.options].some(o => o.value === prevDll)) dllSel.value = prevDll;

  exeSel.innerHTML = _exes.length
    ? `<option value="">— select EXE —</option>` + _exes.map(x =>
        `<option value="${x.id}">${x.name}  (#${x.id} · ${fmtSize(x.size)})</option>`).join("")
    : `<option value="">— no EXEs in workspace yet —</option>`;
  if (prevExe && [...exeSel.options].some(o => o.value === prevExe)) exeSel.value = prevExe;

  if (bindSel) {
    bindSel.innerHTML = `<option value="">— none —</option>` + _binds.map(b =>
      `<option value="${b.id}">${b.name}  (#${b.id} · ${fmtSize(b.size)})</option>`).join("");
    if (prevBind && [...bindSel.options].some(o => o.value === prevBind)) bindSel.value = prevBind;
  }

  syncBindRenameExt();
}

function syncBindRenameExt() {
  const extEl = $("#sl-bind-rename-ext");
  if (!extEl) return;
  const bindSel = $("#sl-bind-sel");
  const id = bindSel?.value;
  const bind = id ? _binds.find(b => b.id === id) : null;
  if (bind?.name) {
    const dot = bind.name.lastIndexOf(".");
    extEl.textContent = dot !== -1 ? bind.name.slice(dot) : "";
  } else {
    extEl.textContent = "";
  }
}


// ─── build ────────────────────────────────────────────────────────────────

function syncBuildMode() {
  const mode = $("input[name=mode]:checked", $("#form-build"))?.value;
  $("#field-sideload-config")?.classList.toggle("hidden", mode !== "sideload");
  $("#field-exe-name")?.classList.toggle("hidden", mode === "sideload");
}
$$("input[name=mode]").forEach(r => r.addEventListener("change", () => {
  syncBuildMode();
  // Persist the chosen mode so it survives page reloads
  try { localStorage.setItem("zeroBuildMode", r.value); } catch (_) {}
}));
// Restore last-used mode on boot (before first syncBuildMode call)
try {
  const _savedMode = localStorage.getItem("zeroBuildMode");
  if (_savedMode) {
    const _modeEl = $(`input[name=mode][value="${_savedMode}"]`, $("#form-build"));
    if (_modeEl) _modeEl.checked = true;
  }
} catch (_) {}
syncBuildMode();

$("#sl-bind-sel")?.addEventListener("change", syncBindRenameExt);

$("#form-build").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#out-build"), form = e.target;
  out.textContent = ""; out.classList.remove("ok", "bad");

  const mode = $("input[name=mode]:checked", form)?.value;
  const body = {
    mode,
    uac:                form.uac.checked,
    rwx:                form.rwx.checked,
    debug:              form.debug.checked,
    synthetic:          form.synthetic.checked,
    exe_output_name:    $("#bld-exe-name")?.value.trim()   || "",
    encrypt_history_id: $("#bld-payload-sel")?.value       || "",
    dll_id:             $("#sl-dll-sel")?.value            || "",
    exe_id:             $("#sl-exe-sel")?.value            || "",
    sideload_rename:    getFilenameInputValue("sl-dll-rename"),
    host_rename:        getFilenameInputValue("sl-host-rename"),
    zip_name:           getFilenameInputValue("sl-zip-name"),
    bind_id:            $("#sl-bind-sel")?.value           || "",
    bind_rename:        getFilenameInputValue("sl-bind-rename"),
  };

  const btn = $("button.primary", form);
  btn.disabled = true; btn.textContent = "Building…";
  try {
    const r = await fetch("/api/build", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const reader = r.body.getReader(), decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf = decoder.decode(value, { stream: true });
      writeConsole(out, buf);
    }
    const last = out.textContent.trim().split("\n").at(-1);
    const m = last?.match(/\[exit (-?\d+)\]/);
    if (m) { out.classList.toggle("ok", m[1] === "0"); out.classList.toggle("bad", m[1] !== "0"); }
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  finally { btn.disabled = false; btn.textContent = "Build"; refreshBuildHistory(); }
});

// ─── profiles ─────────────────────────────────────────────────────────────

// ─── profiles ─────────────────────────────────────────────────────────────

let _encProfiles = [];
let _bldProfiles = [];
let _curEncProfileId = null, _curEncProfileName = "";
let _curBldProfileId = null, _curBldProfileName = "";

async function refreshEncProfiles() {
  try { _encProfiles = await fetch("/api/profiles/encrypt").then(r => r.json()); _encProfiles.sort((a,b) => a.name.localeCompare(b.name)); }
  catch (_) { _encProfiles = []; }
  renderEncProfiles();
}

async function refreshBldProfiles() {
  try { _bldProfiles = await fetch("/api/profiles/build").then(r => r.json()); _bldProfiles.sort((a,b) => a.name.localeCompare(b.name)); }
  catch (_) { _bldProfiles = []; }
  renderBldProfiles();
}

function _renderProfileList(profiles, listEl, emptyEl, loadFn, delFn) {
  listEl.innerHTML = "";
  if (!profiles.length) { emptyEl.classList.remove("hidden"); return; }
  emptyEl.classList.add("hidden");
  for (const p of profiles) {
    const li = document.createElement("li");
    li.className = "mgmt-item";
    li.innerHTML = `
      <div class="mi-info" style="cursor:pointer" data-show="${p.id}">
        <div class="mi-name">${p.name}</div>
        <div class="mi-meta" style="font-size:10px;color:var(--text-mute)">${_profileMeta(p)}</div>
      </div>
      <div class="mi-btns">
        <button class="btn-sm primary" data-load="${p.id}">Load</button>
        <button class="btn-sm btn-danger" data-del="${p.id}">✕</button>
      </div>`;
    listEl.appendChild(li);
  }
  listEl.querySelectorAll("[data-show]").forEach(el => el.addEventListener("click", async (e) => {
    e.stopPropagation();
    const id = el.dataset.show;
    const p = profiles.find(x => x.id === id);
    if (!p) return;
    document.querySelectorAll(".profile-popup-overlay").forEach(x => x.remove());
    // ensure lookup arrays are populated
    const _safeJson = async (url) => { try { const r = await fetch(url); if (!r.ok || r.headers.get("content-type")?.includes("text/html")) return []; return r.json(); } catch(_) { return []; } };
    if (!_encryptHistory.length) _encryptHistory = await _safeJson("/api/encrypt/history");
    if (!_donutJobs.length)      _donutJobs      = await _safeJson("/api/donut/jobs");
    if (!_wallets.length)        _wallets        = await _safeJson("/api/wallets");
    if (!_dlls.length)           _dlls           = await _safeJson("/api/dlls");
    if (!_exes.length)           _exes           = await _safeJson("/api/exes");
    if (!_binds.length)          _binds          = await _safeJson("/api/binds");
    const rows = [];
    if (p.type === "build" || p.mode) {
      rows.push(["Mode", p.mode || "exe"]);
      rows.push(["UAC", p.uac ? "yes" : "no"]);
      rows.push(["RWX", p.rwx ? "yes" : "no"]);
      rows.push(["Debug", p.debug ? "yes" : "no"]);
      rows.push(["Synthetic stack", p.synthetic ? "yes" : "no"]);
      if (p.exe_output_name) rows.push(["Output", p.exe_output_name]);
      if (p.dll_id)  { const d = _dlls.find(x => x.id === p.dll_id);  rows.push(["DLL",       d ? d.name : p.dll_id]); }
      if (p.exe_id)  { const x = _exes.find(x => x.id === p.exe_id);  rows.push(["Host EXE",  x ? x.name : p.exe_id]); }
      if (p.zip_name)  rows.push(["ZIP name",  p.zip_name]);
      if (p.bind_id) { const b = _binds.find(x => x.id === p.bind_id); rows.push(["Bind file", b ? b.name : p.bind_id]); }
      if (p.encrypt_history_id) { const e = _encryptHistory.find(x => x.id === p.encrypt_history_id); rows.push(["Payload.h", e ? (e.donut_label || fmtTimeShort(e.created_at)) : p.encrypt_history_id.slice(0,8)]); }
    } else {
      if (p.shellcode_job_id) { const j = _donutJobs.find(x => x.id === p.shellcode_job_id); rows.push(["Shellcode", j ? (j.label || j.id.slice(0,8)) : p.shellcode_job_id.slice(0,8)]); }
      if (p.wallet_id) { const w = _wallets.find(x => x.id === p.wallet_id); rows.push(["Wallet", w ? w.name : p.wallet_id.slice(0,12) + "…"]); }
    }
    const overlay = document.createElement("div");
    overlay.className = "profile-popup-overlay";
    const win = document.createElement("div");
    win.className = "profile-popup";
    win.innerHTML =
      `<div class="profile-popup-header">
        <span class="profile-popup-title">${p.name}</span>
        <button class="profile-popup-close">✕</button>
      </div>
      <div class="profile-popup-body">` +
      rows.map(([k,v]) => `<div class="profile-popup-row"><span class="profile-popup-k">${k}</span><span class="profile-popup-v">${v}</span></div>`).join("") +
      `</div>`;
    overlay.appendChild(win);
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.addEventListener("click", e => { if (e.target === overlay) close(); });
    win.querySelector(".profile-popup-close").addEventListener("click", close);
  }));
  listEl.querySelectorAll("[data-load]").forEach(b => b.addEventListener("click", () => loadFn(b.dataset.load)));
  listEl.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", () => delFn(b.dataset.del)));
}

function _profileMeta(p) {
  if (p.type === "build" || (!p.type && p.mode)) {
    const flags = [p.mode||"exe", p.uac?"uac":"", p.rwx?"rwx":"", p.debug?"dbg":""].filter(Boolean).join(" · ");
    return flags + (p.encrypt_history_id ? ` · enc:#${p.encrypt_history_id.slice(0,6)}` : "");
  }
  return (p.shellcode_job_id ? `#${p.shellcode_job_id.slice(0,6)}` : "—");
}

function renderEncProfiles() {
  _renderProfileList(_encProfiles, $("#enc-profile-list"), $("#enc-profile-empty"),
    loadEncProfile, deleteEncProfile);
}
function renderBldProfiles() {
  _renderProfileList(_bldProfiles, $("#bld-profile-list"), $("#bld-profile-empty"),
    loadBldProfile, deleteBldProfile);
}

function loadEncProfile(id) {
  const p = _encProfiles.find(x => x.id === id);
  if (!p) return;
  _curEncProfileId = id; _curEncProfileName = p.name;
  $("#btn-show-save-enc-profile").textContent = `↺ ${p.name}`;
  if (p.shellcode_job_id && _cddValidIds.has(p.shellcode_job_id)) {
    cddSetValue("enc-sc-job-wrap", "enc-sc-job", p.shellcode_job_id);
  }
  // restore wallet CDD
  const wWrap   = $("#enc-wallet-wrap");
  const wHidden = $("#enc-wallet-id");
  if (wWrap && wHidden) {
    if (p.wallet_id) {
      wHidden.value = p.wallet_id;
      const item = wWrap.querySelector(`.cdd-item[data-value="${CSS.escape(p.wallet_id)}"]`);
      if (item) {
        _cddSetDisplay(wWrap, item.innerHTML);
        wWrap.querySelectorAll(".cdd-item").forEach(i => i.classList.toggle("cdd-selected", i === item));
      } else {
        _cddSetDisplay(wWrap, "— select a wallet —");
        wHidden.value = "";
      }
    } else {
      wHidden.value = "";
      _cddSetDisplay(wWrap, "— select a wallet —");
      wWrap.querySelectorAll(".cdd-item").forEach(i => i.classList.remove("cdd-selected"));
    }
  }
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === "encrypt"));
  $$(".panel").forEach(pp => pp.classList.toggle("active", pp.id === "panel-encrypt"));
  _openEncSaveRow();
}

function loadBldProfile(id) {
  const p = _bldProfiles.find(x => x.id === id);
  if (!p) return;
  _curBldProfileId = id; _curBldProfileName = p.name;
  $("#btn-show-save-bld-profile").textContent = `↺ ${p.name}`;
  const modeEl = $(`#form-build input[name=mode][value="${p.mode || "exe"}"]`);
  if (modeEl) { modeEl.checked = true; try { localStorage.setItem("zeroBuildMode", p.mode||"exe"); } catch(_){} }
  $("#bld-uac").checked   = !!p.uac;
  $("#bld-rwx").checked   = !!p.rwx;
  $("#bld-debug").checked = !!p.debug;
  $("#bld-syn").checked   = !!p.synthetic;
  const dllSel = $("#sl-dll-sel");
  if (dllSel && p.dll_id) { dllSel.value = p.dll_id; if (dllSel.value !== p.dll_id) dllSel.value = ""; }
  const exeSel = $("#sl-exe-sel");
  if (exeSel && p.exe_id) { exeSel.value = p.exe_id; if (exeSel.value !== p.exe_id) exeSel.value = ""; }
  setFilenameInputValue("sl-dll-rename",  p.sideload_rename || "");
  setFilenameInputValue("sl-host-rename", p.host_rename     || "");
  setFilenameInputValue("sl-zip-name",    p.zip_name        || "");
  const bindSel = $("#sl-bind-sel");
  if (bindSel && p.bind_id) { bindSel.value = p.bind_id; if (bindSel.value !== p.bind_id) bindSel.value = ""; }
  syncBindRenameExt();
  setFilenameInputValue("sl-bind-rename", p.bind_rename || "");
  if ($("#bld-exe-name"))   $("#bld-exe-name").value   = p.exe_output_name || "";
  // Payload.h selector — set hidden value then let refreshPayloadSelector sync CDD display
  const payloadSel = $("#bld-payload-sel");
  if (payloadSel) payloadSel.value = p.encrypt_history_id || "";
  refreshPayloadSelector();
  syncBuildMode();
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === "build"));
  $$(".panel").forEach(pp => pp.classList.toggle("active", pp.id === "panel-build"));
  _openBldSaveRow();
}

async function deleteEncProfile(id) {
  if (!confirm("Delete this encrypt profile?")) return;
  await fetch(`/api/profiles/${id}`, { method: "DELETE" });
  if (_curEncProfileId === id) { _curEncProfileId = null; _curEncProfileName = ""; $("#btn-show-save-enc-profile").textContent = "Save"; }
  refreshEncProfiles();
}
async function deleteBldProfile(id) {
  if (!confirm("Delete this build profile?")) return;
  await fetch(`/api/profiles/${id}`, { method: "DELETE" });
  if (_curBldProfileId === id) { _curBldProfileId = null; _curBldProfileName = ""; $("#btn-show-save-bld-profile").textContent = "Save"; }
  refreshBldProfiles();
}

function collectEncryptData() {
  return {
    shellcode_job_id: $("#enc-sc-job")?.value || "",
    wallet_id:        $("#enc-wallet-id")?.value || "",
  };
}
function collectBuildData() {
  return {
    exe_output_name:    $("#bld-exe-name")?.value.trim()   || "",
    encrypt_history_id: $("#bld-payload-sel")?.value       || "",
    dll_id:             $("#sl-dll-sel")?.value            || "",
    exe_id:             $("#sl-exe-sel")?.value            || "",
    sideload_rename:    getFilenameInputValue("sl-dll-rename"),
    host_rename:        getFilenameInputValue("sl-host-rename"),
    zip_name:           getFilenameInputValue("sl-zip-name"),
    bind_id:            $("#sl-bind-sel")?.value           || "",
    bind_rename:        getFilenameInputValue("sl-bind-rename"),
    mode:               $("input[name=mode]:checked")?.value || "exe",
    uac:                $("#bld-uac")?.checked   || false,
    rwx:                $("#bld-rwx")?.checked   || false,
    debug:              $("#bld-debug")?.checked || false,
    synthetic:          $("#bld-syn")?.checked   || false,
  };
}

// ── save row helpers ───────────────────────────────────────────────────────

function _makeSaveRow(rowId, nameId, confirmId, cancelId, saveasId,
                      getCurId, getCurName, setCurId, setCurName,
                      apiBase, refreshFn, btnId) {
  const row     = $(`#${rowId}`);
  const nameEl  = $(`#${nameId}`);
  const confBtn = $(`#${confirmId}`);
  const canBtn  = $(`#${cancelId}`);
  const saLink  = $(`#${saveasId}`);
  const showBtn = $(`#${btnId}`);

  function close() { row.classList.add("hidden"); nameEl.value = ""; }
  function open(forceNew = false) {
    const cid = getCurId();
    if (!forceNew && cid) {
      nameEl.value = getCurName(); confBtn.textContent = "Update"; saLink.classList.remove("hidden");
    } else {
      nameEl.value = ""; confBtn.textContent = "Save"; saLink.classList.add("hidden");
    }
    row.classList.remove("hidden"); nameEl.focus(); nameEl.select();
  }

  showBtn.addEventListener("click", () => open());
  canBtn.addEventListener("click", close);
  saLink.addEventListener("click", e => { e.preventDefault(); setCurId(null); setCurName(""); open(true); });

  return { open, close };
}

// ── Encrypt save row ──────────────────────────────────────────────────────

const _encSaveRow = _makeSaveRow(
  "enc-profile-save-row", "enc-profile-name-input",
  "btn-confirm-save-enc-profile", "btn-cancel-save-enc-profile", "btn-enc-saveas-new",
  () => _curEncProfileId, () => _curEncProfileName,
  v => { _curEncProfileId = v; }, v => { _curEncProfileName = v; },
  "/api/profiles/encrypt", () => refreshEncProfiles(), "btn-show-save-enc-profile"
);
function _openEncSaveRow(forceNew) { _encSaveRow.open(forceNew); }

$("#btn-confirm-save-enc-profile").addEventListener("click", async () => {
  const name = $("#enc-profile-name-input").value.trim();
  if (!name) { $("#enc-profile-name-input").focus(); return; }
  const body = { name, ...collectEncryptData() };
  if (_curEncProfileId) {
    await fetch(`/api/profiles/${_curEncProfileId}`, { method:"PUT", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
    _curEncProfileName = name;
    $("#btn-show-save-enc-profile").textContent = `↺ ${name}`;
  } else {
    const j = await fetch("/api/profiles/encrypt", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) }).then(r=>r.json()).catch(()=>({}));
    if (j.profile) { _curEncProfileId = j.profile.id; _curEncProfileName = j.profile.name; $("#btn-show-save-enc-profile").textContent = `↺ ${j.profile.name}`; }
  }
  _encSaveRow.close();
  refreshEncProfiles();
});

// ── Build save row ────────────────────────────────────────────────────────

const _bldSaveRow = _makeSaveRow(
  "bld-profile-save-row", "bld-profile-name-input",
  "btn-confirm-save-bld-profile", "btn-cancel-save-bld-profile", "btn-bld-saveas-new",
  () => _curBldProfileId, () => _curBldProfileName,
  v => { _curBldProfileId = v; }, v => { _curBldProfileName = v; },
  "/api/profiles/build", () => refreshBldProfiles(), "btn-show-save-bld-profile"
);
function _openBldSaveRow(forceNew) { _bldSaveRow.open(forceNew); }

$("#btn-confirm-save-bld-profile").addEventListener("click", async () => {
  const name = $("#bld-profile-name-input").value.trim();
  if (!name) { $("#bld-profile-name-input").focus(); return; }
  const body = { name, ...collectBuildData() };
  if (_curBldProfileId) {
    await fetch(`/api/profiles/${_curBldProfileId}`, { method:"PUT", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
    _curBldProfileName = name;
    $("#btn-show-save-bld-profile").textContent = `↺ ${name}`;
  } else {
    const j = await fetch("/api/profiles/build", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) }).then(r=>r.json()).catch(()=>({}));
    if (j.profile) { _curBldProfileId = j.profile.id; _curBldProfileName = j.profile.name; $("#btn-show-save-bld-profile").textContent = `↺ ${j.profile.name}`; }
  }
  _bldSaveRow.close();
  refreshBldProfiles();
});

// ─── encrypt history ─────────────────────────────────────────────────────

let _encryptHistory = [];

async function refreshEncryptHistory() {
  try { _encryptHistory = await fetch("/api/encrypt/history").then(r => r.json()); }
  catch (_) { _encryptHistory = []; }
  renderEncryptHistory();
}

function renderEncryptHistory() {
  const list  = $("#encrypt-history-list");
  const empty = $("#encrypt-hist-empty");
  list.querySelectorAll(".hist-item").forEach(el => el.remove());

  if (!_encryptHistory.length) { empty.style.display = ""; return; }
  empty.style.display = "none";

  for (const j of _encryptHistory) {
    const el = document.createElement("div");
    el.className = "hist-item";
    // store key fragment safely on element — avoids quote-escaping issues
    el.dataset.key = j.key || "";

    const dot        = j.ok ? `<span class="ji-dot dot-ok">●</span>` : `<span class="ji-dot dot-bad">○</span>`;
    const dateStr    = fmtTimeShort(j.created_at);
    const donutBadge = j.donut_label
      ? `<span class="ji-label-badge">${j.donut_label}</span>`
      : "";

    // download links
    let dls = `<a class="btn-xs" href="/api/encrypt/history/${j.id}/download/payload_h">↓ Payload.h</a>`;
    if (j.dat_size > 0)
      dls += ` <a class="btn-xs primary" href="/api/encrypt/history/${j.id}/download/dat">↓ data.enc</a>`;

    // action buttons
    const copyBtnHtml    = j.dat_size > 0 ? `<button class="btn-xs btn-hist-copy">Copy key</button>` : "";
    const canPublish     = j.ok && j.dat_size > 0;
    const publishBtnHtml = canPublish ? `<button class="btn-xs btn-hist-pub">⚡ Upload</button>` : "";

    // wallet badge shown in meta row
    const walletBadge = j.wallet_address
      ? `<span class="cdd-item-meta" title="${j.wallet_address}">◆ ${trunc(j.wallet_address, 14)}</span>`
      : "";
    const txBadge = (j.arweave_tx_id || j.arweave_meta_tx_id)
      ? `<span class="cdd-item-meta" style="color:var(--accent)">✓ on-chain</span>`
      : "";

    el.innerHTML = `
      <div class="hist-head">
        ${dot}
        <span class="hist-name">#${j.id.slice(0,6)}</span>
        <button class="btn-xs btn-danger hist-del" title="Delete run + files">✕</button>
      </div>
      <div class="hist-meta">
        <span class="ji-id">#${j.id}</span>
        ${donutBadge}
        <span>${j.dat_size ? fmtSize(j.dat_size) + " enc" : ""}</span>
        ${walletBadge}
        ${txBadge}
        <span>${dateStr}</span>
      </div>
      <div class="hist-dls">${dls} ${copyBtnHtml} ${publishBtnHtml}</div>

      <!-- arweave upload output (hidden until ⚡ Upload clicked) -->
      <pre class="hist-pub-out hidden"></pre>`;

    list.appendChild(el);

    // ── wire delete ──
    el.querySelector(".hist-del").addEventListener("click", (ev) => {
      ev.stopPropagation();
      deleteEncryptHistory(j.id);
    });

    // ── wire copy key ──
    el.querySelector(".btn-hist-copy")?.addEventListener("click", async () => {
      const btn = el.querySelector(".btn-hist-copy");
      const orig = btn.textContent;
      try {
        const r = await fetch(`/api/encrypt/history/${j.id}/download/key`);
        const text = await r.text();
        await navigator.clipboard.writeText(text.trim());
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 1800);
      } catch { btn.textContent = "Failed"; setTimeout(() => { btn.textContent = orig; }, 1800); }
    });

    // ── wire upload: POST directly to /api/encrypt/history/<jid>/publish ──
    el.querySelector(".btn-hist-pub")?.addEventListener("click", async () => {
      const out = el.querySelector(".hist-pub-out");
      out.classList.remove("hidden");
      out.textContent = "> uploading to Arweave … (may take 30–60 s)\n";
      out.className = "hist-pub-out";

      const btn = el.querySelector(".btn-hist-pub");
      btn.disabled = true; btn.textContent = "Uploading…";

      try {
        const r  = await fetch(`/api/encrypt/history/${j.id}/publish`, { method: "POST" });
        const jr = await r.json();
        if (jr.stdout) out.textContent += jr.stdout;
        if (jr.stderr) out.textContent += jr.stderr;
        if (jr.ok) {
          let msg = `[+] Upload complete!\n`;
          if (jr.tx_id)    msg += `    TX ID  : ${jr.tx_id}\n`;
          if (jr.data_url) msg += `    URL    : ${jr.data_url}\n`;
          out.textContent += msg;
          out.className = "hist-pub-out ok";
        } else {
          out.textContent += `[-] ${jr.error || jr.stderr || "Failed"}`;
          out.className = "hist-pub-out bad";
        }
      } catch (err) {
        out.textContent += `[network error] ${err}`;
        out.className = "hist-pub-out bad";
      } finally {
        btn.disabled = false; btn.textContent = "⚡ Upload";
      }
    });
  }
}

async function deleteEncryptHistory(id) {
  if (!confirm(`Delete encrypt run #${id} and all its artifacts?`)) return;
  await fetch(`/api/encrypt/history/${id}`, { method: "DELETE" });
  refreshEncryptHistory();
}

$("#btn-refresh-encrypt-hist").addEventListener("click", refreshEncryptHistory);

// ─── build history ────────────────────────────────────────────────────────

let _buildHistory = [];

async function refreshBuildHistory() {
  try { _buildHistory = await fetch("/api/build/history").then(r => r.json()); }
  catch (_) { _buildHistory = []; }
  renderBuildHistory();
  refreshArtifacts();
}

function renderBuildHistory() {
  const list  = $("#build-history-list");
  const empty = $("#build-hist-empty");
  list.querySelectorAll(".hist-item").forEach(el => el.remove());

  if (!_buildHistory.length) { empty.style.display = ""; return; }
  empty.style.display = "none";

  for (const j of _buildHistory) {
    const el = document.createElement("div");
    el.className = "hist-item";
    const dot     = j.ok ? `<span class="ji-dot dot-ok">●</span>` : `<span class="ji-dot dot-bad">○</span>`;
    const dateStr = fmtTimeShort(j.created_at);
    const flags   = [j.mode, j.uac ? "uac" : "", j.rwx ? "rwx" : "", j.debug ? "dbg" : "", j.synthetic ? "syn" : ""]
                      .filter(Boolean).join(" · ");

    let dls = `<a class="btn-xs" href="/api/build/history/${j.id}/download/output" title="Download build log">↓ log</a>`;
    if (j.zip_size > 0)
      dls += ` <a class="btn-xs primary" href="/api/build/history/${j.id}/download/zip" title="Download deployment ZIP">↓ ${j.zip_name}</a>`;
    if (j.binary_size > 0 && (j.mode !== "sideload" || !j.zip_size))
      dls += ` <a class="btn-xs primary" href="/api/build/history/${j.id}/download/binary" title="Download ${j.binary_name}">↓ ${j.binary_name}</a>`;
    if (j.mode === "sideload" && j.binary_size > 0)
      dls += ` <a class="btn-xs" href="/api/build/history/${j.id}/download/binary" title="Download standalone proxy DLL">↓ dll</a>`;
    if (j.sideload_h_size > 0)
      dls += ` <a class="btn-xs" href="/api/build/history/${j.id}/download/sideload_h" title="Download Sideload.h">↓ Sideload.h</a>`;

    el.innerHTML = `
      <div class="hist-head">
        ${dot}
        <span class="hist-name">${(j.mode === "sideload" && j.zip_name) ? j.zip_name : (j.binary_name || "—")}</span>
        <button class="btn-xs btn-danger hist-del" data-hid="${j.id}" title="Delete">✕</button>
      </div>
      <div class="hist-meta">
        <span class="ji-id">#${j.id}</span>
        <span>${flags}</span>
        <span>${j.binary_size ? fmtSize(j.binary_size) : ""}</span>
        <span>${dateStr}</span>
      </div>
      <div class="hist-dls">${dls}</div>`;
    list.appendChild(el);

    el.querySelector(".hist-del").addEventListener("click", (ev) => {
      ev.stopPropagation();
      deleteBuildHistory(j.id);
    });
  }
}

async function deleteBuildHistory(id) {
  if (!confirm(`Delete build #${id} and all its artifacts?`)) return;
  await fetch(`/api/build/history/${id}`, { method: "DELETE" });
  refreshBuildHistory();
}

$("#btn-refresh-build-hist").addEventListener("click", refreshBuildHistory);

// ─── donut ────────────────────────────────────────────────────────────────

let _donutJobs = [];

async function refreshDonutJobs() {
  try { _donutJobs = await fetch("/api/donut/jobs").then(r => r.json()); }
  catch (_) { _donutJobs = []; }
  renderDonutJobs();
}

function renderDonutJobs() {
  const hist  = $("#donut-history");
  const empty = $("#donut-empty");
  hist.querySelectorAll(".job-item").forEach(el => el.remove());

  if (!_donutJobs.length) { empty.style.display = ""; return; }
  empty.style.display = "none";

  for (const j of _donutJobs) {
    const el = document.createElement("div");
    el.className = "job-item";
    const statusDot = j.ok ? "●" : "○";
    const statusCls = j.ok ? "dot-ok" : "dot-bad";
    const labelBadge = j.label
      ? `<span class="ji-label-badge">${j.label}</span>`
      : "";
    el.innerHTML = `
      <div class="ji-head">
        <span class="ji-dot ${statusCls}">${statusDot}</span>
        <span class="ji-id-inline">#${j.id.slice(0, 6)}</span>
        ${labelBadge}
        <span class="ji-name">${j.original_name}</span>
        <button class="btn-xs ji-edit" title="Edit label">✎</button>
        <button class="btn-xs btn-danger ji-del" data-jid="${j.id}" title="Delete">✕</button>
      </div>
      <div class="ji-label-row hidden">
        <input class="ji-label-input" type="text" maxlength="64" placeholder="Label…" value="${j.label || ""}">
        <button class="btn-xs primary ji-label-save">Save</button>
        <button class="btn-xs ji-label-cancel">✕</button>
      </div>
      <div class="ji-meta">
        <span class="ji-id">#${j.id}</span>
        <span>${j.arch_label}</span>
        ${j.converted ? `<span class="ji-converted-badge">x86→x64</span>` : ""}
        ${j.size_in  ? `<span>${fmtSize(j.size_in)} in</span>` : ""}
        ${j.size_out ? `<span>→ ${fmtSize(j.size_out)}</span>` : ""}
      </div>
      <div class="ji-date">${fmtTimeShort(j.created_at)}</div>
      ${j.ok ? `
      <div class="ji-dls">
        <a class="btn-xs" href="/api/donut/jobs/${j.id}/download/original">↓ orig</a>
        <a class="btn-xs primary" href="/api/donut/jobs/${j.id}/download/shellcode">↓ shellcode</a>
      </div>` : ""}`;
    hist.insertBefore(el, hist.firstChild);

    el.querySelector(".ji-del").addEventListener("click", (ev) => {
      ev.stopPropagation();
      deleteDonutJob(j.id);
    });

    const labelRow    = el.querySelector(".ji-label-row");
    const labelInput  = el.querySelector(".ji-label-input");
    el.querySelector(".ji-edit").addEventListener("click", () => {
      labelRow.classList.toggle("hidden");
      if (!labelRow.classList.contains("hidden")) labelInput.focus();
    });
    el.querySelector(".ji-label-cancel").addEventListener("click", () =>
      labelRow.classList.add("hidden"));
    el.querySelector(".ji-label-save").addEventListener("click", () =>
      saveDonutLabel(j.id, labelInput.value));
  }
}

async function saveDonutLabel(id, label) {
  await fetch(`/api/donut/jobs/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ label: label.trim() }),
  });
  await refreshDonutJobs();
  refreshEncryptDropdowns();
}

async function deleteDonutJob(id) {
  if (!confirm(`Delete job #${id} and its files?`)) return;
  await fetch(`/api/donut/jobs/${id}`, { method: "DELETE" });
  refreshDonutJobs();
}

$("#form-donut").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out    = $("#out-donut");
  const result = $("#donut-result");
  result.classList.add("hidden"); result.innerHTML = "";
  writeConsole(out, "> running stub …\n", { reset: true });
  const btn = $("button.primary", e.target);
  btn.disabled = true; btn.textContent = "Converting…";
  try {
    const r = await fetch("/api/donut", { method: "POST", body: new FormData(e.target) });
    const j = await r.json();
    if (j.stdout) writeConsole(out, j.stdout);
    if (j.stderr) writeConsole(out, j.stderr);
    writeConsole(out, `\n[exit ${j.code ?? (j.ok ? 0 : -1)}]\n`, { ok: j.ok });
    if (j.ok && j.job) {
      result.innerHTML = `
        <a class="dl-link" href="/api/donut/jobs/${j.job.id}/download/shellcode">
          ⬇ shellcode_${j.job.id}.bin (${fmtSize(j.job.size_out)})
        </a>`;
      result.classList.remove("hidden");
      refreshDonutJobs();
      // Update encrypt dropdown if build page is in view
      refreshEncryptDropdowns();
    }
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  finally { btn.disabled = false; btn.textContent = "Convert"; }
});

// ─── wallets ──────────────────────────────────────────────────────────────

let _wallets = [];
let _selWalletId = null;


async function refreshWallets() {
  try { _wallets = await fetch("/api/wallets").then(r => r.json()); }
  catch (_) { _wallets = []; }
  renderWallets();
  if (_selWalletId && !_wallets.find(w => w.id === _selWalletId)) {
    _selWalletId = null;
    showWalletPanel(null);
  }
}

function renderWallets() {
  const list  = $("#wallet-list");
  const empty = $("#wallet-empty");
  list.querySelectorAll(".wallet-item").forEach(el => el.remove());

  if (!_wallets.length) { empty.style.display = ""; return; }
  empty.style.display = "none";

  for (const w of _wallets) {
    const el = document.createElement("div");
    el.className = "wallet-item" + (w.id === _selWalletId ? " selected" : "");
    el.dataset.wid = w.id;
    el.innerHTML = `
      <div class="wi-name">${w.name}</div>
      <div class="wi-addr">${trunc(w.address, 28)}</div>
      <div class="wi-date">${fmtTimeShort(w.created_at)}</div>`;
    el.addEventListener("click", () => selectWallet(w.id));
    list.appendChild(el);
  }
}

function selectWallet(id) {
  if (id !== _selWalletId) {
    [$("#out-publish"), $("#out-lookup")].forEach(el => {
      if (el) { el.textContent = ""; el.classList.remove("ok", "bad"); }
    });
  }
  _selWalletId = id;
  renderWallets();
  showWalletPanel(_wallets.find(w => w.id === id) || null);
}

function showWalletPanel(w) {
  const panel = $("#wallet-panel");
  const none  = $("#wallet-none");
  if (!w) {
    panel.classList.add("hidden"); none.classList.remove("hidden"); return;
  }
  none.classList.add("hidden"); panel.classList.remove("hidden");
  $("#wp-name").textContent = w.name;
  $("#wp-addr").textContent = w.address;
  $("#btn-wallet-dl-kp").href = `/api/wallets/${w.id}/keypair`;
  $("#wallet-rename-row").classList.add("hidden");
  // clear upload/lookup outputs when switching wallets
  const outPub = $("#out-publish");
  const outLkp = $("#out-lookup");
  if (outPub) { outPub.textContent = ""; outPub.classList.remove("ok", "bad"); }
  if (outLkp) { outLkp.textContent = ""; outLkp.classList.remove("ok", "bad"); }
  const datFile = $("#wp-dat-file");
  if (datFile) datFile.value = "";
  fetchWalletBalance(w.id);
}

async function fetchWalletBalance(wid) {
  const el  = $("#wp-balance");
  const btn = $("#btn-refresh-balance");
  if (!el) return;
  el.textContent = "…";
  el.style.color = "";
  if (btn) btn.disabled = true;
  try {
    const r = await fetch(`/api/wallets/${wid}/balance`);
    const j = await r.json();
    if (j.ok) {
      const ar = j.ar.toFixed(6);
      el.textContent = `${ar} AR`;
      el.style.color = j.ar > 0 ? "var(--accent)" : "var(--text-mute)";
    } else {
      el.textContent = "error";
      el.style.color = "var(--red)";
    }
  } catch {
    el.textContent = "offline";
    el.style.color = "var(--text-mute)";
  } finally {
    if (btn) btn.disabled = false;
  }
}

// refresh balance
$("#btn-refresh-balance").addEventListener("click", () => {
  if (_selWalletId) fetchWalletBalance(_selWalletId);
});

// copy address
$("#btn-copy-addr").addEventListener("click", async () => {
  const addr = $("#wp-addr").textContent.trim();
  if (!addr) return;
  try {
    await navigator.clipboard.writeText(addr);
    const btn = $("#btn-copy-addr");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy"; }, 1800);
  } catch {
    const sel = window.getSelection(), range = document.createRange();
    range.selectNodeContents($("#wp-addr"));
    sel.removeAllRanges(); sel.addRange(range);
  }
});

// create wallet
$("#btn-create-wallet").addEventListener("click", async () => {
  const name = $("#new-wallet-name").value.trim() || "Wallet";
  const btn  = $("#btn-create-wallet");
  btn.disabled = true; btn.textContent = "Creating…";
  try {
    const r = await fetch("/api/wallets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const j = await r.json();
    if (j.ok) {
      $("#new-wallet-name").value = "";
      await refreshWallets();
      selectWallet(j.wallet.id);
    } else {
      alert("Create failed: " + (j.stderr || j.error || "unknown"));
    }
  } catch (err) { alert(`Network error: ${err}`); }
  finally { btn.disabled = false; btn.textContent = "+ Create"; }
});

// rename
$("#btn-wallet-rename").addEventListener("click", () => {
  const row = $("#wallet-rename-row");
  row.classList.toggle("hidden");
  if (!row.classList.contains("hidden")) {
    const w = _wallets.find(x => x.id === _selWalletId);
    $("#wallet-rename-input").value = w?.name || "";
    $("#wallet-rename-input").focus();
  }
});
$("#btn-cancel-rename").addEventListener("click", () =>
  $("#wallet-rename-row").classList.add("hidden"));
$("#btn-confirm-rename").addEventListener("click", async () => {
  if (!_selWalletId) return;
  const name = $("#wallet-rename-input").value.trim();
  if (!name) return;
  await fetch(`/api/wallets/${_selWalletId}`, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  $("#wallet-rename-row").classList.add("hidden");
  await refreshWallets();
  selectWallet(_selWalletId);
});

// delete
$("#btn-wallet-delete").addEventListener("click", async () => {
  if (!_selWalletId) return;
  const w = _wallets.find(x => x.id === _selWalletId);
  if (!confirm(`Delete wallet "${w?.name}"?\nThe keypair stored on this server will be permanently erased.`)) return;
  await fetch(`/api/wallets/${_selWalletId}`, { method: "DELETE" });
  _selWalletId = null;
  showWalletPanel(null);
  refreshWallets();
});

// upload to arweave (wallet panel — standalone file upload)
$("#btn-arweave-upload").addEventListener("click", async () => {
  if (!_selWalletId) return;
  const out     = $("#out-publish");
  const datFile = $("#wp-dat-file")?.files[0];
  if (!datFile) {
    writeConsole(out, "[-] Select a data.enc file.\n", { ok: false, reset: true }); return;
  }
  writeConsole(out, "> uploading to Arweave … (may take 30–60 s)\n", { reset: true });
  const btn = $("#btn-arweave-upload");
  btn.disabled = true; btn.textContent = "Uploading…";
  try {
    const fd = new FormData();
    fd.append("data_enc", datFile);
    const r = await fetch(`/api/wallets/${_selWalletId}/publish`, { method: "POST", body: fd });
    const j = await r.json();
    if (j.stdout) writeConsole(out, j.stdout);
    if (j.stderr) writeConsole(out, j.stderr);
    if (j.ok) {
      let msg = `[+] Upload complete!\n`;
      if (j.tx_id)    msg += `    TX ID  : ${j.tx_id}\n`;
      if (j.data_url) msg += `    URL    : ${j.data_url}\n`;
      writeConsole(out, msg, { ok: true });
    } else {
      writeConsole(out, `[-] ${j.error || j.stderr || "Failed"}\n`, { ok: false });
    }
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  finally { btn.disabled = false; btn.textContent = "Upload to Arweave"; }
});

// scan wallet transactions via GraphQL
async function doLookup() {
  if (!_selWalletId) return;
  const out = $("#out-lookup");
  const btn = $("#btn-lookup-tx");
  btn.disabled = true;
  writeConsole(out, "> scanning wallet transactions via arweave.net/graphql …\n", { reset: true });
  try {
    const r = await fetch(`/api/wallets/${_selWalletId}/lookup`, { method: "POST" });
    const j = await r.json();
    if (!j.ok) {
      writeConsole(out, `[-] ${j.error || j.stderr || "Failed"}\n`, { ok: false }); return;
    }
    const txs = j.transactions || [];
    writeConsole(out, `[*] Wallet: ${j.address}\n[*] Found ${txs.length} transaction(s)\n`);
    if (!txs.length) {
      writeConsole(out, "[*] No transactions yet.\n");
    } else {
      for (const tx of txs) {
        const blockStr = tx.block ? `block #${tx.block}` : "no block?";
        const appName = tx.tags?.["App-Name"] || "";
        const txType  = tx.tags?.["zero-loader-type"] || "";
        const tagStr  = txType ? `  [${txType}]` : (appName ? `  [${appName}]` : "");
        let line = `\n── ${tx.tx_id}  (${blockStr})${tagStr}\n    ${tx.url}\n`;
        if (tx.pending) {
          line += `    ⏳ gateway 404 — data not yet served (may take 30-60 min after block confirmation)\n`;
        } else if (tx.error) {
          line += `    ✗ ${tx.error}\n`;
        } else if (tx.payload_v2) {
          line += `    ✓ combined format — header: ${tx.header}\n`;
        } else if (tx.meta) {
          line += `    ~ old meta JSON (no longer used): ${JSON.stringify(tx.meta)}\n`;
        } else if (tx.raw !== undefined) {
          line += `    ~ unrecognised format: ${tx.raw.slice(0, 80)}\n`;
        }
        writeConsole(out, line);
      }
      writeConsole(out, "\n[+] Scan complete.\n", { ok: true });
    }
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  finally { btn.disabled = false; }
}

$("#btn-lookup-tx").addEventListener("click", doLookup);

// ─── Payload.h selector (build panel) ────────────────────────────────────

async function refreshPayloadSelector() {
  const wrap   = $("#bld-payload-sel-wrap");
  const hidden = $("#bld-payload-sel");
  if (!wrap || !hidden) return;
  const prev = hidden.value;
  const list = wrap.querySelector(".cdd-list");

  try {
    const runs = await fetch("/api/encrypt/history").then(r => r.json());
    list.innerHTML = "";

    // placeholder
    const ph = document.createElement("div");
    ph.className = "cdd-item cdd-placeholder";
    ph.textContent = "— use existing Payload.h in project root —";
    ph.addEventListener("click", () => {
      hidden.value = "";
      _cddSetDisplay(wrap, "— use existing Payload.h in project root —");
      wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.remove("cdd-selected"));
      _cddClose();
    });
    list.appendChild(ph);

    const ok = runs.filter(r => r.ok);
    for (const r of ok) {
      const item = document.createElement("div");
      item.className = "cdd-item";
      item.dataset.value = r.id;
      const labelHtml  = r.donut_label
        ? `<span class="cdd-label-badge">${r.donut_label}</span>`
        : "";
      item.innerHTML = `
        <span class="cdd-item-id">#${r.id.slice(0,6)}</span>
        ${labelHtml}
        <span class="cdd-item-meta">${fmtTimeShort(r.created_at)}</span>`;
      item.addEventListener("click", () => {
        hidden.value = r.id;
        _cddSetDisplay(wrap, item.innerHTML);
        wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.toggle("cdd-selected", i === item));
        _cddClose();
      });
      if (r.id === prev) {
        item.classList.add("cdd-selected");
        _cddSetDisplay(wrap, item.innerHTML);
      }
      list.appendChild(item);
    }

    if (!prev || !ok.find(r => r.id === prev)) {
      _cddSetDisplay(wrap, "— use existing Payload.h in project root —");
      hidden.value = "";
    }

    const trigger = wrap.querySelector(".cdd-trigger");
    trigger.onclick = (e) => {
      e.stopPropagation();
      const isOpen = wrap.classList.contains("open");
      _cddClose();
      if (!isOpen) { wrap.classList.add("open"); list.classList.remove("hidden"); }
    };
  } catch (_) {}
}

// ─── pools ────────────────────────────────────────────────────────────────

let _pools = [];
let _poolEditId = null;
let _poolStatusTimer = null;
let _torStatus = null;  // cached tor status for onion URL generation

async function _fetchJson(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok && r.headers.get("content-type")?.includes("text/html")) {
    throw new Error(`Server returned ${r.status} — is the server running the latest code?`);
  }
  return r.json();
}

async function refreshPools() {
  try { _pools = await _fetchJson("/api/pools"); }
  catch (_) { _pools = []; }
  // fetch tor status to get onion address for URL copy
  try {
    const ts = await fetch("/api/tor/status").then(r => r.json());
    const onion = ts.running && ts.services?.length ? ts.services[0].onion : null;
    _torStatus = { onion };
  } catch (_) { _torStatus = { onion: null }; }
  await _refreshBldProfilesForPool();
  renderPools();
  _schedulePoolStatus();
}

async function _refreshBldProfilesForPool() {
  // Refresh build profiles for the create/edit selector
  try {
    if (!_bldProfiles.length)
      _bldProfiles = await fetch("/api/profiles/build").then(r => r.json()); _bldProfiles.sort((a,b) => a.name.localeCompare(b.name));
  } catch (_) {}
}

function _populatePoolProfileSel(selectedId) {
  const sel = $("#pf-profile-sel");
  if (!sel) return;
  sel.innerHTML = _bldProfiles.length
    ? `<option value="">— select a build profile —</option>` +
      _bldProfiles.map(p =>
        `<option value="${p.id}" ${p.id === selectedId ? "selected" : ""}>${p.name}  (#${p.id} · ${p.mode || "exe"})</option>`
      ).join("")
    : `<option value="">— no build profiles yet —</option>`;
}

function renderPools() {
  const list  = $("#pool-list");
  const empty = $("#pool-list-empty");
  list.querySelectorAll(".pool-item").forEach(el => el.remove());

  if (!_pools.length) { empty.style.display = ""; return; }
  empty.style.display = "none";

  for (const pool of _pools) {
    const el = document.createElement("div");
    el.className = "pool-item";
    el.dataset.pid = pool.id;

    const count   = pool.ready_count ?? 0;
    const target  = pool.target_count ?? 10;
    const paused  = !!pool.paused;
    const cntCls  = count === 0 ? "empty" : (count >= target ? "full" : "");
    const bldHtml = pool.building
      ? `<span class="pi-building">⟳ building</span>`
      : paused ? `<span class="pi-paused">⏸ paused</span>` : "";
    const torOnion = _torStatus?.onion || null;
    const localUrl = `${location.protocol}//${location.host}/d/${pool.slug}`;
    const torUrl   = torOnion ? `http://${torOnion}/d/${pool.slug}` : null;

    el.innerHTML = `
      <div class="pi-row">
        <span class="pi-name">${pool.name}</span>
        <span class="pi-slug">/d/${pool.slug}</span>
        <div class="pi-status">
          <span class="pi-count ${cntCls}">${count} / ${target} ready</span>
          ${bldHtml}
        </div>
        <div class="pi-spacer"></div>
        <div class="pi-btns">
          <button class="btn-xs" data-copy-local title="${localUrl}">Local</button>
          <button class="btn-xs" data-copy-tor title="${torUrl || ''}" ${torUrl ? '' : 'disabled'}>Tor</button>
          <button class="btn-xs ${paused ? "primary" : ""}" data-pause title="${paused ? "Resume filling" : "Pause filling"}">${paused ? "▶ Resume" : "⏸ Pause"}</button>
          <button class="btn-xs btn-danger" data-clear title="Clear all ready builds">Clear</button>
          <button class="btn-xs" data-edit title="Edit pool settings">Edit</button>
          <button class="btn-xs btn-danger" data-del title="Delete pool">✕</button>
        </div>
      </div>
      <!-- inline edit row (hidden) -->
      <div class="pi-edit-row hidden" data-edit-row>
        <label>Name<input type="text" class="pi-edit-name" value="${pool.name}"></label>
        <label>Build profile
          <select class="pi-edit-profile select-field-sm"></select>
        </label>
        <label>Target<input type="number" class="pi-edit-target" value="${target}" min="1" max="50"></label>
        <div class="pi-edit-actions">
          <button class="btn-xs primary" data-save-edit>Save</button>
          <button class="btn-xs" data-cancel-edit>✕</button>
        </div>
      </div>`;

    // populate the edit profile selector
    const editSel = el.querySelector(".pi-edit-profile");
    editSel.innerHTML = _bldProfiles.length
      ? _bldProfiles.map(p =>
          `<option value="${p.id}" ${p.id === pool.profile_id ? "selected" : ""}>${p.name}  (#${p.id})</option>`
        ).join("")
      : `<option value="">— none —</option>`;

    // wire buttons
    function flashCopy(btn, text) {
      navigator.clipboard.writeText(text).catch(() => {});
      const orig = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = orig; }, 1500);
    }
    el.querySelector("[data-copy-local]").addEventListener("click", e => flashCopy(e.currentTarget, localUrl));
    if (torUrl) el.querySelector("[data-copy-tor]").addEventListener("click", e => flashCopy(e.currentTarget, torUrl));

    el.querySelector("[data-pause]").addEventListener("click", async () => {
      await fetch(`/api/pools/${pool.id}/pause`, { method: "POST" });
      await refreshPools();
    });


    el.querySelector("[data-clear]").addEventListener("click", async () => {
      if (!confirm(`Clear all ${count} ready build(s) from "${pool.name}"?`)) return;
      await fetch(`/api/pools/${pool.id}/clear`, { method: "POST" });
      await refreshPools();
    });

    const editRow = el.querySelector("[data-edit-row]");
    el.querySelector("[data-edit]").addEventListener("click", () => {
      editRow.classList.toggle("hidden");
    });
    el.querySelector("[data-cancel-edit]").addEventListener("click", () => {
      editRow.classList.add("hidden");
    });
    el.querySelector("[data-save-edit]").addEventListener("click", async () => {
      const name       = el.querySelector(".pi-edit-name").value.trim();
      const profile_id = el.querySelector(".pi-edit-profile").value;
      const target_count = parseInt(el.querySelector(".pi-edit-target").value) || 10;
      const r = await _fetchJson(`/api/pools/${pool.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, profile_id, target_count }),
      }).catch(() => ({}));
      if (r.ok) { editRow.classList.add("hidden"); await refreshPools(); }
    });

    el.querySelector("[data-del]").addEventListener("click", async () => {
      if (!confirm(`Delete pool "${pool.name}" (/d/${pool.slug})?\nAll ${count} ready build(s) will be discarded.`)) return;
      await fetch(`/api/pools/${pool.id}`, { method: "DELETE" });
      await refreshPools();
    });

    list.appendChild(el);
  }
}

// auto-refresh status while any pool is building
function _schedulePoolStatus() {
  clearInterval(_poolStatusTimer);
  if (_pools.some(p => p.building)) {
    _poolStatusTimer = setInterval(async () => {
      // lightweight status poll — only update counts, don't re-render profile selectors
      try {
        const fresh = await _fetchJson("/api/pools");
        if (JSON.stringify(fresh) !== JSON.stringify(_pools)) {
          _pools = fresh;
          renderPools();
        }
        if (!_pools.some(p => p.building)) clearInterval(_poolStatusTimer);
      } catch (_) { clearInterval(_poolStatusTimer); }
    }, 3000);
  }
}

// new pool form
$("#btn-pool-new").addEventListener("click", async () => {
  _poolEditId = null;
  $("#pool-form-title").textContent = "New Pool";
  $("#pf-name").value   = "";
  $("#pf-slug").value   = "";
  $("#pf-target").value = "10";
  $("#pf-slug").disabled = false;
  await _refreshBldProfilesForPool();
  _populatePoolProfileSel("");
  $("#pool-form-error").classList.add("hidden");
  $("#btn-pool-form-confirm").textContent = "Create";
  $("#pool-form-wrap").classList.remove("hidden");
  $("#pf-name").focus();
});

$("#btn-pool-form-cancel").addEventListener("click", () => {
  $("#pool-form-wrap").classList.add("hidden");
  $("#pool-form-error").classList.add("hidden");
});

$("#btn-pool-form-confirm").addEventListener("click", async () => {
  const name       = $("#pf-name").value.trim();
  const slug       = $("#pf-slug").value.trim().toLowerCase();
  const profile_id = $("#pf-profile-sel").value;
  const target_count = parseInt($("#pf-target").value) || 10;
  const errEl = $("#pool-form-error");
  errEl.classList.add("hidden");

  if (!name) { showPoolErr("Name is required."); return; }
  if (!slug)  { showPoolErr("Slug is required."); return; }
  if (!/^[a-z0-9][a-z0-9-]{0,29}$/.test(slug)) {
    showPoolErr("Slug must be lowercase alphanumeric + hyphens, 1–30 chars."); return;
  }
  if (!profile_id) { showPoolErr("Select a build profile."); return; }

  const btn = $("#btn-pool-form-confirm");
  btn.disabled = true; btn.textContent = "Creating…";
  try {
    const r = await _fetchJson("/api/pools", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, slug, profile_id, target_count }),
    });
    if (r.ok) {
      $("#pool-form-wrap").classList.add("hidden");
      await refreshPools();
    } else {
      showPoolErr(r.error || "Failed to create pool.");
    }
  } catch (err) {
    showPoolErr(`Network error: ${err}`);
  } finally {
    btn.disabled = false; btn.textContent = "Create";
  }
});

function showPoolErr(msg) {
  const el = $("#pool-form-error");
  el.textContent = msg;
  el.classList.remove("hidden");
}

// ─── Tor ──────────────────────────────────────────────────────────────────

async function torRefresh() {
  let s = {};
  try { s = await fetch("/api/tor/status").then(r => r.json()); } catch { }

  const dot   = $("#tor-dot");
  const label = $("#tor-status-label");
  const meta  = $("#tor-status-meta");

  if (s.running) {
    dot.className = "tor-dot running";
    label.textContent = "Running";
    label.style.color = "var(--ok)";
    meta.textContent  = `PID ${s.pid}`;
  } else {
    dot.className = "tor-dot stopped";
    label.textContent = "Stopped";
    label.style.color = "var(--err)";
    meta.textContent  = "";
  }
  $("#btn-tor-start").disabled   = !!s.running;
  $("#btn-tor-stop").disabled    = !s.running;
  $("#btn-tor-restart").disabled = !s.running;

  const list = $("#tor-service-list");
  const svcs = s.services || [];
  if (!svcs.length) {
    list.innerHTML = '<p class="empty-note">No hidden services found in torrc.</p>';
  } else {
    list.innerHTML = svcs.map(svc => {
      const onionHtml = svc.onion
        ? `<span class="tor-onion">${svc.onion}</span>
           <button class="btn-sm" style="font-size:10px" onclick="torCopy('${svc.onion}',this)">Copy</button>`
        : `<span class="tor-onion-placeholder">not yet generated — start Tor first</span>`;

      const ports = (svc.ports || []).map(p =>
        `<span class="tor-port-badge">:${p.virtual} → ${p.target}</span>`
      ).join("");

      const urls = (svc.ports || []).map(p => {
        if (!svc.onion) return "";
        const url = `http://${svc.onion}:${p.virtual}`;
        return `<div class="tor-url-row">
          <span>${url}</span>
          <button class="btn-sm" style="font-size:10px" onclick="torCopy('${url}',this)">Copy</button>
        </div>`;
      }).join("");

      return `<div class="tor-service-card">
        <div style="display:flex;align-items:center;gap:10px">${onionHtml}</div>
        <div class="tor-dir">${svc.dir}</div>
        <div class="tor-ports">${ports || '<span style="font-size:11px;color:var(--text-mute)">no ports</span>'}</div>
        ${urls}
      </div>`;
    }).join("");
  }
}

async function torCopy(text, btn) {
  try { await navigator.clipboard.writeText(text); } catch { }
  const orig = btn.textContent;
  btn.textContent = "Copied!";
  setTimeout(() => { btn.textContent = orig; }, 1500);
}

async function torAction(endpoint) {
  ["btn-tor-start","btn-tor-stop","btn-tor-restart","btn-tor-refresh"].forEach(id => {
    const el = $("#" + id); if (el) el.disabled = true;
  });
  try {
    const r = await fetch(`/api/tor/${endpoint}`, { method: "POST" });
    const j = await r.json();
    if (!j.ok) alert("Tor error: " + (j.error || "unknown"));
  } catch (e) { alert("Request failed: " + e); }
  await torRefresh();
  ["btn-tor-start","btn-tor-stop","btn-tor-restart","btn-tor-refresh"].forEach(id => {
    const el = $("#" + id); if (el) el.disabled = false;
  });
}

async function torLoadLog() {
  const box = $("#tor-log-box");
  if (!box) return;
  try {
    const j = await fetch("/api/tor/log").then(r => r.json());
    box.textContent = (j.lines || []).join("\n") || "(no log entries)";
    box.scrollTop = box.scrollHeight;
  } catch { box.textContent = "(failed to load log)"; }
}

$("#btn-tor-start").addEventListener("click",   () => torAction("start"));
$("#btn-tor-stop").addEventListener("click",    () => torAction("stop"));
$("#btn-tor-restart").addEventListener("click", () => torAction("restart"));
$("#btn-tor-refresh").addEventListener("click", torRefresh);
$("#btn-tor-log-refresh").addEventListener("click", torLoadLog);

$("#btn-tor-port").addEventListener("click", async () => {
  const virtual = $("#tor-vport").value.trim();
  const target  = $("#tor-target").value.trim();
  const msg     = $("#tor-port-msg");
  if (!virtual || !target) { msg.textContent = "fill both fields"; msg.style.color = "var(--err)"; return; }
  msg.textContent = "Saving…"; msg.style.color = "var(--text-mute)";
  try {
    const r = await fetch("/api/tor/port", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ virtual, target }),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = "Saved — restart Tor to apply"; msg.style.color = "var(--ok)";
      await torRefresh();
    } else {
      msg.textContent = j.error || "error"; msg.style.color = "var(--err)";
    }
  } catch (e) { msg.textContent = String(e); msg.style.color = "var(--err)"; }
  setTimeout(() => { msg.textContent = ""; }, 4000);
});


// ─── boot ─────────────────────────────────────────────────────────────────

refreshEncProfiles();
refreshBldProfiles();
refreshEncryptDropdowns();
refreshSideloadAssets();
refreshEncryptHistory();
refreshBuildHistory();
refreshPayloadSelector();

// Restore tab from URL hash — must run after all let declarations above
(function () {
  const hash = location.hash.replace("#", "");
  navigateTo(VALID_PAGES.has(hash) ? hash : "build", false);
})();
