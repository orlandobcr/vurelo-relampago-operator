// Vurelo Relampago Operator · web UI · clean v2

// ============ Globals (declared at top to avoid TDZ) ============
let POLLERS_STARTED = false;
const STATE = {
  view: "login",
  email: null,
  balance: [],
  queue: [],
  processing: new Set(),
  done: new Set(),
  failed: new Set(),
  autoMode: false,
  expiresIn: null,
  refreshCount: 0,
  googleUser: null,
  sessionWasAlive: false,  // detect transition alive → dead
};

// ============ Helpers ============
const $ = id => document.getElementById(id);
const fmt = n => Number(n || 0).toLocaleString("es-CO", { maximumFractionDigits: 2 });

async function API(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  return r.json();
}

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function showMsg(el, text, kind = "ok") {
  el.className = "msg " + kind;
  el.textContent = text;
}

// ============ View switching ============
function setView(view) {
  STATE.view = view;
  $("view-login").classList.add("hidden");
  $("view-mfa").classList.add("hidden");
  $("view-app").classList.add("hidden");
  if (view === "login" || view === "mfa") {
    $(`view-${view}`).classList.remove("hidden");
    return;
  }
  $("view-app").classList.remove("hidden");
  setSubview(view === "dashboard" ? "home" : view);
}

function setSubview(name) {
  document.querySelectorAll(".subview").forEach(el => el.classList.add("hidden"));
  const target = document.querySelector(`.subview[data-view="${name}"]`);
  if (target) target.classList.remove("hidden");
  document.querySelectorAll(".nav-link").forEach(el => {
    el.classList.toggle("active", el.dataset.view === name);
  });
  // Triggers de carga al entrar a la vista
  if (name === "trueno") loadTrueno();
  if (name === "attention") loadAttention();
  if (name === "logs") loadEvents();
  if (name === "settings") loadSettings();
}

function setStatusDot(connected, email, expiresIn, refreshCount) {
  $("status-dot").className = "dot " + (connected ? "on" : "off");
  let txt = connected ? "conectado" : "desconectado";
  if (connected && expiresIn != null) {
    const m = Math.floor(expiresIn / 60), s = expiresIn % 60;
    txt += ` · token ${m}:${String(s).padStart(2, "0")}`;
    if (refreshCount) txt += ` · ${refreshCount} refresh`;
  }
  $("status-text").textContent = txt;
  $("email-text").textContent = email ? `· ${email}` : "";
  $("logout-btn").style.display = connected ? "" : "none";
}

// ============ LOGIN flow ============
async function doLogin() {
  const email = $("login-email").value.trim();
  const password = $("login-password").value;
  if (!email || !password) {
    showMsg($("login-msg"), "Email y password requeridos", "err");
    return;
  }
  showMsg($("login-msg"), "Validando...", "busy");
  $("login-btn").disabled = true;
  try {
    const r = await API("/api/login/password", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    if (r.ok && r.next_step === "mfa_totp") {
      showMsg($("login-msg"), "OK · ingresa el PIN", "ok");
      setTimeout(() => { setView("mfa"); $("mfa-pin").focus(); }, 400);
    } else {
      showMsg($("login-msg"), r.message || "Error", "err");
    }
  } catch (e) {
    showMsg($("login-msg"), "Network · " + e.message, "err");
  } finally {
    $("login-btn").disabled = false;
  }
}

async function doMfa() {
  const pin = $("mfa-pin").value.trim();
  if (pin.length !== 6) {
    showMsg($("mfa-msg"), "PIN debe tener 6 dígitos", "err");
    return;
  }
  showMsg($("mfa-msg"), "Validando...", "busy");
  $("mfa-btn").disabled = true;
  try {
    const r = await API("/api/login/mfa", {
      method: "POST",
      body: JSON.stringify({ pin }),
    });
    if (r.ok) {
      showMsg($("mfa-msg"), "✓ Sesión activa", "ok");
      setTimeout(async () => {
        setView("dashboard");
        await loadStatus();
        await loadBalance();
        await loadQueue();
        startPollers();
      }, 600);
    } else {
      showMsg($("mfa-msg"), r.message || "PIN inválido", "err");
      $("mfa-pin").value = "";
      $("mfa-pin").focus();
    }
  } catch (e) {
    showMsg($("mfa-msg"), "Network · " + e.message, "err");
  } finally {
    $("mfa-btn").disabled = false;
  }
}

async function doLogout() {
  await API("/api/logout", { method: "POST" });
  STATE.email = null;
  setStatusDot(false);
  setView("login");
}

// ============ Loaders ============
async function loadStatus() {
  try {
    const s = await API("/api/status");
    const r = s.relampago || {};
    const wasAlive = STATE.sessionWasAlive;
    STATE.email = r.email;
    STATE.expiresIn = r.token_expires_in_seconds;
    STATE.refreshCount = r.refresh_count;
    STATE.sessionWasAlive = !!r.logged_in;
    setStatusDot(r.logged_in, r.email, r.token_expires_in_seconds, r.refresh_count);
    STATE.autoMode = s.auto_mode;
    if ($("auto-toggle")) {
      $("auto-toggle").checked = s.auto_mode;
      $("auto-label").textContent = s.auto_mode ? "AUTO 🟢" : "MANUAL";
    }

    // Banner · service pausado si Google está OK pero Relampago session muerta
    const banner = $("service-paused-banner");
    if (banner) {
      banner.classList.toggle("hidden", r.logged_in);
    }

    if (STATE.view !== "login" && STATE.view !== "mfa" && !r.logged_in) {
      // Transition alive → dead · explicar y mover a login
      if (wasAlive) {
        alert("⚠ La sesión Relampago expiró.\n\n" +
              "Mientras dure este estado:\n" +
              "  · NO se procesarán dispersiones (manual NI auto)\n" +
              "  · NO se enviarán alertas de saldo (balance fetch falla)\n" +
              "  · El refresh background está detenido\n\n" +
              "Re-loguéate con email + password + PIN TOTP para reactivar.");
      }
      setView("login");
    }

    // Actualizar contexto en la pantalla de login (mostrar Google user)
    const ctx = $("login-context");
    if (ctx && STATE.googleUser) {
      ctx.innerHTML = `Conectado con Google · <strong>${escapeHtml(STATE.googleUser.email)}</strong>`;
    }
    // Header · google user
    const gu = $("google-user");
    if (gu && STATE.googleUser) {
      gu.textContent = `Google · ${STATE.googleUser.email}`;
    }
    updateSidebarFooter();
  } catch (e) {}
}

async function loadGoogleUser() {
  try {
    const r = await API("/api/me");
    if (r.authenticated && r.user) {
      STATE.googleUser = r.user;
      const gu = $("google-user");
      if (gu) gu.textContent = `Google · ${r.user.email}`;
      const ctx = $("login-context");
      if (ctx) ctx.innerHTML = `Conectado con Google · <strong>${escapeHtml(r.user.email)}</strong>`;
    }
  } catch (e) {}
}

function updateSidebarFooter() {
  const ss = $("sidebar-status");
  if (!ss) return;
  if (STATE.expiresIn != null) {
    const m = Math.floor(STATE.expiresIn / 60), s = STATE.expiresIn % 60;
    ss.innerHTML = `Token · ${m}m ${s}s<br>Refresh · ${STATE.refreshCount || 0}`;
  } else {
    ss.textContent = "—";
  }
}

async function loadBalance() {
  try {
    const r = await API("/api/balance");
    const list = $("balance-list");
    if (!list) return;
    if (!r.ok) {
      list.innerHTML = `<div class="muted">Error · ${r.error || "no data"}</div>`;
      return;
    }
    const accs = (r.data && r.data.accounts) || [];
    list.innerHTML = accs.map(a => `
      <div class="balance-row">
        <div>
          <div class="balance-type">${escapeHtml(a.accountType)}</div>
        </div>
        <div class="balance-amount">$ ${fmt(a.actualBalance)}</div>
      </div>
    `).join("");
  } catch (e) {}
}

async function loadQueue() {
  try {
    const r = await API("/api/queue");
    const list = $("queue-list");
    const counter = $("queue-count");
    const nav = $("nav-kashport-count");
    if (!list) return;
    if (!r.ok) {
      list.innerHTML = `<div class="muted">${r.error === "no_token"
        ? "Configura el token Kashport en ⚙️ Configuración"
        : (r.body || r.error || "error")}</div>`;
      if (counter) counter.textContent = "0";
      if (nav) nav.textContent = "0";
      return;
    }
    const items = (r.data && r.data.items) || [];
    STATE.queue = items;
    if (counter) counter.textContent = String(items.length);
    if (nav) nav.textContent = String(items.length);
    if (!items.length) {
      list.innerHTML = `<div class="muted">No hay items pending</div>`;
      return;
    }
    list.innerHTML = items.map(renderQueueItem).join("");
    items.forEach(it => {
      const p = document.querySelector(`[data-id="${it.id}"] .btn-process`);
      const rj = document.querySelector(`[data-id="${it.id}"] .btn-reject`);
      if (p && !p.disabled) p.addEventListener("click", () => processItem(it.id));
      if (rj) rj.addEventListener("click", () => rejectItem(it.id));
    });
  } catch (e) {}
}

function renderQueueItem(it) {
  let cls = "";
  let lbl = "";
  if (STATE.processing.has(it.id)) { cls = "processing"; lbl = "⏳"; }
  else if (STATE.done.has(it.id))   { cls = "done"; lbl = "✓"; }
  else if (STATE.failed.has(it.id)) { cls = "failed"; lbl = "✗"; }
  const d = it.destination || {};
  const key = d.key_value || d.account_number || "—";

  // Rule check · si bloqueado · botón disabled + razón
  const rc = it.rule_check || { ok: true };
  const blocked = !rc.ok;
  const blockTxt = blocked
    ? `<div class="qi-blocked">🚫 ${escapeHtml(rc.detail || rc.reason || "Bloqueado por regla")}</div>`
    : "";
  const processBtn = blocked
    ? `<button class="btn-disabled btn-process" disabled title="${escapeHtml(rc.detail || '')}">⛔ ${rc.reason === 'min_gap' ? 'Espera gap' : 'Anti-duplicado'}</button>`
    : `<button class="btn-success btn-process">▶ Procesar</button>`;

  return `
    <div class="queue-item ${cls} ${blocked ? 'rule-blocked' : ''}" data-id="${escapeHtml(it.id)}">
      <div class="qi-info">
        <div class="qi-name">${escapeHtml(d.fullname || "—")} ${lbl}</div>
        <div class="qi-meta">
          ${(it.rail || "").toUpperCase()} · ${escapeHtml(key)}
          · ${escapeHtml(d.doc_type || "CC")} ${escapeHtml(d.doc_number || "")}
        </div>
        ${blockTxt}
      </div>
      <div class="qi-amount">$ ${fmt(it.amount_cop)}</div>
      ${cls ? "" : `
        <div class="qi-actions">
          ${processBtn}
          <button class="btn-danger btn-reject">✗ Rechazar</button>
        </div>
      `}
    </div>
  `;
}

async function processItem(id) {
  STATE.processing.add(id);
  rerenderQueueOnly();
  try {
    const r = await API(`/api/process/${id}`, { method: "POST" });
    STATE.processing.delete(id);
    if (r.ok || r.auto_rejected) STATE.done.add(id);
    else if (r.rule_blocked) {
      // NO marcar como failed · solo skip · permitir retry después
      alert(`⏸ Bloqueado por regla\n\n${r.message || r.reason}`);
    } else {
      STATE.failed.add(id);
    }
    rerenderQueueOnly();
    await loadBalance();
    await loadSent();
  } catch (e) {
    STATE.processing.delete(id);
    STATE.failed.add(id);
    rerenderQueueOnly();
  }
}

async function rejectItem(id) {
  if (!confirm("¿Marcar como RECHAZADO y devolver saldo?")) return;
  STATE.processing.add(id);
  rerenderQueueOnly();
  const r = await API(`/api/reject/${id}`, {
    method: "POST",
    body: JSON.stringify({ reason: "manual_reject", detail: "Rechazado manualmente" }),
  });
  STATE.processing.delete(id);
  if (r.ok) STATE.done.add(id); else STATE.failed.add(id);
  rerenderQueueOnly();
}

function rerenderQueueOnly() {
  const list = $("queue-list");
  if (!list) return;
  list.innerHTML = STATE.queue.map(renderQueueItem).join("");
  STATE.queue.forEach(it => {
    const p = document.querySelector(`[data-id="${it.id}"] .btn-process`);
    const rj = document.querySelector(`[data-id="${it.id}"] .btn-reject`);
    if (p) p.addEventListener("click", () => processItem(it.id));
    if (rj) rj.addEventListener("click", () => rejectItem(it.id));
  });
}

async function loadSent() {
  try {
    const r = await API("/api/sent");
    const items = r.items || [];
    const list = $("sent-list");
    const counter = $("sent-count");
    if (counter) counter.textContent = String(items.length);
    if (!list) return;
    if (!items.length) {
      list.innerHTML = `<div class="muted">Sin dispersiones enviadas aún</div>`;
      return;
    }
    list.innerHTML = items.map(it => {
      const sc = (it.current_state || "unknown").toLowerCase();
      return `
        <div class="sent-item ${sc}">
          <div>
            <div class="sent-name">${escapeHtml(it.payee_name || "—")}</div>
            <div class="sent-meta">
              ${escapeHtml(it.payee_bank || "")} · ${escapeHtml(it.payee_key || "")}
              · vtrx ${(it.relampago_tx_id || "").slice(0, 18)}
              · ${(it.ts_iso || "").slice(11, 19)}
            </div>
          </div>
          <div class="sent-amount">$ ${fmt(it.amount_cop || 0)}</div>
          <span class="state-pill ${sc}">${escapeHtml(it.current_state || "?")}</span>
        </div>
      `;
    }).join("");
  } catch (e) {}
}

async function loadTrueno() {
  try {
    const filter = $("trueno-filter") ? $("trueno-filter").value : "";
    const url = "/api/trueno" + (filter ? `?state=${filter}` : "");
    const r = await API(url);
    const items = r.items || [];
    const list = $("trueno-list");
    const counter = $("trueno-count");
    const nav = $("nav-trueno-count");
    if (counter) counter.textContent = String(items.length);
    if (nav) nav.textContent = String(items.length);
    if (!list) return;
    if (!items.length) {
      list.innerHTML = `<div class="muted">Sin transacciones · click "↻ Sync ahora"</div>`;
      return;
    }
    list.innerHTML = items.map(it => {
      const isFee = (it.trx_type || "").includes("fee");
      const sc = (it.state || "unknown").toLowerCase();
      return `
        <div class="trueno-item ${sc}${isFee ? " fee" : ""}">
          <div>
            <div class="sent-name">
              ${escapeHtml(it.payee_name || "—")}
              ${it.declination_reason ? `<span style="color:#fca5a5;font-size:11px"> · ${escapeHtml(it.declination_reason)}</span>` : ""}
            </div>
            <div class="sent-meta">
              ${escapeHtml(it.payee_bank || "")} · ${escapeHtml(it.payee_key || "")}
              · ${escapeHtml(it.external_provider || "")}
            </div>
            <div class="trueno-desc">${escapeHtml(it.description || "")} · ${(it.transaction_id || "").slice(0, 20)}</div>
          </div>
          <div class="sent-amount" style="color:${(it.amount || 0) < 0 ? '#fca5a5' : '#6ee7b7'}">
            $ ${fmt(Math.abs(it.amount || 0))}
          </div>
          <span class="state-pill ${sc}">${escapeHtml(it.state || "?")}</span>
        </div>
      `;
    }).join("");
  } catch (e) {}
}

async function loadAttention() {
  try {
    const r = await API("/api/attention?open=1");
    const items = r.items || [];
    const list = $("attention-list");
    const counter = $("attn-count");
    const nav = $("nav-attn-count");
    if (counter) counter.textContent = String(items.length);
    if (nav) nav.textContent = String(items.length);
    if (!list) return;
    if (!items.length) {
      list.innerHTML = `<div class="muted">✓ Sin alertas · todo en orden</div>`;
      return;
    }
    list.innerHTML = items.map(it => `
      <div class="attn-item">
        <div class="attn-kind">${escapeHtml(it.kind)} · ${escapeHtml(it.severity)}</div>
        <div class="attn-desc">${escapeHtml(it.description || "")}</div>
        <div class="attn-meta">
          ${escapeHtml(it.payee_name || "")} · $ ${fmt(it.amount_cop || 0)}
          · vtrx ${(it.relampago_tx_id || "").slice(0, 18)}
        </div>
        <div class="attn-actions">
          <button class="btn-tiny" onclick="window.ackAttention(${it.id})">✓ Marcar visto</button>
        </div>
      </div>
    `).join("");
  } catch (e) {}
}

window.ackAttention = async (id) => {
  await API(`/api/attention/${id}/ack`, { method: "POST" });
  loadAttention(); loadStats();
};

async function loadStats() {
  try {
    const r = await API("/api/stats");
    if ($("stat-sent")) $("stat-sent").textContent = r.sent_total || 0;
    if ($("stat-trueno")) $("stat-trueno").textContent = r.trueno_total || 0;
    if ($("stat-rejected")) $("stat-rejected").textContent = r.trueno_rejected || 0;
    if ($("stat-attn")) $("stat-attn").textContent = r.attention_open || 0;
    if ($("nav-trueno-count")) $("nav-trueno-count").textContent = r.trueno_total || 0;
    if ($("nav-attn-count")) $("nav-attn-count").textContent = r.attention_open || 0;
  } catch (e) {}
}

async function loadEvents() {
  try {
    const r = await API("/api/events");
    const log = $("event-log");
    if (!log) return;
    log.innerHTML = (r.events || []).slice(-100).reverse().map(e => `
      <div class="log-line">
        <span class="log-ts">${e.ts}</span>
        <span class="log-kind">${escapeHtml(e.kind)}</span>
        <span class="log-payload">${escapeHtml(JSON.stringify(e.payload).slice(0, 200))}</span>
      </div>
    `).join("");
  } catch (e) {}
}

async function loadSettings() {
  try {
    const s = await API("/api/status");
    const r = s.relampago || {};
    if ($("session-info")) $("session-info").innerHTML = `
      Email · ${r.email || "—"}<br>
      Logged in · ${r.logged_in ? "✓" : "✗"}<br>
      Token expira · ${r.token_expires_in_seconds != null ? r.token_expires_in_seconds + "s" : "—"}<br>
      Refresh · ${r.refresh_count || 0} OK · ${r.refresh_errors || 0} errors
    `;
    const stats = await API("/api/stats");
    if ($("storage-info")) $("storage-info").innerHTML = `
      DB · ${stats.db_path || "—"}<br>
      Enviadas · ${stats.sent_total} (hoy ${stats.sent_today})<br>
      Trueno cached · ${stats.trueno_total}<br>
      Attention open · ${stats.attention_open}
    `;
    await loadThresholds();
    await loadRecipients();
    await loadDispersionRules();
  } catch (e) {}
}

async function loadDispersionRules() {
  const r = await API("/api/dispersion-rules");
  const gap = $("rule-gap-seconds");
  const win = $("rule-window-min");
  const cur = $("rule-current");
  if (gap) gap.value = r.min_gap_seconds;
  if (win) win.value = r.same_payee_window_minutes;
  if (cur) cur.textContent = `Actual · gap ${r.min_gap_seconds}s · ventana anti-duplicado ${r.same_payee_window_minutes} min`;
}

async function loadThresholds() {
  const tbody = $("threshold-rows");
  if (!tbody) return;
  const r = await API("/api/thresholds");
  const items = r.items || [];
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">Sin thresholds</td></tr>`;
    return;
  }
  tbody.innerHTML = items.map(it => {
    const alerted = it.last_alert_sent_at ? true : false;
    return `
      <tr data-account-type="${escapeHtml(it.account_type)}">
        <td><strong>${escapeHtml(it.account_type)}</strong></td>
        <td>
          <input type="number" class="thr-input" value="${it.threshold_cop}" min="0" step="1000000">
        </td>
        <td>
          <span class="threshold-state ${alerted ? 'alert' : 'ok'}">
            ${alerted ? '⚠ alertado · esperando recuperación' : '✓ OK'}
          </span><br>
          <label class="muted small">
            <input type="checkbox" class="thr-enabled" ${it.enabled ? 'checked' : ''}> habilitada
          </label>
        </td>
        <td><button class="btn-tiny thr-save">Guardar</button></td>
      </tr>
    `;
  }).join("");
  tbody.querySelectorAll(".thr-save").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      const tr = e.target.closest("tr");
      const acc = tr.dataset.accountType;
      const thrInput = tr.querySelector(".thr-input");
      const enabledChk = tr.querySelector(".thr-enabled");
      btn.disabled = true;
      btn.textContent = "...";
      await API(`/api/thresholds/${encodeURIComponent(acc)}`, {
        method: "POST",
        body: JSON.stringify({
          threshold_cop: Number(thrInput.value),
          enabled: enabledChk.checked,
        }),
      });
      btn.textContent = "✓ guardado";
      setTimeout(() => { btn.textContent = "Guardar"; btn.disabled = false; }, 1200);
      loadThresholds();
    });
  });
}

async function loadRecipients() {
  const ta = $("recipients-input");
  if (!ta) return;
  const r = await API("/api/recipients");
  ta.value = (r.recipients || []).join("\n");
}

// ============ Pollers ============
function startPollers() {
  if (POLLERS_STARTED) return;
  POLLERS_STARTED = true;
  setInterval(loadStatus, 3000);
  setInterval(loadBalance, 30000);
  setInterval(loadQueue, 10000);
  setInterval(loadEvents, 5000);
  setInterval(loadSent, 15000);
  setInterval(loadAttention, 12000);
  setInterval(loadStats, 8000);
  setInterval(() => {
    // Decrement countdown UI locally entre pollers
    if (STATE.expiresIn != null && STATE.expiresIn > 0) {
      STATE.expiresIn--;
      setStatusDot(true, STATE.email, STATE.expiresIn, STATE.refreshCount);
      updateSidebarFooter();
    }
  }, 1000);
  // Initial loads
  loadSent(); loadStats(); loadAttention();
}

async function doSyncTrueno(btn) {
  if (btn) { btn.disabled = true; const old = btn.textContent; btn.textContent = "⟳ syncing..."; }
  await API("/api/sync-trueno", { method: "POST" });
  await loadTrueno();
  await loadAttention();
  await loadStats();
  if (btn) { btn.disabled = false; btn.textContent = "↻ Sync ahora"; }
}

// ============ Event wiring ============
document.addEventListener("DOMContentLoaded", () => {
  // Login buttons
  $("login-btn").addEventListener("click", doLogin);
  $("mfa-btn").addEventListener("click", doMfa);
  $("mfa-pin").addEventListener("input", (e) => {
    if (e.target.value.length === 6) doMfa();
  });
  $("logout-btn").addEventListener("click", doLogout);

  // Sidebar nav
  document.querySelectorAll(".nav-link").forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      setSubview(el.dataset.view);
    });
  });

  // Refresh buttons (may not exist if not on dashboard yet)
  const wire = (id, fn) => { const el = $(id); if (el) el.addEventListener("click", fn); };
  wire("refresh-balance", loadBalance);
  wire("refresh-queue", loadQueue);
  wire("refresh-sent", loadSent);
  wire("refresh-trueno", () => doSyncTrueno($("refresh-trueno")));
  wire("sync-trueno-btn", () => doSyncTrueno($("sync-trueno-btn")));
  wire("manual-refresh-session", async () => {
    const r = await API("/api/refresh", { method: "POST" });
    alert(r.ok ? "✓ Refresh OK" : "Token aún válido · refresh prematuro");
    await loadStatus();
  });
  wire("logout-from-settings", doLogout);

  // Trueno filter
  const tf = $("trueno-filter");
  if (tf) tf.addEventListener("change", loadTrueno);

  // Auto toggle
  const auto = $("auto-toggle");
  if (auto) auto.addEventListener("change", async (e) => {
    const enabled = e.target.checked;
    if (enabled && !confirm("AUTO procesa TODOS los pending sin click. ¿Continuar?")) {
      e.target.checked = false; return;
    }
    await API("/api/auto", { method: "POST", body: JSON.stringify({ enabled }) });
    STATE.autoMode = enabled;
    $("auto-label").textContent = enabled ? "AUTO 🟢" : "MANUAL";
  });

  // Kashport save
  const ks = $("kashport-save");
  if (ks) ks.addEventListener("click", async () => {
    const token = $("kashport-token").value.trim();
    if (!token) { showMsg($("kashport-msg"), "Pega un token", "err"); return; }
    await API("/api/kashport/token", { method: "POST", body: JSON.stringify({ token }) });
    showMsg($("kashport-msg"), "✓ Token guardado", "ok");
    await loadQueue();
  });

  // Save dispersion rules
  const srRules = $("save-rules");
  if (srRules) srRules.addEventListener("click", async () => {
    const gap = parseInt($("rule-gap-seconds").value || "0", 10);
    const win = parseInt($("rule-window-min").value || "0", 10);
    const r = await API("/api/dispersion-rules", {
      method: "POST",
      body: JSON.stringify({ min_gap_seconds: gap, same_payee_window_minutes: win }),
    });
    if (r.ok) {
      showMsg($("rules-msg"), `✓ Reglas guardadas · gap ${r.min_gap_seconds}s · ventana ${r.same_payee_window_minutes}m`, "ok");
      loadDispersionRules();
    } else {
      showMsg($("rules-msg"), "✗ Error guardando reglas", "err");
    }
  });

  // Save recipients + test email
  const sr = $("save-recipients");
  if (sr) sr.addEventListener("click", async () => {
    const emails = $("recipients-input").value.split("\n").map(e => e.trim()).filter(Boolean);
    await API("/api/recipients", { method: "POST", body: JSON.stringify({ emails }) });
    showMsg($("alerts-msg"), `✓ ${emails.length} destinatarios guardados`, "ok");
    loadRecipients();
  });
  const te = $("test-email");
  if (te) te.addEventListener("click", async () => {
    te.disabled = true; te.textContent = "Enviando...";
    const r = await API("/api/test-email", { method: "POST" });
    te.disabled = false; te.textContent = "Enviar email de prueba";
    if (r.ok) showMsg($("alerts-msg"), `✓ Email enviado a ${r.recipients_count} destinatarios`, "ok");
    else showMsg($("alerts-msg"), `✗ Error · ${r.error}`, "err");
  });

  // Initial load
  (async () => {
    await loadGoogleUser();          // Google user info → mostrar email en UI
    await loadStatus();
    if (STATE.email) {
      setView("dashboard");
      await loadBalance();
      await loadQueue();
      startPollers();
    } else {
      setView("login");
    }
  })();
});
