// 应用主逻辑：状态管理、界面渲染、同步流程
import {
  escapeHtml,
  formatDateTime,
  relativeTime,
  hostOf,
  initialsOf,
  colorOf,
  nowISO,
  uuid,
  clamp,
} from './util.js';
import {
  createEmptyVault,
  sealVault,
  openVault,
  decryptWithKey,
  changeMasterPassword,
  assertEnvelope,
  deriveKey,
  KDF_ITERATIONS,
} from './crypto.js';
import {
  totp,
  totpRemaining,
  totpProgress,
  parseOtpauthUri,
  buildOtpauthUri,
  normalizeTotp,
} from './totp.js';
import { parseAnyTotp } from './migration.js';
import {
  generatePassword,
  generatePassphrase,
  estimateEntropy,
  strengthOf,
  buildPool,
} from './generator.js';
import {
  normalizeEntry,
  deleteEntry,
  mergeVaults,
  searchEntries,
  sortEntries,
  vaultStats,
  exportCsv,
  exportJson,
  parseCsvImport,
  parseJsonImport,
  purgeTombstones,
} from './vault.js';
import { SyncClient, SyncError } from './sync.js';
import { openQrScanner } from './qrscan.js';
import {
  listSnapshots,
  recordSnapshot,
  removeSnapshot,
  clearSnapshots,
  snapshotCount,
  formatBytes,
} from './backup.js';

/* ============================== 基础工具 ============================== */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const icon = (name) => `<svg><use href="#i-${name}"></use></svg>`;

const LS = { vault: 'pm.vault', sync: 'pm.sync', ui: 'pm.ui' };

const DEFAULT_SETTINGS = {
  autoLockMinutes: 5,
  clipboardClearSeconds: 30,
  generator: {
    mode: 'password',
    length: 20,
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: true,
    customChars: '',
    words: 4,
    separator: '-',
    capitalize: true,
    addNumber: false,
  },
};

const state = {
  key: null,
  masterPassword: null,
  salt: null,
  iterations: KDF_ITERATIONS,
  header: null,
  envelope: null,
  vault: null,
  unlocked: false,
  dirty: false,
  filter: 'all',
  query: '',
  selectedId: null,
  revealed: new Set(),
  sync: { url: '', token: '', lastSyncAt: null },
  ui: { theme: 'dark' },
  deviceId: '',
  saveTimer: null,
  idleTimer: null,
  lastActivity: Date.now(),
  totpBusy: false,
  modalStack: [],
};

/* ============================== 启动 ============================== */

function init() {
  loadPrefs();
  applyTheme();
  if (!globalThis.crypto?.subtle) {
    showInsecureNotice();
    return;
  }
  if (window.innerWidth < 480) {
    $('#search').placeholder = '搜索…';
  }
  bindEvents();
  const env = readLocalEnvelope();
  if (env) {
    state.envelope = env;
    state.header = env.header;
    showLock('unlock');
  } else {
    showLock('create');
  }
  registerServiceWorker();
}

function showInsecureNotice() {
  const host = location.hostname || '127.0.0.1';
  const httpsUrl = `https://${host}:8443`;
  $('#lock').innerHTML = `<div class="lock-card">
    <div class="brand">
      <div class="brand-logo">${icon('alert')}</div>
      <div><h1>需要安全连接</h1><p>当前地址无法启用加密</p></div>
    </div>
    <p class="hint" style="font-size:13.5px;line-height:1.85;color:var(--muted)">
      浏览器只在 <b>HTTPS</b> 或 <b>localhost</b> 下开放 WebCrypto 加密接口。
      通过局域网 IP 的 HTTP 地址访问时，保险库无法解密。
    </p>
    <p class="hint" style="font-size:13.5px;line-height:1.85;color:var(--muted)">
      请改用下面的 HTTPS 地址（首次访问会提示证书不受信任，点「高级 → 继续前往」即可）：
    </p>
    <a class="btn primary block" href="${httpsUrl}" style="text-decoration:none;margin-top:4px">${httpsUrl}</a>
    <p class="lock-note">${icon('lock')} 证书由电脑端自动生成，仅用于局域网加密传输</p>
  </div>`;
}

function loadPrefs() {
  try {
    const ui = JSON.parse(localStorage.getItem(LS.ui) || '{}');
    state.ui = { theme: ui.theme === 'light' ? 'light' : 'dark' };
  } catch {
    /* 忽略 */
  }
  try {
    const sync = JSON.parse(localStorage.getItem(LS.sync) || '{}');
    state.sync = {
      url: sync.url || '',
      token: sync.token || '',
      lastSyncAt: sync.lastSyncAt || null,
    };
  } catch {
    /* 忽略 */
  }
  state.deviceId = localStorage.getItem('pm.device') || '';
  if (!state.deviceId) {
    state.deviceId = uuid();
    localStorage.setItem('pm.device', state.deviceId);
  }
}

function savePrefs() {
  localStorage.setItem(LS.ui, JSON.stringify(state.ui));
  localStorage.setItem(LS.sync, JSON.stringify(state.sync));
}

function applyTheme() {
  document.documentElement.dataset.theme = state.ui.theme;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', state.ui.theme === 'dark' ? '#0d0f14' : '#f4f6fa');
}

function toggleTheme() {
  state.ui.theme = state.ui.theme === 'dark' ? 'light' : 'dark';
  applyTheme();
  savePrefs();
}

function readLocalEnvelope() {
  try {
    const raw = localStorage.getItem(LS.vault);
    if (!raw) return null;
    const env = JSON.parse(raw);
    assertEnvelope(env);
    return env;
  } catch {
    return null;
  }
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

/* ============================== 锁屏 ============================== */

let lockMode = 'unlock';

function showLock(mode) {
  lockMode = mode;
  $('#lock').hidden = false;
  $('#main').hidden = true;
  $('#confirm-wrap').hidden = mode !== 'create';
  $('#pw-strength').hidden = true;
  $('#lock-submit').textContent = mode === 'create' ? '创建保险库' : '解锁';
  $('#lock-sub').textContent =
    mode === 'create' ? '首次使用，请设置一个主密码' : '输入主密码解锁';
  $('#master-password').value = '';
  $('#master-password2').value = '';
  $('#lock-error').hidden = true;
  $('#master-password').setAttribute(
    'autocomplete',
    mode === 'create' ? 'new-password' : 'current-password',
  );
  setTimeout(() => $('#master-password').focus(), 120);
}

function lockError(message) {
  const el = $('#lock-error');
  el.textContent = message;
  el.hidden = !message;
}

async function handleLockSubmit(event) {
  event.preventDefault();
  const pw = $('#master-password').value;
  const btn = $('#lock-submit');
  lockError('');

  if (lockMode === 'create') {
    const pw2 = $('#master-password2').value;
    if (pw.length < 8) return lockError('主密码至少需要 8 位字符');
    if (pw !== pw2) return lockError('两次输入的主密码不一致');
    btn.disabled = true;
    btn.textContent = '正在创建…';
    try {
      const vault = createEmptyVault();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const key = await deriveKey(pw, salt, KDF_ITERATIONS);
      const header = { revision: 0, updatedAt: nowISO(), deviceId: state.deviceId };
      const env = await sealVault(vault, key, { salt, iterations: KDF_ITERATIONS, header });
      state.key = key;
      state.salt = salt;
      state.iterations = KDF_ITERATIONS;
      state.masterPassword = pw;
      state.vault = vault;
      state.header = header;
      state.envelope = env;
      localStorage.setItem(LS.vault, JSON.stringify(env));
      enterApp();
      toast('保险库已创建，请牢记主密码', 'ok');
    } catch (err) {
      lockError(err.message || '创建失败');
    } finally {
      btn.disabled = false;
      btn.textContent = '创建保险库';
    }
    return;
  }

  if (!pw) return lockError('请输入主密码');
  btn.disabled = true;
  btn.textContent = '正在解锁…';
  try {
    const env = state.envelope || readLocalEnvelope();
    if (!env) throw new Error('本机没有找到保险库');
    const opened = await openVault(env, pw);
    state.key = opened.key;
    state.salt = opened.salt;
    state.iterations = opened.iterations;
    state.masterPassword = pw;
    state.vault = opened.vault;
    state.header = opened.header;
    state.envelope = env;
    state.dirty = false;
    enterApp();
  } catch (err) {
    lockError(err.code === 'BAD_PASSWORD' ? '主密码错误，请重试' : err.message || '解锁失败');
  } finally {
    btn.disabled = false;
    btn.textContent = '解锁';
  }
}

function enterApp() {
  state.unlocked = true;
  $('#lock').hidden = true;
  $('#main').hidden = false;
  $('#master-password').value = '';
  $('#master-password2').value = '';
  state.selectedId = null;
  state.query = '';
  $('#search').value = '';
  purgeTombstones(state.vault, 90);
  render();
  startTotpTicker();
  resetIdle();
}

function lockVault(silent = false) {
  if (!state.unlocked) return;
  state.unlocked = false;
  state.key = null;
  state.masterPassword = null;
  state.vault = null;
  state.selectedId = null;
  state.revealed.clear();
  stopTotpTicker();
  closeAllModals();
  $('#main').hidden = true;
  $('#main').classList.remove('detail-open');
  showLock('unlock');
  if (!silent) toast('保险库已锁定', 'ok');
}

/* ============================== 持久化 ============================== */

function scheduleSave() {
  state.dirty = true;
  clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => {
    persist().catch((err) => toast(`保存失败：${err.message}`, 'err'));
  }, 450);
}

async function persist() {
  if (!state.unlocked || !state.key) return;
  const header = { ...state.header, updatedAt: nowISO() };
  const env = await sealVault(state.vault, state.key, {
    salt: state.salt,
    iterations: state.iterations,
    header,
  });
  state.header = header;
  state.envelope = env;
  localStorage.setItem(LS.vault, JSON.stringify(env));
  recordSnapshot(env);
}

function settings() {
  const s = state.vault?.settings || {};
  return {
    ...DEFAULT_SETTINGS,
    ...s,
    generator: { ...DEFAULT_SETTINGS.generator, ...(s.generator || {}) },
  };
}

function updateSettings(patch) {
  state.vault.settings = { ...settings(), ...patch };
  scheduleSave();
}

/* ============================== 渲染 ============================== */

function render() {
  if (!state.unlocked) return;
  renderFilters();
  renderList();
  renderDetail();
}

function visibleEntries() {
  let list = searchEntries(state.vault.entries, state.query);
  if (state.filter === 'fav') list = list.filter((e) => e.favorite);
  else if (state.filter === 'totp') list = list.filter((e) => e.totp);
  else if (state.filter === 'note') list = list.filter((e) => e.type === 'note');
  return sortEntries(list);
}

function renderFilters() {
  const stats = vaultStats(state.vault);
  const items = [
    { key: 'all', label: '全部', count: stats.total },
    { key: 'fav', label: '收藏', count: stats.favorites },
    { key: 'totp', label: '含 2FA', count: stats.withTotp },
    { key: 'note', label: '笔记', count: stats.notes },
  ];
  $('#filters').innerHTML = items
    .map(
      (it) =>
        `<button class="chip ${state.filter === it.key ? 'active' : ''}" data-filter="${it.key}">${it.label}<span class="count">${it.count}</span></button>`,
    )
    .join('');
}

function renderList() {
  const list = visibleEntries();
  const el = $('#entry-list');
  if (!list.length) {
    el.innerHTML = `<div class="empty-list">${
      state.query ? '没有匹配的条目' : '还没有条目<br>点击右下角「新建条目」开始'
    }</div>`;
    return;
  }
  el.innerHTML = list
    .map((e) => {
      const sub = e.type === 'note' ? '安全笔记' : e.username || hostOf(e.url) || '—';
      return `<button class="entry-item ${e.id === state.selectedId ? 'active' : ''}" data-id="${e.id}">
        <span class="avatar" style="background:${colorOf(e.title)}">${escapeHtml(initialsOf(e.title))}</span>
        <span class="entry-main">
          <span class="entry-title">${escapeHtml(e.title)}</span>
          <span class="entry-sub">${escapeHtml(sub)}</span>
        </span>
        <span class="entry-badges">
          ${e.totp ? '<span class="badge totp">2FA</span>' : ''}
          ${e.type === 'note' ? '<span class="badge note">笔记</span>' : ''}
          ${e.favorite ? '<span class="badge star">★</span>' : ''}
        </span>
      </button>`;
    })
    .join('');
}

function renderDetail() {
  const el = $('#detail');
  const entry = state.vault.entries.find((e) => e.id === state.selectedId && !e.deletedAt);
  if (!entry) {
    el.innerHTML = `<div class="detail-empty">
      <div>
        <div class="big">${icon('shield')}</div>
        <h3>选择一个条目查看详情</h3>
        <p>或按 Ctrl / ⌘ + K 搜索，Ctrl / ⌘ + N 新建</p>
      </div>
    </div>`;
    return;
  }

  const rows = [];
  if (entry.type === 'login') {
    if (entry.username) {
      rows.push(rowHtml('user', '用户名', escapeHtml(entry.username), 'copy-username', entry.username));
    }
    if (entry.password) {
      const revealed = state.revealed.has(entry.id);
      rows.push(`<div class="row">
        <div class="row-icon">${icon('key')}</div>
        <div class="row-body">
          <div class="row-label">密码</div>
          <div class="row-value mono ${revealed ? '' : 'masked'}" id="pw-value">${
            revealed ? escapeHtml(entry.password) : '•'.repeat(Math.min(16, Math.max(8, entry.password.length)))
          }</div>
        </div>
        <div class="row-actions">
          <button class="icon-btn" data-act="toggle-pw" title="${revealed ? '隐藏' : '显示'}">${icon(revealed ? 'eye-off' : 'eye')}</button>
          <button class="icon-btn" data-act="copy-pw" title="复制密码">${icon('copy')}</button>
        </div>
      </div>`);
    }
    if (entry.url) {
      const href = /^https?:\/\//i.test(entry.url) ? entry.url : `https://${entry.url}`;
      rows.push(`<div class="row">
        <div class="row-icon">${icon('link')}</div>
        <div class="row-body">
          <div class="row-label">网址</div>
          <div class="row-value"><a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(hostOf(entry.url) || entry.url)}</a></div>
        </div>
        <div class="row-actions">
          <button class="icon-btn" data-act="copy-url" title="复制网址">${icon('copy')}</button>
        </div>
      </div>`);
    }
    if (entry.totp) {
      rows.push(`<div class="row totp-row" data-totp-id="${entry.id}">
        <div class="row-icon">${icon('clock')}</div>
        <div class="row-body">
          <div class="row-label">动态验证码 · ${escapeHtml(entry.totp.issuer || entry.totp.account || '2FA')}</div>
          <div class="totp-code">••• •••</div>
          <div class="totp-meta">剩余 <span class="totp-left">--</span> 秒</div>
        </div>
        <div class="ring" style="--p:0"></div>
        <div class="row-actions">
          <button class="icon-btn" data-act="copy-totp" title="复制验证码">${icon('copy')}</button>
        </div>
      </div>`);
    }
  }

  const tags = (entry.tags || []).length
    ? `<div class="tags">${entry.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('')}</div>`
    : '';

  el.innerHTML = `
    <div class="detail-head">
      <button class="icon-btn only-mobile" data-act="back" title="返回">${icon('back')}</button>
      <span class="avatar" style="background:${colorOf(entry.title)}">${escapeHtml(initialsOf(entry.title))}</span>
      <div class="detail-title">
        <h2>${escapeHtml(entry.title)}</h2>
        <p>${escapeHtml(entry.type === 'note' ? '安全笔记' : entry.username || hostOf(entry.url) || '账号密码')}</p>
      </div>
      <div class="detail-actions">
        <button class="icon-btn" data-act="fav" title="收藏">${icon('star')}</button>
        <button class="icon-btn" data-act="edit" title="编辑">${icon('pencil')}</button>
        <button class="icon-btn" data-act="delete" title="删除">${icon('trash')}</button>
      </div>
    </div>
    ${rows.length ? `<div class="card">${rows.join('')}</div>` : ''}
    ${entry.notes ? `<div class="card"><div class="row-label" style="padding:12px 16px 0">备注</div><div class="notes-block">${escapeHtml(entry.notes)}</div></div>` : ''}
    ${tags}
    <div class="meta-line">
      <span>创建于 ${formatDateTime(entry.createdAt)}</span>
      <span>更新于 ${relativeTime(entry.updatedAt)}</span>
      ${entry.totp ? `<span>2FA：${escapeHtml(entry.totp.algorithm)} · ${entry.totp.digits} 位 · ${entry.totp.period}s</span>` : ''}
    </div>
  `;
  updateTotpWidgets();
}

function rowHtml(iconName, label, valueHtml, act, raw) {
  return `<div class="row">
    <div class="row-icon">${icon(iconName)}</div>
    <div class="row-body">
      <div class="row-label">${label}</div>
      <div class="row-value">${valueHtml}</div>
    </div>
    <div class="row-actions">
      <button class="icon-btn" data-act="${act}" title="复制">${icon('copy')}</button>
    </div>
  </div>`;
}

/* ============================== TOTP 计时 ============================== */

let totpTimer = null;

function startTotpTicker() {
  stopTotpTicker();
  totpTimer = setInterval(updateTotpWidgets, 1000);
}

function stopTotpTicker() {
  if (totpTimer) clearInterval(totpTimer);
  totpTimer = null;
}

async function updateTotpWidgets() {
  if (state.totpBusy || !state.unlocked) return;
  const nodes = $$('[data-totp-id]');
  if (!nodes.length) return;
  state.totpBusy = true;
  try {
    for (const node of nodes) {
      const entry = state.vault.entries.find((e) => e.id === node.dataset.totpId);
      if (!entry?.totp) continue;
      const period = entry.totp.period || 30;
      const left = totpRemaining(period);
      const progress = totpProgress(period);
      try {
        const code = await totp({ ...entry.totp });
        const codeEl = node.querySelector('.totp-code');
        if (codeEl) {
          codeEl.textContent = formatCode(code);
          codeEl.classList.toggle('expiring', left <= 5);
        }
        node.dataset.code = code;
      } catch {
        const codeEl = node.querySelector('.totp-code');
        if (codeEl) codeEl.textContent = '密钥无效';
      }
      const leftEl = node.querySelector('.totp-left');
      if (leftEl) leftEl.textContent = String(left);
      const ring = node.querySelector('.ring');
      if (ring) {
        ring.style.setProperty('--p', String(progress));
        ring.classList.toggle('warn', left <= 5);
      }
    }
  } finally {
    state.totpBusy = false;
  }
}

function formatCode(code) {
  const s = String(code);
  if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
  if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
  return s;
}

/* ============================== 剪贴板 / 提示 ============================== */

function legacyCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;pointer-events:none';
  document.body.appendChild(ta);
  ta.select();
  ta.setSelectionRange(0, text.length);
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

async function copyText(text, label = '已复制') {
  if (!text) return;
  try {
    let done = false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        done = true;
      } catch {
        done = false;
      }
    }
    if (!done) done = legacyCopy(text);
    if (!done) throw new Error('copy failed');
    toast(label, 'ok');
    const seconds = settings().clipboardClearSeconds;
    if (seconds > 0) {
      setTimeout(async () => {
        try {
          if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText('');
          }
        } catch {
          /* 忽略 */
        }
      }, seconds * 1000);
    }
  } catch {
    toast('复制失败，请手动选择文本', 'err');
  }
}

function toast(message, type = 'ok', duration = 2600) {
  const root = $('#toast-root');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `${icon(type === 'err' ? 'alert' : type === 'warn' ? 'alert' : 'check')}<span>${escapeHtml(message)}</span>`;
  root.appendChild(el);
  setTimeout(() => {
    el.classList.add('out');
    setTimeout(() => el.remove(), 220);
  }, duration);
}

/* ============================== 弹窗 ============================== */

function openModal({ title, body, footer = '', wide = false, onMount, onClose }) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.innerHTML = `<div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true">
    <div class="modal-head"><h3>${escapeHtml(title)}</h3>
      <button class="icon-btn" data-close title="关闭">${icon('x')}</button>
    </div>
    <div class="modal-body">${body}</div>
    ${footer ? `<div class="modal-foot">${footer}</div>` : ''}
  </div>`;
  const close = () => {
    backdrop.remove();
    state.modalStack = state.modalStack.filter((m) => m !== close);
    onClose?.();
  };
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) close();
    if (e.target.closest('[data-close]')) close();
  });
  $('#modal-root').appendChild(backdrop);
  state.modalStack.push(close);
  onMount?.($('.modal', backdrop), close);
  return { root: backdrop, close };
}

function closeAllModals() {
  for (const close of [...state.modalStack].reverse()) close();
  state.modalStack = [];
}

function confirmDialog({ title, message, okText = '确定', danger = false }) {
  return new Promise((resolve) => {
    let settled = false;
    const { close } = openModal({
      title,
      body: `<p style="margin:0;font-size:14px;line-height:1.7;color:var(--muted)">${escapeHtml(message)}</p>`,
      footer: `<button class="btn ghost" data-cancel>取消</button>
               <button class="btn ${danger ? 'danger' : 'primary'}" data-ok>${escapeHtml(okText)}</button>`,
      onMount(root, closeFn) {
        root.querySelector('[data-ok]').onclick = () => {
          settled = true;
          closeFn();
          resolve(true);
        };
        root.querySelector('[data-cancel]').onclick = () => {
          settled = true;
          closeFn();
          resolve(false);
        };
      },
      onClose: () => {
        if (!settled) resolve(false);
      },
    });
    void close;
  });
}

function promptPassword({ title, message, okText = '确定' }) {
  return new Promise((resolve) => {
    let settled = false;
    openModal({
      title,
      body: `<p style="margin:0 0 14px;font-size:13.5px;line-height:1.7;color:var(--muted)">${escapeHtml(message || '')}</p>
        <label class="field"><span class="field-label">主密码</span>
        <input type="password" id="prompt-pw" autocomplete="current-password" placeholder="请输入主密码"></label>`,
      footer: `<button class="btn ghost" data-cancel>取消</button>
               <button class="btn primary" data-ok>${escapeHtml(okText)}</button>`,
      onMount(root, closeFn) {
        const input = root.querySelector('#prompt-pw');
        setTimeout(() => input.focus(), 80);
        const submit = () => {
          const value = input.value;
          if (!value) return;
          settled = true;
          closeFn();
          resolve(value);
        };
        root.querySelector('[data-ok]').onclick = submit;
        root.querySelector('[data-cancel]').onclick = () => {
          settled = true;
          closeFn();
          resolve(null);
        };
        input.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') submit();
        });
      },
      onClose: () => {
        if (!settled) resolve(null);
      },
    });
  });
}

/* ============================== 条目编辑 ============================== */

function openEditor(entry = null) {
  const isNew = !entry;
  const e = entry
    ? JSON.parse(JSON.stringify(entry))
    : normalizeEntry({ type: 'login', title: '' });
  const gen = settings().generator;

  const body = `
    <div class="segmented" id="f-type" style="margin-bottom:18px">
      <button data-type="login" class="${e.type !== 'note' ? 'active' : ''}">账号密码</button>
      <button data-type="note" class="${e.type === 'note' ? 'active' : ''}">安全笔记</button>
    </div>
    <label class="field"><span class="field-label">名称</span>
      <input id="f-title" type="text" value="${escapeHtml(e.title)}" placeholder="例如：GitHub、公司邮箱" maxlength="120">
    </label>
    <div id="login-fields" ${e.type === 'note' ? 'hidden' : ''}>
      <label class="field"><span class="field-label">用户名 / 邮箱</span>
        <input id="f-username" type="text" value="${escapeHtml(e.username)}" autocomplete="off" spellcheck="false">
      </label>
      <label class="field"><span class="field-label">密码</span>
        <div class="input-wrap">
          <input id="f-password" type="text" value="${escapeHtml(e.password)}" autocomplete="off" spellcheck="false" style="font-family:var(--mono)">
          <button type="button" class="icon-btn inside" id="f-gen" title="生成密码">${icon('shuffle')}</button>
        </div>
      </label>
      <label class="field"><span class="field-label">网址</span>
        <input id="f-url" type="text" value="${escapeHtml(e.url)}" placeholder="example.com" autocomplete="off" spellcheck="false">
      </label>
      <label class="field"><span class="field-label">2FA 密钥（可选）</span>
        <div class="input-wrap">
          <input id="f-totp" type="text" value="${escapeHtml(e.totp?.secret || '')}" placeholder="粘贴 otpauth:// 链接或 Base32 密钥" autocomplete="off" spellcheck="false" style="font-family:var(--mono);padding-right:52px">
          <button type="button" class="icon-btn inside" id="f-scan" title="扫描 2FA 二维码">${icon('camera')}</button>
        </div>
      </label>
      <p class="hint" id="f-totp-hint">支持 otpauth:// 链接、Base32 密钥，或从 Google Authenticator / Aegis 导入</p>
      <div id="f-totp-extra" ${e.totp ? '' : 'hidden'}>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <label class="field"><span class="field-label">发行方</span>
            <input id="f-issuer" type="text" value="${escapeHtml(e.totp?.issuer || '')}" placeholder="GitHub">
          </label>
          <label class="field"><span class="field-label">账号</span>
            <input id="f-account" type="text" value="${escapeHtml(e.totp?.account || '')}" placeholder="me@example.com">
          </label>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
          <label class="field"><span class="field-label">算法</span>
            <select id="f-algo">
              ${['SHA1', 'SHA256', 'SHA512']
                .map((a) => `<option value="${a}" ${e.totp?.algorithm === a ? 'selected' : ''}>${a}</option>`)
                .join('')}
            </select>
          </label>
          <label class="field"><span class="field-label">位数</span>
            <select id="f-digits">
              <option value="6" ${e.totp?.digits !== 8 ? 'selected' : ''}>6 位</option>
              <option value="8" ${e.totp?.digits === 8 ? 'selected' : ''}>8 位</option>
            </select>
          </label>
          <label class="field"><span class="field-label">周期（秒）</span>
            <input id="f-period" type="number" min="10" max="120" value="${e.totp?.period || 30}">
          </label>
        </div>
      </div>
    </div>
    <label class="field"><span class="field-label">备注</span>
      <textarea id="f-notes" placeholder="安全问题答案、恢复码等">${escapeHtml(e.notes)}</textarea>
    </label>
    <label class="field"><span class="field-label">标签</span>
      <input id="f-tags" type="text" value="${escapeHtml((e.tags || []).join(', '))}" placeholder="用逗号分隔，例如：工作, 邮箱">
    </label>
    <label class="check ${e.favorite ? 'on' : ''}" id="f-fav-wrap" style="margin-bottom:4px">
      <input type="checkbox" id="f-fav" ${e.favorite ? 'checked' : ''}> 加入收藏
    </label>
  `;

  const footer = `<button class="btn ghost" data-cancel>取消</button>
    <button class="btn primary" data-save>${isNew ? '添加' : '保存'}</button>`;

  openModal({
    title: isNew ? '新建条目' : '编辑条目',
    body,
    footer,
    wide: true,
    onMount(root, close) {
      let type = e.type;
      let totpData = e.totp ? { ...e.totp } : null;

      const typeBtns = $$('#f-type button', root);
      typeBtns.forEach((btn) => {
        btn.onclick = () => {
          type = btn.dataset.type;
          typeBtns.forEach((b) => b.classList.toggle('active', b === btn));
          root.querySelector('#login-fields').hidden = type === 'note';
        };
      });

      const favWrap = root.querySelector('#f-fav-wrap');
      root.querySelector('#f-fav').onchange = (ev) => {
        favWrap.classList.toggle('on', ev.target.checked);
      };

      const totpInput = root.querySelector('#f-totp');
      const extra = root.querySelector('#f-totp-extra');
      const hint = root.querySelector('#f-totp-hint');

      const parseTotpInput = () => {
        const raw = totpInput.value.trim();
        if (!raw) {
          totpData = null;
          extra.hidden = true;
          hint.textContent = '支持 otpauth:// 链接、Base32 密钥，或从 Google Authenticator / Aegis 导入';
          hint.classList.remove('warn');
          return;
        }
        try {
          if (/^otpauth:\/\//i.test(raw)) {
            const parsed = parseOtpauthUri(raw);
            totpData = normalizeTotp(parsed);
            totpInput.value = parsed.secret;
            root.querySelector('#f-issuer').value = parsed.issuer || '';
            root.querySelector('#f-account').value = parsed.account || '';
            root.querySelector('#f-algo').value = parsed.algorithm;
            root.querySelector('#f-digits').value = String(parsed.digits);
            root.querySelector('#f-period').value = String(parsed.period);
            hint.textContent = `已识别：${parsed.issuer || '未命名'} · ${parsed.algorithm} · ${parsed.digits} 位`;
          } else {
            totpData = normalizeTotp({
              secret: raw,
              issuer: root.querySelector('#f-issuer').value,
              account: root.querySelector('#f-account').value,
              algorithm: root.querySelector('#f-algo').value,
              digits: Number(root.querySelector('#f-digits').value),
              period: Number(root.querySelector('#f-period').value),
            });
            hint.textContent = '已识别为 Base32 密钥';
          }
          hint.classList.remove('warn');
          extra.hidden = false;
        } catch (err) {
          totpData = null;
          hint.textContent = `无法识别：${err.message}`;
          hint.classList.add('warn');
        }
      };

      totpInput.addEventListener('change', parseTotpInput);
      totpInput.addEventListener('blur', parseTotpInput);

      root.querySelector('#f-scan').onclick = () => {
        openQrScanner({
          title: '扫描 2FA 二维码',
          onScan: (text) => {
            if (/^otpauth-migration:\/\//i.test(text)) {
              try {
                const list = parseAnyTotp(text);
                totpInput.value = buildOtpauthUri(list[0]);
                parseTotpInput();
                toast(`迁移包包含 ${list.length} 个账号，已填入第一个；批量导入请到「设置 → 导入」`, 'warn', 4000);
              } catch (err) {
                toast(`二维码内容无法识别：${err.message}`, 'err');
              }
              return;
            }
            totpInput.value = text;
            parseTotpInput();
          },
        });
      };
      ['#f-issuer', '#f-account', '#f-algo', '#f-digits', '#f-period'].forEach((sel) => {
        root.querySelector(sel).addEventListener('change', () => {
          if (!totpData) return;
          totpData = normalizeTotp({
            ...totpData,
            issuer: root.querySelector('#f-issuer').value,
            account: root.querySelector('#f-account').value,
            algorithm: root.querySelector('#f-algo').value,
            digits: Number(root.querySelector('#f-digits').value),
            period: Number(root.querySelector('#f-period').value),
          });
        });
      });

      root.querySelector('#f-gen').onclick = () => {
        openGenerator({
          initial: settings().generator,
          onUse: (value) => {
            root.querySelector('#f-password').value = value;
          },
        });
      };

      root.querySelector('[data-cancel]').onclick = close;
      root.querySelector('[data-save]').onclick = () => {
        const title = root.querySelector('#f-title').value.trim();
        const username = root.querySelector('#f-username')?.value ?? '';
        const password = root.querySelector('#f-password')?.value ?? '';
        const url = root.querySelector('#f-url')?.value ?? '';
        const notes = root.querySelector('#f-notes').value;
        const tags = root
          .querySelector('#f-tags')
          .value.split(/[,，]/)
          .map((t) => t.trim())
          .filter(Boolean);
        const favorite = root.querySelector('#f-fav').checked;

        if (type === 'login' && !title && !username && !password && !url) {
          toast('请至少填写名称或账号信息', 'warn');
          return;
        }
        if (totpInput.value.trim() && !totpData) parseTotpInput();
        if (totpInput.value.trim() && !totpData) {
          toast('2FA 密钥无法识别，请检查格式', 'err');
          return;
        }

        const payload = {
          ...e,
          type,
          title: title || username || url || '未命名条目',
          username: type === 'note' ? '' : username,
          password: type === 'note' ? '' : password,
          url: type === 'note' ? '' : url,
          notes,
          tags,
          favorite,
          totp: type === 'note' ? null : totpData,
          updatedAt: nowISO(),
        };

        if (isNew) {
          state.vault.entries.push(normalizeEntry(payload));
        } else {
          const idx = state.vault.entries.findIndex((x) => x.id === e.id);
          if (idx >= 0) state.vault.entries[idx] = normalizeEntry(payload);
        }
        state.selectedId = payload.id;
        scheduleSave();
        render();
        close();
        toast(isNew ? '条目已添加' : '修改已保存', 'ok');
      };
    },
  });
}

/* ============================== 密码生成器 ============================== */

function openGenerator({ initial, onUse } = {}) {
  const opts = { ...settings().generator, ...(initial || {}) };
  let current = '';

  const body = `
    <div class="gen-output">
      <div class="gen-value placeholder" id="gen-value">点击下方按钮生成</div>
      <button class="icon-btn" id="gen-refresh" title="重新生成">${icon('refresh')}</button>
      <button class="icon-btn" id="gen-copy" title="复制">${icon('copy')}</button>
    </div>
    <div class="gen-meter">
      <div class="bar"><i id="gen-bar"></i></div>
      <span id="gen-strength">—</span>
    </div>
    <div class="segmented" id="gen-mode" style="margin-bottom:18px">
      <button data-mode="password" class="${opts.mode !== 'passphrase' ? 'active' : ''}">随机密码</button>
      <button data-mode="passphrase" class="${opts.mode === 'passphrase' ? 'active' : ''}">易记短语</button>
    </div>
    <div id="gen-password-opts">
      <div class="range-row">
        <label>长度</label>
        <input type="range" id="gen-length" min="6" max="64" value="${opts.length}">
        <span class="val" id="gen-length-val">${opts.length}</span>
      </div>
      <div class="check-grid">
        <label class="check ${opts.upper ? 'on' : ''}"><input type="checkbox" id="gen-upper" ${opts.upper ? 'checked' : ''}> 大写字母 A-Z</label>
        <label class="check ${opts.lower ? 'on' : ''}"><input type="checkbox" id="gen-lower" ${opts.lower ? 'checked' : ''}> 小写字母 a-z</label>
        <label class="check ${opts.digits ? 'on' : ''}"><input type="checkbox" id="gen-digits" ${opts.digits ? 'checked' : ''}> 数字 0-9</label>
        <label class="check ${opts.symbols ? 'on' : ''}"><input type="checkbox" id="gen-symbols" ${opts.symbols ? 'checked' : ''}> 符号 !@#$</label>
        <label class="check ${opts.excludeAmbiguous ? 'on' : ''}"><input type="checkbox" id="gen-ambiguous" ${opts.excludeAmbiguous ? 'checked' : ''}> 排除易混淆字符</label>
        <label class="check"><input type="checkbox" id="gen-require" checked> 每类至少一个</label>
      </div>
      <label class="field"><span class="field-label">自定义字符（可选）</span>
        <input id="gen-custom" type="text" value="${escapeHtml(opts.customChars || '')}" placeholder="例如：中文、特殊符号">
      </label>
    </div>
    <div id="gen-passphrase-opts" hidden>
      <div class="range-row">
        <label>单词数</label>
        <input type="range" id="gen-words" min="3" max="8" value="${opts.words}">
        <span class="val" id="gen-words-val">${opts.words}</span>
      </div>
      <label class="field"><span class="field-label">分隔符</span>
        <input id="gen-sep" type="text" value="${escapeHtml(opts.separator)}" maxlength="3">
      </label>
      <div class="check-grid">
        <label class="check ${opts.capitalize ? 'on' : ''}"><input type="checkbox" id="gen-cap" ${opts.capitalize ? 'checked' : ''}> 首字母大写</label>
        <label class="check ${opts.addNumber ? 'on' : ''}"><input type="checkbox" id="gen-num" ${opts.addNumber ? 'checked' : ''}> 末尾加数字</label>
      </div>
    </div>
  `;

  const footer = `<button class="btn ghost" data-cancel>关闭</button>
    <button class="btn primary" data-use>使用此密码</button>`;

  openModal({
    title: '密码生成器',
    body,
    footer,
    onMount(root, close) {
      const valueEl = root.querySelector('#gen-value');
      const barEl = root.querySelector('#gen-bar');
      const strengthEl = root.querySelector('#gen-strength');
      let mode = opts.mode === 'passphrase' ? 'passphrase' : 'password';

      const readOpts = () => ({
        mode,
        length: Number(root.querySelector('#gen-length').value),
        upper: root.querySelector('#gen-upper').checked,
        lower: root.querySelector('#gen-lower').checked,
        digits: root.querySelector('#gen-digits').checked,
        symbols: root.querySelector('#gen-symbols').checked,
        excludeAmbiguous: root.querySelector('#gen-ambiguous').checked,
        requireEach: root.querySelector('#gen-require').checked,
        customChars: root.querySelector('#gen-custom').value,
        words: Number(root.querySelector('#gen-words').value),
        separator: root.querySelector('#gen-sep').value,
        capitalize: root.querySelector('#gen-cap').checked,
        addNumber: root.querySelector('#gen-num').checked,
      });

      const generate = () => {
        const o = readOpts();
        try {
          current = o.mode === 'passphrase' ? generatePassphrase(o) : generatePassword(o);
          valueEl.textContent = current;
          valueEl.classList.remove('placeholder');
          const bits = estimateEntropy(o);
          const s = strengthOf(bits);
          barEl.style.width = `${Math.min(100, (bits / 128) * 100)}%`;
          barEl.style.background = s.color;
          strengthEl.textContent = `${s.label} · ${bits} 位熵`;
          strengthEl.style.color = s.color;
        } catch (err) {
          current = '';
          valueEl.textContent = err.message;
          valueEl.classList.add('placeholder');
          barEl.style.width = '0%';
          strengthEl.textContent = '—';
        }
      };

      const syncMode = () => {
        root.querySelector('#gen-password-opts').hidden = mode !== 'password';
        root.querySelector('#gen-passphrase-opts').hidden = mode !== 'passphrase';
        $$('#gen-mode button', root).forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
      };

      $$('#gen-mode button', root).forEach((btn) => {
        btn.onclick = () => {
          mode = btn.dataset.mode;
          syncMode();
          generate();
        };
      });

      root.querySelector('#gen-length').oninput = (ev) => {
        root.querySelector('#gen-length-val').textContent = ev.target.value;
        generate();
      };
      root.querySelector('#gen-words').oninput = (ev) => {
        root.querySelector('#gen-words-val').textContent = ev.target.value;
        generate();
      };
      $$('.check input', root).forEach((cb) => {
        cb.onchange = () => {
          cb.closest('.check').classList.toggle('on', cb.checked);
          generate();
        };
      });
      ['#gen-custom', '#gen-sep'].forEach((sel) => {
        root.querySelector(sel).oninput = generate;
      });
      root.querySelector('#gen-refresh').onclick = generate;
      root.querySelector('#gen-copy').onclick = () => copyText(current, '密码已复制');
      root.querySelector('[data-cancel]').onclick = close;
      root.querySelector('[data-use]').onclick = () => {
        if (!current) return;
        if (onUse) {
          onUse(current);
          close();
          toast('已填入密码', 'ok');
        } else {
          copyText(current, '密码已复制');
        }
      };

      syncMode();
      generate();
    },
  });
}

/* ============================== 设置 ============================== */

function openSettings(tab = 'general') {
  const s = settings();
  const body = `
    <div class="section-title">安全</div>
    <div class="setting-row">
      <div class="text"><b>自动锁定</b><span>无操作一段时间后自动锁定保险库</span></div>
      <select id="set-autolock">
        ${[
          [1, '1 分钟'],
          [5, '5 分钟'],
          [15, '15 分钟'],
          [30, '30 分钟'],
          [60, '1 小时'],
          [0, '永不'],
        ]
          .map(([v, l]) => `<option value="${v}" ${s.autoLockMinutes === v ? 'selected' : ''}>${l}</option>`)
          .join('')}
      </select>
    </div>
    <div class="setting-row">
      <div class="text"><b>剪贴板自动清除</b><span>复制密码后自动清空剪贴板</span></div>
      <select id="set-clipboard">
        ${[
          [0, '不清除'],
          [15, '15 秒'],
          [30, '30 秒'],
          [60, '60 秒'],
        ]
          .map(([v, l]) => `<option value="${v}" ${s.clipboardClearSeconds === v ? 'selected' : ''}>${l}</option>`)
          .join('')}
      </select>
    </div>
    <div class="setting-row">
      <div class="text"><b>修改主密码</b><span>重新加密整个保险库</span></div>
      <button class="btn sm ghost" id="set-changepw">修改</button>
    </div>

    <div class="section-title">局域网同步</div>
    <div class="sync-status" id="sync-status">
      <span class="dot"></span>
      <span id="sync-status-text">${
        state.sync.url
          ? `已配置：${escapeHtml(state.sync.url)}${state.sync.lastSyncAt ? ` · 上次同步 ${relativeTime(state.sync.lastSyncAt)}` : ''}`
          : '尚未配置同步服务器'
      }</span>
    </div>
    <label class="field"><span class="field-label">服务器地址</span>
      <input id="set-sync-url" type="text" value="${escapeHtml(state.sync.url)}" placeholder="https://192.168.1.10:8443" spellcheck="false">
    </label>
    <label class="field"><span class="field-label">同步口令</span>
      <input id="set-sync-token" type="text" value="${escapeHtml(state.sync.token)}" placeholder="XXXX-XXXX-XXXX-XXXX" spellcheck="false" style="font-family:var(--mono)">
    </label>
    <p class="hint">在电脑上运行 <code>scripts/start-windows.bat</code>（或 <code>node server/server.js</code>），
      控制台会显示局域网地址与同步口令。手机请用 <b>https://IP:8443</b> 访问（证书警告点「继续前往」），
      并与电脑连接同一个 Wi-Fi。</p>
    <div style="display:flex;gap:10px;margin-top:12px">
      <button class="btn sm ghost" id="set-sync-test">测试连接</button>
      <button class="btn sm primary" id="set-sync-now">立即同步</button>
    </div>

    <div class="section-title">数据与备份</div>
    <div class="setting-row">
      <div class="text"><b>自动加密备份</b><span>本机保留最近 8 份加密快照，误删或覆盖后可回滚 · 当前 ${snapshotCount()} 份</span></div>
      <button class="btn sm ghost" id="set-backups">管理</button>
    </div>
    <div class="setting-row">
      <div class="text"><b>导出加密备份</b><span>导出 .json 保险库文件（需主密码才能打开）</span></div>
      <button class="btn sm ghost" id="set-export-vault">导出</button>
    </div>
    <div class="setting-row">
      <div class="text"><b>导入加密备份</b><span>从 .json 恢复，可合并或覆盖当前保险库</span></div>
      <button class="btn sm ghost" id="set-import-vault">导入</button>
    </div>
    <div class="setting-row">
      <div class="text"><b>导入明文数据</b><span>CSV / JSON / 2FA 密钥</span></div>
      <button class="btn sm ghost" id="set-import">导入</button>
    </div>
    <div class="setting-row">
      <div class="text"><b>导出明文</b><span>CSV / JSON，便于迁移到其他软件（注意安全）</span></div>
      <button class="btn sm ghost" id="set-export-plain">导出</button>
    </div>
    <div class="setting-row">
      <div class="text"><b>清空所有数据</b><span>删除本机保险库与自动备份，操作不可恢复</span></div>
      <button class="btn sm danger" id="set-wipe">清空</button>
    </div>

    <div class="section-title">外观</div>
    <div class="setting-row">
      <div class="text"><b>主题</b><span>深色 / 浅色</span></div>
      <button class="btn sm ghost" id="set-theme">${state.ui.theme === 'dark' ? '切换到浅色' : '切换到深色'}</button>
    </div>

    <div class="section-title">关于</div>
    <p class="hint" style="margin:0">
      密码保险库 v1.1 · 本地加密，零依赖。<br>
      加密：PBKDF2-SHA256（${KDF_ITERATIONS.toLocaleString()} 次）+ AES-256-GCM；2FA：RFC 6238 TOTP。<br>
      参考开源项目：KeePassXC、KeePassDX、Bitwarden、Aegis Authenticator；二维码解码使用 jsQR（Apache-2.0）。
    </p>
  `;

  openModal({
    title: '设置',
    body,
    wide: true,
    footer: `<button class="btn primary" data-close>完成</button>`,
    onMount(root, close) {
      root.querySelector('#set-autolock').onchange = (ev) => {
        updateSettings({ autoLockMinutes: Number(ev.target.value) });
        resetIdle();
      };
      root.querySelector('#set-clipboard').onchange = (ev) => {
        updateSettings({ clipboardClearSeconds: Number(ev.target.value) });
      };
      root.querySelector('#set-changepw').onclick = () => {
        close();
        openChangePassword();
      };
      root.querySelector('#set-theme').onclick = () => {
        toggleTheme();
        close();
        openSettings();
      };
      root.querySelector('#set-sync-url').onchange = (ev) => {
        state.sync.url = ev.target.value.trim();
        savePrefs();
      };
      root.querySelector('#set-sync-token').onchange = (ev) => {
        state.sync.token = ev.target.value.trim();
        savePrefs();
      };
      root.querySelector('#set-sync-test').onclick = async (ev) => {
        const btn = ev.currentTarget;
        state.sync.url = root.querySelector('#set-sync-url').value.trim();
        state.sync.token = root.querySelector('#set-sync-token').value.trim();
        savePrefs();
        btn.disabled = true;
        btn.textContent = '连接中…';
        try {
          const info = await new SyncClient({ baseUrl: state.sync.url, token: state.sync.token }).info();
          setSyncStatus(root, 'ok', `连接成功 · 服务器 ${info.name} · 版本 ${info.revision}${info.hasVault ? '' : '（空）'}`);
        } catch (err) {
          setSyncStatus(root, 'err', err.message);
        } finally {
          btn.disabled = false;
          btn.textContent = '测试连接';
        }
      };
      root.querySelector('#set-sync-now').onclick = () => {
        state.sync.url = root.querySelector('#set-sync-url').value.trim();
        state.sync.token = root.querySelector('#set-sync-token').value.trim();
        savePrefs();
        close();
        runSync();
      };
      root.querySelector('#set-import').onclick = () => {
        close();
        openImport();
      };
      root.querySelector('#set-backups').onclick = () => {
        close();
        openBackupManager();
      };
      root.querySelector('#set-import-vault').onclick = () => {
        close();
        importEncryptedBackup();
      };
      root.querySelector('#set-export-vault').onclick = () => {
        downloadFile(
          `密码保险库-备份-${dateStamp()}.json`,
          JSON.stringify(state.envelope, null, 2),
          'application/json',
        );
        toast('加密备份已导出', 'ok');
      };
      root.querySelector('#set-export-plain').onclick = () => {
        close();
        openExportPlain();
      };
      root.querySelector('#set-wipe').onclick = async () => {
        const ok = await confirmDialog({
          title: '清空所有数据',
          message: '将删除本机保存的保险库，且无法恢复。建议先导出加密备份。确定继续吗？',
          okText: '确认清空',
          danger: true,
        });
        if (!ok) return;
        localStorage.removeItem(LS.vault);
        clearSnapshots();
        close();
        lockVault(true);
        state.envelope = null;
        showLock('create');
        toast('本机数据已清空', 'ok');
      };
    },
  });
}

function setSyncStatus(root, type, text) {
  const el = root.querySelector('#sync-status');
  if (!el) return;
  el.className = `sync-status ${type}`;
  root.querySelector('#sync-status-text').textContent = text;
}

function openChangePassword() {
  openModal({
    title: '修改主密码',
    body: `<p class="hint" style="margin:0 0 14px">修改后需要用新密码重新加密整个保险库，其他设备同步时需要输入新密码。</p>
      <label class="field"><span class="field-label">当前主密码</span>
        <input type="password" id="cp-old" autocomplete="current-password"></label>
      <label class="field"><span class="field-label">新主密码</span>
        <input type="password" id="cp-new" autocomplete="new-password"></label>
      <label class="field"><span class="field-label">确认新主密码</span>
        <input type="password" id="cp-new2" autocomplete="new-password"></label>
      <p class="lock-error" id="cp-error" hidden></p>`,
    footer: `<button class="btn ghost" data-cancel>取消</button>
             <button class="btn primary" data-ok>确认修改</button>`,
    onMount(root, close) {
      const err = root.querySelector('#cp-error');
      root.querySelector('[data-cancel]').onclick = close;
      root.querySelector('[data-ok]').onclick = async () => {
        const oldPw = root.querySelector('#cp-old').value;
        const newPw = root.querySelector('#cp-new').value;
        const newPw2 = root.querySelector('#cp-new2').value;
        err.hidden = true;
        if (newPw.length < 8) {
          err.textContent = '新主密码至少需要 8 位字符';
          err.hidden = false;
          return;
        }
        if (newPw !== newPw2) {
          err.textContent = '两次输入的新密码不一致';
          err.hidden = false;
          return;
        }
        try {
          const result = await changeMasterPassword(state.envelope, oldPw, newPw);
          state.key = result.key;
          state.salt = result.salt;
          state.iterations = result.iterations;
          state.masterPassword = newPw;
          state.vault = result.vault;
          state.header = result.header;
          state.envelope = result.envelope;
          localStorage.setItem(LS.vault, JSON.stringify(result.envelope));
          close();
          toast('主密码已修改', 'ok');
        } catch (e) {
          err.textContent = e.code === 'BAD_PASSWORD' ? '当前主密码不正确' : e.message;
          err.hidden = false;
        }
      };
    },
  });
}

/* ============================== 导入 / 导出 ============================== */

function openImport() {
  const body = `
    <div class="segmented" id="imp-tab" style="margin-bottom:16px">
      <button data-tab="file" class="active">从文件导入</button>
      <button data-tab="text">粘贴文本 / 2FA</button>
    </div>
    <div id="imp-file">
      <label class="file-drop" id="imp-drop">
        <input type="file" id="imp-input" accept=".csv,.json,.txt" hidden>
        ${icon('upload')}
        <b>选择文件</b>
        <span id="imp-filename">支持 CSV / JSON / TXT，点击选择</span>
      </label>
      <p class="hint">支持：本应用导出的 JSON、Bitwarden / Chrome / KeePass 的 CSV、Aegis / andOTP 的 JSON、2FA 密钥文本。</p>
    </div>
    <div id="imp-text" hidden>
      <label class="field"><span class="field-label">粘贴内容</span>
        <textarea id="imp-textarea" placeholder="otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&#10;或每行一条：发行方,账号,密钥"></textarea>
      </label>
      <div style="display:flex;gap:10px;margin-bottom:10px">
        <button type="button" class="btn sm ghost" id="imp-scan">${icon('camera')} 扫描二维码</button>
      </div>
      <p class="hint">支持 otpauth:// 链接、Google Authenticator 迁移链接（otpauth-migration://）、Base32 密钥列表。</p>
    </div>
    <div id="imp-preview" class="hint" style="margin-top:8px"></div>
  `;
  openModal({
    title: '导入数据',
    body,
    wide: true,
    footer: `<button class="btn ghost" data-cancel>取消</button>
             <button class="btn primary" data-ok disabled>开始导入</button>`,
    onMount(root, close) {
      let parsed = null;
      let tab = 'file';
      const okBtn = root.querySelector('[data-ok]');
      const preview = root.querySelector('#imp-preview');

      $$('#imp-tab button', root).forEach((btn) => {
        btn.onclick = () => {
          tab = btn.dataset.tab;
          $$('#imp-tab button', root).forEach((b) => b.classList.toggle('active', b === btn));
          root.querySelector('#imp-file').hidden = tab !== 'file';
          root.querySelector('#imp-text').hidden = tab !== 'text';
        };
      });

      const showPreview = (entries, source) => {
        parsed = entries;
        okBtn.disabled = !entries.length;
        preview.innerHTML = entries.length
          ? `已识别 <b>${entries.length}</b> 条（${escapeHtml(source)}），其中含 2FA 的 <b>${entries.filter((e) => e.totp).length}</b> 条。`
          : '没有识别到可导入的数据';
      };

      const parseText = (text, name = '') => {
        const trimmed = String(text || '').trim();
        if (!trimmed) return;
        try {
          if (/^otpauth-migration:\/\//i.test(trimmed) || /^otpauth:\/\//i.test(trimmed)) {
            const list = parseAnyTotp(trimmed);
            showPreview(
              list.map((t) =>
                normalizeEntry({
                  title: t.issuer || t.account || '2FA 条目',
                  username: t.account,
                  totp: t,
                }),
              ),
              '2FA 密钥',
            );
            return;
          }
          if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
            const data = JSON.parse(trimmed);
            if (data.application === 'dsh-passvault' || (Array.isArray(data.entries) && data.entries[0]?.id)) {
              showPreview((data.entries || []).map(normalizeEntry), '本应用 JSON');
            } else if (data.entries?.[0]?.info || (Array.isArray(data) && data[0]?.secret)) {
              const list = parseAnyTotp(trimmed);
              showPreview(
                list.map((t) => normalizeEntry({ title: t.issuer || t.account || '2FA', username: t.account, totp: t })),
                'andOTP / 2FA JSON',
              );
            } else {
              showPreview(parseJsonImport(trimmed), 'JSON');
            }
            return;
          }
          const firstLine = trimmed.split(/\r?\n/)[0] || '';
          if (/\.csv$/i.test(name) || looksLikeCsvHeader(firstLine)) {
            showPreview(parseCsvImport(trimmed), 'CSV');
            return;
          }
          const list = parseAnyTotp(trimmed);
          showPreview(
            list.map((t) => normalizeEntry({ title: t.issuer || t.account || '2FA', username: t.account, totp: t })),
            '2FA 密钥',
          );
        } catch (err) {
          parsed = null;
          okBtn.disabled = true;
          preview.innerHTML = `<span style="color:var(--danger)">${escapeHtml(err.message)}</span>`;
        }
      };

      root.querySelector('#imp-input').onchange = (ev) => {
        const file = ev.target.files?.[0];
        if (!file) return;
        root.querySelector('#imp-filename').textContent = file.name;
        const reader = new FileReader();
        reader.onload = () => parseText(String(reader.result), file.name);
        reader.readAsText(file, 'utf-8');
      };
      const textarea = root.querySelector('#imp-textarea');
      textarea.oninput = (ev) => parseText(ev.target.value);
      root.querySelector('#imp-scan').onclick = () => {
        openQrScanner({
          title: '扫描 2FA 二维码',
          onScan: (text) => {
            textarea.value = text;
            parseText(text, '');
          },
        });
      };

      root.querySelector('[data-cancel]').onclick = close;
      okBtn.onclick = () => {
        if (!parsed?.length) return;
        const existing = new Set(
          state.vault.entries.filter((e) => !e.deletedAt).map((e) => `${e.title}|${e.username}`),
        );
        let added = 0;
        let skipped = 0;
        for (const item of parsed) {
          const key = `${item.title}|${item.username}`;
          if (existing.has(key)) {
            skipped++;
            continue;
          }
          state.vault.entries.push(normalizeEntry({ ...item, id: uuid() }));
          existing.add(key);
          added++;
        }
        scheduleSave();
        render();
        close();
        toast(`已导入 ${added} 条${skipped ? `，跳过重复 ${skipped} 条` : ''}`, 'ok');
      };
    },
  });
}

/* ============================== 备份与恢复 ============================== */

function openBackupManager() {
  const renderList = () => {
    const snaps = listSnapshots();
    if (!snaps.length) {
      return `<div class="empty-list" style="padding:26px 10px">还没有快照<br>修改数据或点「立即创建快照」后会生成</div>`;
    }
    return snaps
      .map(
        (s) => `<div class="setting-row">
          <div class="text"><b>${escapeHtml(s.label)}</b>
            <span>保险库版本 ${s.revision} · ${formatBytes(s.size)}</span></div>
          <div style="display:flex;gap:6px">
            <button class="btn sm ghost" data-restore="${s.id}">恢复</button>
            <button class="btn sm ghost" data-del="${s.id}">删除</button>
          </div>
        </div>`,
      )
      .join('');
  };

  openModal({
    title: '自动加密备份',
    body: `<p class="hint" style="margin:0 0 12px">
        每次修改后自动保存一份密文快照，本机保留最近 8 份（上限 2 MB）。
        快照同样使用主密码加密，可直接回滚误删或误改。</p>
      <div id="bk-list">${renderList()}</div>`,
    wide: true,
    footer: `<button class="btn ghost" data-snap>立即创建快照</button>
      <div class="spacer"></div>
      <button class="btn primary" data-close>完成</button>`,
    onMount(root, close) {
      const listEl = root.querySelector('#bk-list');
      const refresh = () => {
        listEl.innerHTML = renderList();
      };
      root.querySelector('[data-snap]').onclick = () => {
        if (!state.envelope) return;
        recordSnapshot(state.envelope, { force: true });
        refresh();
        toast('已创建加密快照', 'ok');
      };
      listEl.addEventListener('click', async (ev) => {
        const delBtn = ev.target.closest('[data-del]');
        if (delBtn) {
          removeSnapshot(delBtn.dataset.del);
          refresh();
          toast('快照已删除', 'ok');
          return;
        }
        const restoreBtn = ev.target.closest('[data-restore]');
        if (!restoreBtn) return;
        const snap = listSnapshots().find((x) => x.id === restoreBtn.dataset.restore);
        if (!snap) return;
        const done = await restoreFromEnvelope(snap.envelope, snap.label);
        if (done) close();
      });
    },
  });
}

/** 用备份信封恢复：自动尝试当前密钥，失败再让用户输入主密码 */
async function restoreFromEnvelope(env, label) {
  let vault = null;
  let opened = null;
  let password = null;

  try {
    vault = await decryptWithKey(env, state.key);
  } catch {
    const pw = await promptPassword({
      title: '输入主密码',
      message: `「${label}」使用了不同的主密码，请输入该备份的主密码。`,
      okText: '解密',
    });
    if (!pw) return false;
    try {
      opened = await openVault(env, pw);
    } catch {
      toast('主密码错误，无法解密该备份', 'err');
      return false;
    }
    vault = opened.vault;
    password = pw;
  }

  const mode = await askRestoreMode(label, vault);
  if (!mode) return false;

  if (mode === 'replace') {
    state.vault = vault;
    if (opened) {
      state.key = opened.key;
      state.salt = opened.salt;
      state.iterations = opened.iterations;
      state.masterPassword = password;
    }
  } else {
    const { vault: merged } = mergeVaults(state.vault, vault);
    state.vault = merged;
  }

  scheduleSave();
  render();
  toast(mode === 'replace' ? '已恢复到该备份' : '已合并备份中的内容', 'ok');
  return true;
}

function askRestoreMode(label, vault) {
  const count = (vault.entries || []).filter((e) => !e.deletedAt).length;
  return new Promise((resolve) => {
    let settled = false;
    openModal({
      title: '选择恢复方式',
      body: `<p class="hint" style="margin:0 0 14px">
          「${escapeHtml(label)}」包含 ${count} 个条目，请选择如何处理当前保险库。</p>
        <div class="choice-list">
          <button class="choice" data-mode="merge"><span class="num">1</span><span><b>合并（推荐）</b><span>保留现有条目，并把备份中更新或新增的条目合入</span></span></button>
          <button class="choice" data-mode="replace"><span class="num">2</span><span><b>覆盖当前保险库</b><span>用这份备份完整替换现有内容</span></span></button>
        </div>`,
      onMount(root, close) {
        root.querySelectorAll('.choice').forEach((btn) => {
          btn.onclick = () => {
            settled = true;
            close();
            resolve(btn.dataset.mode);
          };
        });
      },
      onClose: () => {
        if (!settled) resolve(null);
      },
    });
  });
}

function importEncryptedBackup() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json,application/json';
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    try {
      const env = JSON.parse(await file.text());
      assertEnvelope(env);
      await restoreFromEnvelope(env, file.name);
    } catch (err) {
      toast(`导入失败：${err.message}`, 'err', 4000);
    }
  };
  input.click();
}

function openExportPlain() {
  openModal({
    title: '导出明文数据',
    body: `<p class="hint" style="margin:0 0 14px;color:var(--warning)">
        导出的文件包含明文密码，请仅在可信设备上操作，用完后及时删除。</p>
      <div class="choice-list">
        <button class="choice" data-kind="csv"><span class="num">1</span><span><b>CSV（Bitwarden 兼容）</b><span>可导入 Bitwarden、1Password、KeePass 等</span></span></button>
        <button class="choice" data-kind="json"><span class="num">2</span><span><b>JSON（本应用格式）</b><span>包含全部字段与 2FA 密钥</span></span></button>
        <button class="choice" data-kind="otp"><span class="num">3</span><span><b>2FA 链接列表</b><span>otpauth:// 文本，可导入其他验证器</span></span></button>
      </div>`,
    onMount(root, close) {
      $$('.choice', root).forEach((btn) => {
        btn.onclick = () => {
          const kind = btn.dataset.kind;
          const alive = state.vault.entries.filter((e) => !e.deletedAt);
          if (kind === 'csv') {
            downloadFile(`密码保险库-${dateStamp()}.csv`, '\uFEFF' + exportCsv(alive), 'text/csv');
          } else if (kind === 'json') {
            downloadFile(`密码保险库-${dateStamp()}.json`, exportJson(state.vault), 'application/json');
          } else {
            const lines = alive
              .filter((e) => e.totp)
              .map((e) => buildOtpauthUri({ ...e.totp, issuer: e.totp.issuer || e.title, account: e.totp.account || e.username }));
            if (!lines.length) {
              toast('没有包含 2FA 的条目', 'warn');
              return;
            }
            downloadFile(`2fa-${dateStamp()}.txt`, lines.join('\n'), 'text/plain');
          }
          close();
          toast('已导出', 'ok');
        };
      });
    },
  });
}

const CSV_HEADER_WORDS = [
  'name', 'title', 'username', 'password', 'url', 'login', 'login_uri', 'login_username',
  'login_password', 'login_totp', 'notes', 'folder', 'account', 'web site', 'comments',
  '账户', '账号', '密码', '名称', '标题', '网址', '备注', '用户名',
];

function looksLikeCsvHeader(line) {
  const cells = String(line || '')
    .split(',')
    .map((c) => c.replace(/^"|"$/g, '').trim().toLowerCase());
  if (cells.length < 2) return false;
  return cells.some((c) => CSV_HEADER_WORDS.includes(c));
}

function toBase64Utf8(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

/**
 * 保存文件：浏览器走下载；安卓 App 内写入缓存后调起系统分享，让用户存到「文件 / 网盘」
 */
async function downloadFile(filename, content, mime) {
  const cap = window.Capacitor;
  const fsPlugin = cap?.isNativePlatform?.() ? cap?.Plugins?.Filesystem : null;
  if (fsPlugin) {
    try {
      const written = await fsPlugin.writeFile({
        path: filename,
        data: toBase64Utf8(content),
        directory: 'CACHE',
        encoding: 'base64',
        recursive: true,
      });
      const share = cap?.Plugins?.Share;
      if (share) {
        await share.share({
          title: filename,
          dialogTitle: '保存或分享文件',
          files: [written.uri],
          url: written.uri,
        });
        toast('已生成文件，可在分享面板中保存', 'ok');
      } else {
        toast(`已保存到缓存目录：${filename}`, 'ok', 4000);
      }
      return;
    } catch (err) {
      // 继续尝试浏览器下载
      console.warn('原生保存失败，改用浏览器下载', err);
    }
  }

  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

function dateStamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

/* ============================== 同步 ============================== */

async function runSync() {
  if (!state.sync.url) {
    toast('请先在设置中填写同步服务器地址', 'warn');
    openSettings();
    return;
  }
  const btn = $('#sync-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  try {
    const client = new SyncClient({ baseUrl: state.sync.url, token: state.sync.token });
    const info = await client.info();
    if (!info.hasVault) {
      await pushVault(client, 0);
      toast('已上传保险库到服务器', 'ok');
      return;
    }
    const remote = await client.pull();
    const remoteRev = Number(remote.header.revision);

    if (remoteRev === state.header.revision) {
      if (state.dirty) {
        await pushVault(client, remoteRev);
        toast('已同步到服务器', 'ok');
      } else {
        toast('已是最新版本', 'ok');
      }
      return;
    }

    if (remoteRev > state.header.revision) {
      if (!state.dirty) {
        await adoptRemote(remote);
        toast('已从服务器更新', 'ok');
        return;
      }
      const choice = await askConflict(remote);
      if (!choice) return;
      if (choice === 'remote') {
        await adoptRemote(remote);
        toast('已使用服务器版本', 'ok');
      } else if (choice === 'local') {
        await pushVault(client, remoteRev);
        toast('已用本地版本覆盖服务器', 'ok');
      } else {
        const remoteVault = await decryptRemote(remote);
        const { vault, stats } = mergeVaults(state.vault, remoteVault);
        state.vault = vault;
        await pushVault(client, remoteRev);
        render();
        toast(`已合并：新增 ${stats.added}，更新 ${stats.updated}`, 'ok');
      }
      return;
    }

    // 服务器版本落后于本地基线
    await pushVault(client, remoteRev);
    toast('已同步到服务器', 'ok');
  } catch (err) {
    if (err instanceof SyncError) toast(err.message, 'err', 4000);
    else toast(err.message || '同步失败', 'err', 4000);
  } finally {
    btn.disabled = false;
    btn.innerHTML = icon('refresh');
  }
}

async function pushVault(client, baseRevision) {
  const header = {
    revision: baseRevision + 1,
    updatedAt: nowISO(),
    deviceId: state.deviceId,
  };
  const env = await sealVault(state.vault, state.key, {
    salt: state.salt,
    iterations: state.iterations,
    header,
  });
  await client.push(env, baseRevision);
  state.header = header;
  state.envelope = env;
  state.dirty = false;
  state.sync.lastSyncAt = nowISO();
  savePrefs();
  localStorage.setItem(LS.vault, JSON.stringify(env));
}

async function decryptRemote(remote) {
  try {
    return await decryptWithKey(remote, state.key);
  } catch {
    // 两台设备各自创建过保险库时盐值不同，用同一个主密码重新派生即可
    if (state.masterPassword) {
      try {
        const opened = await openVault(remote, state.masterPassword);
        state.key = opened.key;
        state.salt = opened.salt;
        state.iterations = opened.iterations;
        return opened.vault;
      } catch {
        /* 继续走手动输入 */
      }
    }
    const pw = await promptPassword({
      title: '需要主密码',
      message: '服务器上的保险库使用了不同的主密码，请输入该保险库的主密码以继续。',
      okText: '解密',
    });
    if (!pw) throw new Error('已取消');
    const opened = await openVault(remote, pw);
    state.key = opened.key;
    state.salt = opened.salt;
    state.iterations = opened.iterations;
    state.masterPassword = pw;
    return opened.vault;
  }
}

async function adoptRemote(remote) {
  const vault = await decryptRemote(remote);
  state.vault = vault;
  state.header = remote.header;
  state.envelope = remote;
  state.dirty = false;
  state.sync.lastSyncAt = nowISO();
  savePrefs();
  localStorage.setItem(LS.vault, JSON.stringify(remote));
  recordSnapshot(remote, { force: true });
  render();
}

function askConflict(remote) {
  return new Promise((resolve) => {
    let settled = false;
    openModal({
      title: '发现同步冲突',
      body: `<p class="hint" style="margin:0 0 14px">
          服务器上的版本（v${remote.header.revision}，${formatDateTime(remote.header.updatedAt)}）比本机记录的版本更新，
          而本机也有未同步的修改。</p>
        <div class="choice-list">
          <button class="choice" data-choice="merge"><span class="num">1</span><span><b>合并两边修改（推荐）</b><span>按条目更新时间合并，保留双方最新的内容</span></span></button>
          <button class="choice" data-choice="remote"><span class="num">2</span><span><b>使用服务器版本</b><span>放弃本机未同步的修改</span></span></button>
          <button class="choice" data-choice="local"><span class="num">3</span><span><b>用本机覆盖服务器</b><span>放弃服务器上的修改</span></span></button>
        </div>`,
      onMount(root, close) {
        $$('.choice', root).forEach((btn) => {
          btn.onclick = () => {
            settled = true;
            close();
            resolve(btn.dataset.choice);
          };
        });
      },
      onClose: () => {
        if (!settled) resolve(null);
      },
    });
  });
}

/* ============================== 空闲锁定 ============================== */

function resetIdle() {
  state.lastActivity = Date.now();
  clearTimeout(state.idleTimer);
  const minutes = settings().autoLockMinutes;
  if (!minutes || !state.unlocked) return;
  state.idleTimer = setTimeout(() => {
    if (Date.now() - state.lastActivity >= minutes * 60_000) lockVault();
    else resetIdle();
  }, minutes * 60_000 + 500);
}

/* ============================== 事件绑定 ============================== */

function bindEvents() {
  $('#lock-form').addEventListener('submit', handleLockSubmit);
  $('#toggle-pw').addEventListener('click', () => {
    const input = $('#master-password');
    const isPw = input.type === 'password';
    input.type = isPw ? 'text' : 'password';
    $('#toggle-pw').innerHTML = icon(isPw ? 'eye-off' : 'eye');
  });
  $('#theme-btn').addEventListener('click', toggleTheme);
  $('#restore-btn').addEventListener('click', restoreFromFile);

  $('#master-password').addEventListener('input', (ev) => {
    if (lockMode !== 'create') return;
    if (!ev.target.value) {
      $('#pw-strength').hidden = true;
      return;
    }
    const bits = estimatePasswordBits(ev.target.value);
    const s = strengthOf(bits);
    const wrap = $('#pw-strength');
    wrap.hidden = false;
    $('.strength-bar i', wrap).style.width = `${Math.min(100, (bits / 100) * 100)}%`;
    $('.strength-bar i', wrap).style.background = s.color;
    $('.strength-text', wrap).textContent = `强度：${s.label}（约 ${bits} 位熵）`;
  });

  $('#search').addEventListener('input', (ev) => {
    state.query = ev.target.value;
    renderList();
  });

  $('#filters').addEventListener('click', (ev) => {
    const chip = ev.target.closest('[data-filter]');
    if (!chip) return;
    state.filter = chip.dataset.filter;
    renderFilters();
    renderList();
  });

  $('#entry-list').addEventListener('click', (ev) => {
    const item = ev.target.closest('[data-id]');
    if (!item) return;
    state.selectedId = item.dataset.id;
    renderList();
    renderDetail();
    $('#main').classList.add('detail-open');
  });

  $('#add-btn').addEventListener('click', () => openEditor(null));
  $('#gen-btn').addEventListener('click', () => openGenerator());
  $('#settings-btn').addEventListener('click', () => openSettings());
  $('#lock-btn').addEventListener('click', () => lockVault());
  $('#sync-btn').addEventListener('click', runSync);
  $('#menu-btn').addEventListener('click', () => {
    $('#main').classList.remove('detail-open');
  });

  $('#detail').addEventListener('click', async (ev) => {
    const btn = ev.target.closest('[data-act]');
    if (!btn) return;
    const entry = state.vault.entries.find((e) => e.id === state.selectedId);
    if (!entry) return;
    const act = btn.dataset.act;
    if (act === 'back') {
      $('#main').classList.remove('detail-open');
    } else if (act === 'copy-username') {
      copyText(entry.username, '用户名已复制');
    } else if (act === 'copy-pw') {
      copyText(entry.password, '密码已复制');
    } else if (act === 'copy-url') {
      copyText(entry.url, '网址已复制');
    } else if (act === 'copy-totp') {
      const node = btn.closest('[data-totp-id]');
      const code = node?.dataset.code;
      if (code) copyText(code, '验证码已复制');
      else toast('验证码尚未生成', 'warn');
    } else if (act === 'toggle-pw') {
      if (state.revealed.has(entry.id)) state.revealed.delete(entry.id);
      else state.revealed.add(entry.id);
      renderDetail();
    } else if (act === 'edit') {
      openEditor(entry);
    } else if (act === 'fav') {
      entry.favorite = !entry.favorite;
      entry.updatedAt = nowISO();
      scheduleSave();
      render();
      toast(entry.favorite ? '已加入收藏' : '已取消收藏', 'ok');
    } else if (act === 'delete') {
      const ok = await confirmDialog({
        title: '删除条目',
        message: `确定删除「${entry.title}」吗？此操作会同步到其他设备。`,
        okText: '删除',
        danger: true,
      });
      if (!ok) return;
      deleteEntry(state.vault, entry.id);
      state.selectedId = null;
      scheduleSave();
      render();
      $('#main').classList.remove('detail-open');
      toast('条目已删除', 'ok');
    }
  });

  document.addEventListener('keydown', (ev) => {
    const mod = ev.ctrlKey || ev.metaKey;
    if (mod && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      if (state.unlocked) $('#search').focus();
    } else if (mod && ev.key.toLowerCase() === 'n' && state.unlocked) {
      ev.preventDefault();
      openEditor(null);
    } else if (mod && ev.key.toLowerCase() === 'l' && state.unlocked) {
      ev.preventDefault();
      lockVault();
    } else if (ev.key === 'Escape') {
      if (state.modalStack.length) {
        state.modalStack[state.modalStack.length - 1]();
      } else if (state.unlocked) {
        $('#main').classList.remove('detail-open');
      }
    }
  });

  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((type) => {
    window.addEventListener(type, () => {
      if (state.unlocked) {
        state.lastActivity = Date.now();
        resetIdle();
      }
    }, { passive: true });
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && state.unlocked) {
      const minutes = settings().autoLockMinutes;
      if (minutes && Date.now() - state.lastActivity > minutes * 60_000) lockVault();
    }
  });

  window.addEventListener('beforeunload', () => {
    if (state.dirty) persist().catch(() => {});
  });
}

function estimatePasswordBits(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  if (!pw) return 0;
  return Math.round(pw.length * Math.log2(Math.max(pool, 2)));
}

/* ============================== 备份恢复 ============================== */

function restoreFromFile() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const env = JSON.parse(text);
      assertEnvelope(env);
      state.envelope = env;
      state.header = env.header;
      localStorage.setItem(LS.vault, JSON.stringify(env));
      showLock('unlock');
      toast('备份已载入，请输入该备份的主密码', 'ok');
    } catch (err) {
      lockError(`无法读取备份文件：${err.message}`);
    }
  };
  input.click();
}

/* ============================== 启动 ============================== */

init();
