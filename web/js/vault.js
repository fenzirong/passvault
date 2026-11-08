// 保险库数据模型：条目、合并、搜索、导入导出
import { uuid, nowISO, normalizeSearch } from './util.js';
import { normalizeTotp } from './totp.js';

export const ENTRY_TYPES = { login: '账号密码', note: '安全笔记' };

/** 创建/规范化条目 */
export function normalizeEntry(input = {}) {
  const ts = nowISO();
  const entry = {
    id: input.id || uuid(),
    type: input.type === 'note' ? 'note' : 'login',
    title: String(input.title ?? '').trim(),
    username: String(input.username ?? ''),
    password: String(input.password ?? ''),
    url: String(input.url ?? '').trim(),
    notes: String(input.notes ?? ''),
    tags: Array.isArray(input.tags)
      ? Array.from(new Set(input.tags.map((t) => String(t).trim()).filter(Boolean)))
      : [],
    totp: null,
    favorite: Boolean(input.favorite),
    createdAt: input.createdAt || ts,
    updatedAt: input.updatedAt || ts,
    deletedAt: input.deletedAt || null,
  };
  if (input.totp) {
    try {
      entry.totp = normalizeTotp(input.totp);
    } catch {
      entry.totp = null;
    }
  }
  if (!entry.title) {
    entry.title = entry.url || entry.username || entry.totp?.issuer || entry.totp?.account || '未命名条目';
  }
  return entry;
}

export function touchEntry(entry) {
  entry.updatedAt = nowISO();
  return entry;
}

/** 软删除（保留墓碑，便于多设备合并） */
export function deleteEntry(vault, id) {
  const e = vault.entries.find((x) => x.id === id);
  if (!e) return false;
  e.deletedAt = nowISO();
  e.updatedAt = e.deletedAt;
  e.password = '';
  e.totp = null;
  e.notes = '';
  return true;
}

/** 清理超过指定天数的墓碑 */
export function purgeTombstones(vault, days = 90) {
  const cutoff = Date.now() - days * 86_400_000;
  const before = vault.entries.length;
  vault.entries = vault.entries.filter(
    (e) => !e.deletedAt || new Date(e.deletedAt).getTime() > cutoff,
  );
  return before - vault.entries.length;
}

function pickNewer(a, b) {
  const ta = new Date(a.updatedAt || 0).getTime();
  const tb = new Date(b.updatedAt || 0).getTime();
  if (ta === tb) return a; // 时间相同优先保留本地
  return ta > tb ? a : b;
}

/**
 * 合并两个保险库（按条目 id + updatedAt，删除墓碑参与比较）
 * @returns {{vault: object, stats: {added:number, updated:number, removed:number}}}
 */
export function mergeVaults(local, remote) {
  const map = new Map();
  for (const e of remote.entries || []) map.set(e.id, e);
  let added = 0;
  let updated = 0;
  for (const e of local.entries || []) {
    const other = map.get(e.id);
    if (!other) {
      map.set(e.id, e);
      added++;
      continue;
    }
    const winner = pickNewer(e, other);
    if (winner !== other) updated++;
    map.set(e.id, winner);
  }
  const merged = {
    ...local,
    entries: Array.from(map.values()),
    settings: { ...(remote.settings || {}), ...(local.settings || {}) },
    updatedAt: nowISO(),
  };
  const removed = merged.entries.filter((e) => e.deletedAt).length;
  return { vault: merged, stats: { added, updated, removed } };
}

/** 搜索（标题、账号、网址、标签、备注） */
export function searchEntries(entries, query) {
  const q = normalizeSearch(query).trim();
  const alive = entries.filter((e) => !e.deletedAt);
  if (!q) return alive;
  const terms = q.split(/\s+/).filter(Boolean);
  return alive.filter((e) => {
    const hay = normalizeSearch(
      [e.title, e.username, e.url, e.notes, (e.tags || []).join(' '), e.totp?.issuer, e.totp?.account]
        .filter(Boolean)
        .join(' '),
    );
    return terms.every((t) => hay.includes(t));
  });
}

export function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return String(a.title).localeCompare(String(b.title), 'zh-Hans-CN');
  });
}

export function vaultStats(vault) {
  const alive = (vault.entries || []).filter((e) => !e.deletedAt);
  return {
    total: alive.length,
    logins: alive.filter((e) => e.type === 'login').length,
    notes: alive.filter((e) => e.type === 'note').length,
    withTotp: alive.filter((e) => e.totp).length,
    favorites: alive.filter((e) => e.favorite).length,
  };
}

/* ------------------------------ CSV ------------------------------ */

/** RFC 4180 CSV 解析 */
export function parseCsv(text) {
  const src = String(text || '').replace(/^\uFEFF/, '');
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += ch;
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch === '\r') {
      // 忽略
    } else {
      field += ch;
    }
  }
  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((c) => String(c).trim() !== ''));
}

function csvEscape(value) {
  const s = String(value ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** 导出为 Bitwarden 兼容 CSV（可被多数密码管理器导入） */
export function exportCsv(entries) {
  const header = [
    'folder',
    'favorite',
    'type',
    'name',
    'notes',
    'fields',
    'reprompt',
    'login_uri',
    'login_username',
    'login_password',
    'login_totp',
  ];
  const lines = [header.join(',')];
  for (const e of entries.filter((x) => !x.deletedAt)) {
    lines.push(
      [
        (e.tags || [])[0] || '',
        e.favorite ? 1 : 0,
        e.type === 'note' ? 'note' : 'login',
        e.title,
        e.notes,
        '',
        0,
        e.url,
        e.username,
        e.password,
        e.totp?.secret || '',
      ]
        .map(csvEscape)
        .join(','),
    );
  }
  return lines.join('\r\n');
}

const HEADER_ALIASES = {
  title: ['name', 'title', 'account', '账户', '名称', '标题', 'account name'],
  username: ['login_username', 'username', 'login name', 'user', 'login', '用户名', '账号', '登录名'],
  password: ['login_password', 'password', 'pass', '密码'],
  url: ['login_uri', 'url', 'website', 'web site', 'site', '网址', '网站'],
  notes: ['notes', 'note', 'comments', 'comment', '备注', '注释'],
  totp: ['login_totp', 'totp', 'otp', 'otpauth', '2fa', 'twofactor'],
  folder: ['folder', 'group', 'category', '分组', '文件夹'],
  favorite: ['favorite', 'starred', '收藏'],
  type: ['type', '类型'],
};

function matchHeader(name) {
  const n = String(name || '').trim().toLowerCase();
  for (const [key, aliases] of Object.entries(HEADER_ALIASES)) {
    if (aliases.includes(n)) return key;
  }
  return null;
}

/** 解析 CSV 导入（Bitwarden / Chrome / KeePass / 1Password 等） */
export function parseCsvImport(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error('CSV 内容为空或缺少表头');
  const header = rows[0].map(matchHeader);
  if (!header.includes('title') && !header.includes('username')) {
    throw new Error('无法识别 CSV 表头，请确认包含 name/username/password 等列');
  }
  const out = [];
  for (const row of rows.slice(1)) {
    const rec = {};
    header.forEach((key, i) => {
      if (key) rec[key] = row[i] ?? '';
    });
    if (!rec.title && !rec.username && !rec.password) continue;
    let totp = null;
    if (rec.totp) {
      const raw = String(rec.totp).trim();
      if (/^otpauth:\/\//i.test(raw)) {
        try {
          const u = new URL(raw.replace(/^otpauth:\/\//i, 'https://'));
          totp = normalizeTotp({
            secret: u.searchParams.get('secret') || '',
            issuer: u.searchParams.get('issuer') || '',
            account: decodeURIComponent(u.pathname.replace(/^\//, '')),
            algorithm: u.searchParams.get('algorithm') || 'SHA1',
            digits: u.searchParams.get('digits') || 6,
            period: u.searchParams.get('period') || 30,
          });
        } catch {
          totp = null;
        }
      } else if (raw) {
        try {
          totp = normalizeTotp({ secret: raw });
        } catch {
          totp = null;
        }
      }
    }
    out.push(
      normalizeEntry({
        type: String(rec.type || '').toLowerCase() === 'note' ? 'note' : 'login',
        title: rec.title,
        username: rec.username,
        password: rec.password,
        url: rec.url,
        notes: rec.notes,
        tags: rec.folder ? [rec.folder] : [],
        favorite: /^(1|true|yes|是)$/i.test(String(rec.favorite || '')),
        totp,
      }),
    );
  }
  if (!out.length) throw new Error('CSV 中没有可导入的条目');
  return out;
}

/** 解析 JSON 导入（本应用导出格式 / Bitwarden 未加密导出） */
export function parseJsonImport(text) {
  const data = JSON.parse(text);
  const list = Array.isArray(data) ? data : data.items || data.entries;
  if (!Array.isArray(list)) throw new Error('JSON 结构无法识别');
  const out = [];
  for (const item of list) {
    if (!item || typeof item !== 'object') continue;
    const login = item.login || {};
    const totpRaw = login.totp || item.totp || '';
    let totp = null;
    if (totpRaw) {
      try {
        if (typeof totpRaw === 'string' && /^otpauth:\/\//i.test(totpRaw)) {
          const u = new URL(totpRaw.replace(/^otpauth:\/\//i, 'https://'));
          totp = normalizeTotp({
            secret: u.searchParams.get('secret') || '',
            issuer: u.searchParams.get('issuer') || '',
            account: decodeURIComponent(u.pathname.replace(/^\//, '')),
          });
        } else if (typeof totpRaw === 'object') {
          totp = normalizeTotp(totpRaw);
        } else {
          totp = normalizeTotp({ secret: String(totpRaw) });
        }
      } catch {
        totp = null;
      }
    }
    out.push(
      normalizeEntry({
        type: item.type === 2 || item.type === 'note' ? 'note' : 'login',
        title: item.name || item.title || '',
        username: login.username || item.username || '',
        password: login.password || item.password || '',
        url: (login.uris && login.uris[0] && (login.uris[0].uri || login.uris[0])) || item.url || '',
        notes: item.notes || '',
        tags: item.folder ? [item.folder] : item.tags || [],
        favorite: Boolean(item.favorite),
        totp,
      }),
    );
  }
  if (!out.length) throw new Error('JSON 中没有可导入的条目');
  return out;
}

/** 导出为应用自身的 JSON（明文，仅用于迁移，请妥善保管） */
export function exportJson(vault) {
  return JSON.stringify(
    {
      application: 'dsh-passvault',
      exportedAt: nowISO(),
      entries: (vault.entries || []).filter((e) => !e.deletedAt),
    },
    null,
    2,
  );
}
