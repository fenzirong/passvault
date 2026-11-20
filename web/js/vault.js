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
    groups: Array.isArray(input.groups)
      ? Array.from(new Set(input.groups.map((g) => String(g || '').trim()).filter(Boolean)))
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

/* ------------------------------ 分组 ------------------------------ */

/** 规范化分组对象 */
export function normalizeGroup(input = {}) {
  const ts = nowISO();
  return {
    id: input.id || uuid(),
    name: String(input.name ?? '').trim(),
    createdAt: input.createdAt || ts,
    updatedAt: input.updatedAt || ts,
    deletedAt: input.deletedAt || null,
  };
}

/** 兼容旧保险库：补齐 groups 字段 */
export function ensureGroups(vault) {
  if (!vault) return [];
  if (!Array.isArray(vault.groups)) vault.groups = [];
  vault.groups = vault.groups.filter((g) => g && g.id).map((g) => normalizeGroup(g));
  for (const e of vault.entries || []) {
    if (!Array.isArray(e.groups)) e.groups = [];
  }
  return vault.groups;
}

/** 按名称找分组（忽略大小写与首尾空格） */
export function findGroupByName(vault, name) {
  const target = String(name || '').trim().toLowerCase();
  if (!target) return null;
  return (vault.groups || []).find((g) => !g.deletedAt && g.name.toLowerCase() === target) || null;
}

/** 新建分组（同名已存在则直接返回） */
export function createGroup(vault, name, { id } = {}) {
  const clean = String(name || '').trim();
  if (!clean) throw new Error('分组名不能为空');
  const existing = findGroupByName(vault, clean);
  if (existing) return existing;
  const group = normalizeGroup({ id, name: clean });
  if (!Array.isArray(vault.groups)) vault.groups = [];
  vault.groups.push(group);
  return group;
}

export function renameGroup(vault, id, name) {
  const group = (vault.groups || []).find((g) => g.id === id);
  const clean = String(name || '').trim();
  if (!group || !clean) return false;
  group.name = clean;
  group.updatedAt = nowISO();
  return true;
}

/** 删除分组：条目上的引用一并清掉（条目本身保留） */
export function deleteGroup(vault, id) {
  const group = (vault.groups || []).find((g) => g.id === id);
  if (!group) return false;
  group.deletedAt = nowISO();
  group.updatedAt = group.deletedAt;
  for (const e of vault.entries || []) {
    if (Array.isArray(e.groups) && e.groups.includes(id)) {
      e.groups = e.groups.filter((g) => g !== id);
      e.updatedAt = nowISO();
    }
  }
  return true;
}

/** 分组 id → 名称 */
export function groupNameMap(vault) {
  const map = {};
  for (const g of vault.groups || []) {
    if (g && g.id && !g.deletedAt) map[g.id] = g.name;
  }
  return map;
}

/** 把外部导入的分组并入保险库，返回「导入 id → 本地 id」映射 */
export function mergeGroups(vault, incoming = []) {
  const map = new Map();
  for (const g of incoming) {
    const name = String(g?.name || '').trim();
    if (!name) continue;
    const existing = findGroupByName(vault, name);
    if (existing) {
      map.set(String(g.id || name), existing.id);
      continue;
    }
    const created = createGroup(vault, name, { id: g.id });
    map.set(String(g.id || name), created.id);
  }
  return map;
}

export function touchEntry(entry) {
  entry.updatedAt = nowISO();
  return entry;
}

/**
 * 导入去重用的键。
 * 必须带上 2FA 账号：同一个发行方下的多个账号（如两个 GitHub）标题相同、
 * 用户名都为空，只用 title|username 会把第二个当成重复丢掉。
 */
export function entryKey(entry) {
  return [entry?.title || '', entry?.username || '', entry?.totp?.account || ''].join('|');
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

/** 合并两份分组列表（按 id，取较新的名字，保留墓碑） */
export function mergeGroupLists(local = [], remote = []) {
  const map = new Map();
  for (const g of remote) {
    if (g && g.id) map.set(g.id, normalizeGroup(g));
  }
  for (const g of local) {
    if (!g || !g.id) continue;
    const other = map.get(g.id);
    map.set(g.id, other ? pickNewer(normalizeGroup(g), other) : normalizeGroup(g));
  }
  return Array.from(map.values());
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
    groups: mergeGroupLists(local.groups, remote.groups),
    settings: { ...(remote.settings || {}), ...(local.settings || {}) },
    updatedAt: nowISO(),
  };
  const removed = merged.entries.filter((e) => e.deletedAt).length;
  return { vault: merged, stats: { added, updated, removed } };
}

/** 搜索（标题、账号、网址、标签、分组名、备注） */
export function searchEntries(entries, query, groupNames = {}) {
  const q = normalizeSearch(query).trim();
  const alive = entries.filter((e) => !e.deletedAt);
  if (!q) return alive;
  const terms = q.split(/\s+/).filter(Boolean);
  return alive.filter((e) => {
    const groupText = (e.groups || []).map((g) => groupNames[g] || '').join(' ');
    const hay = normalizeSearch(
      [e.title, e.username, e.url, e.notes, (e.tags || []).join(' '), groupText, e.totp?.issuer, e.totp?.account]
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
export function exportCsv(entries, groupNames = {}) {
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
    const folder = (e.groups || []).map((g) => groupNames[g]).filter(Boolean)[0] || '';
    lines.push(
      [
        folder,
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
  const groups = [];
  const groupIndex = new Map();
  const groupIdOf = (name) => {
    const clean = String(name || '').trim();
    if (!clean) return null;
    if (!groupIndex.has(clean)) {
      const id = uuid();
      groupIndex.set(clean, id);
      groups.push({ id, name: clean });
    }
    return groupIndex.get(clean);
  };
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
    const groupId = groupIdOf(rec.folder);
    out.push(
      normalizeEntry({
        type: String(rec.type || '').toLowerCase() === 'note' ? 'note' : 'login',
        title: rec.title,
        username: rec.username,
        password: rec.password,
        url: rec.url,
        notes: rec.notes,
        groups: groupId ? [groupId] : [],
        favorite: /^(1|true|yes|是)$/i.test(String(rec.favorite || '')),
        totp,
      }),
    );
  }
  if (!out.length) throw new Error('CSV 中没有可导入的条目');
  return { entries: out, groups };
}

/** 解析 JSON 导入（本应用导出格式 / Bitwarden 未加密导出） */
export function parseJsonImport(text) {
  const data = JSON.parse(text);
  const list = Array.isArray(data) ? data : data.items || data.entries;
  if (!Array.isArray(list)) throw new Error('JSON 结构无法识别');
  const out = [];
  const groups = [];
  const groupIndex = new Map();
  const groupIdOf = (name) => {
    const clean = String(name || '').trim();
    if (!clean) return null;
    if (!groupIndex.has(clean)) {
      const id = uuid();
      groupIndex.set(clean, id);
      groups.push({ id, name: clean });
    }
    return groupIndex.get(clean);
  };
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
    const groupId = groupIdOf(item.folder);
    out.push(
      normalizeEntry({
        type: item.type === 2 || item.type === 'note' ? 'note' : 'login',
        title: item.name || item.title || '',
        username: login.username || item.username || '',
        password: login.password || item.password || '',
        url: (login.uris && login.uris[0] && (login.uris[0].uri || login.uris[0])) || item.url || '',
        notes: item.notes || '',
        tags: Array.isArray(item.tags) ? item.tags : [],
        groups: groupId ? [groupId] : [],
        favorite: Boolean(item.favorite),
        totp,
      }),
    );
  }
  if (!out.length) throw new Error('JSON 中没有可导入的条目');
  return { entries: out, groups };
}

/** 导出为应用自身的 JSON（明文，仅用于迁移，请妥善保管） */
export function exportJson(vault) {
  return JSON.stringify(
    {
      application: 'dsh-passvault',
      exportedAt: nowISO(),
      groups: (vault.groups || []).filter((g) => !g.deletedAt),
      entries: (vault.entries || []).filter((e) => !e.deletedAt),
    },
    null,
    2,
  );
}
