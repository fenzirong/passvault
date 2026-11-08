// 自动加密快照：只保存密文，可在误删/覆盖后回滚
import { formatDateTime } from './util.js';

const KEY = 'pm.backups';
const MAX_SNAPSHOTS = 8;
const MIN_INTERVAL_MS = 5 * 60 * 1000;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024;

function readAll() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list.filter((s) => s && s.envelope) : [];
  } catch {
    return [];
  }
}

function writeAll(list) {
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    // 空间不足时丢弃最旧的一半再试一次
    try {
      localStorage.setItem(KEY, JSON.stringify(list.slice(-Math.ceil(list.length / 2))));
    } catch {
      /* 放弃写入 */
    }
  }
}

function totalBytes(list) {
  return list.reduce((n, s) => n + (s.size || 0), 0);
}

/** 读取快照列表（新 → 旧） */
export function listSnapshots() {
  return readAll()
    .map((s, index) => ({
      id: s.id,
      at: s.at,
      revision: s.revision,
      size: s.size || 0,
      label: formatDateTime(s.at),
      envelope: s.envelope,
      index,
    }))
    // 时间相同（同一毫秒写入）时按写入顺序倒排，保证「最新在前」
    .sort((a, b) => new Date(b.at) - new Date(a.at) || b.index - a.index)
    .map(({ index, ...rest }) => rest);
}

/**
 * 记录一份加密快照
 * @returns {boolean} 是否真的写入
 */
export function recordSnapshot(envelope, { force = false, minIntervalMs = MIN_INTERVAL_MS } = {}) {
  if (!envelope?.data) return false;
  const list = readAll();
  const last = list[list.length - 1];
  const now = Date.now();
  if (!force && last) {
    const sameContent = last.envelope?.data === envelope.data;
    const tooSoon = now - new Date(last.at).getTime() < minIntervalMs;
    if (sameContent || tooSoon) return false;
  }

  const size = JSON.stringify(envelope).length;
  const entry = {
    id: `bk_${now}_${Math.random().toString(36).slice(2, 8)}`,
    at: new Date(now).toISOString(),
    revision: envelope.header?.revision ?? 0,
    size,
    envelope,
  };
  list.push(entry);

  // 数量与体积双重限制
  while (list.length > MAX_SNAPSHOTS || totalBytes(list) > MAX_TOTAL_BYTES) {
    list.shift();
  }
  writeAll(list);
  return true;
}

export function removeSnapshot(id) {
  const list = readAll().filter((s) => s.id !== id);
  writeAll(list);
}

export function clearSnapshots() {
  localStorage.removeItem(KEY);
}

export function snapshotCount() {
  return readAll().length;
}

export function formatBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
