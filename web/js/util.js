// 通用工具函数（浏览器与 Node 均可使用）
export const enc = new TextEncoder();
export const dec = new TextDecoder();

/** 字节数组 -> Base64 */
export function b64encode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
  }
  return btoa(bin);
}

/** Base64 -> 字节数组 */
export function b64decode(str) {
  const bin = atob(String(str).replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Base64URL -> 字节数组（容忍缺少填充） */
export function b64urlDecode(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  return b64decode(s);
}

export function b64urlEncode(bytes) {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function hexEncode(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** RFC 4122 v4 UUID */
export function uuid() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = hexEncode(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function nowISO() {
  return new Date().toISOString();
}

export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** 恒定时间字符串比较，避免时序侧信道 */
export function timingSafeEqual(a, b) {
  const x = String(a);
  const y = String(b);
  let diff = x.length ^ y.length;
  const len = Math.max(x.length, y.length);
  for (let i = 0; i < len; i++) {
    diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/** 将任意字符串规范化为可比较的搜索文本 */
export function normalizeSearch(text) {
  return String(text ?? '').toLowerCase().normalize('NFKC');
}

export function formatDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function relativeTime(iso) {
  if (!iso) return '从未';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '从未';
  const diff = Date.now() - t;
  if (diff < 60_000) return '刚刚';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  if (diff < 30 * 86_400_000) return `${Math.floor(diff / 86_400_000)} 天前`;
  return formatDateTime(iso);
}

/** 从网址中提取用于显示的主机名 */
export function hostOf(url) {
  if (!url) return '';
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`);
    return u.hostname.replace(/^www\./, '');
  } catch {
    return String(url).slice(0, 40);
  }
}

/** 首字母（用于列表头像） */
export function initialsOf(title) {
  const t = String(title || '?').trim();
  if (!t) return '?';
  const first = Array.from(t)[0];
  return /[a-z]/i.test(first) ? first.toUpperCase() : first;
}

/** 根据名称生成稳定的头像配色 */
export function colorOf(text) {
  let h = 0;
  for (const ch of String(text || '')) h = (h * 31 + ch.codePointAt(0)) % 360;
  return `hsl(${h} 62% 46%)`;
}
