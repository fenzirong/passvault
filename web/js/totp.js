// TOTP / HOTP 实现（RFC 4226、RFC 6238）与 otpauth:// 解析
import { base32Decode, base32Encode } from './base32.js';

const subtle = globalThis.crypto.subtle;

const ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

/** Steam 令牌的字符表（Aegis / Steam 官方一致） */
export const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export function normalizeAlgorithm(value) {
  const v = String(value || 'SHA1').toUpperCase().replace(/[-_]/g, '');
  if (v === 'SHA1' || v === 'SHA256' || v === 'SHA512') return v;
  return 'SHA1';
}

/** 计算 HMAC 并做 RFC 4226 动态截断，返回 31 位整数 */
async function truncate({ secret, counter, algorithm = 'SHA1' }) {
  const keyBytes = typeof secret === 'string' ? base32Decode(secret) : secret;
  if (!keyBytes || keyBytes.length === 0) throw new Error('2FA 密钥为空');
  const key = await subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: ALGORITHMS[normalizeAlgorithm(algorithm)] },
    false,
    ['sign'],
  );
  const msg = new Uint8Array(8);
  let c = Math.floor(counter);
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const mac = new Uint8Array(await subtle.sign('HMAC', key, msg));
  const offset = mac[mac.length - 1] & 0x0f;
  return (
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff)
  );
}

/** 生成一次性口令（HOTP 计数器为任意整数） */
export async function hotp({ secret, counter, algorithm = 'SHA1', digits = 6 }) {
  const bin = await truncate({ secret, counter, algorithm });
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** 生成 Steam 令牌（5 位，Base-26 字符表） */
export async function steam({ secret, timestamp = Date.now(), period = 30 }) {
  const counter = Math.floor(timestamp / 1000 / (period || 30));
  let bin = await truncate({ secret, counter, algorithm: 'SHA1' });
  let out = '';
  for (let i = 0; i < 5; i++) {
    out += STEAM_ALPHABET[bin % 26];
    bin = Math.floor(bin / 26);
  }
  return out;
}

/** 生成 TOTP 验证码（type 为 steam 时走 Steam 字符表） */
export async function totp({
  secret,
  algorithm = 'SHA1',
  digits = 6,
  period = 30,
  timestamp = Date.now(),
  type = 'totp',
}) {
  if (type === 'steam') return steam({ secret, timestamp, period });
  const counter = Math.floor(timestamp / 1000 / period);
  return hotp({ secret, counter, algorithm, digits });
}

/** 当前周期剩余秒数 */
export function totpRemaining(period = 30, timestamp = Date.now()) {
  const p = period || 30;
  return p - (Math.floor(timestamp / 1000) % p);
}

/** 当前周期进度 0~1 */
export function totpProgress(period = 30, timestamp = Date.now()) {
  const p = period || 30;
  return (Math.floor(timestamp / 1000) % p) / p;
}

/**
 * 解析 otpauth:// URI
 * 支持 totp / hotp / steam，兼容大小写、缺失 issuer、带空格/连字符的密钥
 */
export function parseOtpauthUri(uri) {
  const raw = String(uri || '').trim();
  if (!/^otpauth:\/\//i.test(raw)) throw new Error('不是 otpauth:// 链接');
  const url = new URL(raw.replace(/^otpauth:\/\//i, 'https://'));
  const type = url.hostname.toLowerCase();
  if (type !== 'totp' && type !== 'hotp' && type !== 'steam') {
    throw new Error(`不支持的 2FA 类型：${type}`);
  }

  const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const params = url.searchParams;
  const secret = (params.get('secret') || '').replace(/\s/g, '');
  if (!secret) throw new Error('链接中缺少 secret 参数');

  let issuer = params.get('issuer') || '';
  let account = label;
  if (label.includes(':')) {
    const [a, ...rest] = label.split(':');
    if (!issuer) issuer = a.trim();
    account = rest.join(':').trim();
  }
  issuer = issuer.trim();
  account = account.trim();

  const digits = clampDigits(params.get('digits'), type);
  const period = Number(params.get('period')) || 30;
  const counter = Number(params.get('counter')) || 0;

  return {
    type,
    secret: secret.toUpperCase().replace(/=+$/, ''),
    issuer,
    account,
    algorithm: normalizeAlgorithm(params.get('algorithm')),
    digits,
    period: period > 0 ? period : 30,
    counter,
  };
}

/** 生成 otpauth:// URI（用于导出/迁移） */
export function buildOtpauthUri(totpData) {
  const {
    secret,
    issuer = '',
    account = '',
    algorithm = 'SHA1',
    period = 30,
    type = 'totp',
  } = totpData;
  const digits = clampDigits(totpData.digits, type);
  const label = issuer ? `${issuer}:${account || issuer}` : account || 'account';
  const params = new URLSearchParams();
  params.set('secret', String(secret).replace(/\s/g, '').toUpperCase());
  if (issuer) params.set('issuer', issuer);
  params.set('algorithm', normalizeAlgorithm(algorithm));
  params.set('digits', String(digits));
  if (type === 'hotp') params.set('counter', String(totpData.counter || 0));
  else params.set('period', String(period));
  return `otpauth://${type}/${encodeURIComponent(label)}?${params.toString()}`;
}

/** 位数规范化：Steam 固定 5 位，其余允许 5~10 位（Aegis 支持 1~10） */
export function clampDigits(value, type = 'totp') {
  if (type === 'steam') return 5;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 5 || n > 10) return 6;
  return n;
}

/** 校验并规范化 2FA 配置 */
export function normalizeTotp(input) {
  if (!input) return null;
  const secret = String(input.secret || '').replace(/[\s-]/g, '').toUpperCase();
  if (!secret) return null;
  // 先做一次解码校验，避免保存无法使用的密钥
  base32Decode(secret);
  const type = input.type === 'hotp' ? 'hotp' : input.type === 'steam' ? 'steam' : 'totp';
  return {
    secret,
    issuer: String(input.issuer || '').trim(),
    account: String(input.account || '').trim(),
    algorithm: type === 'steam' ? 'SHA1' : normalizeAlgorithm(input.algorithm),
    digits: clampDigits(input.digits, type),
    period: Number(input.period) > 0 ? Number(input.period) : 30,
    type,
    counter: Number(input.counter) || 0,
  };
}

export { base32Decode, base32Encode };
