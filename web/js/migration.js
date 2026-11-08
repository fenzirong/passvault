// 2FA 批量导入：Google Authenticator 迁移包（otpauth-migration://）、Aegis、andOTP、纯密钥列表
import { b64decode, b64urlDecode } from './util.js';
import { base32Encode } from './base32.js';
import { normalizeTotp, parseOtpauthUri } from './totp.js';

/* ------------------------- 极简 Protobuf 解析 ------------------------- */

function readVarint(buf, pos) {
  let result = 0;
  let shift = 0;
  let p = pos;
  while (p < buf.length) {
    const byte = buf[p++];
    result += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return [result, p];
    shift += 7;
    if (shift > 63) throw new Error('Protobuf varint 过长');
  }
  throw new Error('Protobuf 数据被截断');
}

function readFields(buf) {
  const fields = [];
  let pos = 0;
  while (pos < buf.length) {
    let tag;
    [tag, pos] = readVarint(buf, pos);
    const fieldNo = Math.floor(tag / 8);
    const wireType = tag & 7;
    if (wireType === 0) {
      let value;
      [value, pos] = readVarint(buf, pos);
      fields.push({ fieldNo, wireType, value });
    } else if (wireType === 2) {
      let len;
      [len, pos] = readVarint(buf, pos);
      const value = buf.subarray(pos, pos + len);
      pos += len;
      fields.push({ fieldNo, wireType, value });
    } else if (wireType === 1) {
      pos += 8;
    } else if (wireType === 5) {
      pos += 4;
    } else {
      throw new Error(`不支持的 Protobuf 线类型：${wireType}`);
    }
  }
  return fields;
}

const ALGO_MAP = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };
const DIGITS_MAP = { 1: 6, 2: 8 };
const TYPE_MAP = { 1: 'hotp', 2: 'totp' };

/** 解析 Google Authenticator 导出的 otpauth-migration://offline?data=... */
export function parseGoogleMigration(uri) {
  const raw = String(uri || '').trim();
  const m = raw.match(/[?&]data=([^&]+)/i);
  if (!m) throw new Error('迁移链接中缺少 data 参数');
  let payload;
  try {
    payload = b64urlDecode(decodeURIComponent(m[1]));
  } catch {
    payload = b64decode(decodeURIComponent(m[1]));
  }

  const top = readFields(payload);
  const out = [];
  for (const f of top) {
    if (f.fieldNo !== 1 || f.wireType !== 2) continue;
    const sub = readFields(f.value);
    const item = { secret: '', name: '', issuer: '', algorithm: 'SHA1', digits: 6, type: 'totp', counter: 0 };
    for (const s of sub) {
      if (s.fieldNo === 1 && s.wireType === 2) item.secret = base32Encode(s.value);
      else if (s.fieldNo === 2 && s.wireType === 2) item.name = new TextDecoder().decode(s.value);
      else if (s.fieldNo === 3 && s.wireType === 2) item.issuer = new TextDecoder().decode(s.value);
      else if (s.fieldNo === 4) item.algorithm = ALGO_MAP[s.value] || 'SHA1';
      else if (s.fieldNo === 5) item.digits = DIGITS_MAP[s.value] || 6;
      else if (s.fieldNo === 6) item.type = TYPE_MAP[s.value] || 'totp';
      else if (s.fieldNo === 7) item.counter = s.value;
    }
    if (!item.secret) continue;
    out.push(
      normalizeTotp({
        secret: item.secret,
        issuer: item.issuer,
        account: item.name,
        algorithm: item.algorithm,
        digits: item.digits,
        period: 30,
        type: item.type,
        counter: item.counter,
      }),
    );
  }
  if (!out.length) throw new Error('迁移包中没有可用的 2FA 条目');
  return out;
}

/* ------------------------- 其他常见导出格式 ------------------------- */

/** Aegis Authenticator 明文 JSON 导出 */
export function parseAegis(json) {
  const data = typeof json === 'string' ? JSON.parse(json) : json;
  const list = Array.isArray(data) ? data : data.entries;
  if (!Array.isArray(list)) throw new Error('不是有效的 Aegis 导出文件');
  const out = [];
  for (const e of list) {
    if (!e || !e.info || !e.info.secret) continue;
    if (e.type && e.type !== 'totp' && e.type !== 'hotp') continue;
    out.push(
      normalizeTotp({
        secret: e.info.secret,
        issuer: e.issuer || '',
        account: e.name || e.account || '',
        algorithm: e.info.algo || 'SHA1',
        digits: e.info.digits || 6,
        period: e.info.period || 30,
        type: e.type || 'totp',
        counter: e.info.counter || 0,
      }),
    );
  }
  if (!out.length) throw new Error('Aegis 文件中没有可用的 2FA 条目');
  return out;
}

/** andOTP 明文 JSON 导出 */
export function parseAndOtp(json) {
  const list = typeof json === 'string' ? JSON.parse(json) : json;
  if (!Array.isArray(list)) throw new Error('不是有效的 andOTP 导出文件');
  const out = [];
  for (const e of list) {
    if (!e || !e.secret) continue;
    out.push(
      normalizeTotp({
        secret: e.secret,
        issuer: e.issuer || '',
        account: e.label || '',
        algorithm: e.algorithm || 'SHA1',
        digits: e.digits || 6,
        period: e.period || 30,
        type: e.type === 'HOTP' ? 'hotp' : 'totp',
        counter: e.counter || 0,
      }),
    );
  }
  if (!out.length) throw new Error('andOTP 文件中没有可用的 2FA 条目');
  return out;
}

/**
 * 通用 2FA 文本解析：每行一条，支持
 *   otpauth://totp/...
 *   发行方:账号:密钥
 *   账号,密钥
 *   纯 Base32 密钥
 */
export function parseTotpText(text) {
  const out = [];
  const lines = String(text || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  for (const line of lines) {
    if (/^otpauth:\/\//i.test(line)) {
      out.push(normalizeTotp(parseOtpauthUri(line)));
      continue;
    }
    const parts = line.split(/[,;\t|]/).map((s) => s.trim()).filter(Boolean);
    if (parts.length >= 2) {
      const secret = parts[parts.length - 1];
      const issuer = parts.length >= 3 ? parts[0] : '';
      const account = parts.length >= 3 ? parts[1] : parts[0];
      out.push(normalizeTotp({ secret, issuer, account }));
      continue;
    }
    out.push(normalizeTotp({ secret: line, issuer: '', account: '' }));
  }
  const valid = out.filter(Boolean);
  if (!valid.length) throw new Error('没有识别到有效的 2FA 密钥');
  return valid;
}

/** 自动识别 2FA 导入内容 */
export function parseAnyTotp(input) {
  const text = String(input || '').trim();
  if (!text) throw new Error('内容为空');
  if (/^otpauth-migration:\/\//i.test(text)) return parseGoogleMigration(text);
  if (/^otpauth:\/\//i.test(text)) return [normalizeTotp(parseOtpauthUri(text))];
  if (text.startsWith('{') || text.startsWith('[')) {
    const data = JSON.parse(text);
    if (Array.isArray(data) || data.entries) {
      if (data.entries && data.entries[0]?.info) return parseAegis(data);
      if (Array.isArray(data) && data[0]?.secret) return parseAndOtp(data);
    }
    throw new Error('无法识别的 JSON 格式');
  }
  return parseTotpText(text);
}
