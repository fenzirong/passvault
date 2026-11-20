// Aegis Authenticator 兼容层：明文 / 加密（scrypt + AES-256-GCM）双向导入导出
//
// 格式依据 Aegis 源码（beemdevelopment/Aegis）：
//   VaultFile.java        → {version:1, header:{slots,params}, db}
//   VaultFile.Header      → slots / params 为 null 表示明文导出
//   Slot.java             → {type,uuid,key,key_params}，key 与 nonce/tag 都是 **hex**
//   PasswordSlot.java     → 额外 {n,r,p,salt(hex),repaired,is_backup}
//   CryptoUtils.java      → AES/GCM/NoPadding，key 32B，nonce 12B，tag 16B，
//                           scrypt N=1<<15, r=8, p=1，无 AAD
//   Vault.java            → db = {version:3, entries:[...], groups:[...], icons_optimized}
//   VaultEntry.java       → {type,uuid,name,issuer,note,favorite,icon,info,groups}
//   OtpInfo.java          → info = {secret(Base32), algo, digits} + period / counter
//
// 注意：Aegis 的 nonce/tag/salt/key 全部是十六进制字符串，只有 db 是 Base64。
import { b64decode, b64encode, enc, hexEncode, randomBytes, uuid } from './util.js';
import { normalizeTotp } from './totp.js';

export const AEGIS_FILE_VERSION = 1;
export const AEGIS_DB_VERSION = 3;
export const AEGIS_SCRYPT = { n: 1 << 15, r: 8, p: 1 };
const TAG_SIZE = 16;
const NONCE_SIZE = 12;
const KEY_SIZE = 32;

const subtle = globalThis.crypto.subtle;

/* ============================== 十六进制 ============================== */

export function hexDecode(str) {
  const s = String(str || '').replace(/\s+/g, '');
  if (s.length % 2) throw new Error('十六进制字符串长度不是偶数');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('十六进制字符串包含非法字符');
    out[i] = byte;
  }
  return out;
}

/* ============================== scrypt（RFC 7914） ============================== */

function rotl(a, b) {
  return (a << b) | (a >>> (32 - b));
}

/** Salsa20/8 核心，原地变换 16 个 32 位字 */
function salsa208(B) {
  const x = new Int32Array(16);
  x.set(B);
  for (let i = 0; i < 8; i += 2) {
    x[4] ^= rotl(x[0] + x[12], 7);
    x[8] ^= rotl(x[4] + x[0], 9);
    x[12] ^= rotl(x[8] + x[4], 13);
    x[0] ^= rotl(x[12] + x[8], 18);
    x[9] ^= rotl(x[5] + x[1], 7);
    x[13] ^= rotl(x[9] + x[5], 9);
    x[1] ^= rotl(x[13] + x[9], 13);
    x[5] ^= rotl(x[1] + x[13], 18);
    x[14] ^= rotl(x[10] + x[6], 7);
    x[2] ^= rotl(x[14] + x[10], 9);
    x[6] ^= rotl(x[2] + x[14], 13);
    x[10] ^= rotl(x[6] + x[2], 18);
    x[3] ^= rotl(x[15] + x[11], 7);
    x[7] ^= rotl(x[3] + x[15], 9);
    x[11] ^= rotl(x[7] + x[3], 13);
    x[15] ^= rotl(x[11] + x[7], 18);
    x[1] ^= rotl(x[0] + x[3], 7);
    x[2] ^= rotl(x[1] + x[0], 9);
    x[3] ^= rotl(x[2] + x[1], 13);
    x[0] ^= rotl(x[3] + x[2], 18);
    x[6] ^= rotl(x[5] + x[4], 7);
    x[7] ^= rotl(x[6] + x[5], 9);
    x[4] ^= rotl(x[7] + x[6], 13);
    x[5] ^= rotl(x[4] + x[7], 18);
    x[11] ^= rotl(x[10] + x[9], 7);
    x[8] ^= rotl(x[11] + x[10], 9);
    x[9] ^= rotl(x[8] + x[11], 13);
    x[10] ^= rotl(x[9] + x[8], 18);
    x[12] ^= rotl(x[15] + x[14], 7);
    x[13] ^= rotl(x[12] + x[15], 9);
    x[14] ^= rotl(x[13] + x[12], 13);
    x[15] ^= rotl(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; i++) B[i] = (B[i] + x[i]) | 0;
}

/** BlockMix：B 为 32r 个 32 位字，Y 为同尺寸临时区 */
function blockMix(B, Y, r) {
  const X = new Int32Array(16);
  X.set(B.subarray((2 * r - 1) * 16, (2 * r - 1) * 16 + 16));
  for (let i = 0; i < 2 * r; i++) {
    for (let j = 0; j < 16; j++) X[j] ^= B[i * 16 + j];
    salsa208(X);
    Y.set(X, i * 16);
  }
  // 偶数块在前、奇数块在后
  for (let i = 0; i < r; i++) B.set(Y.subarray(2 * i * 16, 2 * i * 16 + 16), i * 16);
  for (let i = 0; i < r; i++) B.set(Y.subarray((2 * i + 1) * 16, (2 * i + 1) * 16 + 16), (r + i) * 16);
}

function romix(B, N, r) {
  const words = 32 * r;
  const X = new Int32Array(B);
  const V = new Int32Array(N * words);
  const Y = new Int32Array(words);
  for (let i = 0; i < N; i++) {
    V.set(X, i * words);
    blockMix(X, Y, r);
  }
  for (let i = 0; i < N; i++) {
    const j = X[(2 * r - 1) * 16] & (N - 1);
    const off = j * words;
    for (let k = 0; k < words; k++) X[k] ^= V[off + k];
    blockMix(X, Y, r);
  }
  return X;
}

async function pbkdf2Sha256(password, salt, iterations, dkLen) {
  const key = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key,
    dkLen * 8,
  );
  return new Uint8Array(bits);
}

/**
 * scrypt 派生（与 Aegis 的 SCrypt.generate 等价）
 * @param {string|Uint8Array} password
 * @param {string|Uint8Array} salt
 * @param {{n?:number, r?:number, p?:number, dkLen?:number}} params
 */
export async function scrypt(
  password,
  salt,
  { n = AEGIS_SCRYPT.n, r = AEGIS_SCRYPT.r, p = AEGIS_SCRYPT.p, dkLen = KEY_SIZE } = {},
) {
  if (!Number.isInteger(n) || n < 2 || (n & (n - 1)) !== 0) throw new Error('scrypt 的 N 必须是 2 的幂');
  if (!Number.isInteger(r) || r < 1) throw new Error('scrypt 的 r 非法');
  if (!Number.isInteger(p) || p < 1) throw new Error('scrypt 的 p 非法');
  const pw = typeof password === 'string' ? enc.encode(password) : password;
  const sl = typeof salt === 'string' ? enc.encode(salt) : salt;
  const blockBytes = 128 * r;
  const B = new Uint8Array(await pbkdf2Sha256(pw, sl, 1, p * blockBytes));
  for (let i = 0; i < p; i++) {
    const offset = i * blockBytes;
    const words = new Int32Array(B.buffer, B.byteOffset + offset, blockBytes / 4);
    const out = romix(words, n, r);
    new Int32Array(B.buffer, B.byteOffset + offset, blockBytes / 4).set(out);
  }
  return pbkdf2Sha256(pw, B, 1, dkLen);
}

/* ============================== AES-256-GCM ============================== */

async function aesKey(raw) {
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** 加密并拆出 tag（与 Aegis 的 CryptResult 一致：data 不含 tag） */
async function gcmEncrypt(keyBytes, plaintext, nonce = randomBytes(NONCE_SIZE)) {
  const key = await aesKey(keyBytes);
  const out = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: TAG_SIZE * 8 }, key, plaintext),
  );
  return {
    data: out.subarray(0, out.length - TAG_SIZE),
    nonce,
    tag: out.subarray(out.length - TAG_SIZE),
  };
}

async function gcmDecrypt(keyBytes, data, nonce, tag) {
  const key = await aesKey(keyBytes);
  const joined = new Uint8Array(data.length + tag.length);
  joined.set(data, 0);
  joined.set(tag, data.length);
  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: TAG_SIZE * 8 }, key, joined),
  );
}

/* ============================== 识别 ============================== */

/** 是否是 Aegis 导出文件（明文或加密） */
export function isAegisFile(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  if (typeof obj.version !== 'number' || !obj.header || typeof obj.header !== 'object') return false;
  return typeof obj.db === 'string' || (obj.db && typeof obj.db === 'object');
}

/** 是否是加密的 Aegis 导出 */
export function isEncryptedAegis(obj) {
  return isAegisFile(obj) && typeof obj.db === 'string';
}

/* ============================== 导入 ============================== */

const SUPPORTED_TYPES = new Set(['totp', 'hotp', 'steam']);

function aegisTypeToTotp(type, info) {
  const t = String(type || 'totp').toLowerCase();
  if (t === 'steam') {
    return normalizeTotp({
      secret: info.secret,
      issuer: 'Steam',
      account: '',
      algorithm: 'SHA1',
      digits: 5,
      period: 30,
      type: 'steam',
    });
  }
  if (t === 'hotp') {
    return normalizeTotp({
      secret: info.secret,
      algorithm: info.algo || 'SHA1',
      digits: info.digits || 6,
      type: 'hotp',
      counter: Number(info.counter) || 0,
    });
  }
  return normalizeTotp({
    secret: info.secret,
    algorithm: info.algo || 'SHA1',
    digits: info.digits || 6,
    period: Number(info.period) || 30,
    type: 'totp',
  });
}

/**
 * 解析 Aegis 明文 db 对象
 * @returns {{entries: object[], groups: {id:string,name:string}[], skipped: object[]}}
 */
export function parseAegisDb(db) {
  if (!db || typeof db !== 'object' || !Array.isArray(db.entries)) {
    throw new Error('Aegis 数据库结构不正确（缺少 entries）');
  }
  const groups = [];
  const groupIds = new Set();
  for (const g of Array.isArray(db.groups) ? db.groups : []) {
    const id = String(g?.uuid || g?.id || '').trim();
    const name = String(g?.name || '').trim();
    if (!id || !name || groupIds.has(id)) continue;
    groupIds.add(id);
    groups.push({ id, name });
  }

  const entries = [];
  const skipped = [];
  const ts = new Date().toISOString();
  for (const raw of db.entries) {
    if (!raw || typeof raw !== 'object') continue;
    const type = String(raw.type || 'totp').toLowerCase();
    const info = raw.info || {};
    const label = String(raw.issuer || raw.name || '未命名');
    if (!SUPPORTED_TYPES.has(type)) {
      skipped.push({ name: label, reason: `暂不支持 ${type} 类型（Aegis 的 mOTP / Yandex）` });
      continue;
    }
    if (!info.secret) {
      skipped.push({ name: label, reason: '缺少密钥' });
      continue;
    }
    let totp;
    try {
      totp = aegisTypeToTotp(type, info);
    } catch (err) {
      skipped.push({ name: label, reason: err.message });
      continue;
    }
    if (!totp) {
      skipped.push({ name: label, reason: '密钥无法解析' });
      continue;
    }
    const name = String(raw.name || '').trim();
    const issuer = String(raw.issuer || '').trim();
    totp.issuer = issuer || totp.issuer || '';
    totp.account = name || totp.account || '';
    const entryGroups = (Array.isArray(raw.groups) ? raw.groups : [])
      .map((g) => String(g || '').trim())
      .filter((g) => groupIds.has(g));
    entries.push({
      id: String(raw.uuid || '').trim() || uuid(),
      type: 'login',
      title: issuer || name || '2FA 条目',
      username: name,
      password: '',
      url: '',
      notes: String(raw.note || ''),
      tags: [],
      groups: entryGroups,
      favorite: Boolean(raw.favorite),
      totp,
      createdAt: ts,
      updatedAt: ts,
      deletedAt: null,
    });
  }
  return { entries, groups, skipped };
}

/** 用密码解开加密的 Aegis 导出，返回明文 db 对象 */
export async function decryptAegisFile(file, password) {
  if (!isEncryptedAegis(file)) throw new Error('这不是加密的 Aegis 导出文件');
  const slots = file.header?.slots;
  if (!Array.isArray(slots) || !slots.length) throw new Error('Aegis 文件里没有可用的密码槽');
  const params = file.header?.params;
  if (!params?.nonce || !params?.tag) throw new Error('Aegis 文件缺少数据库加密参数');

  let masterKey = null;
  let lastError = null;
  for (const slot of slots) {
    if (Number(slot?.type) !== 1) continue; // 只处理密码槽（0=raw, 2=生物识别）
    try {
      const salt = hexDecode(slot.salt);
      const slotKey = await scrypt(password, salt, {
        n: Number(slot.n) || AEGIS_SCRYPT.n,
        r: Number(slot.r) || AEGIS_SCRYPT.r,
        p: Number(slot.p) || AEGIS_SCRYPT.p,
        dkLen: KEY_SIZE,
      });
      const keyParams = slot.key_params || {};
      masterKey = await gcmDecrypt(
        slotKey,
        hexDecode(slot.key),
        hexDecode(keyParams.nonce),
        hexDecode(keyParams.tag),
      );
      break;
    } catch (err) {
      lastError = err;
    }
  }
  if (!masterKey) {
    throw new Error(lastError ? '密码不正确，无法解开 Aegis 备份' : 'Aegis 文件里没有密码槽');
  }

  const plain = await gcmDecrypt(
    masterKey,
    b64decode(file.db),
    hexDecode(params.nonce),
    hexDecode(params.tag),
  );
  let db;
  try {
    db = JSON.parse(new TextDecoder().decode(plain));
  } catch {
    throw new Error('解密成功但内容不是合法 JSON');
  }
  return db;
}

/**
 * 导入 Aegis 导出（自动识别明文 / 加密）
 * @param {string|object} input 文件内容
 * @param {{password?: string}} options 加密文件必须提供密码
 */
export async function importAegis(input, { password = '' } = {}) {
  let file;
  if (typeof input === 'string') {
    try {
      file = JSON.parse(input);
    } catch {
      throw new Error('不是合法的 JSON 文件');
    }
  } else {
    file = input;
  }
  if (!isAegisFile(file)) throw new Error('不是 Aegis 导出文件（缺少 version/header/db）');
  if (Number(file.version) > AEGIS_FILE_VERSION) {
    throw new Error(`Aegis 文件版本 ${file.version} 高于本应用支持的 ${AEGIS_FILE_VERSION}`);
  }

  let db;
  const encrypted = isEncryptedAegis(file);
  if (encrypted) {
    if (!password) {
      const err = new Error('这是加密的 Aegis 备份，需要输入导出时设置的密码');
      err.code = 'NEED_PASSWORD';
      throw err;
    }
    db = await decryptAegisFile(file, password);
  } else {
    db = file.db;
  }
  const parsed = parseAegisDb(db);
  return { ...parsed, encrypted, dbVersion: Number(db?.version) || 0 };
}

/* ============================== 导出 ============================== */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** 把任意 id 变成 Aegis 能接受的 UUID（非 UUID 时按内容稳定派生） */
export function toAegisUuid(id) {
  const value = String(id || '');
  if (UUID_RE.test(value)) return value.toLowerCase();
  // FNV-1a 双通道 → 16 字节 → v4 形态，保证同一 id 每次导出结果一致
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (c + i), 0x85ebca6b) >>> 0;
  }
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    bytes[i] = (h1 >>> (i * 8)) & 0xff;
    bytes[4 + i] = (h2 >>> (i * 8)) & 0xff;
    bytes[8 + i] = (h1 >>> ((i + 2) * 8)) & 0xff;
    bytes[12 + i] = (h2 >>> ((i + 2) * 8)) & 0xff;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const h = hexEncode(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function totpToAegisInfo(totp) {
  const type = totp.type === 'hotp' ? 'hotp' : totp.type === 'steam' ? 'steam' : 'totp';
  const info = {
    secret: String(totp.secret || '').replace(/\s+/g, '').toUpperCase(),
    algo: type === 'steam' ? 'SHA1' : String(totp.algorithm || 'SHA1').toUpperCase(),
    digits: type === 'steam' ? 5 : Number(totp.digits) || 6,
  };
  if (type === 'hotp') info.counter = Number(totp.counter) || 0;
  else info.period = Number(totp.period) || 30;
  return { type, info };
}

/**
 * 把本应用的保险库转成 Aegis 明文 db 对象
 * 只导出带 2FA 的条目（Aegis 是验证器，没有密码字段）
 */
export function buildAegisDb(vault) {
  const groups = (vault.groups || [])
    .filter((g) => g && !g.deletedAt && g.name)
    .map((g) => ({ uuid: toAegisUuid(g.id), name: String(g.name) }));
  const groupIdMap = new Map();
  (vault.groups || []).forEach((g) => {
    if (g && g.id) groupIdMap.set(g.id, toAegisUuid(g.id));
  });

  const entries = [];
  for (const e of vault.entries || []) {
    if (!e || e.deletedAt || !e.totp?.secret) continue;
    const { type, info } = totpToAegisInfo(e.totp);
    entries.push({
      type,
      uuid: toAegisUuid(e.id),
      name: String(e.totp.account || e.username || e.title || ''),
      issuer: String(e.totp.issuer || e.title || ''),
      note: String(e.notes || ''),
      favorite: Boolean(e.favorite),
      icon: null,
      info,
      groups: (e.groups || []).map((g) => groupIdMap.get(g)).filter(Boolean),
    });
  }
  return { version: AEGIS_DB_VERSION, entries, groups, icons_optimized: true };
}

/** 生成 Aegis 明文导出文件对象 */
export function buildAegisPlain(vault) {
  return {
    version: AEGIS_FILE_VERSION,
    header: { slots: null, params: null },
    db: buildAegisDb(vault),
  };
}

/** 生成 Aegis 加密导出文件对象（scrypt + AES-256-GCM，与 Aegis 完全一致） */
export async function buildAegisEncrypted(vault, password, { scryptParams = AEGIS_SCRYPT } = {}) {
  if (!password) throw new Error('加密导出需要设置密码');
  const db = buildAegisDb(vault);
  const masterKey = randomBytes(KEY_SIZE);

  const salt = randomBytes(KEY_SIZE);
  const slotKey = await scrypt(password, salt, { ...scryptParams, dkLen: KEY_SIZE });
  const slotUuid = uuid();
  const slotCrypt = await gcmEncrypt(slotKey, masterKey);

  const dbCrypt = await gcmEncrypt(masterKey, enc.encode(JSON.stringify(db)));

  return {
    version: AEGIS_FILE_VERSION,
    header: {
      slots: [
        {
          type: 1,
          uuid: slotUuid,
          key: hexEncode(slotCrypt.data),
          key_params: {
            nonce: hexEncode(slotCrypt.nonce),
            tag: hexEncode(slotCrypt.tag),
          },
          n: scryptParams.n,
          r: scryptParams.r,
          p: scryptParams.p,
          salt: hexEncode(salt),
          repaired: false,
          is_backup: false,
        },
      ],
      params: {
        nonce: hexEncode(dbCrypt.nonce),
        tag: hexEncode(dbCrypt.tag),
      },
    },
    db: b64encode(dbCrypt.data),
  };
}

/**
 * 导出为 Aegis 文件文本
 * @param {object} vault
 * @param {{password?: string}} options 传 password 则导出加密版
 */
export async function exportAegis(vault, { password = '' } = {}) {
  const file = password ? await buildAegisEncrypted(vault, password) : buildAegisPlain(vault);
  return JSON.stringify(file, null, 2);
}

/** 统计能导出多少条（用于界面提示） */
export function countAegisExportable(vault) {
  return (vault.entries || []).filter((e) => e && !e.deletedAt && e.totp?.secret).length;
}
