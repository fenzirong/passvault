// 生物识别解锁：WebAuthn PRF（浏览器 / Electron）+ 安卓原生 Keystore（Capacitor）
// 原理：用指纹/面容派生的密钥包裹保险库主密钥，解锁时不需要输入主密码。
import { b64encode, b64decode, randomBytes, nowISO } from './util.js';

const STORAGE_KEY = 'pm.bio';
const RP_NAME = '密码保险库';

/* ------------------------------ 存储 ------------------------------ */

export function loadRecord() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const rec = JSON.parse(raw);
    return rec && rec.type ? rec : null;
  } catch {
    return null;
  }
}

export function saveRecord(record) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
}

export function clearRecord() {
  localStorage.removeItem(STORAGE_KEY);
}

/* ------------------------------ 原生插件 ------------------------------ */

function nativePlugin() {
  const cap = globalThis.Capacitor;
  if (!cap?.isNativePlatform?.()) return null;
  return cap.Plugins?.PassVaultBiometric || null;
}

/* ------------------------------ 能力检测 ------------------------------ */

/** WebAuthn 的 rp.id 必须是域名，IP 源（如 192.168.1.10）无法使用 */
function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

export async function isSupported() {
  const native = nativePlugin();
  if (native) {
    try {
      const res = await native.isAvailable();
      return Boolean(res?.available);
    } catch {
      return false;
    }
  }
  if (!globalThis.PublicKeyCredential) return false;
  if (isIpHost(location.hostname)) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/* ------------------------------ WebAuthn ------------------------------ */

function toB64Url(bytes) {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64Url(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return b64decode(s);
}

async function prfKeyFromOutput(output) {
  // PRF 输出是 32 字节，直接作为 AES-256 密钥
  return crypto.subtle.importKey('raw', output, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function webauthnEnroll(rawKey) {
  const salt = randomBytes(32);
  const userId = randomBytes(16);
  const challenge = randomBytes(32);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: RP_NAME, id: location.hostname },
      user: { id: userId, name: 'vault', displayName: RP_NAME },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred',
      },
      timeout: 60_000,
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  if (!credential) throw new Error('未能创建生物识别凭据');

  const ext = credential.getClientExtensionResults?.() || {};
  if (!ext.prf?.enabled) {
    throw new Error('该设备不支持 PRF 扩展，无法用于加密解锁');
  }

  // 创建时通常拿不到 PRF 结果，需要再断言一次
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ id: credential.rawId, type: 'public-key' }],
      userVerification: 'required',
      timeout: 60_000,
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const prf = assertion?.getClientExtensionResults?.()?.prf?.results?.first;
  if (!prf) throw new Error('未能获取生物识别密钥材料');

  const kek = await prfKeyFromOutput(new Uint8Array(prf));
  const iv = randomBytes(12);
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, rawKey);

  return {
    type: 'webauthn',
    credentialId: toB64Url(new Uint8Array(credential.rawId)),
    salt: toB64Url(salt),
    iv: b64encode(iv),
    wrapped: b64encode(new Uint8Array(wrapped)),
    createdAt: nowISO(),
  };
}

async function webauthnUnlock(record) {
  const salt = fromB64Url(record.salt);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ id: fromB64Url(record.credentialId), type: 'public-key' }],
      userVerification: 'required',
      timeout: 60_000,
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const prf = assertion?.getClientExtensionResults?.()?.prf?.results?.first;
  if (!prf) throw new Error('生物识别验证未返回密钥材料');

  const kek = await prfKeyFromOutput(new Uint8Array(prf));
  try {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(record.iv) },
      kek,
      b64decode(record.wrapped),
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error('生物识别密钥已失效，请用主密码解锁后重新启用');
  }
}

/* ------------------------------ 对外接口 ------------------------------ */

/** 启用生物识别：用当前保险库密钥生成包裹记录 */
export async function enroll(rawKey) {
  const native = nativePlugin();
  if (native) {
    const value = b64encode(rawKey);
    await native.save({ key: 'vault-key', value });
    const record = { type: 'native', createdAt: nowISO() };
    saveRecord(record);
    return record;
  }
  const record = await webauthnEnroll(rawKey);
  saveRecord(record);
  return record;
}

/** 用生物识别取回保险库密钥 */
export async function unlock(record = loadRecord()) {
  if (!record) throw new Error('尚未启用生物识别解锁');
  if (record.type === 'native') {
    const native = nativePlugin();
    if (!native) throw new Error('当前环境不支持原生生物识别');
    const res = await native.load({ key: 'vault-key' });
    if (!res?.value) throw new Error('未能读取生物识别密钥');
    return b64decode(res.value);
  }
  return webauthnUnlock(record);
}

/** 关闭生物识别 */
export async function disable() {
  const record = loadRecord();
  clearRecord();
  const native = nativePlugin();
  if (native && record?.type === 'native') {
    try {
      await native.delete({ key: 'vault-key' });
    } catch {
      /* 忽略 */
    }
  }
  return true;
}

export function describe(record = loadRecord()) {
  if (!record) return '';
  return record.type === 'native' ? '系统生物识别' : '指纹 / 面容（WebAuthn）';
}
