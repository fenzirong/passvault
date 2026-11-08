// 保险库加密：PBKDF2-SHA256 派生密钥 + AES-256-GCM 认证加密
// 参考：OWASP Password Storage Cheat Sheet、WebCrypto API 规范
import { b64encode, b64decode, enc, dec, randomBytes, nowISO } from './util.js';

export const VAULT_FORMAT = 'dsh-passvault';
export const VAULT_VERSION = 1;
/** 默认 KDF 迭代次数（OWASP 2023 对 PBKDF2-SHA256 的建议为 600000） */
export const KDF_ITERATIONS = 600_000;
export const MIN_KDF_ITERATIONS = 100_000;

const subtle = globalThis.crypto.subtle;

/** 由主密码派生 AES-GCM 密钥 */
export async function deriveKey(password, salt, iterations = KDF_ITERATIONS) {
  const baseKey = await subtle.importKey('raw', enc.encode(String(password)), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** 附加认证数据：把版本号与同步元数据绑定进密文，防止被篡改 */
export function buildAAD(header) {
  return enc.encode(
    [VAULT_FORMAT, VAULT_VERSION, header.revision, header.updatedAt, header.deviceId].join('|'),
  );
}

/**
 * 加密保险库
 * @param {object} vault 明文保险库对象
 * @param {CryptoKey} key 由 deriveKey 得到的密钥
 * @param {{salt: Uint8Array, iterations: number, header: object}} params
 */
export async function sealVault(vault, key, { salt, iterations, header }) {
  const iv = randomBytes(12);
  const plaintext = enc.encode(JSON.stringify(vault));
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: buildAAD(header), tagLength: 128 },
    key,
    plaintext,
  );
  return {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    kdf: { name: 'PBKDF2-SHA256', iterations, salt: b64encode(salt) },
    cipher: { name: 'AES-256-GCM', iv: b64encode(iv) },
    header: { ...header },
    data: b64encode(new Uint8Array(ciphertext)),
  };
}

/**
 * 解密保险库；主密码错误或数据被篡改时抛出异常
 * @returns {{vault: object, key: CryptoKey, salt: Uint8Array, iterations: number, header: object}}
 */
export async function openVault(envelope, password) {
  assertEnvelope(envelope);
  const salt = b64decode(envelope.kdf.salt);
  const iv = b64decode(envelope.cipher.iv);
  const iterations = Number(envelope.kdf.iterations) || KDF_ITERATIONS;
  const key = await deriveKey(password, salt, iterations);
  let plaintext;
  try {
    plaintext = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: buildAAD(envelope.header),
        tagLength: 128,
      },
      key,
      b64decode(envelope.data),
    );
  } catch {
    const err = new Error('主密码错误，或保险库文件已损坏');
    err.code = 'BAD_PASSWORD';
    throw err;
  }
  let vault;
  try {
    vault = JSON.parse(dec.decode(plaintext));
  } catch {
    const err = new Error('保险库内容无法解析');
    err.code = 'BAD_PAYLOAD';
    throw err;
  }
  return { vault, key, salt, iterations, header: envelope.header };
}

/** 用已有密钥直接解密（同步时无需再次输入主密码） */
export async function decryptWithKey(envelope, key) {
  assertEnvelope(envelope);
  const iv = b64decode(envelope.cipher.iv);
  let plaintext;
  try {
    plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: buildAAD(envelope.header), tagLength: 128 },
      key,
      b64decode(envelope.data),
    );
  } catch {
    const err = new Error('无法解密服务器上的保险库：主密码可能不同');
    err.code = 'BAD_PASSWORD';
    throw err;
  }
  return JSON.parse(dec.decode(plaintext));
}

/** 用新主密码重新加密（保持条目与元数据不变） */
export async function changeMasterPassword(envelope, oldPassword, newPassword) {
  const { vault, header } = await openVault(envelope, oldPassword);
  const salt = randomBytes(16);
  const iterations = KDF_ITERATIONS;
  const key = await deriveKey(newPassword, salt, iterations);
  const nextHeader = { ...header, updatedAt: nowISO() };
  const next = await sealVault(vault, key, { salt, iterations, header: nextHeader });
  return { envelope: next, key, salt, iterations, vault, header: nextHeader };
}

export function assertEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') throw new Error('不是有效的保险库文件');
  if (envelope.format !== VAULT_FORMAT) throw new Error('文件格式不受支持（缺少 dsh-passvault 标识）');
  if (!envelope.kdf?.salt || !envelope.cipher?.iv || !envelope.data) {
    throw new Error('保险库文件结构不完整');
  }
  if (!envelope.header || typeof envelope.header.revision !== 'number') {
    throw new Error('保险库文件缺少同步元数据');
  }
  if (Number(envelope.kdf.iterations) < MIN_KDF_ITERATIONS) {
    throw new Error('保险库的密钥派生参数过弱，已拒绝加载');
  }
}

/** 生成全新的空保险库 */
export function createEmptyVault() {
  const ts = nowISO();
  return {
    schema: 1,
    createdAt: ts,
    updatedAt: ts,
    entries: [],
    settings: {
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
      },
    },
  };
}
