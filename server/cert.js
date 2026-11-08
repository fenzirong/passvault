// 自动生成自签名证书（纯 Node 实现，无需 openssl）
// 用途：安卓浏览器只有在 HTTPS 下才允许使用 WebCrypto（加密保险库必需）
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/* ------------------------------ ASN.1 编码 ------------------------------ */

function derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

const seq = (...items) => tlv(0x30, Buffer.concat(items));
const set = (...items) => tlv(0x31, Buffer.concat(items));
const integer = (buf) => tlv(0x02, buf);
const octetString = (buf) => tlv(0x04, buf);
const utf8String = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const ia5String = (s) => tlv(0x16, Buffer.from(s, 'ascii'));
const bitString = (buf, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), buf]));
const utcTime = (date) => tlv(0x17, Buffer.from(formatUtc(date), 'ascii'));
const explicit = (n, content) => tlv(0xa0 | n, content);
const boolean = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0x00]));

function encodeOid(oid) {
  const parts = oid.split('.').map(Number);
  const bytes = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let v = Math.floor(part / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    bytes.push(...stack);
  }
  return tlv(0x06, Buffer.from(bytes));
}

function formatUtc(date) {
  const p = (n) => String(n).padStart(2, '0');
  return (
    String(date.getUTCFullYear()).slice(2) +
    p(date.getUTCMonth() + 1) +
    p(date.getUTCDate()) +
    p(date.getUTCHours()) +
    p(date.getUTCMinutes()) +
    p(date.getUTCSeconds()) +
    'Z'
  );
}

/* ------------------------------ 证书生成 ------------------------------ */

const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_CN = '2.5.4.3';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_SAN = '2.5.29.17';
const OID_SERVER_AUTH = '1.3.6.1.5.5.7.3.1';

function extension(oid, critical, value) {
  return seq(encodeOid(oid), ...(critical ? [boolean(true)] : []), octetString(value));
}

function lanIPv4() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const item of list || []) {
      if (item.family === 'IPv4' && !item.internal) out.push(item.address);
    }
  }
  return out;
}

/**
 * 生成自签名证书（ECDSA P-256 / SHA-256），包含本机所有局域网 IP 的 SAN
 * @returns {{cert: string, key: string}} PEM 文本
 */
export function generateSelfSignedCert({ commonName = 'PassVault Local', days = 825 } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = publicKey.export({ type: 'spki', format: 'der' });

  const serial = crypto.randomBytes(16);
  serial[0] &= 0x7f; // 保证为正数

  const notBefore = new Date(Date.now() - 86_400_000);
  const notAfter = new Date(Date.now() + days * 86_400_000);

  const name = seq(set(seq(encodeOid(OID_CN), utf8String(commonName))));

  const dnsNames = ['localhost', os.hostname().toLowerCase(), 'passvault.local'].filter(Boolean);
  const ips = ['127.0.0.1', ...lanIPv4()];
  const generalNames = [
    ...dnsNames.map((d) => tlv(0x82, Buffer.from(d, 'ascii'))),
    ...ips.map((ip) => tlv(0x87, Buffer.from(ip.split('.').map(Number)))),
  ];

  const extensions = seq(
    extension(OID_BASIC_CONSTRAINTS, true, seq(boolean(true))),
    extension(OID_KEY_USAGE, true, bitString(Buffer.from([0xa0]), 5)),
    extension(OID_EXT_KEY_USAGE, false, seq(encodeOid(OID_SERVER_AUTH))),
    extension(OID_SAN, false, seq(...generalNames)),
  );

  const tbs = seq(
    explicit(0, integer(Buffer.from([2]))), // v3
    integer(serial),
    seq(encodeOid(OID_ECDSA_SHA256)),
    name,
    seq(utcTime(notBefore), utcTime(notAfter)),
    name,
    spki,
    explicit(3, extensions),
  );

  const signature = crypto.sign('sha256', tbs, privateKey);
  const certificate = seq(tbs, seq(encodeOid(OID_ECDSA_SHA256)), bitString(signature));

  const toPem = (der, label) =>
    `-----BEGIN ${label}-----\n${der
      .toString('base64')
      .match(/.{1,64}/g)
      .join('\n')}\n-----END ${label}-----\n`;

  return {
    cert: toPem(certificate, 'CERTIFICATE'),
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** 确保证书存在；不存在则生成并写入 dataDir */
export function ensureCert(dataDir) {
  const certPath = path.join(dataDir, 'cert.pem');
  const keyPath = path.join(dataDir, 'key.pem');
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    return { certPath, keyPath, created: false };
  }
  const { cert, key } = generateSelfSignedCert();
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(certPath, cert, { mode: 0o600 });
  fs.writeFileSync(keyPath, key, { mode: 0o600 });
  return { certPath, keyPath, created: true };
}
