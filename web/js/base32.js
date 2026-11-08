// RFC 4648 Base32（2FA 密钥标准编码）
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Base32 字符串 -> 字节数组；自动忽略空格、连字符、填充符与大小写 */
export function base32Decode(input) {
  const clean = String(input ?? '')
    .toUpperCase()
    .replace(/[\s\-_=.]/g, '')
    .replace(/0/g, 'O')
    .replace(/1/g, 'I');
  if (!clean) return new Uint8Array(0);

  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`无效的 Base32 字符：${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** 字节数组 -> Base32（无填充） */
export function base32Encode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of u8) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** 判断字符串是否像 Base32 密钥 */
export function looksLikeBase32(str) {
  const s = String(str ?? '').replace(/[\s\-=]/g, '');
  return s.length >= 8 && /^[A-Za-z2-7]+$/.test(s);
}
