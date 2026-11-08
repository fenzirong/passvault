// 核心逻辑单元测试：node --test tests/
import test from 'node:test';
import assert from 'node:assert/strict';

import { base32Decode, base32Encode } from '../web/js/base32.js';
import { totp, hotp, parseOtpauthUri, buildOtpauthUri, normalizeTotp } from '../web/js/totp.js';
import { parseGoogleMigration, parseAegis, parseTotpText } from '../web/js/migration.js';
import {
  createEmptyVault,
  sealVault,
  openVault,
  decryptWithKey,
  deriveKey,
  KDF_ITERATIONS,
} from '../web/js/crypto.js';
import {
  normalizeEntry,
  mergeVaults,
  deleteEntry,
  searchEntries,
  exportCsv,
  parseCsvImport,
  exportJson,
  parseJsonImport,
} from '../web/js/vault.js';
import { generatePassword, generatePassphrase, estimateEntropy, buildPool } from '../web/js/generator.js';
import { b64urlEncode, nowISO } from '../web/js/util.js';

/* ------------------------------ Base32 ------------------------------ */

test('Base32 编解码往返', () => {
  const text = 'Hello, 密码保险库!';
  const bytes = new TextEncoder().encode(text);
  const encoded = base32Encode(bytes);
  assert.match(encoded, /^[A-Z2-7]+$/);
  assert.deepEqual(Array.from(base32Decode(encoded)), Array.from(bytes));
});

test('Base32 容忍空格、连字符与小写', () => {
  const a = base32Decode('JBSWY3DPEHPK3PXP');
  const b = base32Decode('jbsw y3dp-ehpk 3pxp');
  assert.deepEqual(Array.from(a), Array.from(b));
});

/* ------------------------------ TOTP ------------------------------ */

const RFC_SECRET = base32Encode(new TextEncoder().encode('12345678901234567890'));

test('TOTP 符合 RFC 6238 测试向量（SHA1 / 8 位）', async () => {
  const vectors = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];
  for (const [t, expected] of vectors) {
    const code = await totp({ secret: RFC_SECRET, digits: 8, period: 30, timestamp: t * 1000 });
    assert.equal(code, expected, `T=${t}`);
  }
});

test('HOTP 计数器与位数', async () => {
  const code = await hotp({ secret: RFC_SECRET, counter: 0, digits: 6 });
  assert.equal(code.length, 6);
  const code8 = await hotp({ secret: RFC_SECRET, counter: 0, digits: 8 });
  assert.equal(code8.length, 8);
});

test('解析 otpauth:// 链接', () => {
  const uri =
    'otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60';
  const parsed = parseOtpauthUri(uri);
  assert.equal(parsed.type, 'totp');
  assert.equal(parsed.issuer, 'GitHub');
  assert.equal(parsed.account, 'alice@example.com');
  assert.equal(parsed.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(parsed.algorithm, 'SHA256');
  assert.equal(parsed.digits, 8);
  assert.equal(parsed.period, 60);

  const rebuilt = buildOtpauthUri(parsed);
  const again = parseOtpauthUri(rebuilt);
  assert.equal(again.secret, parsed.secret);
  assert.equal(again.issuer, parsed.issuer);
});

test('拒绝无效的 2FA 密钥', () => {
  assert.throws(() => normalizeTotp({ secret: '!!!' }));
  assert.equal(normalizeTotp({ secret: '' }), null);
});

/* --------------------- Google Authenticator 迁移包 --------------------- */

function varint(n) {
  const out = [];
  let v = n;
  while (v > 0x7f) {
    out.push((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return Uint8Array.from(out);
}
function field(num, wire, payload) {
  const tag = varint(num * 8 + wire);
  if (wire === 0) return Uint8Array.from([...tag, ...varint(payload)]);
  const len = varint(payload.length);
  return Uint8Array.from([...tag, ...len, ...payload]);
}
function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

test('解析 Google Authenticator 迁移链接', () => {
  const secretBytes = base32Decode('JBSWY3DPEHPK3PXP');
  const otp = concat([
    field(1, 2, secretBytes),
    field(2, 2, new TextEncoder().encode('alice@example.com')),
    field(3, 2, new TextEncoder().encode('GitHub')),
    field(4, 0, 1), // SHA1
    field(5, 0, 1), // 6 位
    field(6, 0, 2), // TOTP
  ]);
  const payload = concat([field(1, 2, otp), field(2, 0, 1), field(3, 0, 1), field(4, 0, 0), field(5, 0, 1)]);
  const uri = `otpauth-migration://offline?data=${encodeURIComponent(b64urlEncode(payload))}`;
  const list = parseGoogleMigration(uri);
  assert.equal(list.length, 1);
  assert.equal(list[0].secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(list[0].issuer, 'GitHub');
  assert.equal(list[0].account, 'alice@example.com');
  assert.equal(list[0].digits, 6);
});

test('解析 Aegis 与纯文本密钥', () => {
  const aegis = {
    version: 1,
    entries: [
      {
        type: 'totp',
        name: 'bob@example.com',
        issuer: 'GitLab',
        info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 },
      },
    ],
  };
  const list = parseAegis(aegis);
  assert.equal(list[0].issuer, 'GitLab');

  const text = parseTotpText('GitHub,alice,JBSWY3DPEHPK3PXP\nJBSWY3DPEHPK3PXP');
  assert.equal(text.length, 2);
  assert.equal(text[0].issuer, 'GitHub');
});

/* ------------------------------ 加密 ------------------------------ */

test('保险库加密 / 解密 / 错误密码', async () => {
  const vault = createEmptyVault();
  vault.entries.push(normalizeEntry({ title: '测试', username: 'u', password: 'p' }));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey('correct horse battery staple', salt, 120_000);
  const header = { revision: 3, updatedAt: nowISO(), deviceId: 'dev-1' };
  const env = await sealVault(vault, key, { salt, iterations: 120_000, header });

  assert.equal(env.format, 'dsh-passvault');
  assert.equal(env.header.revision, 3);

  const opened = await openVault(env, 'correct horse battery staple');
  assert.equal(opened.vault.entries[0].title, '测试');
  assert.equal(opened.header.revision, 3);

  await assert.rejects(() => openVault(env, 'wrong password'), (err) => err.code === 'BAD_PASSWORD');

  // 篡改头部（AAD）必须导致解密失败
  const tampered = JSON.parse(JSON.stringify(env));
  tampered.header.revision = 4;
  await assert.rejects(() => openVault(tampered, 'correct horse battery staple'));

  // 用已有密钥直接解密
  const direct = await decryptWithKey(env, key);
  assert.equal(direct.entries.length, 1);
});

test('默认 KDF 迭代次数符合 OWASP 建议', () => {
  assert.ok(KDF_ITERATIONS >= 600_000);
});

/* ------------------------------ 合并 ------------------------------ */

test('合并保险库：按更新时间取新，删除墓碑生效', () => {
  const base = createEmptyVault();
  const local = createEmptyVault();
  const remote = createEmptyVault();

  const a = normalizeEntry({ id: 'a', title: 'A', password: 'old', updatedAt: '2024-01-01T00:00:00.000Z' });
  const aNew = { ...a, password: 'new', updatedAt: '2024-02-01T00:00:00.000Z' };
  local.entries.push(aNew);
  remote.entries.push(a);

  const b = normalizeEntry({ id: 'b', title: 'B', updatedAt: '2024-01-01T00:00:00.000Z' });
  remote.entries.push(b);

  const c = normalizeEntry({ id: 'c', title: 'C', updatedAt: '2024-01-01T00:00:00.000Z' });
  local.entries.push(c);
  deleteEntry(local, 'c');

  const { vault, stats } = mergeVaults(local, remote);
  const byId = Object.fromEntries(vault.entries.map((e) => [e.id, e]));
  assert.equal(byId.a.password, 'new');
  assert.ok(byId.b);
  assert.ok(byId.c.deletedAt, '删除墓碑应保留');
  assert.equal(stats.added, 1);
  void base;
});

/* ------------------------------ 搜索 ------------------------------ */

test('搜索支持中文与多关键词', () => {
  const entries = [
    normalizeEntry({ title: '公司邮箱', username: 'me@corp.com', tags: ['工作'] }),
    normalizeEntry({ title: 'GitHub', username: 'alice', url: 'https://github.com' }),
  ];
  assert.equal(searchEntries(entries, '邮箱').length, 1);
  assert.equal(searchEntries(entries, '工作 me').length, 1);
  assert.equal(searchEntries(entries, 'github').length, 1);
  assert.equal(searchEntries(entries, '').length, 2);
});

/* ------------------------------ CSV ------------------------------ */

test('CSV 导出后可再次导入', () => {
  const entries = [
    normalizeEntry({
      title: '示例, 带逗号',
      username: 'user',
      password: 'p"a,ss',
      url: 'https://example.com',
      notes: '第一行\n第二行',
      totp: { secret: 'JBSWY3DPEHPK3PXP' },
    }),
  ];
  const csv = exportCsv(entries);
  const parsed = parseCsvImport(csv);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].title, '示例, 带逗号');
  assert.equal(parsed[0].password, 'p"a,ss');
  assert.equal(parsed[0].notes, '第一行\n第二行');
  assert.equal(parsed[0].totp.secret, 'JBSWY3DPEHPK3PXP');
});

test('兼容 Chrome / KeePass 风格 CSV 表头', () => {
  const chrome = 'name,url,username,password\nGitHub,https://github.com,alice,secret123\n';
  const parsed = parseCsvImport(chrome);
  assert.equal(parsed[0].title, 'GitHub');
  assert.equal(parsed[0].username, 'alice');

  const keepass = '\uFEFF"Account","Login Name","Password","Web Site","Comments"\n"邮箱","me","pw","mail.com","备注"\n';
  const parsed2 = parseCsvImport(keepass);
  assert.equal(parsed2[0].title, '邮箱');
  assert.equal(parsed2[0].url, 'mail.com');
});

test('JSON 导出后可再次导入', () => {
  const vault = createEmptyVault();
  vault.entries.push(normalizeEntry({ title: 'X', username: 'u', password: 'p' }));
  const json = exportJson(vault);
  const parsed = parseJsonImport(json);
  assert.equal(parsed[0].title, 'X');
});

/* ------------------------------ 生成器 ------------------------------ */

test('密码生成满足长度与字符集要求', () => {
  for (let i = 0; i < 30; i++) {
    const pw = generatePassword({ length: 24, upper: true, lower: true, digits: true, symbols: true });
    assert.equal(pw.length, 24);
    assert.match(pw, /[A-Z]/);
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[0-9]/);
    assert.match(pw, /[^A-Za-z0-9]/);
  }
});

test('排除易混淆字符', () => {
  const pool = buildPool({ upper: true, lower: true, digits: true, symbols: false, excludeAmbiguous: true });
  for (const ch of '0O1lI|') assert.ok(!pool.includes(ch), ch);
});

test('自定义字符生效', () => {
  const pw = generatePassword({ length: 40, upper: false, lower: false, digits: false, symbols: false, customChars: '密码' });
  assert.match(pw, /^[密码]+$/);
});

test('易记短语与熵估算', () => {
  const phrase = generatePassphrase({ words: 5, separator: '-', capitalize: true });
  assert.equal(phrase.split('-').length, 5);
  const bits = estimateEntropy({ mode: 'passphrase', words: 5 });
  assert.ok(bits > 40);
  const bits2 = estimateEntropy({ mode: 'password', length: 20, upper: true, lower: true, digits: true, symbols: true });
  assert.ok(bits2 > 100);
});
