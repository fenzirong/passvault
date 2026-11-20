// Aegis 兼容层与分组的回归测试
// 调用方：package.json 的 `npm test` → `node --test tests/*.test.mjs`
// 不读写任何数据文件，全部是内存运算。
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  AEGIS_SCRYPT,
  buildAegisEncrypted,
  buildAegisPlain,
  countAegisExportable,
  decryptAegisFile,
  exportAegis,
  hexDecode,
  importAegis,
  isAegisFile,
  isEncryptedAegis,
  parseAegisDb,
  scrypt,
  toAegisUuid,
} from '../web/js/aegis.js';
import { normalizeTotp, steam, totp } from '../web/js/totp.js';
import { deriveKey, exportRawKey, openVaultWithSecret, sealVault } from '../web/js/crypto.js';
import { enc, randomBytes } from '../web/js/util.js';
import {
  createGroup,
  deleteGroup,
  ensureGroups,
  entryKey,
  groupNameMap,
  mergeGroups,
  mergeVaults,
  normalizeEntry,
  renameGroup,
} from '../web/js/vault.js';

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/* ============================== scrypt ============================== */

test('scrypt 通过 RFC 7914 官方测试向量', async () => {
  // 向量 1：空密码、空盐
  assert.equal(
    hex(await scrypt('', '', { n: 16, r: 1, p: 1, dkLen: 64 })),
    '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442' +
      'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906',
  );
  // 向量 2：password / NaCl，N=1024 r=8 p=16
  assert.equal(
    hex(await scrypt('password', 'NaCl', { n: 1024, r: 8, p: 16, dkLen: 64 })),
    'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162' +
      '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
  );
  // 向量 3：pleaseletmein / SodiumChloride，N=16384 r=8 p=1
  assert.equal(
    hex(await scrypt('pleaseletmein', 'SodiumChloride', { n: 16384, r: 8, p: 1, dkLen: 64 })),
    '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2' +
      'd5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
  );
});

test('scrypt 参数非法时直接报错', async () => {
  await assert.rejects(() => scrypt('x', 'y', { n: 1000 }), /2 的幂/);
  await assert.rejects(() => scrypt('x', 'y', { n: 16, r: 0 }), /r 非法/);
  await assert.rejects(() => scrypt('x', 'y', { n: 16, p: 0 }), /p 非法/);
});

test('Aegis 默认 scrypt 参数与源码一致（N=32768, r=8, p=1）', () => {
  assert.deepEqual(AEGIS_SCRYPT, { n: 32768, r: 8, p: 1 });
});

/* ============================== Steam ============================== */

test('Steam 令牌按 Base-26 字符表生成（RFC 4226 密钥 + counter 0）', async () => {
  // 密钥 "12345678901234567890" 的 Base32；counter=0 时动态截断值为 1284755224
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(await steam({ secret, timestamp: 0 }), 'GG5F5');
  // totp() 在 type=steam 时必须走同一条路径
  assert.equal(await totp({ secret, timestamp: 0, type: 'steam' }), 'GG5F5');
  // 普通 TOTP 仍然是 6 位数字
  assert.match(await totp({ secret, timestamp: 0 }), /^\d{6}$/);
});

test('Steam 条目固定 5 位、SHA1', () => {
  const t = normalizeTotp({ secret: 'JBSWY3DPEHPK3PXP', type: 'steam', digits: 8, algorithm: 'SHA256' });
  assert.equal(t.type, 'steam');
  assert.equal(t.digits, 5);
  assert.equal(t.algorithm, 'SHA1');
});

/* ============================== 明文导入 ============================== */

function sampleAegisDb() {
  return {
    version: 3,
    entries: [
      {
        type: 'totp',
        uuid: '11111111-1111-4111-8111-111111111111',
        name: 'me@example.com',
        issuer: 'GitHub',
        note: '工作账号',
        favorite: true,
        icon: null,
        info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 6, period: 30 },
        groups: ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
      },
      {
        type: 'hotp',
        uuid: '22222222-2222-4222-8222-222222222222',
        name: 'counter-user',
        issuer: 'Legacy',
        note: '',
        favorite: false,
        icon: null,
        info: { secret: 'GEZDGNBVGY3TQOJQ', algo: 'SHA256', digits: 8, counter: 7 },
        groups: [],
      },
      {
        type: 'steam',
        uuid: '33333333-3333-4333-8333-333333333333',
        name: 'steamuser',
        issuer: 'Steam',
        note: '',
        favorite: false,
        icon: null,
        info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA1', digits: 5, period: 30 },
        groups: ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
      },
      {
        type: 'motp',
        uuid: '44444444-4444-4444-8444-444444444444',
        name: 'motp-user',
        issuer: 'Bank',
        note: '',
        favorite: false,
        icon: null,
        info: { secret: 'JBSWY3DPEHPK3PXP', pin: '1234' },
        groups: [],
      },
    ],
    groups: [{ uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: '工作' }],
    icons_optimized: true,
  };
}

test('明文 Aegis 备份：识别、解析条目与分组、跳过不支持的类型', () => {
  const file = { version: 1, header: { slots: null, params: null }, db: sampleAegisDb() };
  assert.equal(isAegisFile(file), true);
  assert.equal(isEncryptedAegis(file), false);

  const { entries, groups, skipped } = parseAegisDb(file.db);
  assert.equal(entries.length, 3, 'motp 应被跳过');
  assert.equal(skipped.length, 1);
  assert.match(skipped[0].reason, /motp/);

  assert.equal(groups.length, 1);
  assert.equal(groups[0].name, '工作');

  const gh = entries.find((e) => e.title === 'GitHub');
  // 与「自己新建的 2FA 条目」同形状：账号只放在 totp.account，不占 username
  assert.equal(gh.username, '');
  assert.equal(gh.totp.account, 'me@example.com');
  assert.equal(gh.notes, '工作账号');
  assert.equal(gh.favorite, true);
  assert.equal(gh.totp.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(gh.totp.type, 'totp');
  assert.deepEqual(gh.groups, ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']);

  const hotp = entries.find((e) => e.totp.type === 'hotp');
  assert.equal(hotp.totp.counter, 7);
  assert.equal(hotp.totp.digits, 8);
  assert.equal(hotp.totp.algorithm, 'SHA256');

  const st = entries.find((e) => e.totp.type === 'steam');
  assert.equal(st.totp.digits, 5);
});

test('importAegis 接受字符串与对象两种输入', async () => {
  const file = { version: 1, header: { slots: null, params: null }, db: sampleAegisDb() };
  const a = await importAegis(JSON.stringify(file));
  const b = await importAegis(file);
  assert.equal(a.entries.length, b.entries.length);
  assert.equal(a.encrypted, false);
  assert.equal(a.dbVersion, 3);
});

test('非 Aegis 文件给出明确错误', async () => {
  await assert.rejects(() => importAegis('{"foo":1}'), /不是 Aegis 导出文件/);
  await assert.rejects(() => importAegis('not json'), /不是合法的 JSON/);
  await assert.rejects(
    () => importAegis({ version: 9, header: {}, db: { entries: [] } }),
    /版本 9 高于/,
  );
});

/* ============================== 加密导入导出 ============================== */

const FAST = { n: 1024, r: 8, p: 1 };

function sampleVault() {
  const work = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: '工作' };
  const life = { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', name: '生活' };
  return {
    schema: 1,
    groups: [work, life],
    entries: [
      normalizeEntry({
        id: '11111111-1111-4111-8111-111111111111',
        title: 'GitHub',
        username: 'me@example.com',
        notes: '备注',
        favorite: true,
        groups: [work.id],
        totp: { secret: 'JBSWY3DPEHPK3PXP', issuer: 'GitHub', account: 'me@example.com' },
      }),
      normalizeEntry({
        id: '22222222-2222-4222-8222-222222222222',
        title: 'Steam',
        username: 'steamuser',
        groups: [work.id, life.id],
        totp: { secret: 'JBSWY3DPEHPK3PXP', type: 'steam', issuer: 'Steam', account: 'steamuser' },
      }),
      normalizeEntry({
        id: '33333333-3333-4333-8333-333333333333',
        title: '只有密码',
        username: 'nopass',
        password: 'secret',
      }),
    ],
  };
}

test('导出为 Aegis 明文：只带 2FA 条目，分组与类型正确', () => {
  const vault = sampleVault();
  assert.equal(countAegisExportable(vault), 2);
  const file = buildAegisPlain(vault);
  assert.equal(file.version, 1);
  assert.equal(file.header.slots, null);
  assert.equal(file.db.version, 3);
  assert.equal(file.db.entries.length, 2, '没有 2FA 的条目不该导出');
  assert.equal(file.db.groups.length, 2);

  const steamEntry = file.db.entries.find((e) => e.type === 'steam');
  assert.equal(steamEntry.info.digits, 5);
  assert.equal(steamEntry.info.algo, 'SHA1');
  assert.equal(steamEntry.groups.length, 2);

  const totpEntry = file.db.entries.find((e) => e.type === 'totp');
  assert.equal(totpEntry.info.period, 30);
  assert.equal(totpEntry.name, 'me@example.com');
  assert.equal(totpEntry.issuer, 'GitHub');
  assert.equal(totpEntry.note, '备注');
  assert.equal(totpEntry.favorite, true);
});

test('加密导出结构与 Aegis 一致（hex 参数 + Base64 db + 密码槽）', async () => {
  const vault = sampleVault();
  const file = await buildAegisEncrypted(vault, 'hunter2', { scryptParams: FAST });
  assert.equal(file.version, 1);
  assert.equal(typeof file.db, 'string');
  assert.equal(isEncryptedAegis(file), true);

  const slot = file.header.slots[0];
  assert.equal(slot.type, 1);
  assert.match(slot.uuid, /^[0-9a-f-]{36}$/);
  assert.equal(slot.n, FAST.n);
  assert.equal(slot.r, FAST.r);
  assert.equal(slot.p, FAST.p);
  assert.equal(slot.repaired, false);
  assert.equal(slot.is_backup, false);
  // 全部是十六进制，不是 Base64
  assert.match(slot.key, /^[0-9a-f]+$/);
  assert.match(slot.salt, /^[0-9a-f]+$/);
  assert.match(slot.key_params.nonce, /^[0-9a-f]{24}$/);
  assert.match(slot.key_params.tag, /^[0-9a-f]{32}$/);
  assert.match(file.header.params.nonce, /^[0-9a-f]{24}$/);
  assert.match(file.header.params.tag, /^[0-9a-f]{32}$/);
  // 主密钥密文 = 32 字节（tag 单独存放）
  assert.equal(hexDecode(slot.key).length, 32);
  assert.equal(hexDecode(slot.salt).length, 32);
});

test('加密导出 → 解密 → 内容与明文导出一致', async () => {
  const vault = sampleVault();
  const plain = buildAegisPlain(vault);
  const enc = await buildAegisEncrypted(vault, 'hunter2', { scryptParams: FAST });
  const db = await decryptAegisFile(enc, 'hunter2');
  assert.deepEqual(db, plain.db);
});

test('密码错误时报错而不是静默失败', async () => {
  const enc = await buildAegisEncrypted(sampleVault(), 'hunter2', { scryptParams: FAST });
  await assert.rejects(() => decryptAegisFile(enc, 'wrong'), /密码不正确/);
});

test('加密文件缺少密码时抛 NEED_PASSWORD', async () => {
  const enc = await buildAegisEncrypted(sampleVault(), 'hunter2', { scryptParams: FAST });
  await assert.rejects(
    () => importAegis(enc),
    (err) => err.code === 'NEED_PASSWORD',
  );
});

test('完整往返：加密导出 → 导入，条目/分组/类型都保住', async () => {
  const vault = sampleVault();
  const enc = await buildAegisEncrypted(vault, 'pw', { scryptParams: FAST });
  const result = await importAegis(enc, { password: 'pw' });
  assert.equal(result.entries.length, 2);
  assert.equal(result.groups.length, 2);
  assert.equal(result.encrypted, true);

  const steamEntry = result.entries.find((e) => e.totp.type === 'steam');
  assert.equal(steamEntry.totp.digits, 5);
  assert.equal(steamEntry.groups.length, 2);
});

test('明文导出文本能被自己导入（exportAegis 默认走明文）', async () => {
  const vault = sampleVault();
  const text = await exportAegis(vault);
  const parsed = JSON.parse(text);
  assert.equal(parsed.header.slots, null);
  const result = await importAegis(text);
  assert.equal(result.entries.length, 2);
  assert.equal(result.encrypted, false);
});

/* ============================== UUID 与分组 ============================== */

test('toAegisUuid 对合法 UUID 原样返回，对其它 id 稳定派生', () => {
  const id = '11111111-1111-4111-8111-111111111111';
  assert.equal(toAegisUuid(id), id);
  const a = toAegisUuid('not-a-uuid');
  const b = toAegisUuid('not-a-uuid');
  assert.equal(a, b, '同一 id 必须得到同一 UUID');
  assert.match(a, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(a, toAegisUuid('another-id'));
});

test('分组：创建 / 重名复用 / 重命名 / 删除并清理条目引用', () => {
  const vault = { entries: [], groups: [] };
  ensureGroups(vault);
  const work = createGroup(vault, '工作');
  assert.equal(vault.groups.length, 1);
  // 同名（忽略大小写与空格）不重复创建
  const again = createGroup(vault, ' 工作 ');
  assert.equal(again.id, work.id);
  assert.equal(vault.groups.length, 1);

  const entry = normalizeEntry({ title: 'A', groups: [work.id] });
  vault.entries.push(entry);

  assert.equal(renameGroup(vault, work.id, '公司'), true);
  assert.equal(groupNameMap(vault)[work.id], '公司');

  assert.equal(deleteGroup(vault, work.id), true);
  assert.notEqual(vault.groups[0].deletedAt, null);
  assert.deepEqual(entry.groups, [], '删除分组后条目引用要被清掉');
  assert.equal(groupNameMap(vault)[work.id], undefined);
});

test('mergeGroups 把导入分组映射到本地 id（同名复用）', () => {
  const vault = { entries: [], groups: [] };
  ensureGroups(vault);
  const existing = createGroup(vault, '工作');
  const map = mergeGroups(vault, [
    { id: 'imported-1', name: '工作' },
    { id: 'imported-2', name: '生活' },
  ]);
  assert.equal(map.get('imported-1'), existing.id, '同名分组应复用本地 id');
  assert.equal(vault.groups.length, 2);
  assert.equal(vault.groups.find((g) => g.name === '生活').id, map.get('imported-2'));
});

test('mergeVaults 会合并分组列表（按 id 取较新的名字）', () => {
  const local = {
    entries: [],
    groups: [{ id: 'g1', name: '旧名字', updatedAt: '2026-01-01T00:00:00.000Z' }],
  };
  const remote = {
    entries: [],
    groups: [
      { id: 'g1', name: '新名字', updatedAt: '2026-06-01T00:00:00.000Z' },
      { id: 'g2', name: '远端独有', updatedAt: '2026-06-01T00:00:00.000Z' },
    ],
  };
  const { vault } = mergeVaults(local, remote);
  assert.equal(vault.groups.length, 2);
  assert.equal(vault.groups.find((g) => g.id === 'g1').name, '新名字');
});

test('normalizeEntry 保留并去重 groups', () => {
  const e = normalizeEntry({ title: 'x', groups: ['a', 'a', ' b ', ''] });
  assert.deepEqual(e.groups, ['a', 'b']);
  assert.deepEqual(normalizeEntry({ title: 'y' }).groups, []);
});

test('entryKey 区分同一发行方下的不同账号（避免导入时误判重复）', () => {
  const a = normalizeEntry({ title: 'GitHub', totp: { secret: 'JBSWY3DPEHPK3PXP', account: 'a@x.com' } });
  const b = normalizeEntry({ title: 'GitHub', totp: { secret: 'JBSWY3DPEHPK3PXP', account: 'b@x.com' } });
  assert.notEqual(entryKey(a), entryKey(b));
  assert.equal(entryKey(a), entryKey(normalizeEntry({ ...a })));
});

/* ============================== 生物识别密钥解析 ============================== */

test('生物识别包裹主密码：同步换了 salt 之后依然能解锁', async () => {
  const vault = { schema: 1, entries: [], groups: [] };
  const saltA = randomBytes(16);
  const saltB = randomBytes(16);
  const envA = await sealVault(vault, await deriveKey('master-pw', saltA, 100_000), {
    salt: saltA,
    iterations: 100_000,
    header: { revision: 1, updatedAt: new Date().toISOString(), deviceId: 'd1' },
  });
  // 同步：换成另一台设备的 salt / iterations（派生密钥完全不同）
  const envB = await sealVault(vault, await deriveKey('master-pw', saltB, 100_000), {
    salt: saltB,
    iterations: 100_000,
    header: { revision: 2, updatedAt: new Date().toISOString(), deviceId: 'd2' },
  });

  const secret = enc.encode('master-pw');
  const openedA = await openVaultWithSecret(envA, secret);
  assert.equal(openedA.vault.schema, 1);
  const openedB = await openVaultWithSecret(envB, secret);
  assert.equal(openedB.vault.schema, 1, '同步后仍然能解开');
  assert.equal(openedB.legacy, undefined);
});

test('兼容旧记录：包裹的是原始密钥时走 legacy 分支', async () => {
  const salt = randomBytes(16);
  const key = await deriveKey('master-pw', salt, 100_000);
  const env = await sealVault({ schema: 1, entries: [], groups: [] }, key, {
    salt,
    iterations: 100_000,
    header: { revision: 1, updatedAt: new Date().toISOString(), deviceId: 'd1' },
  });
  const raw = await exportRawKey(key);
  const opened = await openVaultWithSecret(env, raw);
  assert.equal(opened.legacy, true);
  assert.equal(opened.vault.schema, 1);
});

test('主密码变过时给出 BIO_STALE 而不是静默失败', async () => {
  const salt = randomBytes(16);
  const env = await sealVault({ schema: 1, entries: [], groups: [] }, await deriveKey('new-pw', salt, 100_000), {
    salt,
    iterations: 100_000,
    header: { revision: 1, updatedAt: new Date().toISOString(), deviceId: 'd1' },
  });
  await assert.rejects(
    () => openVaultWithSecret(env, enc.encode('old-pw')),
    (err) => err.code === 'BIO_STALE',
  );
});
