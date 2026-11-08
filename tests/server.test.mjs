// 局域网同步服务集成测试
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createEmptyVault, sealVault, deriveKey } from '../web/js/crypto.js';
import { normalizeEntry } from '../web/js/vault.js';
import { nowISO } from '../web/js/util.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const TOKEN = 'TEST-TOKEN-1234';

async function startServer() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'passvault-'));
  const port = 18000 + Math.floor(Math.random() * 900);
  const child = spawn(
    process.execPath,
    [path.join(ROOT, 'server', 'server.js'), '--port', String(port), '--data', dataDir, '--token', TOKEN],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('服务器启动超时')), 8000);
    child.stdout.on('data', (buf) => {
      if (String(buf).includes('已启动')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on('exit', (code) => reject(new Error(`服务器退出：${code}`)));
  });
  return { child, port, dataDir, base: `http://127.0.0.1:${port}` };
}

async function makeEnvelope(revision, title) {
  const vault = createEmptyVault();
  vault.entries.push(normalizeEntry({ title, username: 'u', password: 'p' }));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey('test-password', salt, 120_000);
  const header = { revision, updatedAt: nowISO(), deviceId: 'test-device' };
  return sealVault(vault, key, { salt, iterations: 120_000, header });
}

test('同步服务：鉴权、上传、拉取、版本冲突', async (t) => {
  const { child, base, dataDir } = await startServer();
  t.after(() => {
    child.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  // 静态页面
  const page = await fetch(`${base}/`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /密码保险库/);

  // 未鉴权
  const noAuth = await fetch(`${base}/api/vault`);
  assert.equal(noAuth.status, 401);

  // 初始状态
  const info = await fetch(`${base}/api/info`, { headers: { 'X-Sync-Token': TOKEN } });
  const infoJson = await info.json();
  assert.equal(infoJson.hasVault, false);
  assert.equal(infoJson.revision, 0);

  // 上传 v1
  const env1 = await makeEnvelope(1, '第一条');
  const put1 = await fetch(`${base}/api/vault`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Sync-Token': TOKEN, 'If-Match': '0' },
    body: JSON.stringify(env1),
  });
  assert.equal(put1.status, 200);
  assert.equal((await put1.json()).revision, 1);

  // 拉取
  const got = await fetch(`${base}/api/vault`, { headers: { 'X-Sync-Token': TOKEN } });
  assert.equal(got.status, 200);
  const gotJson = await got.json();
  assert.equal(gotJson.header.revision, 1);
  assert.equal(gotJson.data, env1.data);

  // 版本冲突
  const env2 = await makeEnvelope(2, '第二条');
  const conflict = await fetch(`${base}/api/vault`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Sync-Token': TOKEN, 'If-Match': '0' },
    body: JSON.stringify(env2),
  });
  assert.equal(conflict.status, 409);
  assert.equal((await conflict.json()).revision, 1);

  // 版本号不连续
  const badRev = await fetch(`${base}/api/vault`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Sync-Token': TOKEN, 'If-Match': '1' },
    body: JSON.stringify(env1),
  });
  assert.equal(badRev.status, 400);

  // 正确上传 v2
  const put2 = await fetch(`${base}/api/vault`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-Sync-Token': TOKEN, 'If-Match': '1' },
    body: JSON.stringify(env2),
  });
  assert.equal(put2.status, 200);
  assert.equal((await put2.json()).revision, 2);

  // 备份文件已生成
  const backups = fs.readdirSync(path.join(dataDir, 'backups'));
  assert.ok(backups.length >= 1);
});

test('同步服务：错误口令被拒绝', async (t) => {
  const { child, base, dataDir } = await startServer();
  t.after(() => {
    child.kill('SIGKILL');
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  const res = await fetch(`${base}/api/vault`, { headers: { 'X-Sync-Token': 'WRONG' } });
  assert.equal(res.status, 401);
});

test('嵌入式启动（Electron 使用）：随机端口 + 可关闭', async () => {
  const { PassVaultServer } = await import('../server/app.js');
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'passvault-embed-'));
  const server = new PassVaultServer({
    port: 0,
    httpsPort: 0,
    host: '127.0.0.1',
    dataDir,
    token: 'EMBED-TOKEN',
    quiet: true,
  });
  const info = await server.start();
  try {
    assert.ok(info.httpPort > 0);
    assert.ok(info.httpsPort > 0);
    assert.notEqual(info.httpPort, info.httpsPort);
    const res = await fetch(`http://127.0.0.1:${info.httpPort}/api/info`);
    const json = await res.json();
    assert.equal(json.app, 'dsh-passvault');
    assert.equal(json.hasVault, false);
  } finally {
    await server.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
