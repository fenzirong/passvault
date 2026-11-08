// 自动加密快照的单元测试（用内存版 localStorage 模拟浏览器环境）
import test from 'node:test';
import assert from 'node:assert/strict';

class MemoryStorage {
  #map = new Map();
  getItem(k) {
    return this.#map.has(k) ? this.#map.get(k) : null;
  }
  setItem(k, v) {
    this.#map.set(k, String(v));
  }
  removeItem(k) {
    this.#map.delete(k);
  }
  clear() {
    this.#map.clear();
  }
  get length() {
    return this.#map.size;
  }
}

globalThis.localStorage = new MemoryStorage();

const { listSnapshots, recordSnapshot, removeSnapshot, clearSnapshots, snapshotCount, formatBytes } =
  await import('../web/js/backup.js');

function fakeEnvelope(revision, payload = 'x') {
  return {
    format: 'dsh-passvault',
    version: 1,
    kdf: { name: 'PBKDF2-SHA256', iterations: 600000, salt: 'AAAA' },
    cipher: { name: 'AES-256-GCM', iv: 'BBBB' },
    header: { revision, updatedAt: new Date().toISOString(), deviceId: 'dev' },
    data: `${payload}-${revision}`,
  };
}

test('记录快照并按时间倒序返回', () => {
  clearSnapshots();
  recordSnapshot(fakeEnvelope(1), { force: true, minIntervalMs: 0 });
  recordSnapshot(fakeEnvelope(2), { force: true, minIntervalMs: 0 });
  const list = listSnapshots();
  assert.equal(list.length, 2);
  assert.ok(new Date(list[0].at) >= new Date(list[1].at));
  assert.equal(list[0].revision, 2);
  assert.ok(list[0].size > 0);
});

test('相同内容或间隔过短不重复写入', () => {
  clearSnapshots();
  const env = fakeEnvelope(3);
  assert.equal(recordSnapshot(env, { minIntervalMs: 60_000 }), true);
  assert.equal(recordSnapshot(env, { minIntervalMs: 60_000 }), false);
  const env2 = fakeEnvelope(4, 'y');
  assert.equal(recordSnapshot(env2, { minIntervalMs: 60_000 }), false);
  assert.equal(recordSnapshot(env2, { minIntervalMs: 60_000, force: true }), true);
});

test('最多保留 8 份，超出后丢弃最旧的', () => {
  clearSnapshots();
  for (let i = 0; i < 12; i++) {
    recordSnapshot(fakeEnvelope(i, `p${i}`), { force: true, minIntervalMs: 0 });
  }
  const list = listSnapshots();
  assert.equal(list.length, 8);
  assert.equal(list[0].revision, 11);
  assert.equal(list.at(-1).revision, 4);
});

test('删除与清空', () => {
  clearSnapshots();
  recordSnapshot(fakeEnvelope(1), { force: true, minIntervalMs: 0 });
  recordSnapshot(fakeEnvelope(2), { force: true, minIntervalMs: 0 });
  const [first] = listSnapshots();
  removeSnapshot(first.id);
  assert.equal(snapshotCount(), 1);
  clearSnapshots();
  assert.equal(snapshotCount(), 0);
});

test('格式化文件大小', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(2048), '2.0 KB');
  assert.equal(formatBytes(3 * 1024 * 1024), '3.00 MB');
});
