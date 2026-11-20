// 局域网发现模块的回归测试：
// 这些断言直接锁住「同一局域网却互相发现不了」的几个根因，改动 discovery.js 时
// 一旦把逐网卡发送、单播应答、出错重试中的任何一条改回去，这里就会红。
//
// 调用方：package.json 的 `npm test` → `node --test tests/*.test.mjs`
// 不读写任何数据文件，全部是内存与回环 UDP。
import test from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';

import {
  DISCOVERY_GROUP,
  DISCOVERY_PORT,
  broadcastOf,
  candidateInterfaces,
  isPrivateAddress,
  isVirtualInterface,
  lanAddresses,
  Discovery,
} from '../server/discovery.js';

/* ---------------------------- 网卡与地址计算 ---------------------------- */

test('broadcastOf 按掩码算出定向广播地址', () => {
  assert.equal(broadcastOf('192.168.1.10', '255.255.255.0'), '192.168.1.255');
  assert.equal(broadcastOf('10.1.2.3', '255.255.0.0'), '10.1.255.255');
  assert.equal(broadcastOf('172.16.5.9', '255.255.240.0'), '172.16.15.255');
  // 掩码缺失时返回 null，调用方会跳过这个网卡
  assert.equal(broadcastOf('192.168.1.10', ''), null);
  assert.equal(broadcastOf('not-an-ip', '255.255.255.0'), null);
});

test('isPrivateAddress 只认 RFC1918', () => {
  assert.equal(isPrivateAddress('192.168.1.1'), true);
  assert.equal(isPrivateAddress('10.0.0.1'), true);
  assert.equal(isPrivateAddress('172.20.1.1'), true);
  assert.equal(isPrivateAddress('172.32.1.1'), false);
  assert.equal(isPrivateAddress('8.8.8.8'), false);
});

test('虚拟网卡被识别出来（Hyper-V / WSL / Docker / VPN）', () => {
  assert.equal(isVirtualInterface('vEthernet (Default Switch)'), true);
  assert.equal(isVirtualInterface('VMware Network Adapter VMnet8'), true);
  assert.equal(isVirtualInterface('docker0'), true);
  assert.equal(isVirtualInterface('tun0'), true);
  assert.equal(isVirtualInterface('Tailscale'), true);
  // 真实的 Wi-Fi / 有线网卡不能被误杀
  assert.equal(isVirtualInterface('WLAN'), false);
  assert.equal(isVirtualInterface('Wi-Fi'), false);
  assert.equal(isVirtualInterface('以太网'), false);
  assert.equal(isVirtualInterface('eth0'), false);
});

test('candidateInterfaces / lanAddresses 不含回环且带掩码与广播地址', () => {
  const list = candidateInterfaces();
  for (const item of list) {
    assert.ok(item.address);
    assert.ok(item.netmask);
    assert.equal(item.linkLocal, String(item.address).startsWith('169.254.'));
    assert.ok(!item.address.startsWith('127.'));
  }
  // 真实网卡（非虚拟）必须排在前面，否则发给对方的第一个地址可能是 Docker 内网
  const firstVirtual = list.findIndex((i) => i.virtual);
  if (firstVirtual >= 0) {
    assert.ok(list.slice(firstVirtual).every((i) => i.virtual || i.linkLocal));
  }
  const lan = lanAddresses();
  for (const a of lan) {
    assert.ok(a.name && a.address);
    assert.ok('virtual' in a && 'netmask' in a);
  }
});

/* ---------------------------- 发现服务核心逻辑 ---------------------------- */

/** 记录 send 调用的假 socket，避免测试真的发广播、也避免多实例抢端口 */
function fakeSocket() {
  const sent = [];
  return {
    sent,
    send(data, offset, length, port, address, cb) {
      sent.push({ port, address, payload: JSON.parse(data.toString('utf8')) });
      if (typeof cb === 'function') cb();
    },
    close() {},
    addMembership() {},
    dropMembership() {},
    setBroadcast() {},
    setMulticastInterface() {},
    removeAllListeners() {},
  };
}

function makeDiscovery(overrides = {}) {
  return new Discovery({
    deviceId: 'self-id',
    name: '测试机',
    httpPort: 8787,
    httpsPort: 8443,
    platform: 'linux',
    log: () => {},
    ...overrides,
  });
}

test('announce 逐网卡发定向广播 + 组播 + 受限广播', () => {
  const d = makeDiscovery();
  const socket = fakeSocket();
  d.started = true;
  d.socket = socket;
  d.bound = true;
  d.announce();

  const targets = d.sendTargets();
  assert.ok(targets.length > 0, '测试机至少要有一张可用网卡');

  // 每张网卡的定向广播地址都必须被发到（这正是旧实现缺的那一步）
  for (const iface of targets) {
    if (!iface.broadcast) continue;
    assert.ok(
      socket.sent.some((s) => s.address === iface.broadcast),
      `没有往 ${iface.address} 所在网段的广播地址 ${iface.broadcast} 发送`,
    );
  }
  assert.ok(socket.sent.some((s) => s.address === DISCOVERY_GROUP), '没有发组播');
  assert.ok(socket.sent.some((s) => s.address === '255.255.255.255'), '没有发受限广播');
  assert.ok(socket.sent.every((s) => s.port === DISCOVERY_PORT));
});

test('announce 的报文带约定字段与本机地址列表', () => {
  const d = makeDiscovery();
  d.started = true;
  d.socket = fakeSocket();
  d.bound = true;
  d.announce();
  const payload = d.socket.sent[0].payload;
  assert.equal(payload.app, 'dsh-passvault');
  assert.equal(payload.id, 'self-id');
  assert.equal(payload.http, 8787);
  assert.equal(payload.https, 8443);
  assert.equal(payload.platform, 'linux');
  assert.ok(Array.isArray(payload.addresses));
  assert.equal(typeof payload.ts, 'number');
});

test('收到别人的通告会记账，并且单播回一条自己的通告', () => {
  const d = makeDiscovery();
  const socket = fakeSocket();
  d.started = true;
  d.socket = socket;
  d.bound = true;

  const msg = Buffer.from(
    JSON.stringify({
      app: 'dsh-passvault',
      v: 2,
      id: 'phone-id',
      name: '安卓手机',
      http: 8787,
      https: 0,
      platform: 'android',
      addresses: ['192.168.1.50'],
      ts: Date.now(),
    }),
  );
  d.onMessage(msg, { address: '192.168.1.50', port: 55555 });

  const peers = d.list();
  assert.equal(peers.length, 1);
  assert.equal(peers[0].id, 'phone-id');
  assert.equal(peers[0].host, '192.168.1.50');
  assert.deepEqual(peers[0].addresses, ['192.168.1.50']);

  // 单播应答必须发到发现端口，而不是对方的临时源端口
  const replies = socket.sent.filter((s) => s.address === '192.168.1.50');
  assert.equal(replies.length, 1);
  assert.equal(replies[0].port, DISCOVERY_PORT);
  assert.equal(replies[0].payload.reply, 1);
  assert.equal(replies[0].payload.id, 'self-id');
});

test('自己的通告与非本应用的报文被忽略', () => {
  const d = makeDiscovery();
  d.started = true;
  d.socket = fakeSocket();
  d.bound = true;

  d.onMessage(Buffer.from(JSON.stringify({ app: 'dsh-passvault', id: 'self-id', http: 8787 })), {
    address: '192.168.1.1',
    port: DISCOVERY_PORT,
  });
  assert.equal(d.list().length, 0);

  d.onMessage(Buffer.from(JSON.stringify({ app: 'other-app', id: 'x' })), {
    address: '192.168.1.2',
    port: DISCOVERY_PORT,
  });
  assert.equal(d.list().length, 0);

  d.onMessage(Buffer.from('not json'), { address: '192.168.1.3', port: DISCOVERY_PORT });
  assert.equal(d.list().length, 0);
  assert.equal(d.socket.sent.length, 0, '不该对无效报文回包');
});

test('重复收到同一设备的通告不会刷屏回包', () => {
  const d = makeDiscovery();
  const socket = fakeSocket();
  d.started = true;
  d.socket = socket;
  d.bound = true;
  const msg = Buffer.from(
    JSON.stringify({ app: 'dsh-passvault', v: 2, id: 'phone-id', name: '手机', http: 8787 }),
  );
  for (let i = 0; i < 5; i++) {
    d.onMessage(msg, { address: '192.168.1.50', port: 40000 + i });
  }
  assert.equal(socket.sent.length, 1, '10 秒内只回一次');
});

test('超过 TTL 的设备会被清掉', () => {
  const d = makeDiscovery();
  d.started = true;
  d.socket = fakeSocket();
  d.bound = true;
  d.peers.set('old-id', {
    id: 'old-id',
    name: '旧设备',
    host: '192.168.1.9',
    addresses: ['192.168.1.9'],
    httpPort: 8787,
    httpsPort: 0,
    platform: '',
    version: 2,
    lastSeen: Date.now() - 60_000,
  });
  assert.equal(d.list().length, 0);
});

test('网络瞬断不会把发现服务停掉，只有致命错误才重建', () => {
  const d = makeDiscovery();
  const socket = fakeSocket();
  d.started = true;
  d.socket = socket;
  d.bound = true;

  // 对端不可达 / 端口不可达属于正常现象
  d.onError(Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }));
  assert.equal(d.socket, socket);
  assert.equal(d.bound, true);
  d.onError(Object.assign(new Error('unreachable'), { code: 'ENETUNREACH' }));
  assert.equal(d.socket, socket);
});

test('self() 报告过滤后的局域网地址', () => {
  const d = makeDiscovery();
  const self = d.self();
  assert.equal(self.id, 'self-id');
  assert.equal(self.httpPort, 8787);
  assert.ok(Array.isArray(self.addresses));
  for (const a of self.addresses) {
    assert.ok(!String(a.address).startsWith('127.'));
  }
});

test('真实 UDP socket 上的报文链路是通的', async () => {
  // 同一台机器上两个 socket 抢同一端口在不同系统上行为不同，
  // 所以这里只验证「报文能真正落到 UDP 端口上」这一段。
  const probePort = 54399;
  const receiver = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  const received = new Promise((resolve) => {
    receiver.once('message', (buf) => resolve(JSON.parse(buf.toString('utf8'))));
  });
  await new Promise((resolve) => receiver.bind(probePort, '127.0.0.1', resolve));

  const d = makeDiscovery({ port: probePort });
  d.started = true;
  d.socket = receiver;
  d.bound = true;
  d.sendTo(receiver, Buffer.from(JSON.stringify(d.payload())), '127.0.0.1', probePort);

  const msg = await received;
  assert.equal(msg.app, 'dsh-passvault');
  assert.equal(msg.id, 'self-id');
  receiver.close();
});
