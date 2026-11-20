#!/usr/bin/env node
/**
 * 局域网自检：排查「明明是同一个 Wi-Fi 却互相发现不了」。
 *
 *   node scripts/lan-check.mjs             # 看网卡 + 监听 10 秒，打印收到谁的通告
 *   node scripts/lan-check.mjs --seconds 30
 *
 * 输出三部分：
 *   1. 网卡列表（标出会被跳过的虚拟网卡）
 *   2. 本机会广播出去的地址——手机要连的就是这里排第一的那个
 *   3. 监听窗口内收到的其它设备
 */
import os from 'node:os';
import {
  candidateInterfaces,
  DISCOVERY_GROUP,
  DISCOVERY_PORT,
  Discovery,
  lanAddresses,
} from '../server/discovery.js';

const args = process.argv.slice(2);
const index = args.indexOf('--seconds');
const seconds = index >= 0 ? Number(args[index + 1]) || 10 : 10;
const line = '─'.repeat(66);

console.log(`\n${line}`);
console.log('  密码保险库 · 局域网自检');
console.log(line);

const ifaces = candidateInterfaces();
if (!ifaces.length) {
  console.log('  ⚠️  没有找到任何可用的 IPv4 网卡（检查是否开启了 Wi-Fi / 网线）');
} else {
  console.log('  网卡：');
  for (const i of ifaces) {
    const tags = [];
    if (i.virtual) tags.push('虚拟，跳过');
    if (i.linkLocal) tags.push('链路本地，跳过');
    if (i.private) tags.push('局域网');
    console.log(
      `    ${i.address.padEnd(15)} ${i.netmask.padEnd(15)} 广播 ${String(i.broadcast || '-').padEnd(15)} ${i.name}  ${tags.join(' ')}`,
    );
  }
}

const adv = lanAddresses();
console.log('\n  将对其他设备广播：');
if (!adv.length) console.log('    （无）');
for (const a of adv) {
  console.log(`    http://${a.address}:8787    https://${a.address}:8443    (${a.name})`);
}

console.log(`\n  监听 UDP ${DISCOVERY_PORT}（组播 ${DISCOVERY_GROUP} + 各网卡定向广播）${seconds} 秒…`);
console.log('  期间请在另一台设备上打开密码保险库，并打开「局域网同步」面板。\n');

const discovery = new Discovery({
  deviceId: `lan-check-${Date.now()}`,
  name: `自检@${os.hostname()}`,
  httpPort: 8787,
  httpsPort: 8443,
  log: (msg) => console.log(`  [warn] ${msg}`),
});
discovery.start();

const seen = new Set();
const timer = setInterval(() => {
  for (const peer of discovery.list()) {
    const key = `${peer.id}:${peer.host}`;
    if (seen.has(key)) continue;
    seen.add(key);
    console.log(
      `  ✅ 发现 ${peer.name}  ${peer.host}:${peer.httpPort}  ${peer.platform || ''}  地址池 ${(peer.addresses || []).join(' / ')}`,
    );
  }
}, 500);

setTimeout(() => {
  clearInterval(timer);
  const peers = discovery.list();
  discovery.stop();
  console.log(`\n  共发现 ${peers.length} 台设备。`);
  if (!peers.length) {
    console.log(`
  一条都没收到，按顺序排查：
    1. 两台设备是否连在同一个 Wi-Fi / 同一个网段（上面 IP 的前三段要一致）
    2. 路由器是否开了「AP 隔离 / 客户端隔离」——开了就永远收不到广播
    3. Windows 防火墙是否放行了 UDP ${DISCOVERY_PORT} 与 TCP 8787/8443
    4. 是否装了 Hyper-V / WSL / Docker / 虚拟机网卡，把默认路由抢走了
       （上面会把它们标成「虚拟，跳过」；若只剩虚拟网卡，说明物理网卡没连上）
    5. 公共 Wi-Fi 常屏蔽组播/广播，换手机热点再试
`);
  }
  console.log(`${line}\n`);
  process.exit(0);
}, seconds * 1000);
