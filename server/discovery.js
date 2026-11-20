// 局域网设备发现（UDP 定向广播 + 组播，参考 LocalSend / Syncthing 的做法）
//
// 这里踩过的坑（v1.5.2 之前「同一局域网却互相发现不了」的根因）：
//   1. 只往 224.0.0.167 和 255.255.255.255 各发一份。多网卡的机器（装了 Hyper-V /
//      WSL2 / VMware / Docker / VPN）上，这两个地址由系统按路由表挑网卡，经常挑中
//      虚拟网卡，包根本到不了 Wi-Fi。必须按网卡的「定向广播地址」逐卡发送。
//   2. addMembership() 不指定网卡时只加入默认多播网卡，收不到别的网卡的组播。
//   3. socket 出错就 stop 掉，之后永不恢复；网卡/网络变化后也不会重新加入。
//   4. 广播是单向的，交换机/路由器一旦过滤广播或开了 AP 隔离就永远发现不了。
//      收到对方的通告后单播回一条自己的通告，只要单向可达就能双向发现。
import dgram from 'node:dgram';
import os from 'node:os';

export const DISCOVERY_PORT = 53318;
export const DISCOVERY_GROUP = '224.0.0.167';
export const APP_ID = 'dsh-passvault';

const PEER_TTL_MS = 15_000;
const ANNOUNCE_INTERVAL_MS = 3_000;
const WATCHDOG_INTERVAL_MS = 5_000;
// 同一个设备的单播回包最小间隔（避免和它自己的 3 秒广播打架）
const REPLY_INTERVAL_MS = 10_000;
// 重绑退避：立刻试一次，然后逐步拉长，最多 30 秒
const REBIND_DELAYS_MS = [200, 500, 1_000, 2_000, 5_000, 10_000, 30_000];

// 明显是虚拟 / 隧道网卡的接口名。这些网卡上的广播不会到达真实局域网，
// 而且它们的地址被当成「本机地址」发给对方时，对方一定连不上。
const VIRTUAL_PATTERNS = [
  /^lo/i,
  /loopback/i,
  /^vmware/i,
  /virtualbox/i,
  /^vboxnet/i,
  /^vethernet/i,
  /hyper-?v/i,
  /^hv[-_]/i,
  /^wsl/i,
  /docker/i,
  /^br-/i,
  /^veth/i,
  /^cni/i,
  /flannel/i,
  /^cali/i,
  /tailscale/i,
  /zerotier/i,
  /^zt[a-z0-9]/i,
  /wireguard/i,
  /^wg\d/i,
  /^utun/i,
  /^tun\d/i,
  /^tap\d/i,
  /^ppp\d/i,
  /bluetooth/i,
  /^awdl/i,
  /^llw/i,
  /teredo/i,
  /isatap/i,
  /^npcap/i,
  /^pseudo/i,
];

export function isVirtualInterface(name) {
  const n = String(name || '');
  return VIRTUAL_PATTERNS.some((re) => re.test(n));
}

/** 由 IPv4 地址与掩码算出定向广播地址（如 192.168.1.10 / 255.255.255.0 → 192.168.1.255） */
export function broadcastOf(address, netmask) {
  const a = ipToInt(address);
  const m = ipToInt(netmask);
  if (a === null || m === null || m === 0) return null;
  return intToIp((a | (~m >>> 0)) >>> 0);
}

function ipToInt(ip) {
  const parts = String(ip || '').split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    out = ((out << 8) | n) >>> 0;
  }
  return out >>> 0;
}

function intToIp(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
}

/** 是否是私有网段地址（169.254 链路本地不算可用） */
export function isPrivateAddress(address) {
  const a = ipToInt(address);
  if (a === null) return false;
  const first = (a >>> 24) & 255;
  const second = (a >>> 16) & 255;
  if (first === 10) return true;
  if (first === 192 && second === 168) return true;
  if (first === 172 && second >= 16 && second <= 31) return true;
  return false;
}

/**
 * 列出可用于局域网通信的 IPv4 网卡。
 * 真实网卡排在前面，虚拟网卡（Hyper-V / WSL / Docker / VPN）排在后面并标记 virtual。
 */
export function candidateInterfaces() {
  const out = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const item of list || []) {
      if (!item || item.internal) continue;
      if (item.family !== 'IPv4' && item.family !== 4) continue;
      const netmask = item.netmask || '255.255.255.0';
      const broadcast = broadcastOf(item.address, netmask);
      out.push({
        name,
        address: item.address,
        netmask,
        broadcast: broadcast && broadcast !== item.address ? broadcast : null,
        cidr: item.cidr || null,
        virtual: isVirtualInterface(name),
        private: isPrivateAddress(item.address),
        linkLocal: String(item.address).startsWith('169.254.'),
      });
    }
  }
  const score = (i) => (i.virtual ? 4 : 0) + (i.linkLocal ? 2 : 0) + (i.private ? 0 : 1);
  out.sort((a, b) => score(a) - score(b));
  return out;
}

/** 对外展示的本机局域网地址（优先真实局域网网卡） */
export function lanAddresses() {
  const usable = candidateInterfaces().filter((i) => !i.linkLocal);
  // 真实网卡存在时，绝不把虚拟网卡（vEthernet / WSL / VMware / Docker）的地址
  // 交给对方 —— 对方会照着这个地址去连，然后必然失败，表现就是
  // 「发现了设备但同步失败」。只有整机都是虚拟网卡时才退回全量。
  const real = usable.filter((i) => !i.virtual);
  const chosen = real.length ? real : usable;
  return chosen.map((i) => ({
    name: i.name,
    address: i.address,
    netmask: i.netmask,
    broadcast: i.broadcast,
    virtual: i.virtual,
  }));
}

export class Discovery {
  constructor({
    deviceId,
    name,
    httpPort,
    httpsPort,
    platform = process.platform,
    version = 2,
    port = DISCOVERY_PORT,
    announceInterval = ANNOUNCE_INTERVAL_MS,
    log = (msg) => console.warn(msg),
  }) {
    this.deviceId = deviceId;
    this.name = name;
    this.httpPort = httpPort;
    this.httpsPort = httpsPort;
    this.platform = platform;
    this.version = version;
    this.port = port;
    this.announceInterval = announceInterval;
    this.warn = log;
    this.peers = new Map();
    this.repliedAt = new Map();
    this.socket = null;
    this.timer = null;
    this.watchdog = null;
    this.bindTimer = null;
    this.bindAttempt = 0;
    this.bound = false;
    this.memberships = new Set();
    this.ifaceSignature = '';
    this.started = false;
  }

  /* ---------------------------- 生命周期 ---------------------------- */

  start() {
    if (this.started) return this;
    this.started = true;
    this.bind();
    this.watchdog = setInterval(() => this.check(), WATCHDOG_INTERVAL_MS);
    this.watchdog.unref?.();
    return this;
  }

  bind() {
    if (this.socket || !this.started) return;
    let socket;
    try {
      socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    } catch (err) {
      this.warn(`[discovery] 创建 UDP socket 失败：${err.message}`);
      this.scheduleBind();
      return;
    }
    this.socket = socket;
    this.bound = false;
    this.memberships.clear();

    socket.on('message', (buf, rinfo) => this.onMessage(buf, rinfo));
    socket.on('error', (err) => this.onError(err));
    socket.once('listening', () => {
      this.bound = true;
      this.bindAttempt = 0;
      try {
        socket.setBroadcast(true);
      } catch (err) {
        this.warn(`[discovery] 打开广播失败：${err.message}`);
      }
      this.joinAll();
      this.announce();
      if (this.timer) clearInterval(this.timer);
      this.timer = setInterval(() => this.announce(), this.announceInterval);
      this.timer.unref?.();
    });
    try {
      socket.bind(this.port);
    } catch (err) {
      this.warn(`[discovery] 绑定 UDP ${this.port} 失败：${err.message}`);
      this.reset(true);
    }
  }

  /** 绑定失败 / socket 失效时按退避重试，绝不永久放弃 */
  scheduleBind() {
    if (!this.started || this.bindTimer) return;
    const delay = REBIND_DELAYS_MS[Math.min(this.bindAttempt, REBIND_DELAYS_MS.length - 1)];
    this.bindAttempt++;
    this.bindTimer = setTimeout(() => {
      this.bindTimer = null;
      this.bind();
    }, delay);
    this.bindTimer.unref?.();
  }

  reset(warnOnce) {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.leaveAll();
    const socket = this.socket;
    this.socket = null;
    this.bound = false;
    if (socket) {
      socket.removeAllListeners();
      try {
        socket.close();
      } catch {
        /* 忽略 */
      }
    }
    if (warnOnce) this.warn('[discovery] 发现服务将稍后重试');
    this.scheduleBind();
  }

  stop() {
    this.started = false;
    if (this.timer) clearInterval(this.timer);
    if (this.watchdog) clearInterval(this.watchdog);
    if (this.bindTimer) clearTimeout(this.bindTimer);
    this.timer = null;
    this.watchdog = null;
    this.bindTimer = null;
    this.leaveAll();
    if (this.socket) {
      const socket = this.socket;
      this.socket = null;
      socket.removeAllListeners();
      try {
        socket.close();
      } catch {
        /* 忽略 */
      }
    }
    this.bound = false;
  }

  /* ---------------------------- 组播成员 ---------------------------- */

  joinAll() {
    const socket = this.socket;
    if (!socket) return;
    const targets = this.sendTargets();
    for (const iface of targets) {
      try {
        socket.addMembership(DISCOVERY_GROUP, iface.address);
        this.memberships.add(iface.address);
      } catch (err) {
        // 单个网卡不支持组播时忽略，该网卡仍然会收到定向广播
        if (!this.memberships.size) {
          this.warn(`[discovery] 加入组播失败（${iface.address}）：${err.message}`);
        }
      }
    }
    if (!this.memberships.size) {
      try {
        socket.addMembership(DISCOVERY_GROUP);
        this.memberships.add('*');
      } catch (err) {
        this.warn(`[discovery] 加入组播失败，仅使用广播：${err.message}`);
      }
    }
    this.ifaceSignature = this.signature();
  }

  leaveAll() {
    const socket = this.socket;
    if (!socket) {
      this.memberships.clear();
      return;
    }
    for (const address of this.memberships) {
      try {
        if (address === '*') socket.dropMembership(DISCOVERY_GROUP);
        else socket.dropMembership(DISCOVERY_GROUP, address);
      } catch {
        /* 忽略 */
      }
    }
    this.memberships.clear();
  }

  /** 网络变化（换 Wi-Fi、插网线、VPN 起来）后重新加入并立刻宣告 */
  check() {
    if (!this.started) return;
    if (!this.socket || !this.bound) {
      if (!this.bindTimer) this.bind();
      return;
    }
    const sig = this.signature();
    if (sig !== this.ifaceSignature) {
      this.leaveAll();
      this.joinAll();
      this.announce();
    }
  }

  signature() {
    return this.sendTargets()
      .map((i) => `${i.address}/${i.netmask}`)
      .join(',');
  }

  /** 发送目标：真实网卡优先；如果全是虚拟网卡，就都发（总比不发好） */
  sendTargets() {
    const all = candidateInterfaces().filter((i) => !i.linkLocal);
    const real = all.filter((i) => !i.virtual);
    return real.length ? real : all;
  }

  /* ---------------------------- 收发 ---------------------------- */

  payload() {
    const addresses = this.sendTargets().map((i) => i.address);
    return {
      app: APP_ID,
      v: this.version,
      id: this.deviceId,
      name: this.name,
      http: this.httpPort,
      https: this.httpsPort,
      platform: this.platform,
      addresses,
      ts: Date.now(),
    };
  }

  announce() {
    const socket = this.socket;
    if (!socket || !this.bound) return;
    const data = Buffer.from(JSON.stringify(this.payload()));
    const targets = this.sendTargets();
    for (const iface of targets) {
      // 定向广播：由网卡自己那条路由送出，不会被默认路由抢走
      if (iface.broadcast) this.sendTo(socket, data, iface.broadcast);
      // 组播：显式指定出口网卡
      try {
        socket.setMulticastInterface(iface.address);
      } catch {
        /* 某些网卡不支持设置出口，忽略 */
      }
      this.sendTo(socket, data, DISCOVERY_GROUP);
    }
    // 受限广播兜底（系统只会从默认网卡发出，成本极低）
    this.sendTo(socket, data, '255.255.255.255');
    this.prune();
  }

  sendTo(socket, data, address, port = this.port) {
    try {
      socket.send(data, 0, data.length, port, address, () => {});
    } catch {
      /* 单次发送失败忽略 */
    }
  }

  /** 收到通告后单播回一条，解决「一方收得到、另一方收不到」的广播过滤问题 */
  reply(rinfo) {
    const socket = this.socket;
    if (!socket || !this.bound || !rinfo?.address) return;
    const data = Buffer.from(JSON.stringify({ ...this.payload(), reply: 1 }));
    // 固定发到发现端口：对方的接收 socket 绑在这个端口上。
    // 不要回到源端口（安卓发送端用的是临时端口，回过去会收到 ICMP 端口不可达）。
    this.sendTo(socket, data, rinfo.address, this.port);
  }

  onMessage(buf, rinfo) {
    let msg;
    try {
      msg = JSON.parse(buf.toString('utf8'));
    } catch {
      return;
    }
    if (!msg || msg.app !== APP_ID || !msg.id || msg.id === this.deviceId) return;

    const now = Date.now();
    const prev = this.peers.get(msg.id);
    const addresses = Array.isArray(msg.addresses)
      ? msg.addresses.filter((a) => typeof a === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(a))
      : [];
    this.peers.set(msg.id, {
      id: String(msg.id),
      name: String(msg.name || '未命名设备'),
      host: rinfo?.address || addresses[0] || '',
      addresses: addresses.length ? addresses : [rinfo?.address].filter(Boolean),
      httpPort: Number(msg.http) || 8787,
      httpsPort: Number(msg.https) || 0,
      platform: String(msg.platform || ''),
      version: Number(msg.v) || 1,
      lastSeen: now,
    });

    // 新设备、对方主动打招呼、或隔了足够久没回过 → 单播回应一次
    const lastReply = this.repliedAt.get(msg.id) || 0;
    if (!prev || msg.hello === true || now - lastReply > REPLY_INTERVAL_MS) {
      this.repliedAt.set(msg.id, now);
      this.reply(rinfo);
    }
  }

  onError(err) {
    const code = err?.code || '';
    // 网络瞬断 / 对端不可达属于正常现象，不能因此把发现服务停掉
    if (
      code === 'ECONNREFUSED' ||
      code === 'EHOSTUNREACH' ||
      code === 'ENETUNREACH' ||
      code === 'EACCES'
    ) {
      return;
    }
    this.warn(`[discovery] UDP 错误（${code || err?.message}），将重建发现服务`);
    this.reset(false);
  }

  prune() {
    const now = Date.now();
    for (const [id, peer] of this.peers) {
      if (now - peer.lastSeen > PEER_TTL_MS) {
        this.peers.delete(id);
        this.repliedAt.delete(id);
      }
    }
  }

  list() {
    this.prune();
    return Array.from(this.peers.values()).sort((a, b) => b.lastSeen - a.lastSeen);
  }

  self() {
    return {
      id: this.deviceId,
      name: this.name,
      httpPort: this.httpPort,
      httpsPort: this.httpsPort,
      platform: this.platform,
      addresses: lanAddresses(),
    };
  }
}
