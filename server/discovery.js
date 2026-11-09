// 局域网设备发现（UDP 组播，参考 LocalSend 的做法）
// 每台运行服务的设备周期性广播自身信息，同时监听其他设备的广播。
import dgram from 'node:dgram';
import os from 'node:os';

export const DISCOVERY_PORT = 53318;
export const DISCOVERY_GROUP = '224.0.0.167';
const PEER_TTL_MS = 15_000;
const ANNOUNCE_INTERVAL_MS = 3_000;

export class Discovery {
  constructor({ deviceId, name, httpPort, httpsPort, platform = process.platform, version = 2 }) {
    this.deviceId = deviceId;
    this.name = name;
    this.httpPort = httpPort;
    this.httpsPort = httpsPort;
    this.platform = platform;
    this.version = version;
    this.peers = new Map();
    this.socket = null;
    this.timer = null;
    this.started = false;
  }

  payload() {
    return {
      app: 'dsh-passvault',
      v: this.version,
      id: this.deviceId,
      name: this.name,
      http: this.httpPort,
      https: this.httpsPort,
      platform: this.platform,
      ts: Date.now(),
    };
  }

  start() {
    if (this.started) return;
    this.started = true;
    try {
      this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      this.socket.on('error', (err) => {
        console.warn('[discovery] UDP 错误：', err.message);
        this.stop();
      });
      this.socket.on('message', (buf, rinfo) => this.onMessage(buf, rinfo));
      this.socket.bind(DISCOVERY_PORT, () => {
        try {
          this.socket.setBroadcast(true);
          this.socket.addMembership(DISCOVERY_GROUP);
        } catch (err) {
          console.warn('[discovery] 加入组播失败，改用广播：', err.message);
        }
        this.announce();
        this.timer = setInterval(() => this.announce(), ANNOUNCE_INTERVAL_MS);
        this.timer.unref?.();
      });
    } catch (err) {
      console.warn('[discovery] 启动失败：', err.message);
    }
  }

  announce() {
    if (!this.socket) return;
    const data = Buffer.from(JSON.stringify(this.payload()));
    const send = (addr) => {
      try {
        this.socket.send(data, 0, data.length, DISCOVERY_PORT, addr, () => {});
      } catch {
        /* 忽略单次发送失败 */
      }
    };
    send(DISCOVERY_GROUP);
    send('255.255.255.255');
    this.prune();
  }

  onMessage(buf, rinfo) {
    let msg;
    try {
      msg = JSON.parse(buf.toString('utf8'));
    } catch {
      return;
    }
    if (!msg || msg.app !== 'dsh-passvault' || !msg.id || msg.id === this.deviceId) return;
    this.peers.set(msg.id, {
      id: msg.id,
      name: String(msg.name || '未命名设备'),
      host: rinfo.address,
      httpPort: Number(msg.http) || 8787,
      httpsPort: Number(msg.https) || 0,
      platform: String(msg.platform || ''),
      version: Number(msg.v) || 1,
      lastSeen: Date.now(),
    });
  }

  prune() {
    const now = Date.now();
    for (const [id, peer] of this.peers) {
      if (now - peer.lastSeen > PEER_TTL_MS) this.peers.delete(id);
    }
  }

  list() {
    this.prune();
    return Array.from(this.peers.values())
      .sort((a, b) => b.lastSeen - a.lastSeen)
      .map(({ lastSeen, ...rest }) => ({ ...rest, lastSeen }));
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

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.socket) {
      try {
        this.socket.close();
      } catch {
        /* 忽略 */
      }
      this.socket = null;
    }
    this.started = false;
  }
}

export function lanAddresses() {
  const out = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const item of list || []) {
      if (item.family === 'IPv4' && !item.internal) out.push({ name, address: item.address });
    }
  }
  return out;
}
