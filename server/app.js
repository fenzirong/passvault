// 局域网同步服务核心（可嵌入 Electron / 作为 CLI 启动）
// - 托管 Web 应用（PWA），手机与电脑浏览器直接访问
// - 提供保险库的拉取/推送接口，带口令鉴权与版本乐观锁
// - 服务端只保存密文，无法解密任何内容
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ensureCert } from './cert.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_WEB_DIR = path.resolve(__dirname, '..', 'web');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

const MAX_BODY = 32 * 1024 * 1024;

function lanAddresses() {
  const out = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const item of list || []) {
      if (item.family === 'IPv4' && !item.internal) out.push({ name, address: item.address });
    }
  }
  return out;
}

export { lanAddresses };

export class PassVaultServer {
  constructor(options = {}) {
    this.opts = {
      port: 8787,
      httpsPort: 8443,
      host: '0.0.0.0',
      dataDir: path.join(__dirname, '..', 'data'),
      webDir: DEFAULT_WEB_DIR,
      token: '',
      noAuth: false,
      noHttps: false,
      cert: '',
      key: '',
      quiet: false,
      ...options,
    };
    this.dataDir = path.resolve(this.opts.dataDir);
    this.vaultFile = path.join(this.dataDir, 'vault.json');
    this.tokenFile = path.join(this.dataDir, 'token.txt');
    this.backupDir = path.join(this.dataDir, 'backups');
    this.state = { revision: 0, updatedAt: null, envelope: null };
    this.token = '';
    this.servers = [];
    this.httpPort = 0;
    this.httpsPort = 0;
    this.authFailures = new Map();
  }

  log(...args) {
    if (!this.opts.quiet) console.log(...args);
  }

  /* ------------------------------ 初始化 ------------------------------ */

  initFs() {
    fs.mkdirSync(this.dataDir, { recursive: true });
    fs.mkdirSync(this.backupDir, { recursive: true });
  }

  loadToken() {
    if (this.opts.noAuth) return '';
    if (this.opts.token) return this.opts.token;
    try {
      const saved = fs.readFileSync(this.tokenFile, 'utf8').trim();
      if (saved) return saved;
    } catch {
      /* 首次运行 */
    }
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const groups = [];
    for (let g = 0; g < 4; g++) {
      let s = '';
      for (let i = 0; i < 4; i++) s += alphabet[crypto.randomInt(alphabet.length)];
      groups.push(s);
    }
    const token = groups.join('-');
    fs.writeFileSync(this.tokenFile, token + '\n', { mode: 0o600 });
    return token;
  }

  loadState() {
    try {
      const raw = fs.readFileSync(this.vaultFile, 'utf8');
      const envelope = JSON.parse(raw);
      this.state = {
        revision: Number(envelope?.header?.revision) || 0,
        updatedAt: envelope?.header?.updatedAt || null,
        envelope,
      };
    } catch {
      this.state = { revision: 0, updatedAt: null, envelope: null };
    }
  }

  /* ------------------------------ 工具 ------------------------------ */

  sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, X-Sync-Token, If-Match',
      'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
      'Access-Control-Expose-Headers': 'ETag',
    });
    res.end(body);
  }

  readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) {
          reject(Object.assign(new Error('请求体过大'), { status: 413 }));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  checkAuth(req) {
    if (!this.token) return true;
    const provided = req.headers['x-sync-token'] || '';
    const a = Buffer.from(String(provided));
    const b = Buffer.from(String(this.token));
    const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!ok) {
      const ip = req.socket.remoteAddress || 'unknown';
      const rec = this.authFailures.get(ip) || { count: 0, until: 0 };
      rec.count++;
      if (rec.count >= 5) rec.until = Date.now() + 30_000;
      this.authFailures.set(ip, rec);
    }
    return ok;
  }

  isLockedOut(req) {
    const ip = req.socket.remoteAddress || 'unknown';
    const rec = this.authFailures.get(ip);
    return Boolean(rec && rec.until > Date.now());
  }

  async writeAtomic(file, content) {
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    await fsp.writeFile(tmp, content, { mode: 0o600 });
    await fsp.rename(tmp, file);
  }

  async backupCurrent() {
    if (!this.state.envelope) return;
    try {
      const name = `vault-r${this.state.revision}-${Date.now()}.json`;
      await fsp.writeFile(path.join(this.backupDir, name), JSON.stringify(this.state.envelope), {
        mode: 0o600,
      });
      const files = (await fsp.readdir(this.backupDir)).filter((f) => f.startsWith('vault-')).sort();
      for (const old of files.slice(0, Math.max(0, files.length - 20))) {
        await fsp.unlink(path.join(this.backupDir, old)).catch(() => {});
      }
    } catch (err) {
      console.warn('[warn] 备份失败：', err.message);
    }
  }

  /* ------------------------------ 静态文件 ------------------------------ */

  async serveStatic(req, res, pathname) {
    let rel = decodeURIComponent(pathname);
    if (rel === '/' || rel === '') rel = '/index.html';
    const webRoot = path.resolve(this.opts.webDir);
    const filePath = path.join(webRoot, path.normalize(rel).replace(/^(\.\.[/\\])+/, ''));
    if (!filePath.startsWith(webRoot)) {
      res.writeHead(403).end('Forbidden');
      return;
    }
    try {
      const stat = await fsp.stat(filePath);
      if (stat.isDirectory()) throw new Error('dir');
      const ext = path.extname(filePath).toLowerCase();
      const etag = `W/"${stat.size}-${Math.floor(stat.mtimeMs)}"`;
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304).end();
        return;
      }
      res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Content-Length': stat.size,
        ETag: etag,
        'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: blob:",
          "media-src 'self' blob:",
          "font-src 'self'",
          "connect-src 'self' http: https:",
          "manifest-src 'self'",
          "base-uri 'none'",
          "form-action 'none'",
        ].join('; '),
      });
      fs.createReadStream(filePath).pipe(res);
    } catch {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('404 未找到');
    }
  }

  /* ------------------------------ API ------------------------------ */

  async handleApi(req, res, url) {
    const { pathname } = url;

    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, X-Sync-Token, If-Match',
        'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
        'Access-Control-Max-Age': '86400',
      });
      res.end();
      return;
    }

    if (this.isLockedOut(req)) {
      this.sendJson(res, 429, { error: '尝试次数过多，请 30 秒后再试' });
      return;
    }

    if (pathname === '/api/info' && req.method === 'GET') {
      this.sendJson(res, 200, {
        app: 'dsh-passvault',
        version: 2,
        name: os.hostname(),
        revision: this.state.revision,
        updatedAt: this.state.updatedAt,
        hasVault: Boolean(this.state.envelope),
        authRequired: Boolean(this.token),
      });
      return;
    }

    if (!this.checkAuth(req)) {
      this.sendJson(res, 401, { error: '同步口令不正确' });
      return;
    }

    if (pathname === '/api/vault' && req.method === 'GET') {
      if (!this.state.envelope) {
        this.sendJson(res, 404, { error: '服务器上还没有保险库' });
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
        ETag: `"${this.state.revision}"`,
      });
      res.end(JSON.stringify(this.state.envelope));
      return;
    }

    if (pathname === '/api/vault' && req.method === 'PUT') {
      const ifMatch = req.headers['if-match'];
      if (ifMatch === undefined) {
        this.sendJson(res, 428, { error: '缺少 If-Match 版本号' });
        return;
      }
      const expected = Number(String(ifMatch).replace(/"/g, ''));
      if (!Number.isFinite(expected)) {
        this.sendJson(res, 400, { error: 'If-Match 版本号无效' });
        return;
      }
      if (expected !== this.state.revision) {
        this.sendJson(res, 409, { error: '版本冲突', revision: this.state.revision });
        return;
      }
      let envelope;
      try {
        envelope = JSON.parse(await this.readBody(req));
      } catch (err) {
        this.sendJson(res, err.status || 400, { error: err.status ? err.message : '请求体不是合法 JSON' });
        return;
      }
      if (
        !envelope ||
        envelope.format !== 'dsh-passvault' ||
        !envelope.header ||
        Number(envelope.header.revision) !== expected + 1
      ) {
        this.sendJson(res, 400, { error: '保险库格式不正确，或版本号不连续' });
        return;
      }
      await this.backupCurrent();
      await this.writeAtomic(this.vaultFile, JSON.stringify(envelope));
      this.state = {
        revision: Number(envelope.header.revision),
        updatedAt: envelope.header.updatedAt,
        envelope,
      };
      this.log(`[sync] 已更新保险库 → 版本 ${this.state.revision}（${new Date().toLocaleString('zh-CN')}）`);
      this.sendJson(res, 200, { ok: true, revision: this.state.revision, updatedAt: this.state.updatedAt });
      return;
    }

    this.sendJson(res, 404, { error: '接口不存在' });
  }

  /* ------------------------------ 启动 / 停止 ------------------------------ */

  async start() {
    this.initFs();
    this.token = this.loadToken();
    this.loadState();

    const listen = (server, port) =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, this.opts.host, () => resolve(server.address().port));
      });

    const handler = async (req, res) => {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      try {
        if (url.pathname.startsWith('/api/')) {
          await this.handleApi(req, res, url);
          return;
        }
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405).end('Method Not Allowed');
          return;
        }
        await this.serveStatic(req, res, url.pathname);
      } catch (err) {
        console.error('[error]', err);
        if (!res.headersSent) this.sendJson(res, 500, { error: '服务器内部错误' });
        else res.end();
      }
    };

    const httpServer = http.createServer(handler);
    this.httpPort = await listen(httpServer, this.opts.port);
    this.servers.push(httpServer);

    if (!this.opts.noHttps) {
      try {
        let cert;
        let key;
        if (this.opts.cert && this.opts.key) {
          cert = fs.readFileSync(this.opts.cert);
          key = fs.readFileSync(this.opts.key);
        } else {
          const generated = ensureCert(this.dataDir);
          cert = fs.readFileSync(generated.certPath);
          key = fs.readFileSync(generated.keyPath);
        }
        const httpsServer = https.createServer({ cert, key }, handler);
        this.httpsPort = await listen(httpsServer, this.opts.httpsPort);
        this.servers.push(httpsServer);
      } catch (err) {
        this.log(`[警告] HTTPS 服务启动失败（${err.message}），手机端将无法使用加密功能。`);
        this.httpsPort = 0;
      }
    }

    return { httpPort: this.httpPort, httpsPort: this.httpsPort, token: this.token };
  }

  async close() {
    await Promise.all(
      this.servers.map((s) => new Promise((resolve) => s.close(() => resolve()))),
    );
    this.servers = [];
  }

  get info() {
    return {
      httpPort: this.httpPort,
      httpsPort: this.httpsPort,
      token: this.token,
      revision: this.state.revision,
      dataDir: this.dataDir,
    };
  }
}
