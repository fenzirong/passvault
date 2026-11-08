// 局域网同步客户端：与本地同步服务（server/server.js）通信
export class SyncError extends Error {
  constructor(message, code = 'SYNC_ERROR', extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

export function normalizeBaseUrl(input) {
  let url = String(input || '').trim();
  if (!url) throw new SyncError('请先填写同步服务器地址', 'NO_URL');
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
  url = url.replace(/\/+$/, '');
  try {
    // 校验 URL 合法性
    new URL(url);
  } catch {
    throw new SyncError('服务器地址格式不正确', 'BAD_URL');
  }
  return url;
}

export class SyncClient {
  constructor({ baseUrl, token = '', timeout = 15000 } = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.token = String(token || '');
    this.timeout = timeout;
  }

  async request(path, { method = 'GET', body, headers = {} } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(this.token ? { 'X-Sync-Token': this.token } : {}),
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        cache: 'no-store',
      });
      const text = await res.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = { raw: text };
      }
      if (!res.ok) {
        if (res.status === 401) throw new SyncError('同步口令不正确', 'UNAUTHORIZED');
        if (res.status === 409) {
          throw new SyncError('服务器上的保险库已被其他设备更新', 'CONFLICT', {
            revision: data?.revision,
          });
        }
        throw new SyncError(data?.error || `服务器返回错误（HTTP ${res.status}）`, 'HTTP_ERROR', {
          status: res.status,
        });
      }
      return data;
    } catch (err) {
      if (err instanceof SyncError) throw err;
      if (err.name === 'AbortError') throw new SyncError('连接超时，请确认电脑与手机在同一局域网', 'TIMEOUT');
      throw new SyncError('无法连接同步服务器，请检查地址与网络', 'NETWORK');
    } finally {
      clearTimeout(timer);
    }
  }

  /** 获取服务器状态 */
  info() {
    return this.request('/api/info');
  }

  /** 拉取服务器上的保险库（未初始化时返回 null） */
  async pull() {
    try {
      return await this.request('/api/vault');
    } catch (err) {
      if (err.status === 404) return null;
      throw err;
    }
  }

  /** 推送保险库；expectedRevision 用于乐观锁 */
  push(envelope, expectedRevision) {
    return this.request('/api/vault', {
      method: 'PUT',
      body: envelope,
      headers: { 'If-Match': String(expectedRevision) },
    });
  }

  /** 测试连通性 */
  async test() {
    const info = await this.info();
    return info;
  }
}
