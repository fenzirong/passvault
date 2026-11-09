// 局域网同步客户端：配对码鉴权 + 跨设备中继
export class SyncError extends Error {
  constructor(message, code = 'SYNC_ERROR', extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

export function normalizeBaseUrl(input) {
  let url = String(input || '').trim();
  if (!url) throw new SyncError('请先选择或填写设备地址', 'NO_URL');
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
  url = url.replace(/\/+$/, '');
  try {
    new URL(url);
  } catch {
    throw new SyncError('设备地址格式不正确', 'BAD_URL');
  }
  return url;
}

export function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

export class SyncClient {
  /**
   * @param {{baseUrl: string, code?: string, token?: string, relay?: {baseUrl: string, code: string}|null, timeout?: number}} options
   */
  constructor({ baseUrl, code = '', token = '', relay = null, timeout = 15000 } = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.code = String(code || '');
    this.token = String(token || '');
    this.relay = relay;
    this.timeout = timeout;
  }

  authHeaders() {
    const headers = {};
    if (this.code) {
      headers['X-Pair-Code'] = this.code;
      headers['X-Sync-Token'] = this.code;
    } else if (this.token) {
      headers['X-Sync-Token'] = this.token;
    }
    return headers;
  }

  async request(path, { method = 'GET', body, headers = {} } = {}) {
    if (this.relay) return this.relayRequest(path, { method, body, headers });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...this.authHeaders(),
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
        cache: 'no-store',
      });
      const text = await res.text();
      return this.handleResponse(res.status, text);
    } catch (err) {
      if (err instanceof SyncError) throw err;
      if (err.name === 'AbortError') throw new SyncError('连接超时，请确认两台设备在同一局域网', 'TIMEOUT');
      throw new SyncError('无法连接该设备，请检查网络', 'NETWORK');
    } finally {
      clearTimeout(timer);
    }
  }

  /** 通过「提供页面的那台设备」转发请求（手机端跨设备时使用） */
  async relayRequest(path, { method = 'GET', body, headers = {} } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout + 5000);
    try {
      const res = await fetch(`${this.relay.baseUrl}/api/relay`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Pair-Code': this.relay.code,
        },
        body: JSON.stringify({
          target: this.baseUrl,
          method,
          path,
          headers: { ...this.authHeaders(), ...headers },
          body: body === undefined ? undefined : JSON.stringify(body),
        }),
        signal: controller.signal,
        cache: 'no-store',
      });
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new SyncError('中继返回了无法解析的内容', 'RELAY');
      }
      if (!res.ok) throw new SyncError(data?.error || '中继失败', 'RELAY');
      return this.handleResponse(Number(data.status) || 500, String(data.body ?? ''));
    } catch (err) {
      if (err instanceof SyncError) throw err;
      if (err.name === 'AbortError') throw new SyncError('中继超时', 'TIMEOUT');
      throw new SyncError('中继失败，请检查网络', 'NETWORK');
    } finally {
      clearTimeout(timer);
    }
  }

  handleResponse(status, text) {
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { raw: text };
    }
    if (status >= 200 && status < 300) return data;
    if (status === 401) throw new SyncError('配对码不正确', 'UNAUTHORIZED');
    if (status === 403) throw new SyncError(data?.error || '没有权限', 'FORBIDDEN');
    if (status === 404) throw new SyncError(data?.error || '设备上还没有保险库', 'NOT_FOUND');
    if (status === 409) {
      throw new SyncError('设备上的保险库已被更新', 'CONFLICT', { revision: data?.revision });
    }
    throw new SyncError(data?.error || `设备返回错误（HTTP ${status}）`, 'HTTP_ERROR', { status });
  }

  info() {
    return this.request('/api/info');
  }

  async pull() {
    try {
      return await this.request('/api/vault');
    } catch (err) {
      if (err.code === 'NOT_FOUND') return null;
      throw err;
    }
  }

  push(envelope, expectedRevision) {
    return this.request('/api/vault', {
      method: 'PUT',
      body: envelope,
      headers: { 'If-Match': String(expectedRevision) },
    });
  }

  test() {
    return this.info();
  }
}

/** 读取当前页面所在设备的发现信息（同源，无需鉴权） */
export async function fetchDiscovery(baseUrl = '') {
  const res = await fetch(`${baseUrl}/api/discovery`, { cache: 'no-store' });
  if (!res.ok) throw new SyncError('无法获取设备列表', 'DISCOVERY');
  return res.json();
}

/** 读取本机配对码（仅本机可访问） */
export async function fetchPairingInfo(baseUrl = '') {
  const res = await fetch(`${baseUrl}/api/pairing`, { cache: 'no-store' });
  if (!res.ok) return null;
  return res.json();
}

export async function rotatePairingCode(baseUrl = '') {
  const res = await fetch(`${baseUrl}/api/pairing/rotate`, { method: 'POST' });
  if (!res.ok) throw new SyncError('无法重新生成配对码', 'ROTATE');
  return res.json();
}
