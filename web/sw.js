// Service Worker：缓存应用外壳，断网也能打开（仅 https / localhost 生效）
//
// 缓存策略（v1.5.4 起）：
//   - 导航请求与外壳文件（index.html / app.js / styles.css）走「网络优先」，
//     拿不到网络才回退缓存。旧版是「缓存优先 + 后台更新」，导致升级后第一次
//     打开仍然是旧界面 —— 桌面端窗口长期不刷新，就表现为「电脑端没有分组」。
//   - 其它静态资源走 stale-while-revalidate。
const CACHE = 'passvault-v7';
const ASSETS = [
  './',
  './index.html',
  './styles.css',
  './manifest.webmanifest',
  './js/app.js',
  './js/util.js',
  './js/crypto.js',
  './js/base32.js',
  './js/totp.js',
  './js/aegis.js',
  './js/migration.js',
  './js/generator.js',
  './js/vault.js',
  './js/sync.js',
  './js/qrscan.js',
  './js/backup.js',
  './js/biometric.js',
  './js/native-server.js',
  './vendor/jsQR.js',
  './vendor/qrcode.js',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

// 必须每次都拿最新的文件：界面与逻辑都在里面
const SHELL = new Set(['/', '/index.html', '/styles.css', '/js/app.js']);
const NETWORK_TIMEOUT_MS = 4000;

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

async function networkFirst(request) {
  const cache = await caches.open(CACHE);
  try {
    const res = await withTimeout(fetch(request), NETWORK_TIMEOUT_MS);
    if (res && res.ok) cache.put(request, res.clone());
    return res;
  } catch {
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached) return cached;
    throw new Error('offline');
  }
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE);
  const cached = await cache.match(request);
  const network = fetch(request)
    .then((res) => {
      if (res && res.ok) cache.put(request, res.clone());
      return res;
    })
    .catch(() => cached);
  return cached || network;
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET') return;
  // 同步接口永远走网络
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/shadow/')) return;
  if (url.origin !== self.location.origin) return;

  const isShell = event.request.mode === 'navigate' || SHELL.has(url.pathname);
  event.respondWith(isShell ? networkFirst(event.request) : staleWhileRevalidate(event.request));
});
