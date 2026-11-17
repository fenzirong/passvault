// 安卓后台同步服务（原生插件）：让手机在后台也能被局域网设备访问
function plugin() {
  const cap = globalThis.Capacitor;
  if (!cap?.isNativePlatform?.()) return null;
  return cap.Plugins?.PassVaultServer || null;
}

export function available() {
  return Boolean(plugin());
}

export async function start({ code, deviceId, name }) {
  const p = plugin();
  if (!p) return null;
  try {
    return await p.start({ code, deviceId, name });
  } catch {
    return null;
  }
}

export async function stop() {
  const p = plugin();
  if (!p) return;
  try {
    await p.stop();
  } catch {
    /* 忽略 */
  }
}

export async function updateVault(envelope) {
  const p = plugin();
  if (!p || !envelope) return;
  try {
    await p.updateVault({ envelope });
  } catch {
    /* 忽略 */
  }
}

export async function getVault() {
  const p = plugin();
  if (!p) return null;
  try {
    return await p.getVault();
  } catch {
    return null;
  }
}

export async function peers() {
  const p = plugin();
  if (!p) return null;
  try {
    const res = await p.peers();
    return Array.isArray(res?.peers) ? res.peers : [];
  } catch {
    return null;
  }
}

export async function status() {
  const p = plugin();
  if (!p) return null;
  try {
    return await p.status();
  } catch {
    return null;
  }
}

export function onVaultUpdated(handler) {
  const p = plugin();
  if (!p) return () => {};
  let removed = false;
  const handle = p.addListener('vaultUpdated', (data) => {
    if (!removed) handler(data);
  });
  return () => {
    removed = true;
    Promise.resolve(handle)
      .then((h) => h?.remove?.())
      .catch(() => {});
  };
}
