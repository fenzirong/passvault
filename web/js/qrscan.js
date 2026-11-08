// 摄像头 / 相册二维码扫描（基于 jsQR，纯前端实现，图像不会离开设备）
const overlayId = 'qr-scanner-overlay';

export function cameraSupported() {
  return Boolean(navigator.mediaDevices && typeof navigator.mediaDevices.getUserMedia === 'function');
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

/**
 * 打开扫码界面
 * @param {{title?: string, hint?: string, onScan: (text: string) => void, onClose?: () => void}} options
 * @returns {{close: () => void}}
 */
export function openQrScanner({ title = '扫描二维码', hint = '将二维码置于取景框内', onScan, onClose } = {}) {
  document.getElementById(overlayId)?.remove();

  const overlay = el('div', 'scan-overlay');
  overlay.id = overlayId;

  const video = el('video', 'scan-video');
  video.setAttribute('playsinline', 'true');
  video.muted = true;

  const canvas = document.createElement('canvas');
  canvas.style.display = 'none';

  const top = el('div', 'scan-top');
  top.append(el('h3', '', title), Object.assign(el('button', 'scan-close', '✕'), { ariaLabel: '关闭' }));
  const closeBtn = top.querySelector('.scan-close');
  closeBtn.setAttribute('aria-label', '关闭');

  const frame = el('div', 'scan-frame');
  frame.appendChild(el('div', 'scan-corners'));

  const bottom = el('div', 'scan-bottom');
  const status = el('p', 'scan-status', '正在启动摄像头…');
  const actions = el('div', 'scan-actions');
  const galleryBtn = el('button', 'scan-btn', '从相册选择');
  const cancelBtn = el('button', 'scan-btn primary', '取消');
  actions.append(galleryBtn, cancelBtn);
  bottom.append(status, actions);

  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = 'image/*';
  fileInput.hidden = true;

  overlay.append(video, canvas, top, frame, bottom, fileInput);
  document.body.appendChild(overlay);

  let stream = null;
  let raf = 0;
  let stopped = false;
  let lastScan = 0;

  function cleanup() {
    if (stopped) return;
    stopped = true;
    cancelAnimationFrame(raf);
    if (stream) {
      for (const track of stream.getTracks()) track.stop();
      stream = null;
    }
    video.srcObject = null;
    overlay.remove();
    onClose?.();
  }

  function succeed(text) {
    const value = String(text || '').trim();
    if (!value) return;
    cleanup();
    onScan?.(value);
  }

  function decodeSource(source, width, height) {
    if (!window.jsQR) return null;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    canvas.width = width;
    canvas.height = height;
    ctx.drawImage(source, 0, 0, width, height);
    const data = ctx.getImageData(0, 0, width, height);
    return window.jsQR(data.data, width, height, { inversionAttempts: 'attemptBoth' });
  }

  function tick() {
    if (stopped) return;
    if (video.readyState >= 2) {
      const now = performance.now();
      if (now - lastScan > 120) {
        lastScan = now;
        try {
          const vw = video.videoWidth || 640;
          const vh = video.videoHeight || 480;
          const scale = Math.min(1, 800 / Math.max(vw, vh));
          const result = decodeSource(video, Math.round(vw * scale), Math.round(vh * scale));
          if (result?.data) {
            succeed(result.data);
            return;
          }
        } catch {
          /* 忽略单帧错误 */
        }
      }
    }
    raf = requestAnimationFrame(tick);
  }

  closeBtn.onclick = cleanup;
  cancelBtn.onclick = cleanup;
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) cleanup();
  });

  galleryBtn.onclick = () => fileInput.click();
  fileInput.onchange = async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    status.textContent = '正在识别图片…';
    try {
      const bitmap = await createImageBitmap(file);
      const scale = Math.min(1, 1000 / Math.max(bitmap.width, bitmap.height));
      const result = decodeSource(bitmap, Math.round(bitmap.width * scale), Math.round(bitmap.height * scale));
      bitmap.close?.();
      if (result?.data) succeed(result.data);
      else status.textContent = '没有在图片中识别到二维码，请换一张试试';
    } catch {
      status.textContent = '图片读取失败';
    }
  };

  if (!window.jsQR) {
    status.textContent = '二维码组件未加载，请刷新页面后重试（或手动粘贴密钥）';
  } else if (!cameraSupported() || !window.isSecureContext) {
    status.textContent = window.isSecureContext
      ? '当前浏览器不支持摄像头调用，可从相册选择二维码图片'
      : '需要 HTTPS 才能使用摄像头，可从相册选择二维码图片';
    video.style.display = 'none';
    frame.style.display = 'none';
  } else {
    navigator.mediaDevices
      .getUserMedia({
        video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
        audio: false,
      })
      .then((s) => {
        if (stopped) {
          s.getTracks().forEach((t) => t.stop());
          return;
        }
        stream = s;
        video.srcObject = s;
        video.play().catch(() => {});
        status.textContent = hint;
        raf = requestAnimationFrame(tick);
      })
      .catch((err) => {
        status.textContent =
          err?.name === 'NotAllowedError'
            ? '摄像头权限被拒绝，可在浏览器设置中允许，或从相册选择图片'
            : err?.name === 'NotFoundError'
              ? '没有找到摄像头，请从相册选择二维码图片'
              : '摄像头启动失败，请从相册选择二维码图片';
        video.style.display = 'none';
        frame.style.display = 'none';
      });
  }

  return { close: cleanup };
}
