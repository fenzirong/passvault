// Electron 桌面端入口：内嵌同步服务 + 原生窗口
import { app, BrowserWindow, Menu, dialog, shell, clipboard } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassVaultServer, lanAddresses } from '../server/app.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isDev = !app.isPackaged;

let mainWindow = null;
let server = null;
let startError = null;

/* ------------------------------ 服务 ------------------------------ */

async function startServer() {
  const dataDir = path.join(app.getPath('userData'), 'data');
  const attempt = async (port, httpsPort) => {
    const instance = new PassVaultServer({
      port,
      httpsPort,
      host: '0.0.0.0',
      dataDir,
      quiet: true,
    });
    await instance.start();
    return instance;
  };
  try {
    return await attempt(8787, 8443);
  } catch {
    // 端口被占用时退回随机端口，保证应用仍可使用
    return attempt(0, 0);
  }
}

/* ------------------------------ 窗口 ------------------------------ */

function createWindow(url) {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 900,
    minHeight: 620,
    title: '密码保险库',
    backgroundColor: '#0d0f14',
    autoHideMenuBar: false,
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });

  mainWindow.once('ready-to-show', () => mainWindow.show());

  // 外部链接用系统浏览器打开
  mainWindow.webContents.setWindowOpenHandler(({ url: target }) => {
    if (/^https?:\/\//i.test(target) && !target.startsWith(url)) {
      shell.openExternal(target);
    }
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, target) => {
    if (!target.startsWith(url)) {
      event.preventDefault();
      shell.openExternal(target);
    }
  });

  mainWindow.loadURL(url);

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

/* ------------------------------ 菜单 ------------------------------ */

function showPhoneHelp() {
  const addrs = lanAddresses();
  const lines = [];
  if (server?.httpsPort) {
    for (const a of addrs) lines.push(`https://${a.address}:${server.httpsPort}`);
  }
  const detail = [
    '手机与电脑连接同一个 Wi-Fi，然后用手机浏览器打开：',
    '',
    lines.length ? lines.join('\n') : '（HTTPS 服务未启动）',
    '',
    '首次访问会提示证书不受信任，选择「高级 → 继续前往」。',
    '',
    `配对码：${server?.pairingCode || '（未设置）'}`,
    '',
    `数据目录：${server?.info.dataDir || ''}`,
  ].join('\n');
  dialog.showMessageBox(mainWindow || undefined, {
    type: 'info',
    title: '手机访问地址',
    message: '在手机上打开密码保险库',
    detail,
    buttons: ['知道了', '复制配对码'],
    defaultId: 0,
    cancelId: 0,
  }).then(({ response }) => {
    if (response === 1 && server?.pairingCode) clipboard.writeText(server.pairingCode);
  });
}

function buildMenu() {
  const template = [
    {
      label: '文件',
      submenu: [
        {
          label: '打开数据目录',
          click: () => {
            if (server) shell.openPath(server.info.dataDir);
          },
        },
        { type: 'separator' },
        { role: 'quit', label: '退出' },
      ],
    },
    {
      label: '同步',
      submenu: [
        { label: '显示手机访问地址…', click: showPhoneHelp },
        {
          label: '在浏览器中打开',
          click: () => {
            if (server) shell.openExternal(`http://127.0.0.1:${server.httpPort}`);
          },
        },
      ],
    },
    {
      label: '视图',
      submenu: [
        { role: 'reload', label: '重新加载' },
        { role: 'togglefullscreen', label: '全屏' },
        { type: 'separator' },
        { role: 'resetZoom', label: '实际大小' },
        { role: 'zoomIn', label: '放大' },
        { role: 'zoomOut', label: '缩小' },
        ...(isDev ? [{ type: 'separator' }, { role: 'toggleDevTools', label: '开发者工具' }] : []),
      ],
    },
    {
      label: '帮助',
      submenu: [
        {
          label: '关于密码保险库',
          click: () =>
            dialog.showMessageBox(mainWindow || undefined, {
              type: 'info',
              title: '关于',
              message: `密码保险库 ${app.getVersion()}`,
              detail:
                '本地加密的密码管理器\n\n加密：PBKDF2-SHA256 + AES-256-GCM\n2FA：RFC 6238 TOTP\n\n数据只保存在本机，不会上传任何服务器。',
              buttons: ['好的'],
            }),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

/* ------------------------------ 启动 ------------------------------ */

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(async () => {
    app.setAppUserModelId('com.passvault.desktop');
    try {
      server = await startServer();
      buildMenu();
      createWindow(`http://127.0.0.1:${server.httpPort}/`);
    } catch (err) {
      startError = err;
      dialog.showErrorBox('启动失败', `无法启动本地服务：${err.message}`);
      app.quit();
    }

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0 && server) {
        createWindow(`http://127.0.0.1:${server.httpPort}/`);
      }
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });

  app.on('before-quit', async () => {
    if (server) {
      try {
        await server.close();
      } catch {
        /* 忽略 */
      }
      server = null;
    }
  });
}

void startError;
