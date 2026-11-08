#!/usr/bin/env node
/**
 * 局域网同步服务 CLI
 * 用法：node server/server.js [--port 8787] [--https-port 8443] ...
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassVaultServer, lanAddresses } from './app.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const opts = {
    port: 8787,
    httpsPort: 8443,
    host: '0.0.0.0',
    dataDir: path.join(ROOT, 'data'),
    token: process.env.SYNC_TOKEN || '',
    noAuth: false,
    noHttps: false,
    cert: '',
    key: '',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--port' || a === '-p') opts.port = Number(next());
    else if (a === '--host') opts.host = next();
    else if (a === '--data') opts.dataDir = path.resolve(next());
    else if (a === '--token') opts.token = next();
    else if (a === '--no-auth') opts.noAuth = true;
    else if (a === '--https-port') opts.httpsPort = Number(next());
    else if (a === '--no-https') opts.noHttps = true;
    else if (a === '--cert') opts.cert = path.resolve(next());
    else if (a === '--key') opts.key = path.resolve(next());
    else if (a === '--help' || a === '-h') {
      console.log(`用法: node server/server.js [选项]

  -p, --port <端口>       HTTP 端口（默认 8787）
      --https-port <端口> HTTPS 端口（默认 8443）
      --no-https          不启动 HTTPS
      --host <地址>       监听地址（默认 0.0.0.0）
      --data <目录>       数据目录（默认 ./data）
      --token <口令>      指定同步口令（默认自动生成并保存在 data/token.txt）
      --no-auth           关闭口令校验（仅建议在完全可信的网络中使用）
      --cert / --key      使用自定义 HTTPS 证书
  -h, --help              显示帮助`);
      process.exit(0);
    }
  }
  return opts;
}

function printBanner(server) {
  const info = server.info;
  const addrs = lanAddresses();
  const line = '─'.repeat(60);
  console.log(`\n${line}`);
  console.log('  🔐 密码保险库 · 局域网同步服务已启动');
  console.log(line);
  console.log(`  本机访问：http://127.0.0.1:${info.httpPort}`);
  for (const a of addrs) {
    console.log(`  局域网：  http://${a.address}:${info.httpPort}   (${a.name})`);
  }
  if (info.httpsPort) {
    console.log('');
    console.log('  📱 手机请使用下面的 HTTPS 地址（浏览器提示证书不受信任时选择“继续访问”）：');
    for (const a of addrs) {
      console.log(`     https://${a.address}:${info.httpsPort}`);
    }
  }
  if (info.token) {
    console.log(`\n  同步口令：${info.token}`);
    console.log('  （在手机/其他电脑的“设置 → 局域网同步”中填写地址与口令）');
  } else {
    console.log('\n  ⚠️  已关闭口令校验（--no-auth），请仅在可信网络中使用');
  }
  console.log(`\n  数据目录：${info.dataDir}`);
  console.log(
    `  当前版本：${info.revision}${server.state.updatedAt ? `（${server.state.updatedAt}）` : '（空保险库）'}`,
  );
  console.log(`${line}\n  按 Ctrl+C 停止服务\n`);
}

const opts = parseArgs(process.argv.slice(2));
const server = new PassVaultServer(opts);

server
  .start()
  .then(() => printBanner(server))
  .catch((err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`\n[错误] 端口被占用：${err.message}`);
      console.error('       可能已有实例在运行，可用 --port 指定其他端口。\n');
    } else {
      console.error('[错误] 服务启动失败：', err);
    }
    process.exit(1);
  });

process.on('SIGINT', async () => {
  await server.close();
  console.log('\n已停止同步服务。');
  process.exit(0);
});
