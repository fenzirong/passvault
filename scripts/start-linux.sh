#!/usr/bin/env bash
# 启动密码保险库（Linux）
set -e
cd "$(dirname "$0")/.."
if ! command -v node >/dev/null 2>&1; then
  echo "未检测到 Node.js，请先安装 Node.js 18 或更高版本：https://nodejs.org/"
  exit 1
fi
( sleep 1; xdg-open http://127.0.0.1:8787 >/dev/null 2>&1 || true ) &
exec node server/server.js "$@"
