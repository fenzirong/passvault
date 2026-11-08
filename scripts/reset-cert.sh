#!/usr/bin/env bash
# 删除自动生成的 HTTPS 证书，下次启动会按当前局域网 IP 重新生成
set -e
cd "$(dirname "$0")/.."
rm -f data/cert.pem data/key.pem
echo "已删除旧证书，重新启动服务即可按当前 IP 重新生成。"
