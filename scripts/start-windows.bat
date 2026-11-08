@echo off
chcp 65001 >nul
title 密码保险库 · 局域网同步服务
cd /d "%~dp0.."

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   [!] 未检测到 Node.js
  echo       请先安装 Node.js 18 或更高版本: https://nodejs.org/zh-cn
  echo       安装完成后重新双击本文件。
  echo.
  pause
  exit /b 1
)

echo 正在启动密码保险库，浏览器将自动打开...
start "" cmd /c "timeout /t 2 >nul & start http://127.0.0.1:8787"
node server\server.js %*
pause
