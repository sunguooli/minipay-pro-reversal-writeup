# MiniPay Pro Lab · 可运行靶场

这是本仓库 writeup 对应的**完整可运行训练靶场**，任何人都可以本地复现整个逆向过程。

## 包含内容

| 文件 | 说明 |
|---|---|
| `MiniPay-Pro-Lab.apk` | 目标应用（Release、R8 混淆、三 ABI，`debuggable=false`） |
| `server/MiniPay-Lab-Server.exe` | 自包含 Windows 服务端（Flask 打包，**无需安装 Python**，双击即用） |
| `server/cert.pem` / `key.pem` | 实验室自签名证书与私钥（仅训练用途，无真实价值） |
| `server/start-server.bat` | 一键启动脚本（自动注入证书路径环境变量） |
| `CHECKSUMS-SHA256.txt` | 交付物校验和 |

## 快速开始

1. **启动服务端**：进入 `server/`，双击 `start-server.bat`，看到 `https://0.0.0.0:5443` 即就绪。
2. **网络前提**：APK 硬编码后端地址为 `192.168.56.1:5443`（VirtualBox Host-Only 网卡地址），且证书 SAN 只认 `192.168.56.1` / `127.0.0.1` / localhost。请确保电脑上有该网段（安装 VirtualBox 或手动添加 host-only 适配器），手机与电脑处于同一环境（模拟器直接可用；真机需自行解决路由）。
3. **安装 APK**：`adb install MiniPay-Pro-Lab.apk`，测试账号 `admin / 123456`（另有 `test / qwer1234`）。
4. **开始逆向**：服务端真正执行 nonce 去重、三阶段设备绑定和签名验算——你只抓包是过不了登录的，协议必须真还原。通关思路见仓库根目录的 [docs/](../docs/) 三篇 writeup。

## 注意事项

- exe 为 PyInstaller 打包的 Windows 程序，首次运行可能触发 SmartScreen 提示（未知发布者），属正常现象；非 Windows 用户可自行用 Flask 重写，协议细节在 `docs/02` 中已完整公开。
- 服务端会打印每个请求的错误码（`risk_mismatch` / `metadata_mismatch` / `CREDENTIAL_INVALID` …），**错误码本身就是提示**，善用它们。
- 所有证书、密钥、账号均为本地安全教育材料，请勿用于任何真实场景。
