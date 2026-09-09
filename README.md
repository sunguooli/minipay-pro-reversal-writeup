# MiniPay Pro 安卓客户端逆向与通信协议全量还原

> 个人安全研究项目 · 2026.08 – 2026.09 · 仅用于本地安全教育

对一个 **R8 full mode 混淆 + Native 加固**（`JNI_OnLoad` 动态注册、隐藏符号、O2 / RELRO / 栈保护）的安卓支付类训练靶场（MiniPay Pro 4.5 Lab），完成了从**全明文抓包**到**脱离 App 的独立协议客户端**的完整逆向闭环。

## 最终成果

- ✅ Pixel 6a（Android 16）真机上 Charles 抓到全量 HTTPS 明文，App 功能不受影响
- ✅ 还原 `X-MP-Proof` 请求签名与 `credential_proof` 登录凭证两套算法（三层 HMAC-SHA256 派生链）
- ✅ Python 独立客户端不依赖 App 进程，打通 `bootstrap → auth/challenge → auth/session → wallet/summary` 全链路，通过服务端验签拿到真实业务数据

## 三道防御墙与攻破路径

| 防御 | 位置 | 攻破方式 |
|---|---|---|
| ① SSL Pinning | Java 层自建 `TrustManager`（内置 `assets/minipay.crt`），`SSLContext.init` | Frida hook `init` 第二参数置 null，TLS 信任交还系统库（Charles CA 已通过 Magisk 模块装入 Android 16 的 conscrypt apex 信任路径） |
| ② 风控门控 | `(c() & 0x10003) != 0` → RISK-21 弹窗 | 不硬改返回值（会触发验签不一致），而是 IDA 定位 Native 电表函数 `sub_2BA4`，`retval.replace(0)` 归零，三方 risk 读数天然一致 |
| ③ 服务端验签 | `X-MP-Proof` 签名绑定 method/path/ts/nonce/session/device/risk/body | 以格式串为锚点倒追数据流，还原三层 HMAC-SHA256 派生链，Python 复现并逐层对拍 |

## 核心算法结论

```
X-MP-Proof:  MP2 kid=lab-k2,ts=<ts>,nonce=<nonce>,risk=00080000,body=<64hex>,sig=<64hex>

k1  = HMAC-SHA256(key="MiniPay.Request.Root/v2",  msg=device_id)
k2  = HMAC-SHA256(key=k1,  msg="req-v2\n" + session)
sig = HMAC-SHA256(key=k2,  msg="MP2\n{method}\n{path}\n{ts}\n{nonce}\n{session}\n{device}\n{risk:%08x}\n{body_sha256}")

credential_proof = "P2." + HMAC-SHA256(
    key=SHA256("MiniPay.Password.Proof/v2" + \0 + account + \0 + password),
    msg="P2\n{account}\n{challenge}\n{device_id}")
```

两个根常量均以 8 字节循环密钥 XOR 加密存放在 `libmpguard.so` 中，通过 IDA dump + Python 异或解出（"解出来得是可读 ASCII"即为自证）。

## 仓库结构

```
├── README.md
├── docs/
│   ├── 00-靶场设计说明.md          # 靶场的防御设计与验收标准（理解难度基线）
│   ├── 01-抓包通关记录.md          # SSL Pinning / 风控门控 / 验签三道墙的拆除全程
│   ├── 02-proof算法还原记录.md     # 三层 HMAC 链还原 + POST 登录攻坚 + 全部踩坑
│   └── 03-从MD5到HMAC-学习全历程.md # 前置关卡 v1→v4 的能力爬坡记录（Notion 笔记精选）
└── client/                         # 自研工具脚本（全部脱敏，仅含实验室内网地址与测试账号）
    ├── minipay_final.js            # 最终版 Frida 脚本：TLS 信任置换 + 电表归零（两个 hook 通关）
    ├── self_minipay.js             # 黄金向量采集 + Native HMAC 现场验证脚本
    ├── minipay_login.py            # 独立客户端：bootstrap → challenge → session 全链
    └── minipay_wallet_test.py      # 鉴权形态实验：Bearer/session 四组对照
```

## 方法论沉淀

1. **先静态画防御地图，再动手**——jadx/IDA 半小时定位三道墙，避免盲撞
2. **格式串/常量当锚点倒追数据流**——混淆代码里锚点优先，函数名靠后
3. **黄金向量当阅卷老师**——hook 取真值，但常量带走、动态值自算；对拍要对到数值层，格式像不算赢
4. **改动面越小越好**——一致性校验体系下，伪造值必然穿帮；观察优先于修改
5. **错误码是有指向性的布防图**——`risk_mismatch` / `metadata_mismatch` / `CREDENTIAL_INVALID` 各指一层，先看码再动手
6. **代码结构是调试工具**——一请求一函数、参数显式传，写死的 bug 才没地方藏

## 时间线

| 阶段 | 内容 | 周期 |
|---|---|---|
| v1 | MD5 + 盐值签名入门（params/data/json 基础） | 2026.08 上旬 |
| v2 | JNI 层分析入门（env 二级指针、vtable 偏移、fastcall） | 2026.08 中旬 |
| v3 | 多 ABI 定位 + CRC32 + AES-128-CBC/Base64 请求体加密还原 | 2026.08 下旬 |
| v4 Pro | SSL Pinning 绕过 + 风控电表 + 三层 HMAC 协议还原 + 独立客户端 | 2026.08.26 – 09.09 |

## 免责声明

本仓库所有材料均针对本地训练靶场（测试账号 `admin/123456`、实验室内网地址），仅用于安全学习与教育目的，不涉及任何真实产品。
