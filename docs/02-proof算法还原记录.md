# MiniPay proof 算法还原全过程（2026-09-05 ~ 09-08）

> 前置：抓包已通关（见《01-抓包通关记录.md》）。本次目标：**脱离 App，用 Python 独立伪造合法请求**。
> 最终成果：boot​​strap / wallet / transactions / auth/challenge 全部伪造成功，服务器返回真实业务数据。

---

## 最终算法结论（速查）

### X-MP-Proof 结构
```
MP2 kid=lab-k2,ts=<ts>,nonce=<nonce>,risk=00080000,body=<64hex>,sig=<64hex>
```

### body 字段
```
body = sha256(HTTP请求体原文).hexdigest()
GET 无请求体 → sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### sig 字段（三层 HMAC-SHA256 派生链）
```python
k1  = hmac.new(b"MiniPay.Request.Root/v2", device_id, sha256).digest()
k2  = hmac.new(k1, b"req-v2\n" + session, sha256).digest()
sig = hmac.new(k2, 签名明文, sha256).hexdigest()

签名明文 = "MP2\n{method}\n{path含query}\n{ts}\n{nonce}\n{session}\n{device}\n{risk:%08x}\n{body_hex}"
```

### 常量与规则
- 根 key：`MiniPay.Request.Root/v2`（23 字节，so 里 XOR 加密存放：`byte_B00[i&7] ^ byte_DDA[i]`，8 字节循环密钥）
- nonce：`secrets.token_bytes(12).hex()` = 24 位 hex
- ts：Unix 秒；`request_window: 120`（服务器容忍 120 秒）
- risk：proof 里 `%08x`（`00080000`），`X-MP-Risk` 头里十进制（`524288`）
- session 为空时明文里是两个相邻 `\n`；challenge 流程后 session 有值，k2 输入要带上
- 签名绑定 method+path+query+ts+nonce+body → **每请求必须重新签，复用必死（metadata_mismatch / nonce 重放）**

### 关键函数（libmpguard.so，IDA 地址）
| 函数 | 作用 |
|---|---|
| sub_1700 | NativeBridge.a() 的 native 实现（proof 生成） |
| sub_2BA4 | 风险电表（native 直读，`retval.replace(0)` 归零） |
| sub_3B00 | SHA-256（输出 32 字节 raw） |
| sub_3FD4 | hex 编码器（1 字节→2 字符） |
| sub_3EB8 | HMAC-SHA256（0x36/0x5C 指纹） |
| sub_2B00 | snprintf 包装（格式串拼装） |
| risk 合成 | `BL sub_2BA4` 后 `ORR w20, w0, w20` → Java 层伪造无解 |

---

## 全过程复盘

### 阶段 0：起点
抓包要挂 frida 掐 TLS + 电表归零，太麻烦 → 目标：还原 X-MP-Proof 生成算法，写独立客户端。

### 阶段 1：黄金向量（hook NativeBridge.a）
- 脚本 `self_minipay.js`：`NB.a.overloads.forEach` 遍历重载，`ol.apply(this, arguments)` 调原函数，前后打印入参/返回值
- 入参 7 字符串 + int risk：`["GET","/api/v2/bootstrap","ts","nonce","session","device","","524288"]`
- 返回值 = 完整 proof 明文
- 发现：ts/nonce 每请求变；body 恒定 `e3b0c442...`；两个空串参数（session 和当时不明的""）；`524288=0x80000`
- 认知：forEach 遍历的是**重载版本**不是参数；hook 值是阅卷老师不是答卷——常量可带走，动态值必须自算

### 阶段 2：risk 定案
- hook Java `p.c()` 返回 0x80000 → 仍 risk_mismatch
- IDA：native 直读电表 + ORR 传入值 → Java 层伪造无解，保留电表归零 hook

### 阶段 3：IDA 静态分析 sub_1700
- 切入法：**格式串当锚点**（`%s\n%s\n...\n%08x\n%s` 和 `%s kid=%s,...sig=%s`），从 body/sig 参数倒追数据流
- 认出 sub_3B00=SHA256（findcrypt 常量表）、sub_3FD4=hex 编码器（v7+=2）、sub_3EB8=HMAC（64 字节 key 块 0x41 边界 + 0x36/0x5C + 嵌套双哈希 64+msg / 96=64+32）
- 读代码技能：栈偏移连续性（v12~v15=64 字节 key 块）；`*((_QWORD*)&v99+1)`={指针,长度} 结构体后半；veorq_s8=向量异或
- **数 sub_3EB8 出现次数：三次** → 三层 HMAC 派生链（一开始误看成一层，被纠正）

### 阶段 4：Python 解根 key
- IDA dump byte_B00(8B)/byte_DDA(23B)，Python XOR → `b"MiniPay.Request.Root/v2"`（可读 ASCII = 解密正确的自证）
- 坑：`bytes(int)` 造零字节串不是取值；空列表用 append

### 阶段 5：Frida native hook 验证
- sub_3EB8 两种现场：①key=根key(23B) msg=device_id（第一层）②keylen=0x20 乱码 key msg=签名明文（第三层，key=上层 32B raw 输出）
- sub_3B00 定位 body：公共函数噪音淹没 → **`this.context.lr` 减基址过滤调用点**（lr=BL+4=0x1D24）→ arg1=0 空输入实锤
- v100 上追 = a() 倒数第二参 = 请求体原文 → GET 空串悬案闭环
- 认知：readCString 遇二进制截断/越界；输出参数 onEnter 是垃圾、onLeave 才是结果；空串物理形态=首字节 00；Frida 17 `this.returnAddress` 失效用 `this.context.lr`

### 阶段 6：Python 复现对拍
- body：`hashlib.sha256(b"").hexdigest()` == 黄金向量 ✅
- sig：三层链 + **分段对拍**（onLeave dump 每层 k1/k2 和 Python 对比）
- 坑：digest() vs hexdigest()；str/bytes 转换；`%08x` 收整数；明文拼装 `%` 格式化 / `"\n".join()`；空 session 双 `\n`
- 多组黄金向量 sig 全对 ✅

### 阶段 7：独立客户端实战
- requests + `verify=False`（只关身份核验不关加密）+ `proxies=127.0.0.1:8888` 过 Charles 对比
- bootstrap 返回真业务数据 ✅
- 复用头打第二个请求 → `metadata_mismatch`：签名绑定语义（服务器重算对比）
- 客户端 4 bug：ts/nonce 生成三次不一致 / get_sig 写死路径 / query 串漏签 / nonce 长度 24→`token_bytes(12)`
- 第二个 GET（auth/challenge 带 query）✅

---

## 已完成：NativeBridge.b() —— credential_proof（2026-09-08 通关）

### 最终算法（速查）
```python
stage1 = sha256(b"MiniPay.Password.Proof/v2" + b"\0" + account + b"\0" + password).digest()  # 32B raw
msg    = "P2\n%s\n%s\n%s" % (account, challenge, device_id)   # 是 challenge，不是 challenge_id！
credential_proof = "P2." + hmac.new(stage1, msg.encode(), sha256).hexdigest()
```
- 根常量：`MiniPay.Password.Proof/v2`（**25 字节**，byte_B00[i&7]^byte_DF1[i]，最后一字节 byte_DF1[24]=0x03，IDA 里容易被当成 padding 漏掉；`__strlen_chk` 第二参数 0x1A=26=25+NUL 可自证）
- 分隔符是 NUL 字节 `\0`（0x00），**不是字符 '0'**（0x30）；两个 `\0` 由长度公式 keylen+1+acctlen+pwlen+1 的两个 +1 自证
- `"P2"` 来自 `strcpy(v55,"P2")`，最终输出前缀 `P2.<64hex>`（hook 真值背书）
- challenge_id 只是请求体里的独立字段，**不进签名明文**

### POST /auth/session 打通（2026-09-08）
- 工作脚本：`minipay_login.py`（bootstrap → challenge → session 全 200）
- 返回：`access_token` + `session_id`（ss_+24hex）+ user 信息（admin/林舟）
- 客户端要点：每个请求一个函数、签名参数显式传；POST 必须 `data=body_bytes`（自己 json.dumps，签和发同一坨字节）；`get_sig` 的 method/body 不许写死

### 错误码指向性（排障字典）
| 错误码 | 指向层 |
|---|---|
| SECURITY_PROOF_INVALID: signature | 层2 X-MP-Proof 的 sig（本次：get_Gsig 写死 GET + 空串 body 哈希） |
| CREDENTIAL_INVALID 账号或密码错误 | 层1 credential_proof（本次：明文塞了 challenge_id 应为 challenge）或凭据本身错 |
| metadata_mismatch / nonce 重放 | 签名绑定语义：每请求重签 |

### 新坑清单
- IDA 数组尾字节被 padding 误导 → 用 strlen_chk 上界/可读 ASCII 完整性交叉验证
- str/bytes 混用：拼接含 NUL 时全程 bytes，别 decode
- 公共函数 install_header 改一半：header 里的 body 和签名明文里的 body 必须同源
- 只看 `.json()` 不看 status_code/text → 错误响应不是 JSON 时异常掩盖真因

### 待办（下一阶段）
1. ~~带 session 的鉴权请求~~ **已完成（2026-09-09）**：`Authorization: Bearer <access_token>`（前缀必需，裸 token → 401 SESSION_REQUIRED）+ session 必须进 k2 和明文第 6 行（漏 → 403 signature）。GET /api/v2/wallet/summary 200，拿到真实钱包数据。注意端点是 /wallet/summary 不是 /wallet（404）。实验脚本 `minipay_wallet_test.py`
2. session（`ss_`+24hex）生成逻辑考据（服务器下发还是客户端派生？本次为服务器返回）
3. 后续：GET /api/v2/transactions?page=1&page_size=20、POST /api/v2/training/receipt（非空 body + session 组合）

### 阶段 8：POST /auth/session 攻坚（2026-09-08 晚 ~ 09-09）

**起点**：GET 两包已通，a() 三层链在手。IDA 静态啃 b()：第一棒确认（25 字节常量 + \0 + account + \0 + 密码 → SHA256）；`strcpy(v55,"P2")` 悬着；v92(challenge)/v93(device_id) 未出场 → 后面必有第二棒。

**黄金向量：看了，但只用了一半**。hook b() 拿到真值 `P2.e62105e2...`——"P2." 前缀当场认出，和 `strcpy(v55,"P2")` 互相背书，**格式层对上了**。但同一次调用的四个入参没有回喂给 Python 复算，**数值层没对**。认知突破：真值拿在手里 ≠ 用了它；完整对拍 = 入参回喂 + 逐字符比对，看到格式像就放行，等于把阅卷老师当观众。challenge vs challenge_id 这笔账因此悬着，最后靠服务器错误码试出答案——拿服务器当阅卷老师，一次请求一次机会，比本地对拍贵得多。

**三连坑（全是自己填的）**：
- byte_DF1 尾部 `3,0,0,0` 当成 padding 没要 → 解出 `MiniPay.Password.Proof/v` 半截串。对照 a() 根 key 的 `/v2` 尾、以及 `__strlen_chk(src, 0x1A)` 的上界 26，长度信息早就泄露了。**IDA 数组尾部"像 padding 的字节"先算进去试，可读串的完整性本身就是校验**
- 伪 C 的 `\0` 当成字符 `'0'`（0x00 vs 0x30）；`src.decode()` 成 str 再拼 NUL，bytes/str 混乱。**拼接含 NUL 就全程 bytes**
- GET 时代每包 body 都是 `e3b0c442...`（空串哈希），肌肉记忆带进 POST。**同形态经验的惯性，换个场景就是坑**

**知识点补票：dict 与 json.dumps**。卡在"dict 不能编码怎么 sha256"→ 点透：dict 是内存对象，线上跑的是字节；哈希只对 bytes 有意义；`json=` 是 requests 背着你 dumps，`data=` 才是给什么发什么。签名场景必须自己 dumps 出 bytes，**签它、发它，同一变量两处用**。服务器只认原始字节哈希，不挑 JSON 格式。

**403 循环与错误码指向性**：
- `SECURITY_PROOF_INVALID: signature` → 层 2 sig：get_Gsig 写死 `"GET"` + 写死空串 body 哈希
- `CREDENTIAL_INVALID 账号或密码错误` → 层 1 credential_proof（或凭据本身）
- **先看码再动手，码是有指向性的**；三层搅在一起时服务器的"不"没有方向

**改一半比没改难查**。body 哈希出现在两个地方：header 的 `body=` 字段 + 签名明文第 9 行。body 参数传进了 install_header（header 对了），调 get_Gsig 时没递进去（明文还签空串）→ header 宣称的和 sig 实际签的自相矛盾。method 线走通了，body 线断在最后一米。**修 bug 要把同一条数据流走到底，走一半的现象是"我明明改了"**。

**凶器一直在屏幕上**：自己加的 `print(planitext)` 每轮都打出第 9 行 `e3b0c442...`——GET 时代见过几百遍的串，出现在 POST 明文里就是红旗。没看出来的原因不是不懂，是**代码铺太开**：install_header/get_Gsig 职责粘连、参数链长、f-string 里嵌套函数调用，写死的 `get_body(b"")` 有地方藏。这正面印证了自己悟的结构原则：**一请求一函数、参数显式传，代码量多一点点，思考范围小一大圈，写死都没地方写死**。

**终局**：补一个参数（函数签名接、内部用、调用处递），403 → 200。拿到 `access_token`、`ss_`+24hex 的 session_id、user(admin/林舟)。独立客户端登录全链打通。

**元教训排序**：① 错误码有指向性，先看码；② 分层隔离，一层绿了碰下一层；③ 对拍要对到数值层，格式像不算赢；④ 修数据流要走全程；⑤ 代码结构是调试工具，不只是审美。

---

## 方法论沉淀

1. **静态定结构**：格式串/常量当锚点倒追数据流；数敏感函数调用次数校验流程模型
2. **hook 取真值**：黄金向量当阅卷老师；lr 偏移过滤公共函数噪音；输出参数 onLeave 读
3. **Python 重写**：常量写死、动态值自算；分段对拍优于端到端
4. **实战验收**：先固定输入对答案，再放开输入打真包
