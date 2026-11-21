# 自研 SSO 组件（openqq-sso-local）

这个目录是**自研 SSO 发送组件的插槽**。组件本身还没实现，但接口契约、构建方式和加载路径都已经定好，
把它填进来就能用，不需要改 OpenQQ 的其它任何代码。

---

## 它要解决的问题

QQ 的 `wrapper.node` 只给 JS 暴露了一个 `sendSsoCmdReqByContend`，实测是**本地白名单网关**
（同一个包走真正的发送链能拿到 p_skey，走它只回 `{}` / 0 毫秒）。拍一拍、内核没有的群管理、
QZone 的 p_skey 全都卡在这一层。

绕过去的唯一办法是**在 QQ 进程内**把包送到真正的 SSO 发送链上。这需要一个进程内的组件，
也就是本目录要产出的 `openqq-sso-local.dll`。

---

## 契约（实现这个就够了）

组件是一个**只依赖 `KERNEL32.dll` 的独立 DLL**，被 `LoadLibraryW` 载入 QQ 进程后：

1. **自建命名管道** `\\.\pipe\openqq-sso.<pid>.control`
   - `<pid>` 用 `GetCurrentProcessId()` 拼，不需要外部传参
   - 只接受一个连接；断开后要能重新接受
2. **按 QHP1 帧格式收发**（和 `native/sso-pipe.cjs` 完全一致，见下）
3. **自己负责**：怎么在进程内拿到真实的发包能力、怎么把 protobuf 包送出去
   —— 这一层是组件的内部实现，`bootstrap.cpp` 不需要知道任何细节

**不需要导出任何函数。** `bootstrap.cpp` 只做一件事：按文件名 `LoadLibraryW`。
管道建出来，JS 侧就连得上；建不出来，JS 侧按超时降级。

---

## QHP1 帧格式

```
偏移  类型   字段
0     u32    magic = 0x31504851 ("QHP1")
4     u16    version = 1
6     u16    op
8     u32    requestId
12    i32    status
16    u32    flags        1 = WantReply, 4 = LoggedIn
20    u32    cmdLen       ≤ 0x1000
24    u32    msgLen       ≤ 0x10000
28    u32    bodyLen      ≤ 0x1000000
32    u64    value0
```

全部 little-endian。头部 40 字节，后面紧跟 `cmd`（UTF-8）、`msg`（UTF-8）、`body`（原始字节）。

| op | 方向 | 含义 |
|---|---|---|
| `0x01` | dll → node | hello，`msg` = pid 字符串 |
| `0x02` | node → dll | 发包，`cmd` = SSO 命令名，`body` = protobuf |
| `0x03` | 双向 | ack（已受理，回包还在路上） |
| `0x04` | dll → node | 回包，`status` + `body` |
| `0x05` | dll → node | 错误，`msg` = 原因 |
| `0x06` | dll → node | 主动推送收到的包 |
| `0x07` | dll → node | 登录态，`flags` 带 `LoggedIn` |
| `0x11` | node → dll | ping，只回 ack |

`requestId` 由 node 侧递增分配，dll 回包时必须原样带回。

---

## 构建与分发

```bash
npm run build:sso-local        # 产出 native/bin/openqq-sso-local.dll
```

**这个产物随发行包一起分发，用户开箱即用、不需要任何编译环境。**
这是自己写的组件，不是别人的闭源件，没有再分发问题；杀软风险靠「发布版不含扫描代码」这条架构约束来压，
不是靠「让用户自己编」来躲。

---

## 加载顺序（`native/bootstrap.cpp` 的 `loadSsoBridge`）

```
① openqq-sso-local.dll       ← 本目录产出，优先
② snowluma-win32-x64.dll     ← 外部可选依赖，用户自装
③ 都没有                     ← 静默跳过，退回「内核 JS + 纯 HTTP」，功能降级但不崩
```

覆盖方式：

```
OPENQQ_SSO_PROVIDER=none|local|snowluma   只启用指定的一个
OPENQQ_LOCAL_SSO_DLL=<绝对路径>           指定本组件位置
OPENQQ_SL_DLL=<绝对路径>                  指定外部组件位置
```

---

## ⚠️ 安全软件边界（必须遵守）

**发布版不得包含任何内存扫描、任意地址读取、全局函数挂接。**

这三项组合会被 Windows Defender 判成通用可疑行为并直接隔离，与代码是否恶意无关 —— 已经发生过一次。

所以实现这个组件时：

- **调试期**：用 `npm run build:native:debug` 产出 `openqq-bootstrap-debug.dll`（含探针），
  在真实 QQ 进程里做一次性逆向，定位发包入口、验证结构体偏移
- **固化**：把逆向结论写成配置表（QQ 版本 → 特征 + 偏移），**不要**把扫描代码带进发布路径
- **发布期**：`npm run build:native` 的护栏会拒绝含探针符号的产物

`scripts/build-native.mjs` 的护栏按产物名分档：发布版带探针符号即构建失败，`-debug` 版不限。

---

## 当前状态

- [x] 加载路径与三路 provider 优先级
- [x] 双产物构建 + 护栏分档
- [x] QHP1 帧协议（`native/sso-pipe.cjs` 已实现客户端）
- [ ] **组件本体**（本目录的 `src/`，待实现）
- [ ] 调试版逆向：定位 QQ 版本对应的发包入口
