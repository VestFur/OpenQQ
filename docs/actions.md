# 发送与动作

改了代码后要重启：Ctrl+C 停掉 OpenQQ，手动退出 QQ，再执行 `npm start`。登录后等到「QQ 会话就绪」，就可以在终端底部的提示符里输入动作并回车。输入时收到的事件会打印在提示符上方，不会打断正在输入的内容。

动作可以从终端标准输入、本机 WebUI、OneBot v11 正向和反向 WebSocket 发出，配置见 [connect.md](connect.md)。还没有 OneBot HTTP 动作服务。

## 快捷命令

下面的号码都是示例，请换成你要测试的账号或群。

```text
/private 123456789 你好，发送测试
/group 987654321 群消息测试
/input 123456789 1
/login
/status
/verbose
/clear
/help
/quit
```

`/verbose` 开关调试信息和 QQ 原始日志的显示，`/clear` 清屏。终端里可以用 Tab 补全命令，用 ↑↓ 翻历史。

`/private`、`/group` 把后面的内容当纯文本发送，长得像 CQ 码的内容也原样发出去。`/input` 提交私聊的输入状态通知，事件码默认是 `1`，其他事件码原样传给 QQ，不去猜含义。`/quit` 解除挂接并退出 OpenQQ，QQ 可以继续运行。

## 动作一览

在终端里每个动作是一行 JSON；文本里的换行写成 JSON 的 `\n`。`echo` 原样返回。

| 类别 | 动作 |
| --- | --- |
| 发送 | `send_private_msg`、`send_group_msg`、`send_msg` |
| 消息 | `get_msg`、`get_forward_msg`、`get_image`、`delete_msg`（撤回）、`set_msg_emoji_like`（表情回应） |
| 群管理 | `set_group_kick`、`set_group_ban`、`set_group_whole_ban`、`set_group_admin`、`set_group_card`、`set_group_name`、`set_group_leave`、`set_group_add_request` |
| 好友 | `set_friend_add_request`、`send_like` |
| 查询 | `get_friend_list`、`get_group_list`、`get_group_info`、`get_group_member_list`、`get_group_member_info`、`get_stranger_info`、`get_login_info`、`get_status`、`get_version_info`、`can_send_image`、`can_send_record` |
| 扩展 | `set_input_status`、`generate_image`（生图）、`clean_cache`、`.handle_quick_operation`（快速操作，见 [connect.md](connect.md)） |

没有列出的动作返回 `1404`。这个版本的 QQ 没有提供戳一戳发送和设置群头衔的接口，所以 `send_poke` 和 `set_group_special_title` 不在其中。

```json
{"action":"send_private_msg","params":{"user_id":123456789,"message":"你好","auto_escape":true},"echo":"send-1"}
{"action":"send_group_msg","params":{"group_id":987654321,"message":"[CQ:at,qq=123456789] 你好 [CQ:face,id=14]"},"echo":"send-2"}
{"action":"send_group_msg","params":{"group_id":987654321,"message":[{"type":"reply","data":{"id":"12"}},{"type":"text","data":{"text":"收到"}}]},"echo":"reply-1"}
{"action":"send_group_msg","params":{"group_id":987654321,"message":[{"type":"image","data":{"file":"C:\\pics\\a.png"}}]},"echo":"image-1"}
{"action":"get_msg","params":{"message_id":12},"echo":"msg-1"}
{"action":"get_forward_msg","params":{"id":"15"},"echo":"forward-1"}
{"action":"set_input_status","params":{"user_id":123456789,"event_type":1},"echo":"typing-1"}
{"action":"get_login_info","echo":"login-1"}
```

`send_msg` 可以指定 `message_type`，也可以只给 `user_id` 或 `group_id` 中的一个来确定目标。

## 消息格式

`message` 可以是纯文本、CQ 码字符串，或最多 100 个消息段的数组。字符串默认按 CQ 码解析：`[CQ:类型,键=值]`，`&amp;`、`&#91;`、`&#93;` 会还原成 `&`、`[`、`]`，值里的逗号写成 `&#44;`；写得不完整的 CQ 码按普通文本处理。指定 `auto_escape:true` 则整个字符串原样当文本发送。

| 消息段 | 说明 |
| --- | --- |
| `text` | 纯文本 |
| `at` | `qq` 为 QQ 号或 `all`；只能用于群聊。`name` 可选，用来指定显示的名字，不填则取群名片或昵称 |
| `face` | `id` 为 QQ 表情编号 |
| `dice`、`rps` | 骰子、猜拳 |
| `reply` | 引用一条消息。`data.id` 是本次运行期间收到或发出的 `message_id`；只能引用同一会话里的消息，每条消息最多一个引用，发送时自动放到最前面 |
| `image` | 图片，见下面「媒体来源」。可选 `summary`（最多 64 个字符） |
| `record` | 语音，必须单独发送 |
| `video` | 视频，必须单独发送；需要封面，见下面 |
| `file` | 文件，必须单独发送；可选 `name` 指定文件名 |
| `json` | 应用（Ark）卡片，`data.data` 为 JSON 对象或其字符串；必须单独发送。QQ 会校验卡片签名，没签名或签名过期的卡片可能被拒绝 |

文本总大小不超过 64 KiB，一条消息最多 20 个媒体段。音乐卡片、商城表情、Markdown、合并转发（node）、分享、位置等其他消息段暂不支持，会返回 `1400` 并写明是哪一种。

## 媒体来源

`image`、`record`、`video`、`file` 的 `data.file`（也接受 `data.url`）可以是：

- 本机的绝对路径，如 `C:\pics\a.png`；
- `file://` 地址；
- `base64://` 或 `data:...;base64,` 数据；
- `http://` 或 `https://` 链接。

不接受相对路径、网络路径（`\\server\share`）和设备路径。

| 类型 | 支持的格式 | 大小上限 | 说明 |
| --- | --- | --- | --- |
| 图片 | png、jpeg、gif、webp、bmp | 30 MiB | 按文件头判断格式和尺寸，不看扩展名 |
| 语音 | SILK；WAV（16 位 PCM）需要可选依赖 `silk-wasm`；其他格式还需要 ffmpeg | 20 MiB | SILK 直接发送 |
| 视频 | MP4、MOV | 200 MiB | 封面用 `thumb`（任意图片来源）指定；不指定则用 ffmpeg 截取首帧；两者都没有就报错 |
| 文件 | 任意 | 200 MiB | |

ffmpeg 取自 `PATH`，也可以用环境变量 `OPENQQ_FFMPEG` 指定。`silk-wasm` 是可选依赖：`npm install` 会尝试安装，装不上也不影响其他功能；构建发布包时如果已安装，会一并带上。没有它时，只能直接发送 SILK 格式的语音。

下载链接的规则：

- 最多跟随 3 次重定向，每次都重新检查地址；
- 默认拒绝指向本机、内网、链路本地和运营商级 NAT 的地址（包括解析到这些地址的域名），防止通过 OpenQQ 访问内部服务。需要时可设置环境变量 `OPENQQ_MEDIA_ALLOW_PRIVATE=1` 放开；
- 使用 Clash 等 fake-ip 模式的 DNS 时域名会解析成 `198.18.x.x`，这个网段不受限制，下载正常；
- 下载、base64 解码和转码产生的临时文件放在 `.runtime/media/`，动作结束后删除，启动时清掉一小时前的残留。你自己的本地文件不会被删除。

发送媒体时，QQ 要等上传完成才返回结果，所以等待时间随文件变大：基础 15 秒，每 MiB 加 4 秒，最长 300 秒。

> 安全提醒：持有 OneBot 令牌的客户端可以让 OpenQQ 发送本机上任何它能读到的文件。请保护好令牌，不要把正向监听暴露到不可信的网络。

## 群管理

下面的动作都需要相应的群权限，QQ 拒绝时返回 `1500` 和原因。QQ 的成功回调只表示它接受了调用；是否真的生效，以随后的群通知为准（OpenQQ 会把它们转成通知事件）。

| 动作 | 参数 | 说明 |
| --- | --- | --- |
| `set_group_kick` | `group_id`、`user_id`、`reject_add_request` | 踢出成员，可选拒绝其再次申请 |
| `set_group_ban` | `group_id`、`user_id`、`duration` | 禁言，秒数 0 到 2592000，默认 1800；0 为解除 |
| `set_group_whole_ban` | `group_id`、`enable` | 全员禁言，默认开启 |
| `set_group_admin` | `group_id`、`user_id`、`enable` | 设置或取消管理员，只有群主可以；默认设置 |
| `set_group_card` | `group_id`、`user_id`、`card` | 修改群名片，最多 60 个字符，不填为清除 |
| `set_group_name` | `group_id`、`group_name` | 修改群名，最多 48 个字符 |
| `set_group_leave` | `group_id`、`is_dismiss` | 退群；`is_dismiss` 为 true 时解散，仅群主可用 |
| `set_group_add_request` | `flag`、`approve`、`reason` | 处理入群申请或邀请 |
| `set_friend_add_request` | `flag`、`approve` | 处理好友申请 |
| `delete_msg` | `message_id` | 撤回，仅限本次运行期间收发过的消息 |
| `send_like` | `user_id`、`times` | 资料点赞，1 到 20 次，默认 1 |

`set_group_add_request` 和 `set_friend_add_request` 用申请事件里的 `flag`。`flag` 的格式是 OpenQQ 自己定的：入群为 `g:<群号>:<通知类型>:<序号>`，好友为 `f:<UID>:<申请时间>`。请原样传回，不要解析或拼接。

查询类动作：

| 动作 | 返回 |
| --- | --- |
| `get_friend_list` | 数组，元素含 `user_id`、`nickname`、`remark`。来自 QQ 最近一次推送的完整好友列表，不会向 QQ 刷新；登录同步完成前返回 `1500`，QQ 号解析不出来的好友会被略过 |
| `get_group_list` | 数组，元素含 `group_id`、`group_name`、`member_count`、`max_member_count`。每次都会向 QQ 刷新 |
| `get_group_info` | 单个群，字段同上，来自最近一次群列表；没有这个群返回 `1404` |
| `get_group_member_list` | 数组，元素含 `user_id`、`nickname`、`card`、`role`（`owner`/`admin`/`member`）、`title`、`join_time`、`last_sent_time`、`level`、`shut_up_timestamp` 等 |
| `get_group_member_info` | 单个成员，字段同上；没有这个成员返回 `1404` |
| `get_stranger_info` | `user_id`、`nickname`、`sex`（`male`/`female`/`unknown`）、`age`；QQ 里查不到这个用户返回 `1404` |

`shut_up_timestamp` 是禁言到期的时间戳（秒），没被禁言为 0。性别、年龄、地区还没有接入，分别固定为 `unknown`、`0`、空。

## 生图

`generate_image` 用控制台「AI 生图」页保存的 Base URL、Key 和模型生成图片（设置见 [bot.md](bot.md#ai-生图)），所以先要在那一页填好 Key。

```json
{"action":"generate_image","params":{"prompt":"一只戴着飞行员护目镜的橘猫，柔和的晨光"},"echo":"img-1"}
{"action":"generate_image","params":{"prompt":"一幅水彩风景","size":"1536x1024","n":2,"group_id":987654321},"echo":"img-2"}
```

| 参数 | 说明 |
| --- | --- |
| `prompt` | 必填，提示词，最多 4000 个字符 |
| `model`、`size`、`n` | 可选，只对这一次调用覆盖保存的模型、尺寸（`auto` 或「宽x高」）和张数（1–4） |
| `group_id` 或 `user_id` | 可选，二选一。给了就把生成的图片作为一条消息发过去；都不给则只返回图片 |

- **不给目标**：返回 `images`，每张有 `file`（形如 `base64://…`，可以直接放进 `image` 段发出去）、`mime`、`width`、`height`、`bytes`，以及模型改写后的提示词 `revised_prompt`（有的话），另有 `model`、`size`、`elapsed_ms`。
- **给了目标**：发送走和 `send_group_msg` / `send_private_msg` 一样的流程，返回 `message_id`；`images` 里只有尺寸等信息，不再带图片数据。图片生成后发送失败时返回错误「图片已生成，但发送失败：…」，图片不会重复生成。
- 返回码：提示词、参数或设置有问题（比如没填 Key）是 `1400`；已经有一个生图任务在进行是 `1503`；接口或网络出错是 `1500`。同一时间只会有一个生图任务，和控制台的生图页共用这个限制。
- 生成通常要几十秒，最长等「AI 生图」页里设置的超时（默认 120 秒）。HTTP 调用可以用 `generate_image_async` 立即返回，在后台生成（给了目标时会照常发送）。每次生成都会向接口计费。

## 表情回应与清理

- `set_msg_emoji_like`：参数 `message_id`（与 `get_msg` 相同的 id 规则）、`emoji_id`（QQ 表情编号，或 emoji 的码点；数字）、`set`（默认 `true`，`false` 取消回应）。只支持群消息；消息必须还在 QQ 的本地记录里（用它的序号来定位），找不到返回 `1404`。这个动作调用 QQ 的 `setMsgEmojiLikes`，已在 QQ 9.9.37-54395 上用群消息验证：添加和取消「赞」（表情 76）都在群里生效。
- `clean_cache`：清理 OpenQQ 自己的媒体临时目录里一小时前的残留，和启动时的清理规则一样；不会动 QQ 的缓存，也不会碰正在使用的文件。

## 读取消息

`get_msg` 按 `message_id` 读取一条消息的内容。收到的 `reply` 段只带被引用消息的 id，把这个 `data.id` 当作 `message_id` 传进来，就能读到被引用的消息；即使它发生在 OpenQQ 启动之前，只要 QQ 本地还留着也能读到。

```json
{"status":"ok","retcode":0,"data":{"time":1794470000,"message_type":"group","message_id":12,"real_id":12,"user_id":123456789,"sender":{"user_id":123456789,"nickname":"昵称","card":"群名片"},"message":[{"type":"text","data":{"text":"内容"}}],"raw_message":"内容","font":0,"group_id":987654321}}
```

私聊没有 `group_id` 和 `card`。限制：

- `message_id` 只认本次运行期间收发过或被引用的消息（映射保存在内存里，最多 1 万条），其他 id 返回 `1404`。
- 已撤回的消息、系统提示、QQ 本地找不到的消息返回 `1404`；QQ 拒绝或 8 秒内没有回应返回 `1500`。
- 读消息不会触发下载：`image` 段只带 `file` 和 `file_id`，需要路径或内容时再调用 `get_image`；合并转发只带 `id`，需要内容时再调用 `get_forward_msg`。

## 合并转发

收到的合并转发会转换成 `forward` 段，`data.id` 可以用于 `get_forward_msg`。如果内容拉取成功，`data.content` 会直接带上转发的内容（最多嵌套 3 层、200 条、512 KiB）。`get_forward_msg` 也接受带有转发的那条消息的 `message_id`，返回：

```json
{"status":"ok","retcode":0,"data":{"messages":[{"time":1794470300,"message_type":"group","user_id":123456789,"sender":{"user_id":123456789,"nickname":"昵称"},"message":[{"type":"text","data":{"text":"内容"}}],"content":[{"type":"text","data":{"text":"内容"}}],"raw_message":"内容","message_format":"array"}]}}
```

每个节点同时有 `message`（NapCat 格式）和 `content`（go-cqhttp 格式）。转发里查不到 QQ 号的作者，`user_id` 是 `0`，昵称保留。`raw_message` 里的转发只写成 `[CQ:forward,id=…]`。

## 回执

发送成功的回执示例：

```json
{"status":"ok","retcode":0,"data":{"message_id":1},"echo":"send-1"}
```

`message_id` 与接收事件、撤回通知共用同一个进程内的映射；QQ 原生的 64 位 ID 不会被转成丢精度的 JavaScript 数字。`echo` 原样返回。

「发送成功」表示收到了与目标、当前账号和请求标识都匹配的 QQ 成功回调，不代表对方已读。输入状态的成功只表示原生通知调用完成，不代表对方客户端一定显示。

## 错误码与限制

| retcode | 含义 |
| --- | --- |
| `1400` | 参数或输入格式无效，没有提交 |
| `1404` | 动作未支持，或者引用/转发/撤回的 id、申请的 flag 不存在或已过期 |
| `1500` | 原生调用失败、QQ 拒绝，或回执无效 |
| `1501` | 超时，已提交的结果可能没有得到确认 |
| `1502` | 会话未就绪、正在重新初始化，或 IPC 断开 |
| `1503` | 动作队列已满（最多 32 个待处理），或单个连接同时进行的动作超过 8 个，没有提交 |

普通动作最多等 15 秒左右（带媒体的发送见上面），IPC 另有兜底超时。OpenQQ 不会自动重发；超时或断线之后，请先在 QQ 里确认消息有没有发出去。重新登录、会话重建或退出 OpenQQ 会阻止还没提交的旧动作，但已经交给 QQ 的发送没法靠断开 IPC 撤回。

`get_login_info` 目前返回账号的 QQ 号，昵称是空字符串。`get_status` 目前只反映原生会话是否可用，没有做完整的网络连通性探测。

## 需要 SSO 通道的动作

下面这些动作走的是 QQ 的 SSO 通道，需要额外提供一个发送组件（可选，**不随本仓库和发行包分发**，见 README 的说明）。没有这个组件时它们会如实返回 `1404` 与「通道未就绪」，其余动作不受影响：

- 协议层动作：`send_poke`、`sso_pipe_send`、`sso_pipe_status`
- OIDB 动作表里的群管理 / 群文件 / 群相册 / 群待办 / Ark 卡片 / p_skey 等
- QZone 读写（需要先拿到 `p_skey`）

`sso_pipe_send` 允许调用方发任意命令名和任意十六进制包体，是这套能力里权限最大的一个口子：**它等同于「以你的 QQ 身份发任意协议请求」**。只在完全信任调用方时启用；前置层与 OpenQQ 之间的令牌是它唯一的访问控制。

## 危险动作与 confirm_danger

不可撤回、且会影响他人的动作（踢人、退群、删好友、改群名、设置管理员、删群文件/群相册等）默认**只构造不发送**，返回 `1404` 并把构造好的包体（`bodyHex`）一并给出，便于核对字段。

要真正执行必须显式带 `confirm_danger: true`。

注意这个参数的性质：它只是调用方自己传的一个布尔值，作用域是**防误触**，不是授权。任何能调用动作的客户端都能带上它，所以不要把它当成权限边界；真正的边界是 OneBot 访问令牌和「谁能连上这个服务」。

## download_file 的限制

- 只接受 `http` / `https`，且必须是公网地址。内网、回环、链路本地、云元数据地址（`169.254.169.254`）、`localhost` / `.local` / `.internal` 这类主机名一律拒绝。
- **不跟随重定向**：目标返回 3xx 直接失败。否则一个公网地址可以 302 到内网，绕过上面的检查。
- 单次响应上限默认 32 MiB，可用 `max_bytes` 调整（1 B ~ 64 MiB），超限即中断，不会把整份响应读进内存。
- 落盘目录固定为 `<openqq>/data/downloads/`，文件名只保留安全字符（`/`、`\` 会被替换，开头的 `.` 会被去掉），因此 `../` 跳不出这个目录。
- `Host`、`Connection`、`Transfer-Encoding` 这类会改变连接本身的请求头会被丢弃，其余（`Referer`、`Authorization` 等）原样转发。

## 凭据类动作

`get_cookies`、`get_credentials`、`get_clientkey`、`get_csrf_token`、`get_pskey` 会把登录凭据（`skey` / `p_skey` / `clientKey` / 由它们算出的 `g_tk`）交给调用方。

也就是说：**任何持有 OneBot 访问令牌的客户端都能拿到这些凭据**，等价于拿到该 QQ 号在相关域上的登录态。部署时请把 OneBot 的令牌和端口当作凭据本身来保护，不要把服务暴露到不受信任的网络。

## 测试情况

所有动作都已在 QQ `9.9.37-54395` 上用测试群和测试账号实测。有两点以客户端显示为准：`send_like` 返回成功但无法读回；关闭全员禁言时 QQ 返回成功，但不会推送通知。

参数校验、UID 转换、并发回执匹配、媒体处理、超时和断线保护都有自动测试。OIDB 的 protobuf 编码（`encodeBySchema`、`wrapOidbBase`、`pb-mini` 的整数校验）、`download_file` 的地址与文件名净化、`nativeRefusal` 的失败文案识别都有不依赖真实 QQ 的单元测试。

## 尚未实现

- `set_group_anonymous` / `set_group_anonymous_ban`：QQ 内核没有对应接口，**回「尚未支持动作」而不是假装成功**。
- 设置群头衔：这个版本的 QQ 没有可用的 set 接口（只有 get）。
- 音乐卡片、群荣誉：内核与协议层都没有稳定入口。
- 四个 `*_stream` 流式下载动作：OneBot 的 HTTP 前置层没有流式帧协议，需要先扩协议；请用 `download_file` 代替。

协议字段参考 [OneBot v11 公开 API](https://github.com/botuniverse/onebot-11/blob/master/api/public.md)。输入状态、申请 `flag` 的格式是 OpenQQ 的扩展。
