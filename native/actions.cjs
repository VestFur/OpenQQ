'use strict';

const { fail, identifier, integer, nativeId } = require('./common.cjs');
const { parseCQ } = require('./cq.cjs');
const admin = require('./admin.cjs');
const { createElementBuilder } = require('./elements.cjs');
// SSO 发包走自研通道（bootstrap 在 QQ 进程内改了一次 std::string 构造的跳转目标），
// 不加载任何第三方注入组件；没有配套 bootstrap 时 sso_pipe_* 与走 OIDB 的动作会如实报错，
// 不影响其余动作。
const pb = require('./pb-mini.cjs');
// OIDB 动作表：一个动作一行，加动作只加一行。
const oidb = require('./oidb-actions.cjs');

// download_file 只接受公网 http(s)。允许任意 URL 会让这个动作变成 SSRF 跳板：打到内网、
// 127.0.0.1、链路本地地址，或者云环境的元数据地址（169.254.169.254）。
const PRIVATE_V4 = [
  [/^0\./, '0.0.0.0/8'],
  [/^10\./, '10.0.0.0/8'],
  [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, '100.64.0.0/10'],
  [/^127\./, '127.0.0.0/8'],
  [/^169\.254\./, '169.254.0.0/16'],
  [/^172\.(1[6-9]|2\d|3[01])\./, '172.16.0.0/12'],
  [/^192\.168\./, '192.168.0.0/16'],
];
const PRIVATE_V6 = [/^::$/, /^::1$/, /^f[cd]/, /^fe[89ab]/, /^::ffff:/];

function assertPublicHttpUrl(raw) {
  let url;
  try { url = new URL(String(raw)); } catch { throw fail('download_file 的 url 不是合法地址'); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw fail('download_file 只支持 http/https');
  if (url.username || url.password) throw fail('download_file 不接受带账号密码的 url');
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) throw fail('download_file 的 url 没有主机名');
  if (host === 'localhost' || /\.(localhost|local|internal|lan|home\.arpa)$/.test(host)) {
    throw fail(`download_file 拒绝本机或内网主机名：${host}`);
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    for (const [pattern, range] of PRIVATE_V4) {
      if (pattern.test(host)) throw fail(`download_file 拒绝内网地址（${range}）：${host}`);
    }
  } else if (host.includes(':')) {
    for (const pattern of PRIVATE_V6) {
      if (pattern.test(host)) throw fail(`download_file 拒绝内网 IPv6 地址：${host}`);
    }
  }
  return url;
}

// 文件名只留安全字符：basename 挡不住 '..'，而 '..' 会让落盘路径跳出 data/downloads。
function safeDownloadName(raw) {
  const cleaned = String(raw ?? '')
    .replace(/[\\/]/g, '_')
    .replace(/[^\w.\- ]+/g, '_')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 100);
  return cleaned && cleaned !== '.' && cleaned !== '..' ? cleaned : '';
}

// 只拦会被 fetch 用来改变连接目标的头，其余（Referer / Authorization 等）原样保留。
const BLOCKED_DOWNLOAD_HEADERS = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'upgrade', 'te']);
function sanitizeDownloadHeaders(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof key !== 'string' || !key.trim()) continue;
    if (BLOCKED_DOWNLOAD_HEADERS.has(key.trim().toLowerCase())) continue;
    if (typeof value !== 'string' && typeof value !== 'number') continue;
    out[key.trim()] = String(value).slice(0, 2000);
  }
  return Object.keys(out).length ? out : null;
}

// 边读边算，超过上限立刻停 —— 一次性 arrayBuffer 会把整份响应读进内存。
async function readBodyCapped(response, maxBytes) {
  if (!response.body) return Buffer.from(await response.arrayBuffer());
  const chunks = [];
  let total = 0;
  for await (const chunk of response.body) {
    total += chunk.length;
    if (total > maxBytes) throw new Error(`响应超过 ${maxBytes} 字节上限`);
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}


const MiB = 1024 * 1024;
// 语义化原生直通表：OneBot 动作名 → 内核 service.method + 参数构造。
// 加一个动作只加一行；参数形状是探出来的（argc 断言 + 错误文案），没探清的不要往这里塞。
// 内核原生方法里的「会话」一律是 {chatType, peerUid, guildId} 这个三元结构，
// 而 OneBot 那边是 group_id / user_id 两个数字。所有互动类动作都要做这一次翻译，
// 所以收敛到一个函数，避免每个动作各写一遍（写歪一处就是 -100 这种找不到原因的回绝）。
function nativePeerOf(params) {
  const ref = params && params.openqq_ref;
  if (ref && typeof ref === 'object' && typeof ref.peerUid === 'string' && ref.peerUid) {
    return { chatType: Number(ref.chatType ?? 2) === 1 ? 1 : 2, peerUid: String(ref.peerUid).slice(0, 64), guildId: String(ref.guildId ?? '') };
  }
  const group = params ? params.group_id : undefined;
  const user = params ? params.user_id : undefined;
  if (group !== undefined && group !== null && String(group) !== '') {
    return { chatType: 2, peerUid: String(group), guildId: '' };
  }
  if (user !== undefined && user !== null && String(user) !== '') {
    return { chatType: 1, peerUid: String(user), guildId: '' };
  }
  throw new Error('需要 group_id 或 user_id（或 openqq_ref.peerUid）');
}

// SnowLuma（功能基准）里同一件事用的是另一套动作名。兼容的含义是「它的名字能直接调」，
// 所以这里只做一次改名映射，不动实现本体——两套名字指向同一段原生调用，不会出现两份行为。
const NATIVE_ALIAS = {
  set_essence_msg: 'add_group_essence',
  delete_essence_msg: 'remove_group_essence',
  delete_group_tag: 'remove_group_tag',
  set_friend_remark: 'set_buddy_remark',
  delete_friend: 'del_buddy',
  get_doubt_friends_add_request: 'get_buddy_req',
  set_doubt_friends_add_request: 'approval_doubt_buddy',
  set_group_reaction: 'set_msg_emoji_like',
  fetch_reaction_summary: 'get_recent_emoji',
  // 群系统消息一族：SL 的 get_group_system_msg 现在有精确实现了，不再交给兼容层猜。
  get_group_system_msg: 'fetch_group_notify',
  get_group_ignored_notifies: 'get_single_screen_notifies',
  set_group_add_request_oidb: 'operate_sys_notify',
  // 精华 / 禁言：主名走实测可用的新方法，SL 那两个老名字当别名一起指向它，
  // 免得再出现「动作注册了但调用时报尚未支持」这种表里不一致。
  get_group_essence_list: 'fetch_group_essence_list',
  get_group_essence_msg_list: 'fetch_group_essence_list',
  query_group_mute_member: 'get_group_shutup_list',
  get_group_shut_list: 'get_group_shutup_list',
  // SL 的两个历史拼写/旧名，指向已验证的主名实现
  click_inline_keyboard_button: 'click_inline_button',
  // OneBot v11 标准名：专属头衔。主名 set_special_title 走 OIDB 0x8fc_2。
  set_group_special_title: 'set_special_title',
  // friend_poke / group_poke 不在这里——别名表只认 NATIVE_OPS 里的动作，
  // 而拍一拍走的是 sso_pipe 分支。三个名字在 validateAction 的拍一拍分支里一起判断。
};

// QZone 全家：29 个动作名从 SnowLuma 打包产物实抽（不是猜的），外加两个凭据调试口。
const QZONE_ACTIONS = new Set([
  'get_cookies', 'get_csrf_token', 'debug_qzone_credential',
  'get_qzone_feeds', 'get_qzone_home_feeds', 'get_qzone_msg_list', 'get_qzone_profile',
  'get_qzone_feed_detail', 'get_qzone_msg_detail',
  'send_qzone_msg', 'delete_qzone_msg', 'set_qzone_msg_right', 'set_qzone_profile', 'set_qzone_ban',
  'like_qzone', 'unlike_qzone', 'comment_qzone', 'get_qzone_share_ark',
  'get_qzone_public_capabilities', 'get_qzone_public_feeds', 'get_qzone_public_feed_detail',
  'get_qzone_public_comments', 'get_qzone_public_replies', 'comment_qzone_public_feed',
  'reply_qzone_public_feed', 'forward_qzone_public_feed',
  'delete_qzone_public_comment', 'delete_qzone_public_reply',
  'set_qzone_public_comment_like', 'set_qzone_public_follow', 'set_qzone_public_like', 'set_qzone_public_upvote',
]);

const NATIVE_OPS = {
  get_profile_like: { service: 'ProfileLike', method: 'getBuddyProfileLike', arity: 1, build: p => [Number(p.user_id)] },
  get_online_clients: { service: 'OnlineStatus', method: 'getOnlineFrdStatusInfos', arity: 0, build: () => [] },
  get_recent_contact: { service: 'RecentContact', method: 'getRecentContactList', arity: 0, build: () => [] },
  delete_custom_face: { service: 'msg', method: 'deleteFavEmoji', arity: 1, build: p => [String(p.emoji_id ?? p.face_id ?? p.id ?? '')] },
  check_url_safely: { service: 'msg', method: 'checkMsgWithUrl', arity: 1, build: p => [{ url: String(p.url ?? p.text ?? '') }] },
  get_group_tags: { service: 'Group', method: 'getGroupTagRecords', arity: 1, build: p => [String(p.group_id ?? '')] },
  translate_en2zh: { service: 'RichMedia', method: 'translateEnWordToZn', arity: 1, build: p => [String(p.text ?? p.words ?? '')] },
  list_filesets: { service: 'FlashTransfer', method: 'getFileSetList', arity: 1, build: p => [{ pageCount: Number(p.count ?? 20), pageIndex: Number(p.index ?? 0) }] },

  // ── 全量实测补齐（OneBot 标准动作 → 内核真实方法；argc 与参数形状均已用 debug_call 在真机确证）──
  // 判据：每条都在真机上跑出过 result:0 或明确的业务回执（不是猜的）。
  set_qq_profile: { service: 'Profile', method: 'setNickName', arity: 1, build: p => [String(p.nickname ?? p.nick ?? '')] },
  set_self_longnick: { service: 'Profile', method: 'setLongNick', arity: 1, build: p => [String(p.longNick ?? p.long_nick ?? p.sign ?? p.longnick ?? '')] },
  set_group_remark: { service: 'Group', method: 'modifyGroupRemark', arity: 2, build: p => [String(p.group_id ?? ''), String(p.remark ?? p.card ?? p.name ?? '')] },
  send_flash_msg: { service: 'FlashTransfer', method: 'sendFlashTransferMsg', arity: 1, build: p => {
      const heads = Array.isArray(p.heads) ? p.heads : [];
      const peer = p.peer_uid ?? p.peerUid ?? '';
      if (!heads.length && !peer) return [{}];
      return [{ MsgHeads: heads.length ? heads : [{ peerUid: String(peer), chatType: Number(p.group_id ? 2 : 1) }] }];
    } },
  delete_flash_file: { service: 'FlashTransfer', method: 'removeFolderFiles', arity: 2, build: p => [String(p.file_set_id ?? p.fileset ?? ''), Array.isArray(p.files) ? p.files : []] },
  send_to_new_members: { service: 'Group', method: 'publishInstructionForNewcomers', arity: 3, build: p => [String(p.group_id ?? ''), String(p.content ?? p.message ?? p.text ?? ''), Array.isArray(p.at) ? p.at : []] },
  mark_msg_as_read: { service: 'msg', method: 'setMsgRead', arity: 1, build: p => [{ chatType: Number(p.group_id ? 2 : 1), peerUid: String(p.group_id ?? p.user_id ?? ''), guildId: '' }] },
  mark_group_msg_as_read: { service: 'msg', method: 'setMsgRead', arity: 1, build: p => [{ chatType: 2, peerUid: String(p.group_id ?? ''), guildId: '' }] },
  mark_private_msg_as_read: { service: 'msg', method: 'setMsgRead', arity: 1, build: p => [{ chatType: 1, peerUid: String(p.user_id ?? ''), guildId: '' }] },
  // 下面两个形状是实测探出来的：forceFetchClientKey('') 直接返回 clientKey/expireTime；
  // getMsgEmojiLikesList 固定 7 参，第一个是 peer 对象，后面 arg 顺序按实测。
  get_clientkey: { service: 'Ticket', method: 'forceFetchClientKey', arity: 1, build: p => [String(p.cmd ?? '')] },
  get_msg_emoji_likes: { service: 'msg', method: 'getMsgEmojiLikesList', arity: 7, build: p => {
    const peer = (p.openqq_ref && typeof p.openqq_ref === 'object' && p.openqq_ref.peerUid)
      ? { chatType: Number(p.openqq_ref.chatType ?? 2), peerUid: String(p.openqq_ref.peerUid), guildId: String(p.openqq_ref.guildId ?? '') }
      : { chatType: p.group_id ? 2 : 1, peerUid: String(p.group_id ?? p.user_id ?? ''), guildId: '' };
    return [peer, String(p.msg_id ?? p.message_id ?? ''), String(p.emoji_id ?? ''), Number(p.count ?? 20), String(p.cookie ?? ''), 0, false];
  } },
  fetch_emoji_like: { service: 'msg', method: 'getMsgEmojiLikesList', arity: 7, build: p => {
    const peer = (p.openqq_ref && typeof p.openqq_ref === 'object' && p.openqq_ref.peerUid)
      ? { chatType: Number(p.openqq_ref.chatType ?? 2), peerUid: String(p.openqq_ref.peerUid), guildId: String(p.openqq_ref.guildId ?? '') }
      : { chatType: p.group_id ? 2 : 1, peerUid: String(p.group_id ?? p.user_id ?? ''), guildId: '' };
    return [peer, String(p.msg_id ?? p.message_id ?? ''), String(p.emoji_id ?? ''), Number(p.count ?? 20), String(p.cookie ?? ''), 0, false];
  } },
  get_ai_record: { service: 'Group', method: 'listAllAIVoice', arity: 1, build: p => [{ groupCode: String(p.group_id ?? '') }] },

  // ── 互动类（「在 QQ 里和人互动」而不是发消息）────────────────────────────
  // 这一族的共同点：动作的结果是服务器侧的一个状态变更，不是一条消息。
  // 它们在内核 wrapper.node 里都有对应方法（argc 用 9 参断言实测过），所以不需要走 SSO 协议包。
  // 约定：arity 是实测真实参数个数，build 必须给出正是这么多的参数；
  // 参数形状没探清的动作一律允许调用方用 raw_args 原样传数组（长度按 arity 校验）。

  // 表情回应（贴表情）：对应 SL 的 set_msg_emoji_like / OIDB 36994
  set_msg_emoji_like: { service: 'msg', method: 'setMsgEmojiLikes', arity: 5, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    // `message_id` 是 OneBot 自增序号，不是 QQ 真 msgId（见 src/onebot.mjs 的 nextId++）。
    // 真 msgId + peerUid 要从 `openqq_ref` 拿 —— 和 reply 段、get_forward_msg、forward_* 完全同一套机制。
    const ref = nativeRef(p.openqq_ref);
    const msgId = ref ? String(ref.msgId) : String(p.message_id ?? p.msg_id ?? '');
    const peer = ref ? String(ref.peerUid) : nativePeerOf(p);
    const isSet = p.is_set === undefined ? true : Boolean(p.is_set);
    return [peer, msgId, String(p.emoji_id ?? p.emoji ?? ''), isSet ? 1 : 0, null];
  } },
  // 最近使用表情（实测  直接返回 emojiInfoList）
  get_recent_emoji: { service: 'msg', method: 'getRecentUseEmojiList', arity: 0, build: () => [] },
  // 内联按钮（机器人卡片上的按钮）：对应 OIDB 4398
  click_inline_button: { service: 'msg', method: 'clickInlineKeyboardButton', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ peer: nativePeerOf(p), msgId: String(p.message_id ?? ''), buttonId: String(p.button_id ?? p.id ?? '') }];
  } },
  click_tofu_button: { service: 'msg', method: 'clickTofuActionButton', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [nativePeerOf(p), String(p.message_id ?? ''), String(p.button_id ?? p.id ?? '')];
  } },
  // 消息标记未读 / 好坏反馈
  set_mark_unread: { service: 'msg', method: 'setMarkUnreadFlag', arity: 2, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [nativePeerOf(p), Boolean(p.unread ?? true)];
  } },
  like_or_dislike_report: { service: 'msg', method: 'likeOrDislikeReportForMsg', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [nativePeerOf(p), String(p.message_id ?? ''), Number(p.like ?? 1)];
  } },
  // 语音转文字（内核自带，对应 SL /fetch_ptt_text 的同族能力）
  translate_ptt_to_text: { service: 'msg', method: 'translatePtt2Text', arity: 3, cbIndex: 2, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [nativePeerOf(p), String(p.message_id ?? ''), {}];
  } },
  // 撤回拍一拍（拍一拍的对照组，验证这一族确实是状态变更而非消息）
  recall_nudge: { service: 'msg', method: 'recallNudge', arity: 2, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [nativePeerOf(p), String(p.message_id ?? '')];
  } },

  // 群精华：对应 OIDB 3756
  add_group_essence: { service: 'Group', method: 'addGroupEssence', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), msgSeq: String(p.message_seq ?? p.msg_seq ?? ''), msgRandom: String(p.message_random ?? p.msg_random ?? '') }];
  } },
  remove_group_essence: { service: 'Group', method: 'removeGroupEssence', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), msgSeq: String(p.message_seq ?? p.msg_seq ?? ''), msgRandom: String(p.message_random ?? p.msg_random ?? '') }];
  } },
  // fetchGroupEssenceList(argc 2) 是"回调式阻塞"方法：传 null 当回调时内核不返回，实测会挂住进程
  // （debug_call 直接 aborted）。getGroupLatestEssenceList 是同数据的同步版，改走它。
  fetch_group_essence_list: { service: 'Group', method: 'getGroupLatestEssenceList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },
  fetch_group_essence_list_legacy: { service: 'Group', method: 'getGroupLatestEssenceList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },
  query_cached_essence: { service: 'Group', method: 'queryCachedEssenceMsg', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },

  // get_pskey 已交给 OIDB（native/oidb-actions.cjs 的 0x102a_0）：
  //    TipOff.getPskey 实测 domainPskeyMap 恒空，留着这条只会短路掉能用的那条。
  //    原来那条保留在下面注释里备查，别再启用。
  // get_pskey: { service: 'TipOff', method: 'getPskey', arity: 2, cbIndex: 1, build: p => { ... } },

  // 群公告（整套：发布/删除/列表/催读/已读回执）
  publish_group_bulletin: { service: 'Group', method: 'publishGroupBulletin', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), content: String(p.content ?? p.text ?? '') }, String(p.content ?? p.text ?? ''), {}];
  } },
  delete_group_bulletin: { service: 'Group', method: 'deleteGroupBulletin', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? ''), String(p.bulletin_id ?? p.feed_id ?? ''), null];
  } },
  get_group_bulletin_list: { service: 'Group', method: 'getGroupBulletinList', arity: 4, cbIndex: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), pageStart: Number(p.page ?? 0), pageLimit: Number(p.count ?? 20) }, Number(p.page ?? 0), Number(p.count ?? 20), {}];
  } },
  remind_group_bulletin_read: { service: 'Group', method: 'remindGroupBulletinRead', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? ''), String(p.bulletin_id ?? p.feed_id ?? ''), null];
  } },
  get_group_bulletin_read_users: { service: 'Group', method: 'getGroupBulletinReadUsers', arity: 6, cbIndex: 5, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? ''), String(p.bulletin_id ?? p.feed_id ?? ''), Number(p.page ?? 0), Number(p.count ?? 20), '', null];
  } },

  // 群标签分类：对应 OIDB 38524/38525/38526
  get_group_tag_list: { service: 'Group', method: 'getGroupTagListByCategory', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? '') }];
  } },
  add_group_tag: { service: 'Group', method: 'addGroupTagToCategory', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    // 实测：字段名必须是 name（传 tag / tagName / tags 一律回 200012 "tag name is empty"）
    return [{ groupCode: String(p.group_id ?? ''), name: String(p.name ?? p.tag ?? '') }];
  } },
  remove_group_tag: { service: 'Group', method: 'removeGroupTagFromCategory', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), name: String(p.name ?? p.tag ?? '') }];
  } },

  // AI 语音：对应 OIDB 37531/37533
  list_ai_voice: { service: 'Group', method: 'listAllAIVoice', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? '') }];
  } },
  save_ai_voice: { service: 'Group', method: 'saveAIVoice', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), voiceId: String(p.voice_id ?? ''), voiceName: String(p.voice_name ?? '') }];
  } },

  // 群成员相关（只读部分）
  get_group_member_level_info: { service: 'Group', method: 'getGroupMemberLevelInfo', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? '') }];
  } },
  // getGroupShutUpMemberList(argc 1) 同样是阻塞式（debug_call aborted）；queryGroupMuteMemberList
  // 是同一份禁言名单的同步版，回 { errCode, rsp: { rspMemberList, totalMemberNum } }。
  get_group_shutup_list: { service: 'Group', method: 'queryGroupMuteMemberList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },
  get_group_shutup_list_legacy: { service: 'Group', method: 'queryGroupMuteMemberList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },
  get_transferable_group_list: { service: 'Group', method: 'getTransferableGroupList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },

  // 好友请求 / 好友管理：对应 OIDB 2909
  // 实测：friendUid 必须是 **uid**（u_xxx 形态）。传 QQ 号会回 316「存在格式非法账号」，
  // 所以只有调用方给了 uid 才能真正通过；传 user_id 时仍然下发，让服务端自己拒绝（不在这里瞎转换）。
  approval_friend_request: { service: 'Buddy', method: 'approvalFriendRequest', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ friendUid: String(p.uid ?? p.user_id ?? p.uin ?? ''), reqTime: String(p.flag ?? p.req_time ?? ''), accept: Boolean(p.approve ?? true) }];
  } },
  approval_doubt_buddy: { service: 'Buddy', method: 'approvalDoubtBuddyReq', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.uin ?? p.user_id ?? ''), Boolean(p.approve ?? true), null];
  } },
  get_buddy_req: { service: 'Buddy', method: 'getBuddyReq', arity: 0, build: () => [] },
  del_buddy: { service: 'Buddy', method: 'delBuddy', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ friendUid: String(p.user_id ?? p.uin ?? '') }];
  } },
  set_buddy_remark: { service: 'Buddy', method: 'setBuddyRemark', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ uid: String(p.user_id ?? p.uin ?? ''), remark: String(p.remark ?? '') }];
  } },
  req_to_add_friends: { service: 'Buddy', method: 'reqToAddFriends', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ uin: String(p.user_id ?? p.uin ?? ''), msg: String(p.comment ?? p.message ?? '') }];
  } },

  // 点赞（在线状态那一族）
  set_like_status: { service: 'OnlineStatus', method: 'setLikeStatus', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ uin: String(p.user_id ?? p.uin ?? ''), status: Number(p.status ?? 0) }];
  } },
  check_like_status: { service: 'OnlineStatus', method: 'checkLikeStatus', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ uin: String(p.user_id ?? p.uin ?? '') }];
  } },
  get_like_list: { service: 'OnlineStatus', method: 'getLikeList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [Number(p.count ?? 20)];
  } },
  do_qun_like: { service: 'Album', method: 'doQunLike', arity: 5, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? ''), String(p.uin ?? ''), Number(p.count ?? 1), String(p.cookie ?? ''), null];
  } },

  // 群文件：对应 OIDB 1750/1753
  trans_group_file: { service: 'RichMedia', method: 'transGroupFile', arity: 2, cbIndex: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), fileId: String(p.file_id ?? ''), busId: Number(p.bus_id ?? 102) }, null];
  } },
  // rename_group_file 同时存在于这里和 oidb-actions.cjs（0x6d6_4）。
  //    同名动作只会有第一个匹配的生效——这条在 NATIVE_OPS，先于 OIDB 表被检查。
  //    目前保留内核版本（尚未实测是否也超时）；若确认超时，删掉这条让它走 OIDB。
  rename_group_file: { service: 'RichMedia', method: 'renameGroupFile', arity: 5, cbIndex: 4, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? ''), String(p.file_id ?? ''), String(p.new_name ?? p.name ?? ''), Number(p.bus_id ?? 102), null];
  } },
  // delete_group_file / rename_group_file 已交给 OIDB（native/oidb-actions.cjs）：
  //   RichMedia.deleteGroupFile 实测 12 秒超时（既不返回也不回调），是坏的内核方法。
  //   OIDB 那两条带 danger:true，默认只构造不发，反而更安全。

  get_group_file_list: { service: 'RichMedia', method: 'getGroupFileList', arity: 2, cbIndex: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), pageStart: Number(p.page ?? 0), pageLimit: Number(p.count ?? 20) }, null];
  } },

  // 翻译 / 天气 / 搜图（这一族是「查询型互动」，不需要发消息）
  image_translate: { service: 'RichMedia', method: 'imageTranslate', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.image_path ?? p.file ?? ''), String(p.source_lang ?? 'auto'), String(p.target_lang ?? 'zh')];
  } },
  get_concern_weather: { service: 'NodeMisc', method: 'getConcernWeather', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{}];
  } },
  get_cities_weather: { service: 'NodeMisc', method: 'getCommonlyUsedCitiesWeather', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{}];
  } },

  // 底栏表情表 / 关键词关联表情
  // 两者的原生断言都是 argc==1，而且那唯一一个参数**就是回调**：
  // 之前把 {} / 字符串填进去，内核等回调等不到，整条 IPC 会挂住（debug_call 实测 aborted），
  // 表现成 retcode 1500 + cbCalled:false。所以这里 cbIndex:0，让执行侧把真函数注入第 0 个参数。
  //
  // 复测（debug_call 逐个形状）：
  //  · fetchBottomEmojiTableList({} / [] / null) 一律 1500 "Cannot convert undefined or null to object"
  //    → 它那唯一一个参数必须是回调，但内核内部又对某个 null 做对象操作，这条路是**内核侧坏的**；
  //  · getKeyWordRelatedEmoji 既无同步返回也不触发回调（1500 超时）。
  // 所以两条都换成实测 rc=0 的等价实现，原名保留成 _legacy：
  //  · 底部表情表 → msg.getRecentUsedFaceList({})  → {result:0, recentUsedFaceList:[...]}
  //  · 关键词关联表情 → msg.fetchGetHitEmotionsByWord({word}) → {result:0, emotionsInfo:{words, isOver, emotionsInfo:[{path,...}]}}
  get_bottom_emoji_table: { service: 'msg', method: 'getRecentUsedFaceList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{}];
  } },
  get_bottom_emoji_table_legacy: { service: 'msg', method: 'getRecentUsedFaceList', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{}];
  } },
  get_keyword_emoji: { service: 'msg', method: 'fetchGetHitEmotionsByWord', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    // 实测：参数必须是对象且带 word 字段（传字符串会回 words:"" 并返回全量，传 {word:'哈哈'} 才按词命中）
    return [{ word: String(p.word ?? p.keyword ?? p.text ?? '') }];
  } },
  get_keyword_emoji_legacy: { service: 'msg', method: 'fetchGetHitEmotionsByWord', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ word: String(p.word ?? p.keyword ?? p.text ?? '') }];
  } },
  // 最近使用表情：**不在这里实现**。validateAction 里 `get_recent_emoji_list` / `get_recent_used_face_list`
  // 有更早的专用分支（kind:'recent_face'），会先接管，写在 NATIVE_OPS 里是走不到的。
  // 那条分支已改成调 getRecentUsedFaceList（getRecentEmojiList 会挂满 20 秒）。

  // ── 群系统消息 / 入群申请 / 好友请求补充（SL 的 get_group_system_msg 一族）──────
  // 之前这批被兼容层按名字猜到了 getGroupMsgLimitFreq 之类的错方法，返回限频数据被当成"系统消息"，
  // 所以进了 COMPAT_DENY。现在给了精确实现，按真方法下发。
  fetch_group_notify: { service: 'Group', method: 'fetchGroupNotify', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), reqType: Number(p.req_type ?? 0) }];
  } },
  get_group_notifies_unread: { service: 'Group', method: 'getGroupNotifiesUnreadCount', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },
  get_single_screen_notifies: { service: 'Group', method: 'getSingleScreenNotifies', arity: 3, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [Boolean(p.doubt ?? false), Number(p.count ?? 20), String(p.cookie ?? '')];
  } },
  get_single_screen_notifies_v2: { service: 'Group', method: 'getSingleScreenNotifiesV2', arity: 4, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [Boolean(p.doubt ?? false), Number(p.count ?? 20), String(p.cookie ?? ''), Number(p.filter ?? 0)];
  } },
  clear_group_notifies: { service: 'Group', method: 'clearGroupNotifies', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), reqType: Number(p.req_type ?? 0) }];
  } },
  operate_sys_notify: { service: 'Group', method: 'operateSysNotify', arity: 2, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ groupCode: String(p.group_id ?? ''), notifySeq: String(p.seq ?? p.flag ?? ''), accept: Boolean(p.approve ?? true) }, {}];
  } },
  get_group_invite_limit: { service: 'Group', method: 'getGroupInviteNoAuthLimitNum', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? '')];
  } },
  invite_to_group: { service: 'Group', method: 'inviteToGroup', arity: 2, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? ''), Array.isArray(p.user_ids) ? p.user_ids.map(String) : [String(p.user_id ?? '')]];
  } },

  // 好友请求补充
  del_buddy_req: { service: 'Buddy', method: 'delBuddyReq', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ friendUid: String(p.uid ?? p.user_id ?? ''), reqTime: String(p.flag ?? '') }];
  } },
  get_buddy_req_unread: { service: 'Buddy', method: 'getBuddyReqUnreadCnt', arity: 0, build: () => [] },
  set_block: { service: 'Buddy', method: 'setBlock', arity: 2, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.uid ?? p.user_id ?? ''), Boolean(p.block ?? true)];
  } },
  is_blocked: { service: 'Buddy', method: 'isBlocked', arity: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.uid ?? p.user_id ?? '')];
  } },
  get_add_friend_blocked_list: { service: 'Buddy', method: 'getAddFriendBlockedList', arity: 2, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [Number(p.page ?? 0), Number(p.count ?? 20)];
  } },
  // ---- 第五批：补剩余缺口（argc 全部实测）----
  // set_group_reaction 不在这里：NATIVE_ALIAS 已把它指到 set_msg_emoji_like，别名优先。
  // setRcvJoinVerifyMsg 的 body 要有 groupCode + uins 列表；只给 groupCode 会回 errCode 1281 "no admin uins"。
  // set_group_admin_receive_verify 已改走 OIDB 0x904_1（见 oidb-actions.cjs），
  // 内核 Group.setRcvJoinVerifyMsg 那条路字段名不对、恒回 1281 "no admin uins"。
  // set_group_robot_add_option 也已改走 OIDB 0xf00_3（见 oidb-actions.cjs），内核那条恒回 21000。
  // fetchMarketEmoticonFaceImages 传关键词回 null —— 内核侧空实现，做不了（见下方 1404 守卫）。
  search_sys_faces: { service: 'Msg', method: 'fetchMarketEmoticonFaceImages', arity: 1, cbIndex: 0, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.keyword ?? p.word ?? '')];
  } },
  // nc_get_user_status：Profile.getStatus 要 **uid** 不是 uin（传 uin 回 316）。
  // 换 uid 必须 await，而 NATIVE_OPS 的 build 是同步的 —— 所以走 handler 分支（kind: 'nc_user_status'）。
  // 这里保留一条兜底（调用方已给 uid 时直接走）。
  nc_get_user_status: { service: 'Profile', method: 'getStatus', arity: 2, cbIndex: 1, build: (p) => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    const id = String(p.uid ?? p.user_id ?? p.uin ?? '');
    return [{ uids: [id] }, null];
  } },
  // onlyUploadFile 传形状化参数回 null（空实现），做不了 —— 见下方 1404 守卫。
  upload_file_stream: { service: 'RichMedia', method: 'onlyUploadFile', arity: 2, cbIndex: 1, build: p => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ filePath: String(p.file ?? p.path ?? ''), fileName: String(p.name ?? '') }, null];
  } },
  // ---- 第六批：一次性补上剩余缺动作（同一轮加完，只重启一次）----
  // add_custom_face 主名走 BDH 三步链路（见 handler 的 custom_face_bdh 分支）。
  // 内核 Msg.addFavEmoji 恒回 decode failed（需 QQ 私有解码串），只留成 legacy 名备查。
  add_custom_face_legacy: { service: 'Msg', method: 'addFavEmoji', arity: 1, build: (p) => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{ emojiId: String(p.emoji_id ?? p.emoji ?? p.file_id ?? ''), isOrigin: 1 }];
  } },
  // set_group_portrait：Avatar 服务只有 forceDownload* 没有 set，先如实报。
  set_group_portrait: { service: 'Avatar', method: 'forceDownloadGroupPortrait', arity: 3, cbIndex: 2, build: (p) => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [String(p.group_id ?? ''), { width: Number(p.width ?? 100), height: Number(p.height ?? 100) }, null];
  } },
  // create_collection / nc_get_packet_status：内核没有对应方法，先接成 win32 不动，让它们回明确错误而不是"尚未支持"。
  create_collection: { service: 'Collection', method: 'addCollection', arity: 1, build: (p) => {
    if (Array.isArray(p.raw_args)) return p.raw_args;
    return [{}];
  } },
  nc_get_packet_status: { service: 'MSF', method: 'getMsfStatus', arity: 0, build: () => [] },
};
const sendActions = ['send_private_msg', 'send_group_msg', 'send_msg'];
const exclusiveTypes = ['json', 'record', 'video', 'file'];
const absolutePath = value => typeof value === 'string' && value.length <= 4096 && !/[\u0000-\u001f]/.test(value)
  && /^(?:[A-Za-z]:[\\/]|\/)/.test(value) && !/^(?:\\\\|\/\/)/.test(value);
const positive = (value, max) => Number.isSafeInteger(value) && value > 0 && value <= max;

// Native references are attached by the main process, which owns the OneBot message_id ↔ QQ msgId mapping.
function nativeRef(value, forward = false) {
  if (!value || typeof value !== 'object' || ![1, 2, 100].includes(value.chatType)
    || typeof value.peerUid !== 'string' || !value.peerUid || value.peerUid.length > 64) return null;
  if (forward) return nativeId(value.root) && nativeId(value.parent)
    ? { chatType: value.chatType, peerUid: value.peerUid, root: value.root, parent: value.parent } : null;
  return nativeId(value.msgId) ? { chatType: value.chatType, peerUid: value.peerUid, msgId: value.msgId } : null;
}

// Media descriptions are produced by the main process (src/media.mjs) after it has fetched and inspected the file.
function mediaRef(value, kind) {
  const bad = () => fail(`${kind} 段的文件没有经过处理，或描述无效`);
  if (!value || typeof value !== 'object' || value.kind !== kind || !absolutePath(value.path) || typeof value.name !== 'string' || !value.name
    || value.name.length > 255 || /[\u0000-\u001f\\/]/.test(value.name) || !positive(value.size, 2 ** 40)) throw bad();
  const media = { kind, path: value.path, name: value.name, size: value.size };
  if (kind === 'image' || kind === 'video') {
    if (!positive(value.width, 65535) || !positive(value.height, 65535) || typeof value.format !== 'string') throw bad();
    Object.assign(media, { width: value.width, height: value.height, format: value.format });
  }
  if (kind === 'image' && !['png', 'jpeg', 'gif', 'webp', 'bmp'].includes(value.format)) throw bad();
  if (kind === 'record' || kind === 'video') {
    if (!positive(value.duration, 86400)) throw bad();
    media.duration = value.duration;
  }
  if (kind === 'video') {
    const thumb = value.thumb;
    if (!['mp4', 'mov'].includes(value.format) || !thumb || typeof thumb !== 'object' || !absolutePath(thumb.path) || !positive(thumb.size, 2 ** 40)
      || !positive(thumb.width, 65535) || !positive(thumb.height, 65535)) throw bad();
    media.thumb = { path: thumb.path, size: thumb.size, width: thumb.width, height: thumb.height, format: String(thumb.format ?? '') };
  }
  return media;
}

function segmentsOf(params) {
  if (params.auto_escape !== undefined && typeof params.auto_escape !== 'boolean') throw fail('auto_escape 必须为布尔值');
  if (typeof params.message === 'string') return params.auto_escape ? [{ type: 'text', data: { text: params.message } }] : parseCQ(params.message);
  if (Array.isArray(params.message) && params.message.length <= 100) return params.message;
  throw fail('message 必须为文本、CQ 码字符串或最多 100 个消息段');
}

// A CQ-code string becomes a segment array up front, so the main process can resolve references and media before validation.
function normalizeParams(request) {
  const params = request?.params;
  if (!sendActions.includes(request?.action) || !params || typeof params !== 'object' || Array.isArray(params)) return request;
  // auto_escape: false means the same as leaving it out, so the CQ string is still parsed (and its media prepared); other values stay for validation.
  if (typeof params.message !== 'string' || (params.auto_escape !== undefined && params.auto_escape !== false)) return request;
  return { ...request, params: { ...params, message: parseCQ(params.message) } };
}

function messageParts(params, chatType) {
  const parts = segmentsOf(params).map(segment => {
    const data = segment?.data && typeof segment.data === 'object' && !Array.isArray(segment.data) ? segment.data : {};
    switch (segment?.type) {
      case 'text':
        if (typeof data.text !== 'string') throw fail('text 段需要 data.text');
        return { type: 'text', text: data.text };
      case 'reply': {
        const ref = nativeRef(data.openqq_ref);
        if (!ref) throw fail('reply 段的 id 无效或引用的消息已过期', 1404);
        return { type: 'reply', ref };
      }
      case 'json': {
        const raw = typeof data.data === 'string' ? data.data : data.data && typeof data.data === 'object' ? JSON.stringify(data.data) : undefined;
        try { if (typeof raw !== 'string' || !JSON.parse(raw) || typeof JSON.parse(raw) !== 'object') throw new Error(); }
        catch { throw fail('json 段的 data 必须是 JSON 对象或其字符串'); }
        return { type: 'json', data: raw };
      }
      case 'at': {
        if (chatType !== 2) throw fail('私聊不能使用 at 段');
        if (String(data.qq) === 'all') return { type: 'at', target: 'all' };
        const name = data.name === undefined ? '' : String(data.name);
        if (name.length > 64 || /[\u0000-\u001f]/.test(name)) throw fail('at 段的 name 过长或包含控制字符');
        return { type: 'at', target: identifier(data.qq, 'at.qq'), name };
      }
      case 'face': {
        const id = typeof data.id === 'string' && /^\d+$/.test(data.id) ? Number(data.id) : data.id;
        if (!Number.isSafeInteger(id) || id < 0 || id > 100000) throw fail('face 段的 id 必须是非负整数');
        return { type: 'face', id };
      }
      case 'dice': case 'rps': return { type: segment.type };
      case 'image': return { type: 'image', media: mediaRef(data.openqq_media, 'image'), summary: typeof data.summary === 'string' ? data.summary.slice(0, 64) : '', emoji: data.as_emoji === true || data.as_emoji === 1 || data.sub_type === 1 || data.sub_type === '1' };
      // 商城/收藏表情：协议上是 marketFaceElement（elementType 11），不是 picElement。
      // 之前把收藏表情当图片发（picSubType=1）会被 QQ 回 rich media transfer failed；
      // 真正的做法是发 mface，字段照 OneBot↔QQ 的既有实现（SnowLuma：image 段挂 emoji_id/emoji_package_id/key 反解回 mface）。
      case 'mface': {
        const emojiId = String(data.emoji_id ?? data.emojiId ?? data.face_id ?? '');
        if (!emojiId) throw fail('mface 段需要 emoji_id（从真实入站 mface 段里抄，形如 hex GUID）');
        return {
          type: 'mface',
          emojiId,
          emojiPackageId: Number(data.emoji_package_id ?? data.tab_id ?? 0) || 0,
          key: String(data.key ?? data.emoji_key ?? ''),
          text: String(data.summary ?? data.text ?? '').slice(0, 64)
        };
      }
      case 'record': case 'video': case 'file': return { type: segment.type, media: mediaRef(data.openqq_media, segment.type) };
      default:
        throw fail(`当前发送支持 text、at、face、mface、image、record、video、file、reply、json、dice、rps 消息段，暂不支持 ${typeof segment?.type === 'string' ? segment.type : '该消息段'}`);
    }
  });
  if (parts.filter(part => part.type === 'reply').length > 1) throw fail('一条消息最多引用一条消息');
  // QQ treats these as the whole message: they cannot carry text, a quote or other segments alongside.
  const exclusive = parts.find(part => exclusiveTypes.includes(part.type));
  if (exclusive && parts.length !== 1) throw fail(`${exclusive.type} 段必须单独发送，不能与其他消息段混合`);
  const texts = parts.filter(part => part.type === 'text').map(part => part.text);
  const json = parts.find(part => part.type === 'json');
  if (!parts.some(part => part.type === 'text' ? part.text.length > 0 : part.type !== 'reply')) throw fail('消息不能为空或超过 64 KiB');
  if (Buffer.byteLength(texts.join('') + (json?.data ?? '')) > 65536) throw fail('消息不能为空或超过 64 KiB');
  const mediaBytes = parts.reduce((total, part) => total + (part.media ? part.media.size + (part.media.thumb?.size ?? 0) : 0), 0);
  // Uploads finish before QQ reports success, so larger files get more time (never less than the text default).
  return { parts, texts, timeout: Math.min(300000, 15000 + Math.ceil(mediaBytes / MiB) * 4000) };
}

function validateAction(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request) || typeof request.action !== 'string') throw fail('需要 {action, params, echo?} 动作对象');
  const params = request.params ?? {};
  if (!params || typeof params !== 'object' || Array.isArray(params)) throw fail('params 必须为对象');
  if (['get_login_info', 'get_status'].includes(request.action)) return { kind: request.action };
  // QZone 全家（29 个，名单从 SnowLuma 打包产物实抽）+ 两个凭据调试口，统一走 kind:'qzone'。
  if (QZONE_ACTIONS.has(request.action)) {
    return { kind: 'qzone', action: request.action, params };
  }
  if (request.action === 'debug_methods') {
    return { kind: 'debug_methods', service: String(params.service ?? 'msg'), keyword: String(params.keyword ?? ''), limit: Math.min(200, Math.max(1, Number(params.limit ?? 80))) };
  }
  if (request.action === 'debug_call') {
    // 通用原生调用口：{service, method, args:[...]} → 真调一次，把返回值或异常原样带回来。
    // 用途：收藏表情这类没有 schema 的私有方法，靠同一个口反复试参数，不必每组参数都重启一次 QQ。
    const service = String(params.service ?? 'msg');
    const method = String(params.method ?? '');
    if (!method) throw fail('debug_call 需要 method');
    const args = Array.isArray(params.args) ? params.args : [];
    return { kind: 'debug_call', service, method, args };
  }
  if (request.action === 'send_oidb_raw' || request.action === 'oidb_raw') {
      return { kind: 'oidb_raw', cmd: request.params.cmd, subCmd: request.params.subCmd, hex: request.params.hex, timeout: request.params.timeout, guid: request.params.guid, mode: request.params.mode, wireName: request.params.wireName };
    }
    if (request.action === 'wrapper_net' || request.action === 'debug_wrapper_net') {
      return { kind: 'wrapper_net' };
    }
    if (request.action === 'debug_wrapper') {
    // 内核顶层导出清单：找 session.get*Service 覆盖不到的能力（SSO/ECDH 这类）。
    return { kind: 'wrapper_dump' };
  }
  if (request.action === 'debug_msf_probe') {
    // 探针：sendMsfRequest 的四个参数类型没文档，把 4 个位置分别换成不同种类，
    // 靠"报错文案变化"反推签名。一次请求跑完所有组合，不再为每种组合重启 QQ。
    return { kind: 'msf_probe' };
  }
  if (request.action === 'send_packet' || request.action === 'debug_sso') {
    // 通用 SSO/OIDB 发包原语：凡是「原生内核没给现成方法、只能走协议包」的能力都从这一个口出去，
    // 不针对单个功能另写直连（拍一拍只是第一个用户）。
    const cmd = String(params.cmd ?? '');
    if (!/^[A-Za-z0-9._]{3,80}$/.test(cmd)) throw fail('send_packet 需要 cmd，形如 OidbSvcTrpcTcp.0xed3_1', 1400);
    const hex = String(params.hex ?? params.body ?? '').replace(/[^0-9a-fA-F]/g, '');
    if (!hex.length || hex.length % 2 || hex.length > 131072) throw fail('hex 必须是非空、偶数长度、≤64KiB 的十六进制串', 1400);
    return { kind: 'sso', cmd, hex, timeout: Math.min(60000, Math.max(1000, Number(params.timeout ?? 12000))) };
  }
  if (request.action === 'debug_services') {
    // 空 service = 列出会话全部 get* 入口；给名字 = 列出该 service 的成员。
    return { kind: 'debug_services', service: params.service === undefined || params.service === null ? '' : String(params.service) };
  }
  if (request.action === 'debug_recent') {
    // 只读调试口：把某个会话的最近消息捞出来并挑出灰条元素，用来回收已经发生过的拍一拍样本。
    const group = params.group_id === undefined ? null : identifier(params.group_id, 'group_id');
    const user = group === null ? identifier(params.user_id, 'user_id') : null;
    if (group === null && user === null) throw fail('debug_recent 需要 user_id 或 group_id');
    return { kind: 'debug_recent', group, user, count: Math.min(50, Math.max(1, Number(params.count ?? 20))) };
  }
  if (request.action === 'debug_native_events') {
    return { kind: 'native_events', pattern: params.pattern === undefined ? '' : String(params.pattern),
      count: Math.min(100, Math.max(1, Number(params.count ?? 20))) };
  }
  if (request.action === 'openqq_services') return { kind: 'services' };
  if (request.action === 'get_friend_list') return { kind: 'friend_list' };
  if (request.action === 'get_group_honor_info') throw fail('getGroupHonorList 的 groupUin/groupCode/group_id/位置参数全部回 errCode 20000 param(group_id) error，需要原生结构体，暂不实现', 1404);
  if (request.action === 'get_essence_msg_list') return { kind: 'essence', group: identifier(params.group_id, 'group_id') };
  // SL 把拍一拍拆成三个名字，参数都是 {user_id, group_id?}：
  // 带 group_id 拍群里的人，不带就拍好友。三个名字走同一条实现，不要放进 NATIVE_ALIAS
  // —— 别名表只认 NATIVE_OPS 里的动作，send_poke 走的是 sso_pipe 分支，放进去会回 1404。
  if (request.action === 'send_poke' || request.action === 'group_poke' || request.action === 'friend_poke') {
    // 拍一拍走 SSO over pipe（OIDB 0xed3_1）—— JS 层那五条路（sendNudge / 灰条 / MSF /
    // sendSsoCmdReqByContend / ECDH）全被 QQ 拒掉，第七条是绕开 JS 层直接从进程内发。
    const blank = (v) => v === undefined || v === null || String(v) === '';
    const group = blank(params.group_id) ? null : identifier(params.group_id, 'group_id');
    const user = blank(params.user_id) ? null : identifier(params.user_id, 'user_id');
    if (group === null && user === null) throw fail(request.action + ' 需要 user_id（被拍的人）', 1400);
    const target = user !== null ? String(user) : String(group);
    const g = group !== null ? String(group) : '0';
    return {
      kind: 'sso_pipe', action: 'send_poke',
      cmd: 'OidbSvcTrpcTcp.0xed3_1',
      body: pb.buildOidbPoke({ groupId: g, userId: target }),
      wantReply: true, timeoutMs: 15000,
    };
  }
  // ── 文件下载：不走内核，直接用 HTTP 取回落盘 ───────────────
  // 内核 RichMedia.downloadFile(4) 传空参只回 rc=0 value=null（既无回传对象也不触发回调），
  // 判断不出成功，所以这里自己取。
  if (request.action === 'download_file') {
    const url = String(params.url ?? '').trim();
    const b64 = String(params.base64 ?? '').trim();
    if (!url && !b64) throw fail('download_file 需要 url 或 base64', 1400);
    if (url) assertPublicHttpUrl(url);
    return {
      kind: 'download_file', action: 'download_file',
      url, base64: b64,
      name: safeDownloadName(params.name),
      headers: sanitizeDownloadHeaders(params.headers),
      maxBytes: integer(params.max_bytes, 'max_bytes', 1, 64 * 1024 * 1024, 32 * 1024 * 1024),
    };
  }
  // set_group_anonymous / set_group_anonymous_ban 保持"尚未支持动作"：
  // 上游没有这两个动作的实现，用成功回执假装支持会让调用方以为匿名设置真的改了。
  // ── 明确做不了的动作：如实返回 1404 + 原因，不假装支持 ────────────────────
  // 群相册 6 个：SL 走自己的 `ctx.bridge.apis.groupAlbum.*`（SnowLuma 私有 bridge），
  //   内核 Album 服务的 getQunFeeds / getQunFeedDetail / getFeedById / quoteToQzone / deleteQunFeed
  //   全部 `Cannot convert undefined or null to object`（硬事实，传 {}、带 groupCode、带 callback 都一样）。
  // 群相册 6 个改走 trpc 命令（OIDB_ACTIONS 里 raw:true 那批），旧 1404 守卫已删。
  // share_peer / share_group_ex / send_tuwen_ark 已改走 OIDB（见 oidb-actions.cjs 的 Ark 段），旧 1404 守卫已删。
  // 闪传/缓存类
  // search_sys_faces / upload_file_stream 已有实现（内核回 null 但通道在），旧 1404 守卫已删。
  if (['create_flash_task', 'clean_stream_temp_file', 'request_decrypt_key'].includes(request.action)) {
    throw fail(request.action + ' 做不了：依赖 SL 的 FlashTransfer 流式任务层，OpenQQ 的内核这层不完整（cleanFailedFiles 之外的都探不通）', 1404);
  }
  // 三个 stream 变体 + fileset：OneBot 的 HTTP 前置层没有流式帧协议
  // （SL 那套是 file_info → file_chunk* → file_complete），硬做要改协议。如实告诉调用方用 download_file。
  if (['download_file_stream', 'download_file_image_stream', 'download_file_record_stream', 'download_fileset'].includes(request.action)) {
    throw fail(request.action + ' 需要流式帧协议（file_info → file_chunk* → file_complete），OneBot HTTP 层没有这层；请改用 download_file（url 或 base64）', 1404);
  }
  // clean_cache：Setting.clearCache 内核侧是死的——[{}] 和 [0] 两种参数都 6009ms 超时，
  // 既不返回也不回调。不假装支持。
  if (request.action === 'clean_cache') {
    throw fail('clean_cache 不可用：Setting.clearCache 两种参数都超时（不返回也不回调），内核侧没有实现', 1404);
  }
  // ── 转发单条消息：Msg.forwardMsg 的 target 要 peerUid，不要 QQ 号 ──
  // uid 用 Profile.getUserDetailInfoByUin(uin) 同步换（110ms、不挂 IPC）。
  // 别再试 UixConvert.getUid —— 那个会把 QQ 挂死（0mwn66ay）。
  // ── 转发单条消息（修正）：源消息用 openqq_ref，目标用 uid ──────────
  // OneBot 的 `message_id` 是主进程自增序号（src/onebot.mjs 的 `nextId++`），**不是 QQ 的 msgId**。
  // 真 msgId 在主进程的 `refs` Map 里，通过参数的 `openqq_ref` 字段传下来
  // （和 `get_forward_msg` / reply 段完全同一套机制，见 nativeRef）。
  if (request.action === 'forward_friend_single_msg' || request.action === 'forward_group_single_msg') {
    const ref = nativeRef(params.openqq_ref);
    if (!ref) throw fail(request.action + ' 的 message_id 无效或引用的消息已过期（仅支持本次运行期间收到的消息）', 1404);
    const isGroup = request.action === 'forward_group_single_msg';
    const target = String((isGroup ? params.group_id : params.user_id) ?? '').trim();
    if (!target) throw fail(request.action + ' 需要 ' + (isGroup ? 'group_id' : 'user_id'), 1400);
    return { kind: 'forward_send', action: request.action, source: ref, targetUin: target, targetChatType: isGroup ? 2 : 1 };
  }
  if (request.action === 'download_rich_media') {
    const fileUuid = String(params.file_id ?? params.fileUuid ?? params.uuid ?? '');
    if (!fileUuid) throw fail('download_rich_media 需要 file_id', 1400);
    return { kind: 'rich_media', fileUuid, fileName: String(params.file_name ?? params.fileName ?? ''), msgId: String(params.message_id ?? params.msg_id ?? ''),
      chatType: Number(params.chat_type ?? 1) === 2 ? 2 : 1, peerUid: String(params.peer_uid ?? '') };
  }
  if (request.action === 'get_group_msg_history') {
    return { kind: 'group_history', group: identifier(params.group_id, 'group_id'), count: Math.min(200, Math.max(1, Number(params.count ?? 20))) };
  }
  if (request.action === 'get_recent_emoji_list' || request.action === 'get_recent_used_face_list') {
    return { kind: 'recent_face', what: request.action };
  }
  if (request.action === 'fetch_custom_face_detail') {
    const count = Number(params.count ?? 48);
    if (!Number.isInteger(count) || count <= 0 || count > 500) throw fail('count 必须是 1~500 的整数', 1400);
    return { kind: 'fav_emoji', count };
  }
  if (request.action === 'set_input_status') {
    if (!Number.isInteger(params.event_type) || params.event_type < 0 || params.event_type > 0x7fffffff) throw fail('event_type 必须是非负 int32');
    return { kind: 'input', target: identifier(params.user_id, 'user_id'), eventType: params.event_type };
  }
  if (request.action === 'get_forward_msg') {
    const ref = nativeRef(params.openqq_ref, true);
    if (!ref) throw fail('合并转发 id 无效或已过期（仅支持本次运行期间收到的消息）', 1404);
    return { kind: 'forward', ref };
  }
  if (request.action === 'get_msg') {
    const ref = nativeRef(params.openqq_ref);
    if (!ref) throw fail('message_id 不存在或已过期（仅支持本次运行期间收发过或被引用的消息）', 1404);
    return { kind: 'get_msg', ref };
  }
  if (request.action === 'get_image') {
    const raw = params.file ?? params.file_id;
    if (typeof raw !== 'string' || !raw.trim() || raw.length > 1024 || /[\u0000-\u001f]/.test(raw)) {
      throw fail('get_image 需要有效的 file 或 file_id');
    }
    return { kind: 'get_image', key: raw.trim() };
  }
  const managed = admin.validate(request, params);
  if (managed) return managed;
  // 语义化原生直通：一个动作一行（service + method + 参数构造）。
  // 参数形状靠 argc 断言和错误文案探出来的，没探清的不进这张表，走 native_call 原样透传。
  const nativeName = NATIVE_ALIAS[request.action] || request.action;
  // 合并转发上传（SL 的 upload_forward_msg / upload_foward_msg）：只上传资源、不发送，返回 res_id。
  // QQ NT 的 Msg.multiForwardMsg(argc=3) 第 1/2 参必须是真实 msgInfos + 目标 peerUid，
  // 空形状一律 `Cannot convert undefined or null to object`，目前没有真消息样本可以定形状。
  // 与其假装成功，这里如实说明并指向已经可用的发送路径。
  if (request.action === 'upload_forward_msg' || request.action === 'upload_foward_msg') {
    throw fail('upload_forward_msg 需要真实消息引用（QQ NT multiForwardMsg 的 msgInfos/peerUid 形状未定）；要发送合并转发请用 send_group_forward_msg / send_private_forward_msg', 1404);
  }
  // nc_get_user_status 走 handler 分支。
  // 正解不是 Profile.getStatus（那个要 uid、传 uin 恒回 316），而是 getUserDetailInfoByUin
  // 返回的 detail.simpleInfo.status —— 实测直接带 status:20 / extStatus / termType 等完整状态，
  // 一次请求就够，不用再换 uid。
  if (request.action === 'nc_get_user_status') {
    return { kind: 'nc_user_status', action: request.action,
      uin: String(params.user_id ?? params.uin ?? params.uid ?? '') };
  }

  if (NATIVE_OPS[nativeName]) {
    const op = NATIVE_OPS[nativeName];
    let args;
    try { args = op.build(params); }
    catch (error) { throw fail(`${request.action} 参数无效: ${error && error.message ? error.message : error}`, 1400); }
    if (!Array.isArray(args)) throw fail(`${request.action} 的参数构造没有返回数组`, 1400);
    // arity 是实测的原生 argc。个数不对时 C++ 只在日志里断言、OneBot 侧只看到一个没头没尾的 1500，
    // 所以这里提前拦下，把「实际几个 / 应该几个」直接说清楚。
    if (Number.isSafeInteger(op.arity) && args.length !== op.arity) {
      throw fail(`${request.action} 需要 ${op.arity} 个原生参数，实际构造了 ${args.length} 个`, 1400);
    }
    return { kind: 'native_op', action: request.action, canonical: nativeName, service: op.service, method: op.method, args, cbIndex: op.cbIndex };
  }
  if (request.action === 'native_call') {
    const method = String(params.method ?? '');
    if (!/^[A-Za-z][A-Za-z0-9_]{1,60}$/.test(method)) throw fail('native_call 需要 method', 1400);
    return { kind: 'native_op', action: 'native_call', service: String(params.service ?? 'msg'), method,
      args: Array.isArray(params.args) ? params.args.slice(0, 12) : [] };
  }
  // ---- SSO over pipe（SnowLuma 组件通道）----
  // 这两条是「内核 JS 层做不到」的兜底口：拍一拍、内核没有的群管理、QZone p_skey 等。
  // 走 \\.\pipe\mojo.<pid>.control，帧格式见 native/sso-pipe.cjs 顶部注释。
  // 群相册上传 —— 纯 HTTP（用 p_skey 算 g_tk），不碰内核也不碰 pipe
  if (request.action === 'upload_image_to_qun_album' || request.action === 'upload_video_to_qun_album') {
    const isVideo = request.action === 'upload_video_to_qun_album';
    const b64 = String(params.image_base64 ?? params.base64 ?? params.file_base64 ?? '').trim();
    if (!b64) throw fail(request.action + ' 需要 image_base64（图片或视频的 base64）', 1400);
    let bytes;
    try { bytes = Buffer.from(b64, 'base64'); } catch (e) { throw fail('image_base64 不是合法 base64', 1400); }
    if (!bytes.length) throw fail('image_base64 解出来是空的', 1400);
    return { kind: 'qun_album_upload', action: request.action, isVideo, bytes,
      uin: String(params.uin ?? params.self_id ?? ''),
      groupId: String(params.group_id ?? ''), albumId: String(params.album_id ?? ''),
      albumName: String(params.album_name ?? ''), title: String(params.title ?? '') };
  }
  // 收藏表情上传（BDH 三步）—— 必须走 handler 分支：要 await + fetch，塞不进同步的 NATIVE_OPS.build
  if (request.action === 'add_custom_face' || request.action === 'add_custom_face_full' || request.action === 'add_custom_face_bdh') {
    const b64 = String(params.image_base64 ?? params.base64 ?? '').trim();
    if (!b64) throw fail(request.action + ' 需要 image_base64（图片 base64）', 1400);
    let bytes;
    try { bytes = Buffer.from(b64, 'base64'); } catch (e) { throw fail('image_base64 不是合法 base64', 1400); }
    if (!bytes.length) throw fail('image_base64 解出来是空的', 1400);
    const uin = String(params.uin ?? params.self_id ?? '');
    if (!uin) throw fail(request.action + ' 需要 uin（或 self_id）', 1400);
    return { kind: 'custom_face_bdh', action: request.action, uin, bytes };
  }
  // ---- OIDB 动作（走 SSO over pipe）----
  // 这一整族是「JS 层没有对应方法」的那批（群设置 / 待办 / 管理员权限 / 闪传改名），
  // 只能走 OIDB。表在 native/oidb-actions.cjs，加动作只加一行。
  // 危险动作（danger:true，不可撤回且影响他人）默认**只构造不发送**，必须显式 confirm_danger 才真发。
  // 这里必须认别名：NATIVE_ALIAS 里的名字（set_group_special_title → set_special_title）
  // 在 OIDB 表里只有主名，直接用 request.action 查表会漏掉它们。
  const oidbName = oidb.OIDB_ACTIONS[request.action] ? request.action
    : (oidb.OIDB_ACTIONS[nativeName] ? nativeName : null);
  if (oidbName) {
    const act = oidb.OIDB_ACTIONS[oidbName];
    let body;
    try { body = oidb.buildOidbBody(oidbName, params); }
    catch (e) { throw fail(`${request.action} 参数无效: ${e && e.message ? e.message : e}`, 1400); }
    if (act.danger && params.confirm_danger !== true) {
      return {
        kind: 'oidb_dryrun', action: request.action, cmd: act.wire,
        bodyHex: body.toString('hex'), bodyLen: body.length,
        note: '危险动作（不可撤回且影响他人）：默认只构造不发送。确认要真发时传 confirm_danger: true',
      };
    }
    return {
      kind: 'sso_pipe', action: request.action, cmd: act.wire,
      body, wantReply: true, timeoutMs: Number(params.timeout) > 0 ? Number(params.timeout) : 15000,
    };
  }
  if (request.action === 'sso_pipe_status') {
    return { kind: 'sso_pipe', action: 'sso_pipe_status' };
  }
  if (request.action === 'sso_pipe_send') {
    const cmd = String(params.cmd ?? '').trim();
    if (!cmd) throw fail('sso_pipe_send 需要 cmd', 1400);
    if (cmd.length > 200) throw fail('sso_pipe_send 的 cmd 太长（>200）', 1400);
    const hex = String(params.hex ?? params.body_hex ?? '').replace(/\s+/g, '');
    if (hex && !/^[0-9a-fA-F]+$/.test(hex)) throw fail('sso_pipe_send 的 hex 不是合法十六进制', 1400);
    if (hex.length % 2 !== 0) throw fail('sso_pipe_send 的 hex 长度必须是偶数', 1400);
    if (hex.length / 2 > 16 * 1024 * 1024) throw fail('sso_pipe_send 的 body 超过 16MB', 1400);
    return {
      kind: 'sso_pipe', action: 'sso_pipe_send', cmd,
      body: Buffer.from(hex, 'hex'),
      wantReply: params.want_reply !== false,
      timeoutMs: Number(params.timeout) > 0 ? Number(params.timeout) : 15000,
    };
  }
  // 兼容动作放在 admin.validate 之后：先让精确实现（send_like / 群信息 / 好友事件）拿到机会，
  // 只处理确认没人管的只读动作，启发式仅限 get/fetch/can 前缀。
  if (COMPAT_ACTIONS.has(request.action) && /^(get|fetch|can)_/.test(request.action) && !['get_login_info','get_status','set_input_status','get_forward_msg','get_image','send_private_msg','send_group_msg','send_msg','get_friend_list','get_stranger_info','fetch_custom_face_detail','get_group_msg_history','set_friend_add_request'].includes(request.action)) {
    return { kind: 'compat', action: request.action, params };
  }
  if (!sendActions.includes(request.action)) throw fail('尚未支持动作: ' + request.action, 1404);
  let type = request.action === 'send_private_msg' ? 'private' : request.action === 'send_group_msg' ? 'group' : params.message_type;
  if (!type) {
    if ((params.user_id !== undefined) === (params.group_id !== undefined)) throw fail('send_msg 需要明确 message_type 或唯一的目标');
    type = params.user_id !== undefined ? 'private' : 'group';
  }
  if (!['private', 'group'].includes(type)) throw fail('message_type 仅支持 private/group');
  const target = identifier(type === 'private' ? params.user_id : params.group_id, type === 'private' ? 'user_id' : 'group_id');
  const chatType = type === 'private' ? 1 : 2;
  return { kind: 'send', chatType, target, ...messageParts(params, chatType) };
}

// QQ 的原生方法把「业务拒绝」放在返回值里而不是抛错：errMsg / msg 里带失败文案。
// 原样报 ok 会让调用方以为成功 —— get_profile_like 的「获取数据失败」、
// check_url_safely 的「param error」、delete_custom_face 的「繁忙」都是这么被吞掉的。
// 只认「有明确失败文案」的情况，不拿数字码判断：errCode 5 这类是「这个群没有精华」的状态，不是失败。
const NATIVE_FAIL_RE = /(失败|错误|繁忙|超时|无权限|拒绝|不存在|没有权限|not exist|failed|failure|error|\berr\b|invalid|denied|timeout|busy)/i;
const NATIVE_FAIL_KEYS = ['errMsg', 'errMs', 'msg', 'message', 'wording', 'errorMsg'];
function nativeRefusal(value, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 2) return null;
  for (const key of NATIVE_FAIL_KEYS) {
    const text = value[key];
    if (typeof text === 'string' && text.trim() && NATIVE_FAIL_RE.test(text)) return text.trim().slice(0, 200);
  }
  // 只下钻这几个已知的包裹层（FlashTransfer 把结果放在 rsp 里），不扫整棵对象以免误伤。
  for (const key of ['rsp', 'value', 'data', 'info']) {
    const nested = nativeRefusal(value[key], depth + 1);
    if (nested) return nested;
  }
  return null;
}

function createActionHandler(session, self, current, options = {}) {
  const operations = new Set();
  const waiting = new Map();
  let disposed = false;

  // 通用原生反射：会话对象上的一切都靠 get*Service 取，写死名单每次探索都要改代码，
  // 所以这里按名字解析，msg/buddy/group/profile/uix/msf/... 都能直接给。
  const namesOf = value => {
    if (!value || (typeof value !== 'object' && typeof value !== 'function')) return [];
    const set = new Set();
    for (let o = value; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
      for (const n of Object.getOwnPropertyNames(o)) if (n !== 'constructor') set.add(n);
    }
    return Array.from(set).sort();
  };
  const serviceOf = name => {
    const key = String(name ?? '');
    if (!/^[A-Za-z][A-Za-z0-9]{0,40}$/.test(key)) return null;
    const camel = key.charAt(0).toUpperCase() + key.slice(1);
    for (const getter of ['get' + camel + 'Service', 'get' + camel, key]) {
      if (typeof session[getter] !== 'function') continue;
      try { const svc = session[getter](); if (svc) return svc; } catch { /* 换下一个名字 */ }
    }
    return null;
  };

  // ── 自研 SSO 发包（不依赖任何第三方注入组件）─────────────────────────
  // bootstrap 在 QQ 进程内改了一次 std::string 构造的跳转目标（4 字节 + 12 字节跳板），
  // 我们只负责把"这一次 body 用我的字节"告诉它（arm），然后调 QQ 自己的
  // Msg.sendSsoCmdReqByContend —— 包由 QQ 自己发、回包也由 QQ 自己收，不碰任何内存扫描。
  // 同一条命令在两个服务名前缀下可达性不同，空回包时换另一个前缀再试一次。
  async function selfSsoSend(cmd, bodyBuf) {
    const armFn = globalThis.__openqqSsoBodyConv;
    if (typeof armFn !== 'function') {
      return { ok: false, status: -1, note: '__openqqSsoBodyConv 不存在：需要新 bootstrap' };
    }
    const st = armFn('status', '');
    if (!st || !st.patched) {
      return { ok: false, status: -1, note: 'body 代劳补丁未安装（bootstrap 启动时应自动装；失败说明 wrapper.node 版本不符）' };
    }
    const bytes = Buffer.isBuffer(bodyBuf) ? bodyBuf : Buffer.from(bodyBuf || []);

    const once = async (name) => {
      const arm = armFn('arm', bytes.toString('hex'));
      if (!arm || !arm.ok) return { ok: false, status: -1, note: 'arm 失败：' + JSON.stringify(arm || null) };
      const t0 = Date.now();
      let res;
      try {
        const svc = session.getMsgService();
        // 占位串只用来触发转换，内容随后由 native 覆盖成真 body。
        res = await Promise.resolve(svc.sendSsoCmdReqByContend(name, 'A'.repeat(bytes.length || 1)));
      } catch (error) {
        return { ok: false, status: -1, ms: Date.now() - t0,
          note: 'sendSsoCmdReqByContend 抛错：' + String((error && error.message) || error).slice(0, 180) };
      }
      const ms = Date.now() - t0;

      let resp = Buffer.alloc(0);
      if (res instanceof Uint8Array) resp = Buffer.from(res);
      else if (typeof res === 'string') resp = Buffer.from(res, 'latin1');
      else if (res && typeof res === 'object') {
        const raw = res.rsp ?? res.body ?? res.data;
        if (raw instanceof Uint8Array) resp = Buffer.from(raw);
        else if (typeof raw === 'string') resp = Buffer.from(raw, 'latin1');
      }

      // 解 OidbBase：1=command 2=subCommand 3=errorCode 4=body 5=errorMsg
      const ob = {};
      {
        let i = 0;
        const rv = () => { let v = 0n, s = 0n, c; do { if (i >= resp.length) throw new Error('eof'); c = resp[i++]; v |= BigInt(c & 0x7f) << s; s += 7n; } while (c & 0x80); return v; };
        while (i < resp.length) {
          let t; try { t = Number(rv()); } catch { break; }
          const field = t >>> 3, wire = t & 7;
          if (wire === 0) { try { ob[field] = Number(rv()); } catch { break; } }
          else if (wire === 2) { const n = Number(rv()); ob[field] = resp.subarray(i, i + n); i += n; }
          else if (wire === 5) i += 4;
          else if (wire === 1) i += 8;
          else break;
        }
      }
      // ⚠️ proto3 省略零值：errorCode==0 时 field3 根本不存在，不能拿 -1 当失败。
      // 另外 trpc 回包（群相册那类）没有 OidbBase 外壳，field3 可能是 bytes 而不是 varint ——
      // 这时它不是错误码，按 0 处理，否则会把成功显示成 errorCode=[object Object]。
      const errorCode = typeof ob[3] === 'number' ? ob[3] : 0;
      return {
        ok: errorCode === 0 && resp.length > 0,
        status: errorCode,
        errorCode,
        // field4 在正常回包里是 bytes，但也见过是 varint 的（这时 ob[4] 是 Number）。
        // 统一成 Buffer，否则下游 .subarray/.length 会抛（get_pskey 就因此报过
        // `body.subarray is not a function`）。
        body: Buffer.isBuffer(ob[4]) ? ob[4] : Buffer.alloc(0),
        errorMsg: ob[5] ? Buffer.from(ob[5]).toString('utf8') : '',
        response: resp,
        ms,
        cmdUsed: name,
        note: resp.length ? '' : '空回包',
      };
    };

    const first = await once(cmd);
    // 有回包（哪怕是业务错误码）就用它 —— 那是服务端的真实答复。
    if (first.response && first.response.length) return first;
    // arm 都失败（补丁没装等）就没必要重试第二个前缀。
    if (!first.ms && first.status === -1) return first;
    const alt = altSsoCmdName(cmd);
    if (!alt) return first;
    const second = await once(alt);
    if (second.response && second.response.length) {
      return { ...second, fallbackFrom: cmd, note: '' };
    }
    return { ...first, note: '两个前缀都没回包（' + cmd + ' / ' + alt + '）' };
  }

  function observe(name, args) {
    const records = name === 'onMsgInfoListUpdate' ? args[0] : name === 'onAddSendMsg' ? [args[0]] : [];
    if (!Array.isArray(records)) return;
    for (const record of records) {
      if (!record || (String(record.senderUin) !== self.uin && !(self.uid && record.senderUid === self.uid))) continue;
      const task = waiting.get(String(record.guildId)) ?? waiting.get(String(record.msgId));
      if (!task || record.chatType !== task.peer.chatType || String(record.peerUid) !== task.peer.peerUid || ![0, 2].includes(record.sendStatus)) continue;
      // Remember our own sends so a later reply to them can be quoted without a lookup.
      if (record.sendStatus === 2) try { options.record?.(record, self.uin); } catch { /* best effort */ }
      task.resolve(record);
    }
  }

  async function execute(request) {
    const action = validateAction(request);
    const operation = { active: true };
    const ensure = () => { if (disposed || !current() || !operation.active) throw fail('原生会话已失效，动作未继续执行', 1502); };
    ensure();
    // 通用 SSO 发包：MSFService.sendMsfRequest 原生断言 argc==4，但四个参数的顺序没文档，
    // 所以把几种可能的排序在同一次请求里挨个试，谁先回调成功就用谁。
    const toHexOf = value => {
      if (value === null || value === undefined) return null;
      try {
        if (Buffer.isBuffer(value)) return { hex: value.toString('hex').slice(0, 4000), bytes: value.length };
        if (value instanceof Uint8Array) return { hex: Buffer.from(value).toString('hex').slice(0, 4000), bytes: value.length };
        if (typeof value === 'string') return { text: value.slice(0, 2000), hex: Buffer.from(value, 'binary').toString('hex').slice(0, 4000) };
        if (typeof value === 'object') return { json: JSON.stringify(value).slice(0, 2000) };
        return { value: String(value).slice(0, 200) };
      } catch { return { unreadable: true }; }
    };
    async function ssoSend(cmd, hex, timeout) {
      const _buffer0 = Buffer.from(hex, 'hex');
      // 重写：两个来源都试 + 无条件留痕（上一版非 0/236 时不留痕，等于看不见结果）
      try {
        const _probe = { cmd, tried: [] };
        const _svcs = [];
        try { if (typeof session.getMsgService === 'function') _svcs.push(['session.getMsgService()', session.getMsgService()]); } catch (e) { _probe.getErr = String(e && e.message || e).slice(0, 120); }
        try { const m2 = serviceOf('msg'); if (m2) _svcs.push(['serviceOf(msg)', m2]); } catch (e) { _probe.svcErr = String(e && e.message || e).slice(0, 120); }
        _probe.svcNames = _svcs.map(x => x[0]);
        _probe.hasContend = _svcs.map(x => [x[0], x[1] && typeof x[1].sendSsoCmdReqByContend === 'function']);
        _probe.svcMethods = _svcs.length ? namesOf(_svcs[0][1]).filter(n => /sso|sso|cmd|req|packet/i.test(n)).slice(0, 20) : [];
        for (const [_src, _svc] of _svcs) {
          if (!_svc || typeof _svc.sendSsoCmdReqByContend !== 'function') continue;
          for (const [_label, _bodyStr] of [['latin1', _buffer0.toString('latin1')], ['fromCharCode', String.fromCharCode(..._buffer0)]]) {
            const _t0 = Date.now();
            try {
              const _ret = _svc.sendSsoCmdReqByContend(cmd, _bodyStr);
              const _rec = { src: _src, label: _label, result: _ret, type: typeof _ret, ms: Date.now() - _t0 };
              _probe.tried.push(_rec);
              if (_ret === 0 || _ret === 236) { globalThis.__openqqContendProbe2 = _probe; return [{ label: 'contend/' + _label, result: _ret, ok: _ret === 0, ms: _rec.ms }]; }
            } catch (_e) { _probe.tried.push({ src: _src, label: _label, error: String(_e && _e.message || _e).slice(0, 200) }); }
          }
        }
        globalThis.__openqqContendProbe2 = _probe;
      } catch (_e3) { globalThis.__openqqContendProbe2 = { cmd, fatal: String(_e3 && _e3.message || _e3).slice(0, 200) }; }
      // : msg.sendSsoCmdReqByContend(cmdName, bodyStr) 是同步 SSO 通道(argc==2)，
      // 0=成功 236=没配路由。之前这里只试 msf.sendMsfRequest（包装层坏的），这条从没被走过。
      try {
        const _msgSvc = typeof session.getMsgService === 'function' ? session.getMsgService() : null;
        if (_msgSvc && typeof _msgSvc.sendSsoCmdReqByContend === 'function') {
          for (const [_label, _bodyStr] of [
            ['contend(cmd, latin1)', _buffer0.toString('latin1')],
            ['contend(cmd, fromCharCode)', String.fromCharCode(..._buffer0)],
          ]) {
            const _t0 = Date.now();
            try {
              const _ret = _msgSvc.sendSsoCmdReqByContend(cmd, _bodyStr);
              globalThis.__openqqContendProbe = { cmd, label: _label, result: _ret, ms: Date.now() - _t0 };
              if (_ret === 0) return [{ label: _label, result: _ret, ok: true, ms: Date.now() - _t0 }];
              if (_ret === 236) return [{ label: _label, result: _ret, ok: false, ms: Date.now() - _t0, error: '236 route not configured' }];
            } catch (_e) { /* 落到 msf 再试 */ }
          }
        }
      } catch (_e2) { /* ignore */ }
      const msf = session.getMSFService();
      if (!msf || typeof msf.sendMsfRequest !== 'function') throw fail('当前 QQ 内核没有 MSFService.sendMsfRequest', 1400);
      const buffer = Buffer.from(hex, 'hex');
      const attempts = [];
      const attempt = (label, invoke) => new Promise(resolve => {
        let settled = false;
        let timer = null;
        const finish = (ok, payload) => {
          if (settled) return;
          settled = true;
          if (timer) clearTimeout(timer);
          attempts.push({ label, ok, ...payload });
          resolve(ok);
        };
        timer = setTimeout(() => finish(false, { error: '等回调超时' }), timeout);
        const callback = (...cbArgs) => finish(true, { cbArgs: cbArgs.map(toHexOf) });
        try { invoke(callback); }
        catch (error) { finish(false, { error: String(error && error.message ? error.message : error).slice(0, 240) }); }
      });
      for (const [label, invoke] of [
        ['(cmd, body, timeout, cb)', cb => msf.sendMsfRequest(cmd, buffer, timeout, cb)],
        ['(cmd, body, cb, timeout)', cb => msf.sendMsfRequest(cmd, buffer, cb, timeout)],
        ['(cmd, hex, timeout, cb)', cb => msf.sendMsfRequest(cmd, hex, timeout, cb)],
        // 报错一直是 "Cannot convert undefined or null to object"，说明它在对某个位置做 Object.keys/展开；
        // 那第 1 参可能不是字符串而是一个描述对象。这几种一起试，一次重启全部验完。
        ['({cmd,body,timeout}, null, null, cb)', cb => msf.sendMsfRequest({ cmd, body: buffer, timeout }, null, null, cb)],
        ['({cmd,body}, null, null, cb)', cb => msf.sendMsfRequest({ cmd, body: buffer }, null, null, cb)],
        ['(cmd, Uint8Array, timeout, cb)', cb => msf.sendMsfRequest(cmd, new Uint8Array(buffer), timeout, cb)],
      ]) {
        if (await attempt(label, invoke)) break;
      }
      return attempts;
    }
    if (action.kind === 'oidb_dryrun') {
      // 危险动作只到这里：把构造好的包给出去，但不发。
      return { status: 'failed', retcode: 1404,
        data: { action: action.action, cmd: action.cmd, bodyHex: action.bodyHex, bodyLen: action.bodyLen, sent: false },
        message: action.note };
    }
    if (action.kind === 'download_file') {
      // 落盘到 <openqq>/data/downloads/：这个目录只存下载结果，不会被当成代码或配置加载。
      const fsMod = require('node:fs');
      const pathMod = require('node:path');
      const dir = pathMod.join(__dirname, '..', 'data', 'downloads');
      fsMod.mkdirSync(dir, { recursive: true });
      const dest = pathMod.join(dir, action.name || ('download-' + Date.now() + '.bin'));
      let buf;
      if (action.base64) {
        buf = Buffer.from(String(action.base64).replace(/^data:[^;]+;base64,/, ''), 'base64');
        if (buf.length > action.maxBytes) {
          return { status: 'failed', retcode: 1400, data: { action: 'download_file', size: buf.length },
            message: `base64 内容超过 ${action.maxBytes} 字节上限` };
        }
      } else {
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), 60000);
        if (timer.unref) timer.unref();
        try {
          // redirect: 'manual' —— 跟随重定向会让一个公网地址 302 到内网，绕过 validateAction 里的主机检查。
          const res = await fetch(action.url, { headers: action.headers || {}, signal: ac.signal, redirect: 'manual' });
          if (res.status >= 300 && res.status < 400) {
            return { status: 'failed', retcode: 1400, data: { action: 'download_file', url: action.url, http: res.status },
              message: '下载失败：目标返回重定向，download_file 不跟随（避免被导向内网）' };
          }
          if (!res.ok) {
            return { status: 'failed', retcode: 1500, data: { action: 'download_file', url: action.url, http: res.status },
              message: '下载失败：HTTP ' + res.status };
          }
          buf = await readBodyCapped(res, action.maxBytes);
        } catch (error) {
          return { status: 'failed', retcode: 1500, data: { action: 'download_file', url: action.url },
            message: '下载失败：' + String(error && error.message ? error.message : error).slice(0, 160) };
        } finally { clearTimeout(timer); }
      }
      fsMod.writeFileSync(dest, buf);
      return { status: 'ok', retcode: 0, data: { action: 'download_file', file: dest, name: pathMod.basename(dest), size: buf.length } };
    }
    if (action.kind === 'forward_send') {
      // 源消息：来自主进程附加的 openqq_ref，里面有真 msgId + 源会话的 peerUid（nativeRef 已校验格式）
      const src = action.source;
      // 目标会话：把 targetUin（QQ 号/群号）换成 peerUid。getUserDetailInfoByUin 是 argc==1 + 异步，必须 await。
      let targetUid = '';
      try {
        const profileSvc = session.getProfileService();
        const det = await profileSvc.getUserDetailInfoByUin(action.targetUin);
        targetUid = String((det && det.detail && (det.detail.uid || (det.detail.simpleInfo && det.detail.simpleInfo.uid))) || '');
      } catch (e) {
        return { status: 'failed', retcode: 1500, data: { action: action.action, targetUin: action.targetUin },
          message: 'getUserDetailInfoByUin 抛错：' + String(e && e.message ? e.message : e).slice(0, 140) };
      }
      if (!targetUid) {
        return { status: 'failed', retcode: 1404, data: { action: action.action, targetUin: action.targetUin },
          message: '拿不到目标 peerUid（getUserDetailInfoByUin 返回空 uid）' };
      }
      const msgSvc = session.getMsgService();
      if (!msgSvc || typeof msgSvc.forwardMsg !== 'function') {
        return { status: 'failed', retcode: 1404, data: { action: action.action }, message: 'Msg.forwardMsg 不可用' };
      }
      // QQ NT 的 forwardMsg(msgInfos, target, options, callback)。
      // msgInfos 每项要 {msgId, msgSeq}；源消息的 peerUid/chatType 来自 openqq_ref。
      const msgInfos = [{
        msgId: String(src.msgId),
        msgSeq: String(src.msgId),
        peerUid: String(src.peerUid),
        chatType: Number(src.chatType),
      }];
      const target = { chatType: action.targetChatType, peerUid: targetUid, guildId: '' };
      const cbOut = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve({ __timeout: true }), 15000);
        if (timer.unref) timer.unref();
        try {
          msgSvc.forwardMsg(msgInfos, target, {}, (...a) => { clearTimeout(timer); resolve(a.length <= 1 ? a[0] : a); });
        } catch (e) {
          clearTimeout(timer);
          resolve({ __throw: String(e && e.message ? e.message : e).slice(0, 200) });
        }
      });
      const ok = Boolean(cbOut) && !cbOut.__timeout && !cbOut.__throw && Number(cbOut.result ?? 0) === 0;
      return {
        status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500,
        data: { action: action.action, sourceMsgId: String(src.msgId), targetUin: action.targetUin,
          targetChatType: action.targetChatType, callback: cbOut },
        ...(ok ? {} : { message: cbOut && cbOut.__timeout ? 'forwardMsg 15 秒无回调（内核没触发）'
          : (cbOut && cbOut.__throw ? 'forwardMsg 抛错：' + cbOut.__throw : 'forwardMsg 回执非 0') }),
      };
    }
    if (action.kind === 'nc_user_status') {
      // 正解：getUserDetailInfoByUin 的 detail.simpleInfo.status 直接带完整在线状态
      // （status/extStatus/batteryStatus/termType/netType/iconType/setTime…），一次请求就够。
      // 不要再去调 Profile.getStatus —— 那个要 uid，而 uid 的四种形状全试过都是 316/116。
      if (!action.uin) return { status: 'failed', retcode: 1400, data: { note: '需要 user_id' } };
      let det;
      try {
        det = await session.getProfileService().getUserDetailInfoByUin(action.uin);
      } catch (e) {
        return { status: 'failed', retcode: 1500, data: { step: 'detail', error: String(e && e.message || e).slice(0, 120) } };
      }
      const d = det && det.detail;
      if (!d) return { status: 'failed', retcode: 1404, data: { step: 'detail', raw: det } };
      const st = (d.simpleInfo && d.simpleInfo.status) || d.status || null;
      const pick = (o, keys) => { const r = {}; for (const k of keys) if (o && o[k] !== undefined) r[k] = o[k]; return r; };
      return {
        status: 'ok', retcode: 0,
        data: {
          user_id: action.uin,
          uin: d.uin, nick: (d.simpleInfo && d.simpleInfo.coreInfo && d.simpleInfo.coreInfo.nick) || '',
          status: st ? st.status : null,
          online: st ? Number(st.status) > 0 : null,
          detail: st ? pick(st, ['status', 'extStatus', 'batteryStatus', 'termType', 'netType', 'iconType',
            'setTime', 'specialFlag', 'showName', 'termDesc', 'activeState', 'offlineType', 'customStatus']) : null,
        },
      };
    }
    if (action.kind === 'qun_album_upload') {
      // ══ 群相册上传（照 SL 的 uploadImageToGroupAlbum 复刻，实测通）══
      // 关键三条（都是踩过的坑）：
      //   ① skey 和 p_skey 都从 ssl.ptlogin2.qq.com/jump 累积 Set-Cookie 拿（同名不同域，只留非空、绝不 delete）
      //   ② bkn 必须用 **skey** 算，不是 p_skey（用 pskey 算会回 ret:-100 登录失败）
      //   ③ clientKey 用内核 Ticket.forceFetchClientKey(1) 拿（96 字符 + keyIndex:"19"）
      const crypto = require('node:crypto');
      const { bytes, groupId, albumId, albumName, title } = action;
      const uin = String(action.uin ?? '');
      const md5hex = crypto.createHash('md5').update(bytes).digest('hex');

      // ① 拿 clientKey（argc==1，要传 null；getter 名可能是 getTicketService）
      let clientKey = '', keyIndex = '19', ckErr = '';
      try {
        const svc = session.getTicketService ? session.getTicketService() : null;
        if (!svc) ckErr = 'no getTicketService';
        else {
          const ck = await Promise.resolve(svc.forceFetchClientKey(null));
          if (ck && ck.clientKey) { clientKey = String(ck.clientKey); keyIndex = String(ck.keyIndex || '19'); }
          else ckErr = 'empty: ' + JSON.stringify(ck || {}).slice(0, 100);
        }
      } catch (e) { ckErr = String(e && e.message || e).slice(0, 120); }
      if (!clientKey) return { status: 'failed', retcode: 1404, data: { step: 'clientkey', error: ckErr } };

      // ② /jump 累积 cookie（同名只留非空，绝不 delete —— 空值会覆盖掉别的域的有值项）
      const cookies = {};
      let cur = `https://ssl.ptlogin2.qq.com/jump?ptlang=1033&clientuin=${uin}&clientkey=${encodeURIComponent(clientKey)}`
        + `&u1=${encodeURIComponent('https://qzone.qq.com/' + uin + '/infocenter')}&keyindex=${keyIndex}`;
      const hops = [];
      for (let hop = 0; hop < 8; hop++) {
        // 每一跳都要有超时：这条链是 QQ 进程内的动作，网络卡住而没有 AbortController
        // 会让整个动作一直挂在 QQ 进程里，直到 IPC 超时都释放不掉。
        const hopAbort = new AbortController();
        const hopTimer = setTimeout(() => hopAbort.abort(), 8000);
        if (hopTimer.unref) hopTimer.unref();
        let res;
        try {
          res = await fetch(cur, { redirect: 'manual', headers: { 'User-Agent': 'Mozilla/5.0' }, signal: hopAbort.signal });
        } catch (error) {
          return { status: 'failed', retcode: 1500,
            data: { step: 'jump', hop, hops, url: cur.slice(0, 120) },
            message: `第 ${hop} 跳超时或失败：` + String(error && error.message ? error.message : error).slice(0, 120) };
        } finally { clearTimeout(hopTimer); }
        hops.push({ hop, status: res.status, setCookie: (res.headers.getSetCookie ? res.headers.getSetCookie() : []).length, loc: String(res.headers.get('location') || '').slice(0, 60) });
        const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
        for (const c of sc) {
          const kv = c.split(';')[0]; const i2 = kv.indexOf('=');
          if (i2 > 0) { const k = kv.slice(0, i2).trim(), v = kv.slice(i2 + 1).trim(); if (v) cookies[k] = v; }
        }
        const loc = res.headers.get('location'); if (!loc) break;
        cur = loc.startsWith('http') ? loc : new URL(loc, cur).href;
      }
      const pskey = cookies['p_skey'] || '';
      const skey = cookies['skey'] || '';
      if (!skey) return { status: 'failed', retcode: 1404, data: { step: 'jump', note: '没拿到 skey', cookieKeys: Object.keys(cookies), hops, clientKeyLen: clientKey.length } };
      const cookieStr = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
      const bkn = (() => { let h = 5381; for (let i = 0; i < skey.length; i++) h = (h + ((h << 5) + skey.charCodeAt(i))) >>> 0; return h & 0x7fffffff; })();

      // ③ 创建上传会话
      const ts = Math.floor(Date.now() / 1000);
      const ctrlBody = { control_req: [{
        uin, token: { type: 4, data: pskey, appid: 5 }, appid: 'qun',
        checksum: md5hex, check_type: 0, file_len: bytes.length,
        env: { refer: 'qzone', deviceInfo: 'h5' }, model: 0,
        biz_req: {
          sPicTitle: title || `album_${ts}.${action.isVideo ? 'mp4' : 'jpg'}`, sPicDesc: '', sAlbumName: albumName, sAlbumID: albumId,
          iAlbumTypeID: 0, iBitmap: 0, iUploadType: 0, iUpPicType: action.isVideo ? 1 : 0, iBatchID: ts,
          sPicPath: '', iPicWidth: 0, iPicHight: 0, iWaterType: 0, iDistinctUse: 0,
          iNeedFeeds: 1, iUploadTime: ts,
          mapExt: { appid: 'qun', userid: groupId },
          stExtendInfo: { mapParams: action.isVideo
            ? { photo_num: '0', video_num: '1', batch_num: '1' }
            : { photo_num: '1', video_num: '0', batch_num: '1' } },
        },
        session: '', asy_upload: 0, cmd: 'FileUpload',
      }] };
      const ctrlUrl = `https://h5.qzone.qq.com/webapp/json/sliceUpload/FileBatchControl/${md5hex}?g_tk=${bkn}`;
      const ctrlResp = await fetch(ctrlUrl, {
        method: 'POST',
        headers: { Cookie: cookieStr, 'Content-Type': 'application/json', Referer: 'https://h5.qzone.qq.com/', Origin: 'https://h5.qzone.qq.com' },
        body: JSON.stringify(ctrlBody),
      });
      const ctrlJson = await ctrlResp.json().catch(() => ({}));
      const uploadSession = ctrlJson && ctrlJson.data && ctrlJson.data.session;
      if (!uploadSession) {
        return { status: 'failed', retcode: 1404, data: {
          step: 'create-session', ret: ctrlJson.ret, msg: String(ctrlJson.msg || '').slice(0, 120),
          note: 'album_id / album_name 必须和群相册里真实的一致' } };
      }

      // ④ 分片上传（每片 16384）
      const SLICE = 16384;
      let seq = 0, offset = 0, lastRet = null;
      while (offset < bytes.length) {
        const end = Math.min(offset + SLICE, bytes.length);
        const chunk = bytes.subarray(offset, end);
        const form = new FormData();
        form.append('uin', uin);
        form.append('appid', 'qun');
        form.append('session', uploadSession);
        form.append('offset', String(offset));
        form.append('data', new Blob([chunk], { type: 'application/octet-stream' }), 'blob');
        form.append('checksum', '');
        form.append('check_type', '0');
        form.append('retry', '0');
        form.append('seq', String(seq));
        form.append('end', String(end));
        form.append('cmd', 'FileUpload');
        form.append('slice_size', String(SLICE));
        form.append('biz_req.iUploadType', '0');
        const url = `https://h5.qzone.qq.com/webapp/json/sliceUpload/FileUpload?seq=${seq}&retry=0&offset=${offset}&end=${end}&total=${bytes.length}&type=form&g_tk=${bkn}`;
        const r = await fetch(url, { method: 'POST', headers: { Cookie: cookieStr }, body: form });
        if (!r.ok) return { status: 'failed', retcode: 1500, data: { step: 'slice', seq, httpStatus: r.status } };
        lastRet = await r.json().catch(() => ({}));
        if (lastRet && lastRet.ret !== 0) {
          return { status: 'failed', retcode: 1404, data: { step: 'slice', seq, ret: lastRet.ret, msg: String(lastRet.msg || '').slice(0, 120) } };
        }
        offset = end; seq++;
      }
      return { status: 'ok', retcode: 0, data: { md5: md5hex, size: bytes.length, slices: seq, hasSkey: Boolean(skey), hasPskey: Boolean(pskey), last: lastRet } };
    }
    if (action.kind === 'custom_face_bdh') {
      // ══ 收藏表情上传（BDH 三步，照 SL 的 AddCustomFace.invoke 复刻）══
      // ① HttpConn.0x6ff_501 → sigSession + 上传服务器 host/port（**已通**，1338 字节，请求/响应都是 field 1281）
      // ② ImgStore.BDHExpressionRoam → token（inner field 8）—— 服务端回 199 "para error"，
      //    包字节与 SL 逐字段一致（含 tail 是 field 1001 这个坑），所以是服务端侧拒绝，不是编码错
      // ③ packHighwayFrame → POST http://host:port/cgi-bin/httpconn?htcmd=0x6FF0087&uin=
      //    这一步依赖 ② 的 token，② 不通时如实返回诊断，不假装成功。
      const crypto = require('node:crypto');
      const pb = require('./pb-mini.cjs');
      const { uin, bytes } = action;
      const md5 = crypto.createHash('md5').update(bytes).digest();
      const emojiId = `${uin}_0_0_0_${md5.toString('hex').toUpperCase()}_0_0`;

      const pbScan = (buf) => {
        const out = {};
        let i = 0;
        const rv = () => { let n = 0, m = 0, b; do { b = buf[i++]; n += (b & 127) * Math.pow(2, m); m += 7; } while (b & 128); return n; };
        while (i < buf.length) {
          let tag; try { tag = rv(); } catch { break; }
          const f = Math.floor(tag / 8), w = tag & 7;
          if (w === 0) { const v = rv(); (out[f] = out[f] || []).push(v); }
          else if (w === 2) { const len = rv(); const s = buf.subarray(i, i + len); i += len; (out[f] = out[f] || []).push(s); }
          else if (w === 5) { (out[f] = out[f] || []).push(buf.readUInt32BE(i)); i += 4; }
          else if (w === 1) { i += 8; } else break;
        }
        return out;
      };

      const inner2 = Buffer.concat([
        pb.vint(1, 0), pb.vint(2, uin), pb.vint(3, 0),
        pb.bytes(4, md5), pb.vint(5, bytes.length),
        pb.vint(6, 2), pb.vint(7, 0), pb.vint(8, 1),
        pb.str(9, '1.0.0'), pb.vint(10, 1),
      ]);
      const tailInner = Buffer.concat([pb.vint(1, 0), pb.vint(2, 0), pb.str(3, '0')]);
      const tail = Buffer.concat([pb.bytes(1, tailInner), pb.vint(2, 1)]);
      // Req 的 tail 是 field 1001（tag 0xCA 0x3E 两字节），不是 field 5 —— 从 SL 的
      // __write_BDHExpressionRoamReq 里 `buf[offset++] = 202; buf[offset++] = 62;` 读出来的。
      const bdhReq = Buffer.concat([pb.vint(1, 3), pb.vint(2, 1), pb.bytes(3, inner2), pb.vint(4, 9), pb.bytes(1001, tail)]);
      const bdhRes = await selfSsoSend('ImgStore.BDHExpressionRoam', bdhReq);
      let token = null, bdhCode = null, bdhMsg = '';
      if (bdhRes && bdhRes.body && bdhRes.body.length) {
        const top = pbScan(bdhRes.body);
        // Resp { 1: field1, 2: field2, 3: inner }，真正的 code/msg/token 都在 inner 里
        const innerTop = top[3] && top[3][0];
        if (innerTop) {
          const it = pbScan(innerTop);
          bdhCode = it[2] && it[2][0];
          bdhMsg = it[3] && it[3][0] ? it[3][0].toString() : '';
          token = (it[8] && it[8][0]) || null;
        }
      }

      // ① HttpConn.0x6ff_501 —— 请求和响应**都是 field 1281**（实测通，1338 字节）。
      //    之前记成"请求是 field 1"是错的：`8a 50` 解 varint = 10250 = (1281<<3)|2。
      const httpConnReq = Buffer.from('8a501f0800100018102001300338013805380a38154802500958086205312e302e31', 'hex');
      const hc = await selfSsoSend('HttpConn.0x6ff_501', httpConnReq);
      const servers = [];
      let sigLen = 0, sessionKeyStr = '';
      if (hc && hc.body && hc.body.length) {
        const outer = pbScan(hc.body);
        const body1281 = outer[1281] && outer[1281][0];
        if (body1281) {
          const inf = pbScan(body1281);
          sigLen = inf[1] && inf[1][0] ? inf[1][0].length : 0;
          sessionKeyStr = inf[2] && inf[2][0] ? inf[2][0].toString() : '';
          const walk = (buf) => {
            const fs = pbScan(buf);
            const ip = fs[2] && fs[2][0];
            const port = fs[3] && fs[3][0];
            if (typeof ip === 'number' && typeof port === 'number' && port > 0 && port <= 65535) {
              servers.push({ host: [(ip >>> 24) & 255, (ip >>> 16) & 255, (ip >>> 8) & 255, ip & 255].join('.'), port });
              return;
            }
            for (const k of Object.keys(fs)) for (const v of fs[k]) if (Buffer.isBuffer(v)) walk(v);
          };
          for (const si of (inf[3] || [])) {
            const fs = pbScan(si);
            if ((fs[1] && fs[1][0]) !== 1) continue;   // serviceType 必须 1
            walk(si);
          }
        }
      }
      const uniq = [...new Map(servers.map((s) => [`${s.host}:${s.port}`, s])).values()];
      const diag = {
        emojiId,
        httpConn: { len: hc && hc.body ? hc.body.length : 0, sigLen, sessionKey: sessionKeyStr, servers: uniq.map((s) => `${s.host}:${s.port}`) },
        bdh: bdhRes ? { status: bdhRes.status, code: bdhCode, msg: bdhMsg, len: bdhRes.body ? bdhRes.body.length : 0, hasToken: Boolean(token) } : null,
      };
      if (!uniq.length) return { status: 'failed', retcode: 1404, data: { step: 'httpconn', ...diag } };
      if (!token) return { status: 'failed', retcode: 1404, data: { step: 'bdh-token', ...diag,
        note: 'BDH 回业务码 ' + bdhCode + ' ' + bdhMsg + '（包字节与 SL 的 AddCustomFace 逐字段一致，服务端仍拒）' } };

      // ③ highway 直传
      const baseHead = Buffer.concat([
        pb.vint(1, 1), pb.vint(2, Number(uin)), pb.str(3, 'PicUp.DataUp'), pb.vint(4, 1),
        pb.vint(5, 0), pb.vint(6, bytes.length), pb.vint(7, 16), pb.vint(8, 9),
      ]);
      const segHead = Buffer.concat([
        pb.vint(1, 0), pb.vint(2, bytes.length), pb.vint(3, 0), pb.vint(4, bytes.length),
        pb.bytes(5, token), pb.bytes(6, md5), pb.bytes(7, md5),
      ]);
      const hwHead = Buffer.concat([
        pb.bytes(1, baseHead), pb.bytes(2, segHead), pb.bytes(3, pb.bytes(1, emojiId)),
        pb.vint(4, 0), pb.vint(6, 9),
      ]);
      const frame = Buffer.alloc(9 + hwHead.length + bytes.length + 1);
      frame[0] = 40;
      frame.writeUInt32BE(hwHead.length, 1);
      frame.writeUInt32BE(bytes.length, 5);
      hwHead.copy(frame, 9);
      bytes.copy(frame, 9 + hwHead.length);
      frame[frame.length - 1] = 41;
      const tries = [];
      for (const s of uniq) {
        const url = `http://${s.host}:${s.port}/cgi-bin/httpconn?htcmd=0x6FF0087&uin=${uin}`;
        try {
          const hr = await fetch(url, {
            method: 'POST', body: frame,
            headers: { Accept: '*/*', Connection: 'Keep-Alive', 'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)', 'Cache-Control': 'no-cache', Pragma: 'no-cache' },
            signal: AbortSignal.timeout(15000),
          });
          const rb = Buffer.from(await hr.arrayBuffer());
          tries.push({ server: `${s.host}:${s.port}`, http: hr.status, respLen: rb.length, respHex: rb.subarray(0, 120).toString('hex') });
          if (hr.ok) return { status: 'ok', retcode: 0, data: { action: action.action, emojiId, size: bytes.length, md5: md5hex, ...diag, upload: tries } };
        } catch (e) { tries.push({ server: `${s.host}:${s.port}`, error: String(e && e.message || e).slice(0, 100) }); }
      }
      return { status: 'failed', retcode: 1500, data: { step: 'highway', ...diag, upload: tries } };
    }
    if (action.kind === 'sso_pipe') {
      // 走 SnowLuma 组件的命名管道发 SSO 包（真发包口）。
      // 判据：回 status 0 + 有 body = 服务器真的回了；status 非 0 时 message 是服务端原文。
      if (action.action === 'sso_pipe_status') {
        // 探活 = 问一次补丁装没装、能不能 arm。装上了才算通道就绪。
        const armFn = globalThis.__openqqSsoBodyConv;
        const st = typeof armFn === 'function' ? (armFn('status', '') || {}) : { patched: false };
        const ok = Boolean(st && st.patched);
        return {
          status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500,
          data: { channel: 'self', patched: Boolean(st && st.patched), ...st },
          ...(ok ? {} : { message: 'body 代劳补丁未安装：需要配套的 openqq-bootstrap（wrapper.node 版本不符时会装不上）' }),
        };
      }
      try {
        const r = await selfSsoSend(action.cmd, action.body);
        return {
          status: r.status === 0 ? 'ok' : 'failed',
          retcode: r.status === 0 ? 0 : 1500,
          data: {
            action: action.action,
            cmd: action.cmd,
            requestLen: action.body.length,
            status: r.status,
            message: r.note || '',
            responseLen: r.body ? r.body.length : 0,
            responseHex: r.body ? r.body.subarray(0, 65536).toString('hex') : '',
          },
        };
      } catch (error) {
        return { status: 'failed', retcode: 1500,
          data: { action: action.action, cmd: action.cmd, requestLen: action.body.length, channel: 'self' },
          message: String(error && error.message ? error.message : error).slice(0, 300) };
      }
    }
    if (action.kind === 'native_op') {
      const svc = serviceOf(action.service);
      if (!svc) return { status: 'failed', retcode: 1404, data: { service: action.service }, message: '找不到 service ' + action.service };
      const fn = svc[action.method];
      if (typeof fn !== 'function') return { status: 'failed', retcode: 1404, data: { service: action.service, method: action.method }, message: 'service 上没有这个方法' };
      // 回调桥：内核里有一批方法（精华列表 / 群公告列表 / 群文件列表…）不 return，结果只从最后一个
      // 参数建成的回调里给出。IPC 传过来的 args 已经被 JSON 序列化过，函数在那种表示里活不下来，
      // 所以回调位置在**执行侧**注入（cbIndex 指向第几个参数），并把回调实参当作返回值上报。
      const callArgs = Array.isArray(action.args) ? action.args.slice() : [];
      const cbIndex = Number.isSafeInteger(action.cbIndex) ? action.cbIndex : -1;
      let cbValue; let cbCalled = false;
      if (cbIndex >= 0 && cbIndex < callArgs.length) {
        callArgs[cbIndex] = (...cbArgs) => { cbCalled = true; cbValue = cbArgs.length <= 1 ? cbArgs[0] : cbArgs; };
      }
      try {
        // 有些方法既不 return 也不回调（参数形状不对时内核会把调用吞掉），
        // 不设上限就会把这一次动作永久挂住，所以给一个有回调的等久一点、没回调的等短一点。
        const waitMs = cbIndex >= 0 ? 12000 : 6000;
        const value = await Promise.race([
          Promise.resolve(fn.apply(svc, callArgs)),
          new Promise((_, reject) => { const t = setTimeout(() => reject(new Error('原生调用超时：该方法既没有同步返回也没有触发回调')), waitMs); if (t.unref) t.unref(); }),
        ]);
        const effective = (value === undefined || value === null) && cbCalled ? cbValue : value;
        let out = effective;
        try { out = JSON.parse(JSON.stringify(effective === undefined ? null : effective)); } catch { out = String(effective); }
        const nativeData = { action: action.action, service: action.service, method: action.method, argc: callArgs.length, via: cbCalled && (value === undefined || value === null) ? 'callback' : 'return', value: out };
        const refusal = nativeRefusal(out);
        if (refusal) return { status: 'failed', retcode: 1500, data: nativeData, message: 'QQ 拒绝' + action.action + '：' + refusal };
        return { status: 'ok', retcode: 0, data: nativeData };
      } catch (error) {
        return { status: 'failed', retcode: 1500, data: { action: action.action, service: action.service, method: action.method, argc: callArgs.length, cbCalled },
          message: String(error && error.message ? error.message : error).slice(0, 300) };
      }
    }
    if (action.kind === 'oidb_raw') {
      // 真·发包口：wrapper.node 的 C++ 符号里有
      //   KernelECDHService::sendOIDBRequest(int cmd, int subCmd, int ?, vector<uint8_t> body, shared_ptr<callback>)
      //   NTWrapperEngine::SendOidbRequest(int, int, int, vector<uint8_t>, IPBMessage, function callback)
      // 先找 engine 实例，再按 C++ 签名试 5/6 参。
      const wrapper = globalThis.__openqq_wrapper;
      if (!wrapper) return { status: 'failed', retcode: 1400, data: null, message: '没有 wrapper 句柄' };
      const cmd = Number(action.cmd);
      const subCmd = Number(action.subCmd ?? 1);
      const body = Buffer.from(String(action.hex || ''), 'hex');
      const timeout = Number(action.timeout ?? 12000);
      const attempts = [];

      // 服务端回包走 engine.onSendSSOReply —— 挂一个旁路记录，供 debug 动作查看。
      // 只挂一次；C++ 侧若不回调，这里就是个空数组（不影响发包本身）。
      try {
        const engForHook = wrapper.NodeIQQNTWrapperEngine && typeof wrapper.NodeIQQNTWrapperEngine.get === 'function'
          ? wrapper.NodeIQQNTWrapperEngine.get() : null;
        if (engForHook && !globalThis.__openqqOidbHookInstalled) {
          globalThis.__openqqOidbHook = globalThis.__openqqOidbHook || [];
          globalThis.__openqqOidbHookInstalled = true;
          const origReply = engForHook.onSendSSOReply;
          engForHook.onSendSSOReply = function (...cbArgs) {
            try {
              globalThis.__openqqOidbHook.push({
                t: Date.now(),
                args: cbArgs.map(x => {
                  if (x instanceof Uint8Array || Buffer.isBuffer(x)) return { bytes: x.length, hex: Buffer.from(x).toString('hex').slice(0, 1200) };
                  try { return JSON.parse(JSON.stringify(x)); } catch { return String(x).slice(0, 200); }
                }),
              });
              if (globalThis.__openqqOidbHook.length > 50) globalThis.__openqqOidbHook.shift();
            } catch {}
            if (typeof origReply === 'function') { try { return origReply.apply(this, cbArgs); } catch {} }
          };
        }
      } catch {}

      const namesOf = (v) => {
        const set = new Set();
        try { for (let o = v, d = 0; o && o !== Object.prototype && d < 3; o = Object.getPrototypeOf(o), d++) for (const n of Object.getOwnPropertyNames(o)) if (n !== 'constructor') set.add(n); } catch {}
        return Array.from(set).sort();
      };

      // ---- 找 engine 实例 ----
      const engines = [];
      const Engine = wrapper.NodeIQQNTWrapperEngine;
      if (Engine && typeof Engine.get === 'function') {
        try { const e = Engine.get(); if (e) engines.push({ label: 'NodeIQQNTWrapperEngine.get()', inst: e }); else attempts.push({ label: 'Engine.get()', note: 'returned null' }); }
        catch (error) { attempts.push({ label: 'Engine.get()', error: String(error && error.message || error).slice(0, 120) }); }
      }
      if (wrapper.__engine) engines.push({ label: 'wrapper.__engine', inst: wrapper.__engine });
      // session 自身也可能有 engine 引用
      for (const k of ['engine', 'wrapperEngine', 'm_engine', 'ntEngine']) {
        try { if (session && session[k]) engines.push({ label: 'session.' + k, inst: session[k] }); } catch {}
      }

      // ---- ECDH 服务实例 ----
      // 实测：new NodeIKernelECDHService 是空壳（cpp_impl 断言失败），
      // 真实现只能从 engine.getECDHService 取。engine 自己也没有 sendOidbRequest。
      const ecdh = [];
      for (const h of engines) {
        const getter = h.inst && h.inst.getECDHService;
        if (typeof getter !== 'function') continue;
        try {
          const inst = getter.call(h.inst);
          if (inst) { ecdh.push({ label: h.label + '.getECDHService()', inst }); break; }
          attempts.push({ label: h.label + '.getECDHService()', note: 'returned null' });
        } catch (error) {
          attempts.push({ label: h.label + '.getECDHService()', error: String(error && error.message || error).slice(0, 160) });
        }
      }
      const ECDH = wrapper.NodeIKernelECDHService;
      // 自建实例是空壳，已移除（见上）

      // ---- 统一试发包 ----
      const trySend = async (holder, methodNames, argSets) => {
        for (const method of methodNames) {
          const fn = holder.inst && holder.inst[method];
          if (typeof fn !== 'function') continue;
          for (const [shapeLabel, build] of argSets) {
            const entry = { holder: holder.label, method, shape: shapeLabel };
            try {
              const result = await new Promise((resolve) => {
                let done = false;
                const finish = (v) => { if (!done) { done = true; resolve(v); } };
                const timer = setTimeout(() => finish({ via: 'timeout' }), timeout);
                if (timer.unref) timer.unref();
                const cb = (...cbArgs) => {
                  clearTimeout(timer);
                  finish({ via: 'callback', argc: cbArgs.length, args: cbArgs.map(a => {
                    if (a instanceof Uint8Array || Buffer.isBuffer(a)) return { bytes: a.length, hex: Buffer.from(a).toString('hex').slice(0, 4000) };
                    try { return JSON.parse(JSON.stringify(a)); } catch { return String(a).slice(0, 200); }
                  }) });
                };
                let ret;
                try { ret = fn.apply(holder.inst, build(cb)); }
                catch (error) { clearTimeout(timer); finish({ via: 'throw', error: String(error && error.message || error).slice(0, 200) }); return; }
                // 实测结论：sendOIDBRequest 同步返回的空对象 {} 就是"已提交"，
                // 它**不会**再触发第二个回调 —— 之前改成"等回调"导致每次都卡满超时、回 1501。
                // 服务端回包走 engine.onSendSSOReply（见下面的钩子），不在这里等。
                if (ret !== undefined) {
                  clearTimeout(timer);
                  const empty = ret && typeof ret === 'object' && !Array.isArray(ret) && Object.keys(ret).length === 0;
                  finish({ via: 'return', submitted: empty === true, value: (() => { try { return JSON.parse(JSON.stringify(ret)); } catch { return String(ret).slice(0, 200); } })() });
                }
              });
              entry.result = result;
              attempts.push(entry);
              if (result.via === 'callback' || result.via === 'return') {
                return { hit: entry, attempts };
              }
            } catch (error) {
              entry.error = String(error && error.message || error).slice(0, 200);
              attempts.push(entry);
            }
          }
        }
        return { hit: null, attempts };
      };

      // ECDH 会话初始化：断言文案实测 init 是 0 参。
      // 只做一次，失败不影响后续（失败原因记在 attempts 里）。
      let initInfo = globalThis.__openqqEcdhInitInfo || null;
      if (!initInfo && ecdh.length) {
        const holder = ecdh[0];
        const rec = { at: Date.now(), steps: [] };
        const stringify = v => { try { return JSON.parse(JSON.stringify(v)); } catch { return String(v).slice(0, 200); } };
        // guid：优先用调用方给的，其次从 engine.getDeviceInfo 取
        let guid = String(action.guid ?? '');
        if (!guid) {
          try {
            const engineInst = (engines[0] && engines[0].inst) || (wrapper.NodeIQQNTWrapperEngine && wrapper.NodeIQQNTWrapperEngine.get && wrapper.NodeIQQNTWrapperEngine.get());
            const di = engineInst && typeof engineInst.getDeviceInfo === 'function' ? engineInst.getDeviceInfo() : null;
            rec.deviceInfo = di ? stringify(di) : 'no getDeviceInfo';
            if (di) guid = String(di.guid || di.deviceGuid || di.deviceId || di.imei || '');
          } catch (e) { rec.deviceInfoError = String(e && e.message || e).slice(0, 200); }
        }
        rec.guid = guid || '(empty)';
        rec.hasInit = typeof holder.inst.init === 'function';
        rec.hasSetGuid = typeof holder.inst.setGuid === 'function';
        rec.methods = namesOf(holder.inst);
        for (const m of ['init', 'setGuid']) {
          const fn = holder.inst && holder.inst[m];
          if (typeof fn !== 'function') { rec.steps.push({ m, skip: 'not a function' }); continue; }
          try {
            const args = m === 'init' ? [] : [guid];
            rec.steps.push({ m, args: args.length, ok: true, returned: stringify(fn.apply(holder.inst, args)) });
          } catch (error) { rec.steps.push({ m, error: String(error && error.message || error).slice(0, 240) }); }
        }
        initInfo = rec;
        globalThis.__openqqEcdhInitInfo = rec;
      }

      // ---- mode=probe：一次把全部发包形状试完，逐条留痕 ----
      if (action.mode === 'probe' && ecdh.length) {
        const inst = ecdh[0].inst;
        const probe = [];
        const sz = v => { try { return JSON.parse(JSON.stringify(v)); } catch { return String(v).slice(0, 160); } };
        const wireName = action.wireName || ('OidbSvcTrpcTcp.0x' + cmd.toString(16) + '_' + subCmd);
        const call = (label, fn, args) => {
          const t0 = Date.now();
          let sync;
          try { sync = fn.apply(inst, args); } catch (e) { probe.push({ label, error: String(e && e.message || e).slice(0, 200), ms: Date.now() - t0 }); return null; }
          probe.push({ label, returned: sz(sync), ms: Date.now() - t0 });
          return sync;
        };
        // 1) setIsDebug(true) —— 让 ECDH 走测试通道
        if (typeof inst.setIsDebug === 'function') call('setIsDebug(true)', inst.setIsDebug, [true]);
        // 2) 各种发包形状
        const noop = () => {};
        const b = body;
        if (typeof inst.sendOIDBRequest === 'function') {
          call('sendOIDBRequest(cmd,sub,0,body,noop)', inst.sendOIDBRequest, [cmd, subCmd, 0, b, noop]);
        }
        if (typeof inst.sendOIDBRequestV2 === 'function') {
          call('sendOIDBRequestV2(cmd,sub,0,body,noop)', inst.sendOIDBRequestV2, [cmd, subCmd, 0, b, noop]);
        }
        if (typeof inst.sendSSORequest === 'function') {
          // 4 参，三种语义都试
          call('sendSSORequest(wireName,body,0,noop)', inst.sendSSORequest, [wireName, b, 0, noop]);
          call('sendSSORequest(cmd,sub,body,noop)', inst.sendSSORequest, [cmd, subCmd, b, noop]);
          call('sendSSORequest(wireName,0,body,noop)', inst.sendSSORequest, [wireName, 0, b, noop]);
        }
        globalThis.__openqqOidbProbe = probe;
        await new Promise(r => setTimeout(r, 2500));
        return {
          status: 'ok', retcode: 0,
          data: {
            cmd, subCmd, hex: action.hex, wireName, mode: 'probe',
            probe,
            initInfo,
            oidbReplies: (globalThis.__openqqOidbHook || []).slice(-20),
          },
        };
      }

      const sendMethods = ['sendOidbRequest', 'SendOidbRequest', 'sendOIDBRequest', 'SendOIDBRequest', 'sendOIDBRequestV2'];
      const shapes = [
        ['(cmd,sub,0,body,cb)', cb => [cmd, subCmd, 0, body, cb]],
        ['(cmd,sub,body,cb)', cb => [cmd, subCmd, body, cb]],
        ['(cmd,sub,0,body,{},cb)', cb => [cmd, subCmd, 0, body, {}, cb]],
        ['(cmd,sub,0,[...body],cb)', cb => [cmd, subCmd, 0, Array.from(body), cb]],
      ];

      for (const h of engines) {
        const r = await trySend(h, sendMethods, shapes);
        if (r.hit) return { status: 'ok', retcode: 0, data: { cmd, subCmd, hex: action.hex, via: h.label, method: r.hit.method, shape: r.hit.shape, result: r.hit.result, attempts, initInfo, engineMethods: namesOf(h.inst) } };
      }
      for (const h of ecdh) {
        const r = await trySend(h, sendMethods.concat(['sendSSORequest', 'SendSSORequest']), shapes);
        if (r.hit) return { status: 'ok', retcode: 0, data: { cmd, subCmd, hex: action.hex, via: h.label, method: r.hit.method, shape: r.hit.shape, result: r.hit.result, attempts, initInfo, ecdhMethods: namesOf(h.inst) } };
      }

      return {
        status: 'failed', retcode: 1500,
        data: {
          cmd, subCmd, hex: action.hex,
          enginesFound: engines.map(e => ({ label: e.label, methods: namesOf(e.inst) })),
          ecdhFound: ecdh.map(e => ({ label: e.label, methods: namesOf(e.inst) })),
          engineStatic: Engine ? namesOf(Engine) : null,
          attempts: attempts.slice(0, 40),
          oidbReplies: (globalThis.__openqqOidbHook || []).slice(-8),
        },
        message: '没有找到可用的发包方法，看 data.enginesFound / ecdhFound / attempts',
      };
    }
    if (action.kind === 'wrapper_net') {
      // 找真正的发包入口：QQ 内核把底层网络/SSO 能力放在这些导出上。
      // 只探测、不发包——先确认哪个对象存在、有哪些方法，再决定怎么用。
      const wrapper = globalThis.__openqq_wrapper;
      if (!wrapper) return { status: 'failed', retcode: 1400, data: null, message: '没有 wrapper 句柄' };
      const describe = (label, value) => {
        const out = { label, type: typeof value };
        if (value === null || value === undefined) return out;
        if (typeof value !== 'object' && typeof value !== 'function') { out.value = String(value).slice(0, 120); return out; }
        const names = new Set();
        let depth = 0;
        try {
          for (let o = value; o && o !== Object.prototype && depth < 4; o = Object.getPrototypeOf(o), depth++) {
            for (const n of Object.getOwnPropertyNames(o)) if (n !== 'constructor') names.add(n);
          }
        } catch (error) { out.protoError = String(error && error.message || error).slice(0, 120); }
        out.methods = Array.from(names).sort();
        out.count = out.methods.length;
        try { out.isClass = /^class\s/.test(Function.prototype.toString.call(value)); } catch {}
        try { out.length = value.length; } catch {}
        return out;
      };

      const targets = ['NodeIQQNTWrapperNetwork', 'NodeIQQNTWrapperUtil', 'NodeIKernelECDHService', 'NodeIQQNTWrapperEngine', 'NodeIQQNTWrapperSession'];
      const statics = targets.map(name => {
        let v;
        try { v = wrapper[name]; } catch (error) { return { label: name, threw: String(error && error.message || error).slice(0, 120) }; }
        return describe(name, v);
      });

      // 尝试实例化 Network（多种参数形状），成功就列方法
      const instances = [];
      const attempts = [
        ['new()', () => new wrapper.NodeIQQNTWrapperNetwork()],
        ['new(fn)', () => new wrapper.NodeIQQNTWrapperNetwork(() => {})],
        ['new(fn,fn)', () => new wrapper.NodeIQQNTWrapperNetwork(() => {}, () => {})],
        ['new({})', () => new wrapper.NodeIQQNTWrapperNetwork({})],
        ['call()', () => wrapper.NodeIQQNTWrapperNetwork()],
      ];
      for (const [label, fn] of attempts) {
        try {
          const inst = fn();
          const d = describe(label, inst);
          d.constructed = true;
          instances.push(d);
          break;
        } catch (error) {
          instances.push({ label, constructed: false, error: String(error && error.message || error).slice(0, 160) });
        }
      }

      // 当前 session 上有没有网络相关的 getter 之外的口
      const sessionKeys = [];
      try {
        for (const n of Object.getOwnPropertyNames(Object.getPrototypeOf(session))) {
          if (/net|sso|pack|msf|send|conn/i.test(n)) sessionKeys.push(n);
        }
      } catch {}

      // globalThis 上有没有别人留下的发包口
      const globals = Object.getOwnPropertyNames(globalThis).filter(n => /pack|sso|msf|net|send|qq/i.test(n)).sort();

      return { status: 'ok', retcode: 0, data: { statics, instances, sessionNetworkGetters: sessionKeys, globals } };
    }
    if (action.kind === 'wrapper_dump') {
      const wrapper = globalThis.__openqq_wrapper;
      if (!wrapper) return { status: 'failed', retcode: 1400, data: null, message: '没有 wrapper 句柄（热注入路径下可能拿不到）' };
      const own = Object.getOwnPropertyNames(wrapper);
      const rows = own.map(name => {
        let kind = 'other';
        try { const v = wrapper[name]; kind = v === null ? 'null' : typeof v; }
        catch (error) { kind = 'throw:' + String(error && error.message || error).slice(0, 60); }
        return { name, kind };
      });
      const interesting = rows.filter(r => /sso|sso|ecdh|msf|packet|send/i.test(r.name));
      return { status: 'ok', retcode: 0, data: { total: rows.length, interesting, all: rows.map(r => r.name) } };
    }
    if (action.kind === 'msf_probe') {
      const msf = session.getMSFService();
      if (!msf || typeof msf.sendMsfRequest !== 'function') return { status: 'failed', retcode: 1400, data: null, message: '没有 MSFService.sendMsfRequest' };
      const cmd = 'OidbSvcTrpcTcp.0xed3_1';
      const payload = Buffer.from('08011001', 'hex');
      const seen = new Set();
      const cases = [
        ['4 个数字 0', () => msf.sendMsfRequest(0, 0, 0, 0)],
        ['4 个字符串', () => msf.sendMsfRequest('a', 'b', 'c', 'd')],
        ['4 个空对象', () => msf.sendMsfRequest({}, {}, {}, {})],
        ['4 个 null', () => msf.sendMsfRequest(null, null, null, null)],
        ['cmd,0,0,0', () => msf.sendMsfRequest(cmd, 0, 0, 0)],
        ['cmd,Buffer,0,0', () => msf.sendMsfRequest(cmd, payload, 0, 0)],
        ['cmd,Buffer,0,{}', () => msf.sendMsfRequest(cmd, payload, 0, {})],
        ['cmd,Buffer,fn,0', () => msf.sendMsfRequest(cmd, payload, () => {}, 0)],
        ['cmd,Buffer,fn,{}', () => msf.sendMsfRequest(cmd, payload, () => {}, {})],
        ['cmd,Buffer,{},fn', () => msf.sendMsfRequest(cmd, payload, {}, () => {})],
        ['cmd,Uint8,1000,fn', () => msf.sendMsfRequest(cmd, new Uint8Array(payload), 1000, () => {})],
        ['cmd,Array,1000,fn', () => msf.sendMsfRequest(cmd, Array.from(payload), 1000, () => {})],
        ['cmd,hexString,1000,fn', () => msf.sendMsfRequest(cmd, payload.toString('hex'), 1000, () => {})],
        ['cmd,Buffer,1000,fn', () => msf.sendMsfRequest(cmd, payload, 1000, () => {})],
      ];
      const results = [];
      for (const [label, fn] of cases) {
        let entry;
        try {
          const returned = fn();
          entry = { label, threw: false, returned: returned === undefined ? 'undefined' : Object.prototype.toString.call(returned) };
        } catch (error) {
          entry = { label, threw: true, error: String(error && error.message ? error.message : error).slice(0, 220) };
        }
        const key = (entry.error ?? entry.returned) + '|' + entry.label.split(',')[0];
        if (!seen.has(entry.error ?? entry.returned)) seen.add(entry.error ?? entry.returned);
        results.push(entry);
      }
      const distinct = Array.from(seen);
      return { status: 'ok', retcode: 0, data: { distinctErrors: distinct, results, note: '看 distinctErrors：哪些组合的报错变了，说明那几个位置被内核真正读取' } };
    }
    if (action.kind === 'sso') {
      const attempts = await ssoSend(action.cmd, action.hex, action.timeout);
      const hit = attempts.find(a => a.ok);
      if (hit) return { status: 'ok', retcode: 0, data: { cmd: action.cmd, hex: action.hex, via: hit.label, cbArgs: hit.cbArgs, attempts } };
      return { status: 'failed', retcode: 1500, data: { cmd: action.cmd, hex: action.hex, attempts, contendProbe: globalThis.__openqqContendProbe2 || null }, message: '所有调用形状都没拿到回调（见 data.attempts / data.contendProbe）' };
    }
    if (action.kind === 'services') {
      if (process.env.OPENQQ_SERVICES !== '1') return { status: 'failed', retcode: 1404, data: null, message: 'openqq_services 会把原生方法列表暴露给任意客户端，默认关闭；本地调试设 OPENQQ_SERVICES=1' };
      const dump = {};
      const names = value => {
        if (!value || (typeof value !== 'object' && typeof value !== 'function')) return [];
        const set = new Set();
        for (let o = value; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
          for (const n of Object.getOwnPropertyNames(o)) if (n !== 'constructor') set.add(n);
        }
        return Array.from(set).sort();
      };
      for (const [key, getter] of [['msg', 'getMsgService'], ['buddy', 'getBuddyService'], ['group', 'getGroupService'], ['profile', 'getProfileService'], ['uix', 'getUixConvertService'], ['msf', 'getMSFService']]) {
        try {
          dump[key] = typeof session[getter] === 'function' ? names(session[getter]()) : 'missing getter';
        } catch (error) {
          dump[key] = 'throw: ' + (error && error.message ? error.message : String(error));
        }
      }
      return { status: 'ok', retcode: 0, data: dump };
    }
    if (action.kind === 'honor' || action.kind === 'essence') {
      const g = action.group;
      const groupSvc = session.getGroupService();
      const attempts = [];
      const cands = action.kind === 'honor'
        ? [['getGroupHonorList', [{ group_id: g }]], ['getGroupHonorList', [{ group_id: String(g) }]], ['getGroupHonorList', [{ groupUin: g }]], ['getGroupHonorList', [{ groupCode: g }]], ['getGroupHonorList', [g]]]
        : [['fetchGroupEssenceList', [{ groupCode: g, pageIndex: 0, pageSize: 20 }]], ['fetchGroupEssenceListV2', [{ groupCode: g, pageIndex: 0, pageSize: 20 }]], ['getGroupLatestEssenceList', [g]]];
      for (const [name, args] of cands) {
        if (typeof groupSvc[name] !== 'function') { attempts.push({ name, error: 'method missing' }); continue; }
        try {
          const value = await groupSvc[name](...args);
          const v = value === undefined ? null : value;
          // 这些方法不抛错，业务失败写在 errCode/errMsg 里（319「登录态白名单校验失败」就是这么藏住的）。
          const ref = nativeRefusal(v);
          if (ref) return { status: 'failed', retcode: 1500, data: { action: action.action, via: name, value: v }, message: 'QQ 拒绝' + (action.action || action.kind) + '：' + ref };
          return { status: 'ok', retcode: 0, data: { action: action.action, via: name, value: v } };
        } catch (error) {
          attempts.push({ name, error: String(error && error.message ? error.message : error).slice(0, 120) });
        }
      }
      return { status: 'failed', retcode: 1500, data: { action: action.action, attempts }, message: '群荣誉/精华没有可用原生方法（见 data.attempts）' };
    }
    if (action.kind === 'debug_methods') {
      const svcMap = { msg: () => session.getMsgService(), buddy: () => session.getBuddyService(), group: () => session.getGroupService(), profile: () => session.getProfileService() };
      const svc = (svcMap[action.service] ?? (() => serviceOf(action.service)))();
      if (!svc) return { status: 'failed', retcode: 1400, data: { services: Object.keys(svcMap) }, message: '找不到 service ' + action.service + '（可用 debug_services 看会话上有哪些）' };
      const names = namesOf(svc).filter(n => typeof n === 'string' && n.includes(action.keyword));
      return { status: 'ok', retcode: 0, data: { service: action.service, keyword: action.keyword, total: names.length, names: names.slice(0, action.limit) } };
    }
    if (action.kind === 'debug_services') {
      // ① 不给 service：只列会话上的 get* 名字（**绝不调用**，某些 getter 会同步阻塞把 QQ 卡住）；
      // ② 给了 service：才真正取一次并列出它的全部成员。
      if (!action.service) {
        const getters = namesOf(session).filter(n => /^get[A-Za-z0-9]+$/.test(n));
        return { status: 'ok', retcode: 0, data: { total: getters.length, getters } };
      }
      const svc = serviceOf(action.service);
      if (!svc) return { status: 'failed', retcode: 1404, data: null, message: '找不到 service ' + action.service };
      const names = namesOf(svc);
      return { status: 'ok', retcode: 0, data: { service: action.service, total: names.length, names } };
    }
    if (action.kind === 'debug_call') {
      const svcMap = {
        msg: () => session.getMsgService(),
        buddy: () => session.getBuddyService(),
        group: () => session.getGroupService(),
        profile: () => session.getProfileService(),
        uix: () => session.getUixConvertService()
      };
      const svc = (svcMap[action.service] ?? (() => serviceOf(action.service)))();
      if (!svc) return { status: 'failed', retcode: 1400, data: { services: Object.keys(svcMap) }, message: '找不到 service ' + action.service };
      const fn = svc[action.method];
      if (typeof fn !== 'function') return { status: 'failed', retcode: 1404, data: { service: action.service, method: action.method }, message: 'service 上没有这个方法', near: namesOf(svc).filter(n => n.toLowerCase().includes(String(action.method).toLowerCase().slice(0, 4))).slice(0, 20) };
      try {
        const value = await fn.apply(svc, action.args);
        let out = value;
        try { out = JSON.parse(JSON.stringify(value === undefined ? null : value)); } catch { out = String(value); }
        return { status: 'ok', retcode: 0, data: { service: action.service, method: action.method, argc: action.args.length, value: out } };
      } catch (error) {
        return { status: 'failed', retcode: 1500, data: { service: action.service, method: action.method, argc: action.args.length }, message: String(error && error.message ? error.message : error).slice(0, 300) };
      }
    }
    if (action.kind === 'debug_recent') {
      const msgSvc = session.getMsgService();
      const attempts = [];
      const tryCall = async (label, fn) => {
        try { const value = await fn(); attempts.push({ label, ok: true }); return { value }; }
        catch (error) { attempts.push({ label, ok: false, error: String(error && error.message ? error.message : error).slice(0, 140) }); return null; }
      };
      const chatType = action.group === null ? 1 : 2;
      const uidOf = async (uin, order) => {
        for (const name of order) {
          try {
            let uid;
            if (name === 'convert') uid = (await session.getUixConvertService().getUid([uin]))?.uidInfo?.get(uin);
            else if (name === 'profile') uid = (await session.getProfileService().getUidByUin('FriendsServiceImpl', [uin]))?.get(uin);
            else uid = (await session.getGroupService().getUidByUins([uin]))?.uids?.get(uin);
            if (/^u_[\w-]+$/.test(uid ?? '')) return uid;
          } catch { /* 下一个来源 */ }
        }
        return undefined;
      };
      const peerUin = action.group === null ? action.user : action.group;
      const peerUid = action.group === null ? await uidOf(action.user, ['convert', 'profile']) : action.group;
      if (!peerUid) return { status: 'failed', retcode: 1500, data: { attempts }, message: '无法把 QQ 号转换为 UID' };
      const peerKey = { chatType, peerUid, guildId: '' };
      const got = await tryCall('getLastMessageList(peerKey)', () => msgSvc.getLastMessageList(peerKey))
        || await tryCall('getLastMessageList(peerUid)', () => msgSvc.getLastMessageList(peerUid))
        || await tryCall('getAioLatestMessages(peerKey)', () => msgSvc.getAioLatestMessages(peerKey))
        || await tryCall('getAioLatestMessages(peerUid)', () => msgSvc.getAioLatestMessages(peerUid));
      if (!got) return { status: 'failed', retcode: 1500, data: { attempts }, message: '读最近消息全部失败（见 data.attempts）' };
      const raw = got.value;
      let list = Array.isArray(raw) ? raw : (raw && (raw.messages ?? raw.msgList ?? raw.list)) || [];
      const listType = list && typeof list === 'object' ? (list.constructor ? list.constructor.name : typeof list) : typeof list;
      if (list && typeof list.values === 'function' && !Array.isArray(list)) list = Array.from(list.values());
      const grays = [];
      for (const m of (Array.isArray(list) ? list : [])) {
        const els = m && m.elements;
        if (!Array.isArray(els)) continue;
        for (const el of els) {
          if (el && el.elementType === 8 && el.grayTipElement) {
            grays.push({ msgId: m.msgId, msgTime: m.msgTime, grayTipElement: el.grayTipElement });
          }
        }
      }
      return { status: 'ok', retcode: 0, data: { attempts, chatType, peerUid, count: Array.isArray(list) ? list.length : null,
        rawKeys: raw && typeof raw === 'object' ? Object.keys(raw) : null, listType, sampleKeys: Array.isArray(list) && list[0] ? Object.keys(list[0]) : null,
        grayCount: grays.length, grays: grays.slice(0, 5) } };
    }
    if (action.kind === 'native_events') {
      // events.cjs 的 receive 会记录每一个原始原生回调名（700 多个里只有一部分有名字）。
      // 那些 argc==1 且"唯一参数就是回调"的方法，结果常常是走 listener 回来的 —— 靠这张表来定位。
      const ring = globalThis.__openqqNativeEvents || [];
      const pattern = action.pattern ? new RegExp(String(action.pattern), 'i') : null;
      const rows = ring.filter(e => !pattern || pattern.test(String(e.name)));
      const byName = {};
      for (const e of rows) byName[e.name] = (byName[e.name] || 0) + 1;
      return { status: 'ok', retcode: 0, data: {
        total: ring.length, matched: rows.length,
        names: Object.entries(byName).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count).slice(0, 80),
        recent: rows.slice(-action.count),
      } };
    }
    if (action.kind === 'poke') {
      // 拍一拍不是消息内容，是 QQ 私有灰条：入站解析（native/events.cjs）认 busiId '1061' + jsonStr.items[].uid。
      // 出站没有权威 proto，所以按形状逐个试，把每种的 retcode 记下来，一次重启全试完。
      const attempts = [];
      const tryCall = async (label, fn) => {
        try { const value = await fn(); attempts.push({ label, ok: true, value: value === undefined ? null : value }); return { value }; }
        catch (error) { attempts.push({ label, ok: false, error: String(error && error.message ? error.message : error).slice(0, 160) }); return null; }
      };
      const msgSvc = session.getMsgService();
      const selfUid = self && self.uid ? self.uid : undefined;
      const selfUin = self && self.uin ? String(self.uin) : undefined;
      const chatType = action.group === null ? 1 : 2;
      const uidOf = async (uin, order) => {
        for (const name of order) {
          try {
            let uid;
            if (name === 'convert') uid = (await session.getUixConvertService().getUid([uin]))?.uidInfo?.get(uin);
            else if (name === 'profile') uid = (await session.getProfileService().getUidByUin('FriendsServiceImpl', [uin]))?.get(uin);
            else uid = (await session.getGroupService().getUidByUins([uin]))?.uids?.get(uin);
            if (/^u_[\w-]+$/.test(uid ?? '')) return uid;
          } catch { /* 下一个来源 */ }
        }
        return undefined;
      };
      // 群聊的 peerUid 必须是**字符串**群号：直接传 identifier 出来的 number，
      // 原生会回 result -2（参数类型不对），这和「第三参数类型错」是同一个 -2 但成因不同。
      const peerUid = action.group === null ? await uidOf(action.user, ['convert', 'profile']) : String(action.group);
      const targetUid = action.group === null
        ? peerUid
        : (action.user === null ? undefined : await uidOf(action.user, ['group', 'convert', 'profile']));
      if (!peerUid) return { status: 'failed', retcode: 1404, data: { attempts }, message: '无法把 QQ 号转换为 UID；未调用拍一拍' };
      if (!selfUid) return { status: 'failed', retcode: 1404, data: { attempts }, message: '拍一拍需要自身 UID，当前会话拿不到' };
      const itemsUid = [{ uid: selfUid }, ...(targetUid ? [{ uid: targetUid }] : [])];
      const itemsRich = itemsUid.map(x => ({ ...x, ...(selfUin ? { uin: selfUin } : {}) }));
      const peer = { chatType, peerUid, guildId: '' };
      const grayOf = jsonStr => [{ elementType: 8, elementId: '', grayTipElement: { jsonGrayTipElement: { busiId: '1061', jsonStr } } }];
      // 实测定论（四条都验过）：
      // ① addLocalJsonGrayTipMsg* 只是本地渲染，QQ 不转发，对方永远看不到；
      // ② 真身是 msg.sendNudge —— 全服务只有它带 Nudge 语义（send_poke 的另一半 recallNudge 是撤回）；
      // ③ 原生断言 argc==3，第三参数必须是 number：传 1 通过类型校验，传 0/2/true/false/uid/uin/'' 全部回 result -2；
      // ④ 即便语法正确，QQ 服务端仍回 result -100（业务侧拒绝，需 aio 上下文或账号权限）。
      // 追加：既然 nudge 接口这条路被服务端拦住，就绕开它 —— 拍一拍在协议上就是一条「只有灰条元素」的消息，
      // 用 sendMsg 把 busiId=1061 的灰条当消息体发出去（拿带 tag 的 peer 换回执），早期 NapCat 也是这么发的。
      async function sendGray(jsonStr) {
        const time = session.getMSFService().getServerTime();
        if (typeof time !== 'string' || !/^[1-9]\d{0,19}$/.test(time)) throw new Error('getServerTime 返回无效值');
        const tag = msgSvc.generateMsgUniqueId(chatType, time);
        if (typeof tag !== 'string' || !/^[1-9]\d*$/.test(tag) || waiting.has(tag)) throw new Error('generateMsgUniqueId 返回无效值');
        const tagged = { chatType, peerUid, guildId: tag };
        const ack = new Promise(resolve => waiting.set(tag, { peer: tagged, resolve }));
        try {
          const result = await msgSvc.sendMsg('0', tagged, grayOf(jsonStr), new Map());
          if (Number(result?.result) !== 0) throw new Error('sendMsg result ' + String(result?.result) + ' ' + String(result?.errMsg ?? ''));
          const record = await Promise.race([ack, new Promise((_, reject) => setTimeout(() => reject(new Error('等发送回执超时')), 15000))]);
          return { result, msgId: record?.msgId ?? null, sendStatus: record?.sendStatus ?? null };
        } finally { waiting.delete(tag); }
      }
      // 拍一拍在协议上是 OIDB 0xed3_1（to_uin=被拍的人、aio_uin=会话），走通用 SSO 口发出去；
      // 内核 sendNudge 被服务端拒、灰条当消息发又回 result 5，所以协议包才是正路。
      const vintBytes = n => {
        const out = [];
        let v = Number(n) >>> 0;
        while (v > 0x7f) { out.push((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
        out.push(v & 0x7f);
        return out;
      };
      const vint = n => Buffer.from(vintBytes(n)).toString('hex');
      // 还没试过的分支：sendNudge 回 -100 有可能是「这个会话不在内核的 AIO 列表里」。
      // 先用 setMsgRead 把会话在内核里激活一次（这个方法本身已在 mark_msg_as_read 上实测可用），
      // 再往下试形状。预热失败不影响后面的判断，只是少一条线索。
      let preheat = null;
      try { preheat = await msgSvc.setMsgRead({ chatType, peerUid, guildId: '' }); }
      catch (error) { preheat = { error: String(error && error.message ? error.message : error).slice(0, 120) }; }
      const shapes = [
        ['msg.sendNudge(peerUid, chatType, 1)', () => msgSvc.sendNudge(peerUid, chatType, 1)],
        ['sendMsg(灰条 1061, items[uid])', () => sendGray(JSON.stringify({ items: itemsUid }))],
        ['sendMsg(灰条 1061, items[uid+uin])', () => sendGray(JSON.stringify({ items: itemsRich }))],
        ['SSO OidbSvcTrpcTcp.0xed3_1', async () => {
          const toUin = Number(action.user);
          const aioUin = Number(action.group === null ? action.user : action.group);
          if (!Number.isSafeInteger(toUin) || !Number.isSafeInteger(aioUin)) throw new Error('拍一拍需要 to_uin/aio_uin 两个数字');
          const hex = '08' + vint(toUin) + '10' + vint(aioUin);
          const ssoAttempts = await ssoSend('OidbSvcTrpcTcp.0xed3_1', hex, 12000);
          const hit = ssoAttempts.find(a => a.ok);
          if (!hit) throw new Error('SSO 无回调: ' + ssoAttempts.map(a => a.label + '=' + (a.error || 'no-cb')).join(' | '));
          return { cmd: 'OidbSvcTrpcTcp.0xed3_1', hex, via: hit.label, cbArgs: hit.cbArgs };
        }],
        // 第五条（新发现）：MsgService 有一个**同步返回**的 SSO 通道 sendSsoCmdReqByContend(argc==2)。
        // 它不挂 IPC（8~80ms 返回），body 的编码方式已实测出来：**原始二进制字符串**
        // （String.fromCharCode(...bytes)；hex/base64/JSON 全部回 result 145「请求包解析失败」）。
        // OidbPoke 结构从 SnowLuma 打包产物里抄到：{uin=1, groupUin=2, friendUin=3, ext=4}。
        // 结果是 result 236「访问接口未配置路由」—— 这条通道是白名单式 SSO，不接 0xed3_1。
        ['msg.sendSsoCmdReqByContend(0xed3_1, OidbPoke bin)', async () => {
          if (typeof msgSvc.sendSsoCmdReqByContend !== 'function') throw new Error('内核没有 sendSsoCmdReqByContend');
          const toUin = Number(action.user);
          const aioUin = Number(action.group === null ? action.user : action.group);
          if (!Number.isSafeInteger(toUin) || !Number.isSafeInteger(aioUin)) throw new Error('拍一拍需要 to_uin/aio_uin 两个数字');
          const bytes = action.group === null
            ? [0x08, ...vintBytes(toUin), 0x18, ...vintBytes(aioUin)]
            : [0x08, ...vintBytes(toUin), 0x10, ...vintBytes(aioUin)];
          const r = await msgSvc.sendSsoCmdReqByContend('OidbSvcTrpcTcp.0xed3_1', String.fromCharCode(...bytes));
          const res = Number(r && r.result);
          if (res !== 0) throw new Error('sendSsoCmdReqByContend result ' + String(res) + ' ' + String((r && r.errMsg) || ''));
          return r;
        }],
      ];
      for (const [label, fn] of shapes) {
        const got = await tryCall(label, fn);
        const value = got ? got.value : null;
        const passed = value && typeof value === 'object'
          && (Number(value.result) === 0 || Number(value.sendStatus) === 2 || value.cmd === 'OidbSvcTrpcTcp.0xed3_1');
        if (passed) return { status: 'ok', retcode: 0, data: { via: label, value, preheat, attempts, note: '拿到底层回执；对方端有没有拍一拍动画要人眼看一次' } };
      }
      const codes = attempts.map(a => a.label + ' => ' + (a.ok ? JSON.stringify(a.value) : '!! ' + a.error));
      const nudge = attempts.find(a => a.label.startsWith('msg.sendNudge('));
      const nativeResult = nudge && nudge.value && typeof nudge.value === 'object' ? Number(nudge.value.result) : null;
      return { status: 'failed', retcode: 1404, data: { preheat, attempts, codes, nativeResult },
        message: '拍一拍五条路都被 QQ 拒绝（逐条见 data.codes）：'
          + '① msg.sendNudge(peerUid, chatType, 1) —— argc 正确、类型正确，服务端回 -2/-100；'
          + '② sendMsg 塞 busiId=1061 灰条 —— result 5；'
          + '③ MSFService.sendMsfRequest —— 包装层坏，14 种形状全报 "Cannot convert undefined or null to object"；'
          + '④ addLocalJsonGrayTipMsg / addLocalGrayTipMsg —— 只本地渲染，QQ 不转发；'
          + '⑤ msg.sendSsoCmdReqByContend（同步 SSO 通道，body 必须是原始二进制字符串）—— 回 236「访问接口未配置路由」，'
          + '说明它是白名单式 SSO 网关，不接 OIDB 0xed3_1。' };
    }
    if (action.kind === 'qzone') {
      // 空间走 Web API（要 p_skey + g_tk），原生这一层只负责把凭据取出来。
      // 定位：拿 p_skey 的正口是 TipOff.getPskey(domains[], cb) ——
      // 第 1 参**必须是 domain 数组**（传字符串一律回 1003 domain no permission），
      // 结果从第 2 参回调下发（同步返回值里的 domainPskeyMap 是空的）。
      const attempts = [];
      const sleep = ms => new Promise(resolve => { const t = setTimeout(resolve, ms); if (t.unref) t.unref(); });
      const QZONE_DOMAINS = ['qzone.qq.com', 'user.qzone.qq.com', 'h5.qzone.qq.com', 'mobile.qzone.qq.com', 'taotao.qq.com'];
      const uin = String(self.uin);
      const p = action.params || {};
      const withCb = async (label, fn, waitMs = 6000) => {
        let got;
        let cbErr = null;
        try { fn((...a) => { got = a.length <= 1 ? a[0] : a; }); }
        catch (error) { cbErr = String(error && error.message ? error.message : error).slice(0, 160); }
        const deadline = Date.now() + waitMs;
        while (got === undefined && Date.now() < deadline) await sleep(100);
        attempts.push({ label, cbCalled: got !== undefined, ...(cbErr ? { error: cbErr } : {}) });
        return got;
      };

      // ── 凭据来源：Ticket.forceFetchClientKey 同步给，TipOff.getPskey 实测恒空 ──
      // 实测：
      //  · forceFetchClientKey(1) **同步返回** 96 字节 clientKey，0 秒；但它每次都不一样，不是登录态，
      //    拿去当 skey 发 QZone 请求会让服务端直接不响应（20 秒卡死）。
      //  · TipOff.getPskey(domains[], cb) 回 result:0 success，可 domainPskeyMap 永远是 {}。
      // 所以只把 clientKey 当"诊断信息"，**不发 QZone 请求**，避免每次动作都卡 20 秒。
      const now = Date.now();
      let cred = globalThis.__openqqQzoneCred;
      // 有真 pskey 才缓存 10 分钟；只拿到 clientKey（等于没拿到）只缓存 15 秒 ——
      // 否则重启后第一次取失败会把空结果锁 10 分钟，后面全是假阴性。
      const ttl = cred && cred.pskey ? 600000 : 15000;
      if (!cred || now - cred.at > ttl) {
        let pskeyMap = {};
        // ：**OIDB 0x102a_0 是唯一能真拿到 p_skey 的路**（TipOff.getPskey 恒空）。
        // 走 SSO over pipe 发 OidbGetPskeyReq{domainList:["qzone.qq.com"]}，回包里 pskey 紧跟在域名后面：
        //   ... 0a 0c "qzone.qq.com" 12 <len> <pskey> ...
        try {
          const r = await selfSsoSend('OidbSvcTrpcTcp.0x102a_0',
            Buffer.from('08aa2010001800220e0a0c717a6f6e652e71712e636f6d', 'hex'));
          if (r && r.status === 0 && r.body && r.body.length) {
            const t = r.body.toString('latin1');
            const di = t.indexOf('qzone.qq.com');
            if (di >= 0) {
              const after = t.slice(di + 'qzone.qq.com'.length);
              const len = after.charCodeAt(1);
              const key = after.slice(2, 2 + len);
              if (key && key.length > 10) pskeyMap = { 'qzone.qq.com': key };
              attempts.push({ label: 'OIDB 0x102a_0 GetPskey', ok: Boolean(key && key.length > 10), len: key.length, responseLen: r.body.length });
            } else attempts.push({ label: 'OIDB 0x102a_0 GetPskey', ok: false, note: 'domain not in response' });
          } else attempts.push({ label: 'OIDB 0x102a_0 GetPskey', ok: false, status: r && r.status });
        } catch (error) {
          attempts.push({ label: 'OIDB 0x102a_0 GetPskey', error: String(error && error.message ? error.message : error).slice(0, 120) });
        }
        // 兜底：TipOff.getPskey（实测恒空，但留着以防某天 QQ 版本变了）
        const tipOff = serviceOf('TipOff');
        if (!Object.keys(pskeyMap).length && tipOff && typeof tipOff.getPskey === 'function') {
          const got = await withCb('TipOff.getPskey(5 domains)', cb => tipOff.getPskey(QZONE_DOMAINS, cb), 2500);
          const map = (got && (got.domainPskeyMap || got.map)) || {};
          const keys = Object.keys(map).filter(k => map[k]);
          if (!attempts.length) attempts.push({ label: 'TipOff.getPskey' });
          attempts[attempts.length - 1].result = got && got.result;
          attempts[attempts.length - 1].errMsg = got && got.errMsg;
          attempts[attempts.length - 1].mapKeys = keys;
          if (keys.length) pskeyMap = map;
        } else attempts.push({ label: 'TipOff.getPskey', error: 'service 上取不到 getPskey' });
        let clientKey = '';
        const ticket = serviceOf('Ticket');
        if (ticket && typeof ticket.forceFetchClientKey === 'function') {
          try {
            // 实测：它**返回对象** {result, errMsg, url, keyIndex, clientKey}，
            // 不是字符串。之前写成 `typeof direct === 'string'` 判断，把 96 字节的 clientKey 直接丢掉，
            // 表现为 hasClientKey:false —— 而且因为不抛错，attempts 里连一条记录都没有，极难归因。
            const direct = await ticket.forceFetchClientKey(1);
            const key = typeof direct === 'string' ? direct : String((direct && (direct.clientKey ?? direct.key)) || '');
            attempts.push({ label: 'forceFetchClientKey', ok: Boolean(key.length > 8), len: key.length,
              result: direct && direct.result, keyIndex: direct && direct.keyIndex });
            if (key.length > 8) clientKey = key;
          } catch (error) { attempts.push({ label: 'forceFetchClientKey', error: String(error && error.message ? error.message : error).slice(0, 120) }); }
        } else attempts.push({ label: 'forceFetchClientKey', error: 'serviceOf("Ticket") 取不到或没有该方法' });
        const real = Object.values(pskeyMap).find(v => typeof v === 'string' && v) || '';
        cred = { at: now, pskey: real, pskeyDomains: Object.keys(pskeyMap), clientKey };
        globalThis.__openqqQzoneCred = cred;
      }
      const pskeyMap = cred.pskey ? { [cred.pskeyDomains[0] || 'qzone.qq.com']: cred.pskey } : {};
      const clientKey = cred.clientKey || '';
      const skey = cred.pskey || clientKey;
      const gtk = (() => { let h = 5381; for (let i = 0; i < skey.length; i++) h += (h << 5) + skey.charCodeAt(i); return h & 0x7fffffff; })();
      const credential = {
        pskeyDomains: cred.pskeyDomains, hasPskey: Boolean(cred.pskey), hasClientKey: Boolean(clientKey),
        clientKeyLen: clientKey.length, g_tk: skey ? gtk : null,
      };

      // QQ 的 uin cookie 是 `o0` + 10 位 uin，只写 `o` + uin 会让服务端返回
      // code:0 但 msglist 为空数组 —— 实测踩到，表现为 total 有值、count 恒 0。
      const cookieText = 'uin=o0' + uin + '; p_skey=' + encodeURIComponent(skey) + '; skey=' + encodeURIComponent(skey) + '; p_uin=o0' + uin;

      if (action.action === 'debug_qzone_credential' || action.action === 'get_cookies' || action.action === 'get_csrf_token') {
        return { status: cred.pskey ? 'ok' : 'failed', retcode: cred.pskey ? 0 : 1404,
          data: { credentials: credential, g_tk: skey ? gtk : null, skeyFound: Boolean(cred.pskey),
            skeyPrefix: skey ? skey.slice(0, 6) + '…' : '', cachedAt: new Date(cred.at).toISOString(), attempts },
          ...(cred.pskey ? {} : { message: '没有真正的 p_skey：TipOff.getPskey 的 domainPskeyMap 恒空，forceFetchClientKey 给的只是 clientKey（每取一次都不同，不是登录态）。空间读写因此不可用。' }) };
      }
      // 只有 clientKey 时**不发请求**：服务端不认这个 cookie，会让调用卡满 20 秒再被上层判超时，
      // 报错反而更含糊。这里直接给出确定结论。
      if (!cred.pskey) {
        return { status: 'failed', retcode: 1404, data: { credentials: credential, attempts },
          message: '空间操作需要 p_skey：内核只给出 clientKey（不是登录态），QZone 会回「请先登录空间」。' +
            '已确认网络通畅（无 cookie 时 28ms 返回 code -3000），所以缺的是凭据不是网络。' };
      }

      // GET 请求不要带 Origin：实测带 `Origin: https://user.qzone.qq.com` 时
      // 服务端回 code:0 + total 有值、但 msglist 恒为空数组；去掉 Origin 立刻拿到 5 条。
      // POST 写入类才需要 Origin，由调用方在 init.headers 里单独给。
      const headers = {
        Cookie: cookieText, Referer: 'https://user.qzone.qq.com/' + uin,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
      };
      const qz = async (url, init) => {
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), 8000);
        if (timer.unref) timer.unref();
        try {
          const res = await fetch(url, { ...(init || {}), headers: { ...headers, ...((init && init.headers) || {}) }, signal: ac.signal });
          const text = await res.text();
          // QZone 的 CGI 不管 format=json 还是 jsonp，都可能回 `_preloadCallback({...});` 这种包装，
          // 直接 JSON.parse 会失败、body 变成 {raw}，表现为 count:0（实测踩到）。
          let body;
          try { body = JSON.parse(text); }
          catch {
            const m = text.match(/^[^(]*\(\s*([\s\S]*?)\s*\)\s*;?\s*$/);
            if (m) { try { body = JSON.parse(m[1]); } catch { body = { raw: text.slice(0, 400) }; } }
            else body = { raw: text.slice(0, 400) };
          }
          return { http: res.status, body };
        } finally { clearTimeout(timer); }
      };
      // num 必须 >= 10：实测num=5/3 时服务端回 code:0 + total 有值、msglist 空数组；
      // num>=10 立刻返回真实数据。所以下限拉到 10，调用方传更小也按 10 发。
      const num = Math.min(50, Math.max(10, Number(p.count ?? 20)));
      const pos = Math.max(0, Number(p.pos ?? 0));
      const need = (name, value) => { if (!value) throw fail(action.action + ' 需要 ' + name); return value; };
      // ── 读取类 ─────────────────────────────────────────────────────────
      if (['get_qzone_feeds', 'get_qzone_msg_list', 'get_qzone_home_feeds', 'get_qzone_profile'].includes(action.action)) {
        const target = String(p.target_uin ?? p.user_id ?? uin);
        const url = 'https://user.qzone.qq.com/proxy/domain/taotao.qq.com/cgi-bin/emotion_cgi_msglist_v6?uin=' + target +
          '&ftype=0&sort=0&pos=' + pos + '&num=' + num + '&replynum=0&g_tk=' + gtk + '&code=1&format=json&need_private_comment=1';
        const got = await qz(url);
        const body = got.body || {};
        const list = Array.isArray(body.msglist) ? body.msglist : (Array.isArray(body.data) ? body.data : []);
        const ok = got.http === 200 && Number(body.code ?? 0) === 0 && !body.message;
        // ：原来只返回 total/count，调用方看不到任何一条内容，等于"读了个寂寞"。
        // 现在把列表也返回（精简字段，避免整个 body 太大）。
        const feeds = list.map((m) => ({
          tid: m.tid != null ? String(m.tid) : null,
          content: String(m.content ?? ''),
          created_time: m.created_time ?? null,
          createTime: m.createTime ?? null,
          cmtnum: m.cmtnum ?? 0,
          likeuniqcount: m.likeuniqcount ?? m.likenum ?? 0,
          ugc_right: m.ugc_right ?? null,
          uin: m.uin ?? null,
          name: m.name ?? null,
        }));
        return { status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500,
          data: { http: got.http, url, total: body.total ?? null, count: feeds.length, msglist: feeds,
            credentials: credential, ...(ok ? {} : { body }) } };
      }
      if (action.action === 'get_qzone_feed_detail' || action.action === 'get_qzone_msg_detail') {
        const tid = need('tid', String(p.tid ?? p.feed_id ?? ''));
        const target = String(p.target_uin ?? p.user_id ?? uin);
        const url = 'https://user.qzone.qq.com/proxy/domain/taotao.qq.com/cgi-bin/emotion_cgi_msgdetail_v6?uin=' + target +
          '&tid=' + encodeURIComponent(tid) + '&t1_source=1&g_tk=' + gtk + '&code=1&format=json';
        const got = await qz(url);
        const ok = got.http === 200 && !got.body?.message;
        return { status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500, data: { http: got.http, url, body: got.body } };
      }

      // ── 写入类（按 SnowLuma 的 qzone.ts 逐参数重写）──────────────
      // SL 的三个 CGI 都用 `h5.qzone.qq.com/proxy/domain/...`，参数一个不能少：
      // 发说说少 `hostuin` 服务端就当没这个空间；删说说 format 必须是 `fs` 不是 `json`。
      // 我们这边 GET 已实测 `user.qzone.qq.com` 不被限流，所以写操作也用 user 前缀，
      // 失败时再回落 h5（SL 的原始前缀）。
      const qzWrite = async (path, params) => {
        const body = new URLSearchParams(params).toString();
        const hosts = ['https://user.qzone.qq.com/proxy/domain/', 'https://h5.qzone.qq.com/proxy/domain/'];
        let last;
        for (const prefix of hosts) {
          last = await qz(prefix + path + '?g_tk=' + gtk, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://user.qzone.qq.com' },
            body,
          });
          const c = Number(last.body?.code ?? 0);
          if (last.http === 200 && c === 0 && !last.body?.message) break; // 成功就不再换 host
        }
        return last;
      };
      if (action.action === 'send_qzone_msg') {
        const content = need('message', String(p.message ?? p.content ?? '').trim());
        const right = Number(p.ugc_right ?? 1);
        if (![1, 4, 16, 64, 128].includes(right)) return { status: 'failed', retcode: 1400, data: { ugc_right: right }, message: 'ugc_right 只能是 1/4/16/64/128' };
        const params = {
          syn_tweet_verson: '1', paramstr: '1', pic_template: '',
          richtype: p.richtype !== undefined ? String(p.richtype) : '',
          richval: String(p.richval ?? ''), special_url: '', subrichtype: '',
          con: content, feedversion: '1', ver: '1', ugc_right: String(right),
          to_sign: '0', who: '1', hostuin: uin, code_version: '1', format: 'json',
          qzreferrer: 'https://user.qzone.qq.com/' + uin,
        };
        const targetUins = Array.isArray(p.target_uins) ? p.target_uins.join('|') : String(p.target_uins ?? '');
        if ((right === 16 || right === 128) && targetUins) params.allow_uins = targetUins;
        const got = await qzWrite('taotao.qzone.qq.com/cgi-bin/emotion_cgi_publish_v6', params);
        // SL 的判据：**响应里必须有 t1_tid / tid**，否则算失败（哪怕 code 是 0）
        const tid = got.body?.t1_tid ?? got.body?.tid ?? null;
        const ok = got.http === 200 && Number(got.body?.code ?? 0) === 0 && Boolean(tid);
        return { status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500,
          data: { http: got.http, tid: tid ? String(tid) : null, time: got.body?.t1_time ?? got.body?.now ?? null,
            ...(ok ? {} : { body: got.body }) },
          ...(ok ? {} : { message: tid ? '' : '发表说说失败：响应缺少 tid（服务端没真发出去）' }) };
      }
      if (action.action === 'delete_qzone_msg') {
        const tid = need('tid', String(p.tid ?? p.feed_id ?? ''));
        const got = await qzWrite('taotao.qzone.qq.com/cgi-bin/emotion_cgi_delete_v6', {
          hostuin: uin, tid, t1_source: '1', code_version: '1', format: 'fs',
          qzreferrer: 'https://user.qzone.qq.com/' + uin,
        });
        const code = Number(got.body?.code ?? 0);
        const sub = Number(got.body?.subcode ?? 0);
        const ok = got.http === 200 && code === 0 && sub === 0;
        return { status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500,
          data: { http: got.http, tid, code, subcode: sub, ...(ok ? {} : { body: got.body }) } };
      }
      if (action.action === 'set_qzone_msg_right') {
        // 实测：`emotion_cgi_update` 不是"改权限"接口，它是**编辑说说正文**的，
        // 不带 `con` 会回 `code -10005「您未输入内容，随便写点什么吧」`（subcode -4004）。
        // 而且 SL 里根本没有 setQzoneMsgRight 这个函数 —— 这个动作是"名字"而非真实能力。
        // 如实返回未实现，不要假装改成功了。
        return { status: 'failed', retcode: 1404,
          data: { action: action.action, tid: String(p.tid ?? p.feed_id ?? '') },
          message: '改说说权限：SL 也没有这个实现；emotion_cgi_update 是"编辑说说正文"的接口，不是改可见范围。要做只能用完整 payload 走编辑流程，暂不实现。' };
      }
      if (action.action === 'like_qzone' || action.action === 'unlike_qzone') {
        // SL 的两条 CGI 是分开的：赞 internal_dolike_app / 取消 internal_unlike_app
        const tid = need('tid', String(p.tid ?? p.feed_id ?? ''));
        const owner = String(p.target_uin ?? p.user_id ?? uin);
        const like = action.action === 'like_qzone';
        const unikey = 'http://user.qzone.qq.com/' + owner + '/mood/' + tid;
        const got = await qzWrite('w.qzone.qq.com/cgi-bin/likes/' + (like ? 'internal_dolike_app' : 'internal_unlike_app'), {
          qzreferrer: 'https://user.qzone.qq.com/' + uin,
          opuin: uin, unikey, curkey: unikey,
          appid: '311', typeid: '0',
          abstime: String(Number(p.abstime ?? 0)),
          fid: tid, from: '1', active: '0', fupdate: '1', format: 'json',
        });
        const code = Number(got.body?.code ?? 0);
        const sub = Number(got.body?.subcode ?? 0);
        const ok = got.http === 200 && code === 0 && sub === 0;
        return { status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500,
          data: { http: got.http, op: like ? 'like' : 'unlike', tid, code, subcode: sub, ...(ok ? {} : { body: got.body }) } };
      }
      if (action.action === 'comment_qzone' || action.action === 'comment_qzone_public_feed') {
        const tid = need('tid', String(p.tid ?? p.feed_id ?? ''));
        const content = need('content', String(p.content ?? p.message ?? '').trim());
        const owner = String(p.target_uin ?? p.user_id ?? uin);
        const got = await qzWrite('taotao.qzone.qq.com/cgi-bin/emotion_cgi_re_feeds', {
          qzreferrer: 'https://user.qzone.qq.com/' + uin,
          inCharset: 'utf-8', outCharset: 'utf-8',
          hostUin: owner, format: 'json', ref: 'feeds',
          // SL 的 topicId 是 <hostUin>_<tid>__1（后面两个下划线）
          topicId: owner + '_' + tid + '__1',
          feedsType: '100', private: '0', paramstr: '1',
          richtype: '', richval: '', isSignIn: '',
          uin, content, plat: 'qzone', source: 'ic', platformid: '52',
        });
        const ok = got.http === 200 && Number(got.body?.code ?? 0) === 0;
        return { status: ok ? 'ok' : 'failed', retcode: ok ? 0 : 1500, data: { http: got.http, tid, body: got.body } };
      }

      // ── 公共号族的旧占位实现已删除─────────────────────────
      // 原来这里有一张 rpcMap，service 名是猜的（qzone_public.Feed 之类），
      // 位置又在真实实现之前，会先把这 13 个动作截走 → 永远走真的那条。
      // 真实三元组见下面的 GOTRPC_OPS（从 SnowLuma 的 qzone.ts 抄的）。

      // ── 其它 ───────────────────────────────────────────────────────────
      if (action.action === 'set_qzone_ban') {
        const target = need('target_uin', String(p.target_uin ?? p.user_id ?? ''));
        const form = 'action=1&uin=' + target + '&code=1&format=json&g_tk=' + gtk;
        const got = await qz('https://user.qzone.qq.com/proxy/domain/w.qzone.qq.com/cgi-bin/right/cgi',
          { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
        return { status: got.http === 200 ? 'ok' : 'failed', retcode: got.http === 200 ? 0 : 1500, data: { http: got.http, target, body: got.body } };
      }
      if (action.action === 'set_qzone_profile') {
        const form = 'nickname=' + encodeURIComponent(String(p.nickname ?? '')) + '&code=1&format=json&g_tk=' + gtk;
        const got = await qz('https://user.qzone.qq.com/proxy/domain/base.qzone.qq.com/cgi-bin/user/cgi',
          { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
        return { status: got.http === 200 ? 'ok' : 'failed', retcode: got.http === 200 ? 0 : 1500, data: { http: got.http, body: got.body } };
      }
      // ── h5 gotrpc 族：公开空间的 14 个动作 ────────────────────────────
      // 三元组（service / method / x-oidb）与请求体结构全部从 SnowLuma 的
      // src/bridge/apis/qzone.ts 抄出来（不是猜的）：
      //   POST https://h5.qzone.qq.com/http2rpc/gotrpc/v1/<service>/<method>?g_tk=<bkn>
      //   头 x-oidb: {"uint32_command":<0x 前段>, "uint32_service_type":<后段>}
      //   返回 {retcode:0, data:{...}}，retcode 非 0 视为失败。
      const GOTRPC_OPS = {
        get_qzone_public_capabilities: ['trpc.public_qzone.entrance_ctrl.EntranceCtrl', 'BatchEntranceWhitelist', '0x9741_0'],
        get_qzone_public_feeds: ['trpc.qzone.feeds_reader.FeedsReader', 'GetPublicRecomFeeds', '0x9a38_0'],
        get_qzone_public_feed_detail: ['trpc.qzone.feeds_reader.FeedsReader', 'GetFeedDetail', '0x97b1_1'],
        get_qzone_public_comments: ['trpc.qzone.feeds_reader.FeedsReader', 'GetComment', '0x9bfd_1'],
        get_qzone_public_replies: ['trpc.qzone.feeds_reader.FeedsReader', 'GetReplies', '0x9bfe_1'],
        comment_qzone_public_feed: ['trpc.qzone.interaction_writer.InteractionWriter', 'AddComment', '0x9676_1'],
        reply_qzone_public_feed: ['trpc.qzone.interaction_writer.InteractionWriter', 'AddReply', '0x9677_1'],
        delete_qzone_public_comment: ['trpc.qzone.interaction_writer.InteractionWriter', 'DeleteComment', '0x9989_0'],
        delete_qzone_public_reply: ['trpc.qzone.interaction_writer.InteractionWriter', 'DeleteReply', '0x998a_0'],
        set_qzone_public_like: ['trpc.qzone.interaction_writer.InteractionWriter', 'DoLike', '0x9699_1'],
        set_qzone_public_comment_like: ['trpc.qzone.interaction_writer.InteractionWriter', 'DoLike', '0x9699_1'],
        set_qzone_public_upvote: ['trpc.public_qzone.interaction.UFOComment', 'Upvote', '0x9d18_1'],
        set_qzone_public_follow: ['trpc.public_qzone.relation.RelationService', 'Follow', '0x9d1a_1'],
        forward_qzone_public_feed: ['trpc.qzone.feeds_writer.FeedsWriter', 'ForwardFeed', '0x969a_1'],
        get_qzone_home_feeds_gotrpc: ['trpc.qzone.feeds_reader.FeedsReader', 'GetMainPageFeeds', '0x9794_2'],
      };
      const gotrpc = async (spec, body) => {
        const [cmdHex, typeStr] = spec[2].split('_');
        const url = 'https://h5.qzone.qq.com/http2rpc/gotrpc/v1/' + spec[0] + '/' + spec[1] + '?g_tk=' + gtk;
        const got = await qz(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Referer: 'https://h5.qzone.qq.com/pc-qzone/index.html',
            'x-web-qua': 'V1_HT5_QZ_9.9.32_001_IDC_B',
            'x-oidb': JSON.stringify({ uint32_command: parseInt(cmdHex, 16), uint32_service_type: Number(typeStr) }),
          },
          body: JSON.stringify(body),
        });
        const r = got.body || {};
        if (Number(r.retcode) !== 0) throw fail(action.action + ' 失败: retcode=' + String(r.retcode) + ' ' + String(r.message || ''), 1500);
        return { http: got.http, retcode: Number(r.retcode), data: r.data };
      };
      const feedParams = () => {
        const src = p.feed && typeof p.feed === 'object' ? p.feed : (p.cell_common ? p : null);
        const f = src && (src.feed && typeof src.feed === 'object' ? src.feed : src);
        const common = (f && f.cell_common) || {};
        const union = common.union_id;
        if (!union || typeof union !== 'object' || !Object.keys(union).length) {
          throw fail(action.action + ' 需要完整动态对象：把 get_qzone_public_feeds / get_qzone_public_feed_detail 返回的原始动态（含 cell_common.union_id）原样放进 feed 参数', 1400);
        }
        const o = { union_id: union };
        if (f.cell_feed_transfer !== undefined) o.cell_feed_transfer = f.cell_feed_transfer;
        return { o, f, common };
      };
      const richContent = x => (typeof x === 'string' ? [{ type: 0, content: x }] : x);
      if (GOTRPC_OPS[action.action]) {
        // 必须复制一份：下面 enable:false 的分支会改写 method/oidb，
        // 直接改表里的数组会把表永久改成 UnLike，之后所有调用都反着来。
        const spec = GOTRPC_OPS[action.action].slice();
        let body;
        switch (action.action) {
          case 'get_qzone_public_capabilities':
            body = { uins: [uin], entrance_types: [1, 15] };
            break;
          case 'get_qzone_public_feeds':
            body = { version: 1, uin, refresh_id: String(p.refresh_id ?? ''), attach_info: String(p.attach_info ?? ''),
              last_client_feed_union_id: String(p.last_client_feed_union_id ?? '') };
            break;
          case 'get_qzone_home_feeds_gotrpc':
            body = { host_uid: '', host_uin: String(p.target_uin ?? p.user_id ?? uin), attach_info: String(p.attach_info ?? ''),
              refresh_attach_info: '', feed_action_domain_type: 1 };
            break;
          case 'get_qzone_public_feed_detail':
            body = { ...feedParams().o, feed_action_domain_type: 3, from_page: 1 };
            break;
          case 'get_qzone_public_comments':
            body = { ...feedParams().o, attach_info: String(p.attach_info ?? p.cursor ?? '') };
            break;
          case 'get_qzone_public_replies': {
            const fp = feedParams();
            const comment = p.comment ?? null;
            if (!comment || typeof comment !== 'object') throw fail('get_qzone_public_replies 需要 comment 对象（用 public_comments 返回的原始评论）', 1400);
            body = { ...fp.o, cur_comment: comment, comment_attach_info: '',
              reply_attach_info: String(p.cursor ?? comment.reply_attach_info ?? ''), page_size: Number(p.page_size ?? 20) };
            break;
          }
          case 'comment_qzone_public_feed': {
            const fp = feedParams();
            body = { ...fp.o, comment: { user: p.user ?? { uin }, content: richContent(p.content ?? p.text ?? '') } };
            break;
          }
          case 'reply_qzone_public_feed': {
            const fp = feedParams();
            const comment = p.comment;
            const reply = p.reply;
            if (!comment || typeof comment !== 'object') throw fail('reply_qzone_public_feed 需要 comment 对象', 1400);
            const targetUser = (reply && reply.user) || comment.user;
            if (!targetUser || typeof targetUser !== 'object') throw fail('reply_qzone_public_feed 的 comment/reply 缺少 user', 1400);
            body = { ...fp.o, comment, reply: { content: richContent(p.content ?? p.text ?? ''), target_user: targetUser, user: p.user ?? { uin } } };
            break;
          }
          case 'delete_qzone_public_comment': {
            const fp = feedParams();
            if (!p.comment || typeof p.comment !== 'object') throw fail('delete_qzone_public_comment 需要 comment 对象', 1400);
            body = { ...fp.o, comment: p.comment };
            break;
          }
          case 'delete_qzone_public_reply': {
            const fp = feedParams();
            if (!p.comment || !p.reply) throw fail('delete_qzone_public_reply 需要 comment 与 reply 两个对象', 1400);
            body = { ...fp.o, comment: p.comment, reply: p.reply };
            break;
          }
          case 'set_qzone_public_like': {
            const fp = feedParams();
            const enable = p.enable === undefined ? true : Boolean(p.enable);
            body = { ...fp.o, like_key: String(p.like_key ?? fp.common.cur_like_key ?? ''), like_type: Number(p.like_type ?? 1) };
            if (!body.like_key) throw fail('set_qzone_public_like 缺 like_key（也可直接传 public_feeds 返回的动态，里面有 cell_common.cur_like_key）', 1400);
            if (!enable) { spec[1] = 'UnLike'; spec[2] = '0x969c_1'; }
            break;
          }
          case 'set_qzone_public_comment_like': {
            const fp = feedParams();
            const enable = p.enable === undefined ? true : Boolean(p.enable);
            const target = p.reply ?? p.comment;
            const likeId = (target && target.like && target.like.id) || p.like_id;
            if (!likeId) throw fail('set_qzone_public_comment_like 需要 comment/reply 里的 like.id（或直接给 like_id）', 1400);
            body = { ...fp.o, like_key: String(likeId), like_type: p.reply ? 3 : 2 };
            if (!enable) { spec[1] = 'UnLike'; spec[2] = '0x969c_1'; }
            break;
          }
          case 'set_qzone_public_upvote': {
            const fp = feedParams();
            body = { ...fp.o };
            if (p.enable === false) { spec[1] = 'Downvote'; spec[2] = '0x9d19_1'; }
            break;
          }
          case 'set_qzone_public_follow': {
            const fp = feedParams();
            const user = (fp.f && fp.f.cell_user_info) || {};
            const uid = String(user.uid ?? '').trim();
            const tUin = String(user.uin ?? '').trim();
            const useUid = (fp.common.domain_type === 3 && uid) || !tUin;
            if (useUid ? !uid : !tUin) throw fail('set_qzone_public_follow 的动态里缺少作者 uid/uin', 1400);
            body = { follow_from_type: 1, ...(useUid ? { target_uid: uid } : { target_uin: tUin }) };
            if (fp.o.union_id && fp.o.union_id.uf_key) body.follow_feed_id = fp.o.union_id.uf_key;
            if (fp.f.cell_feed_transfer !== undefined) body.cell_feed_transfer = fp.f.cell_feed_transfer;
            if (p.enable === false) { spec[1] = 'Unfollow'; spec[2] = '0x9d1b_1'; }
            break;
          }
          case 'forward_qzone_public_feed': {
            const fp = feedParams();
            body = { ...fp.o, reason: String(p.reason ?? p.content ?? '') };
            break;
          }
          default:
            throw fail('gotrpc 表里有 ' + action.action + ' 但没有构造请求体', 1400);
        }
        const got = await gotrpc(spec, body);
        return { status: 'ok', retcode: 0, data: { via: spec[0] + '/' + spec[1], oidb: spec[2], http: got.http, retcode: got.retcode, data: got.data } };
      }
      if (action.action === 'get_qzone_share_ark') {
        // 分享卡片是本地构造的 ark 结构，不需要请求服务器。
        const tid = String(p.tid ?? p.feed_id ?? '');
        const owner = String(p.target_uin ?? p.user_id ?? uin);
        if (!tid) return { status: 'failed', retcode: 1400, data: null, message: 'get_qzone_share_ark 需要 tid' };
        const ark = {
          app: 'com.tencent.qzone.share', view: 'qzoneFeed', ver: '0.0.0.1',
          prompt: String(p.prompt ?? '[QQ空间说说]'), meta: { feedId: tid, uin: owner, url: 'https://user.qzone.qq.com/' + owner + '/mood/' + tid },
        };
        return { status: 'ok', retcode: 0, data: { ark, json: JSON.stringify(ark) } };
      }
      return { status: 'failed', retcode: 1404, data: { action: action.action }, message: '未处理的空间动作: ' + action.action };
    }
    if (action.kind === 'compat') {
      // 只读动作才允许启发式映射；写动作绝不靠猜（会误调 addFriend / addListener 这类有副作用的原生方法）
      if (!/^(get|fetch|can)_/.test(action.action)) {
        return { status: 'failed', retcode: 1404, data: null, message: '写类动作需要显式实现，不做启发式映射: ' + action.action };
      }
      if (COMPAT_DENY.has(action.action)) {
        return { status: 'failed', retcode: 1404, data: { action: action.action }, message: '这个动作的精确映射还没实现（启发式会猜错，已拉黑）: ' + action.action };
      }
      const target = compatService(action.action, session);
      if (!target) return { status: 'failed', retcode: 1404, data: null, message: '这个动作在 QQ 原生服务里没有对应实现: ' + action.action };
      const names = compatCandidates(action.action, target);
      const attempts = [];
      const argShapes = [];
      const p = action.params || {};
      argShapes.push([p]);
      argShapes.push(Object.values(p));
      if (Object.keys(p).length === 1) argShapes.push([Object.values(p)[0]]);
      for (const name of names) {
        ensure();
        for (const args of argShapes) {
          try {
            const value = await target[name](...args);
            const code = value && typeof value === 'object'
              ? [value.result, value.errCode, value.retCode].find(v => typeof v === 'number')
              : undefined;
            if (typeof code === 'number' && code !== 0) {
              attempts.push({ name, argc: args.length, nativeCode: code, errMsg: String(value.errMsg || value.message || '') });
              continue;
            }
            // 启发式分支：业务失败文案同样要认，否则会把「失败」当成命中形状直接报成功。
            const heuristicRefusal = nativeRefusal(value);
            if (heuristicRefusal) {
              attempts.push({ name, argc: args.length, errMsg: heuristicRefusal });
              continue;
            }
            return { status: 'ok', retcode: 0, data: { action: action.action, via: name, args: args.length, value: value === undefined ? null : value } };
          } catch (error) {
            attempts.push({ name, argc: args.length, error: String(error && error.message ? error.message : error).slice(0, 120) });
          }
        }
      }
      return { status: 'failed', retcode: 1500, data: { action: action.action, candidates: names, attempts: attempts.slice(0, 8) }, message: '没有可用的原生方法（见 data.attempts）' };
    }
    if (action.kind === 'group_history') {
      const attempts = [];
      const tryCall = async (label, fn) => {
        try { const value = await fn(); attempts.push({ label, ok: true }); return { value }; }
        catch (error) { attempts.push({ label, ok: false, error: String(error && error.message ? error.message : error).slice(0, 160) }); return null; }
      };
      if (action.kind === 'group_history') {
        const msgSvc = session.getMsgService();
        const g = action.group;
        const n = action.count;
        const peerKey = { chatType: 2, peerUid: g, guildId: '' };
        const result = await tryCall('getLastMessageList(g)', () => msgSvc.getLastMessageList(g))
          || await tryCall('getLastMessageList(peerKey)', () => msgSvc.getLastMessageList(peerKey))
          || await tryCall('getLastMessageList({groupCode})', () => msgSvc.getLastMessageList({ groupCode: g }))
          || await tryCall('getLastMessageList(g, n)', () => msgSvc.getLastMessageList(g, n))
          || await tryCall('getAioLatestMessages(peerKey)', () => msgSvc.getAioLatestMessages(peerKey))
          || await tryCall('getAioLatestMessages(g)', () => msgSvc.getAioLatestMessages(g))
          || await tryCall('getAioLatestMessages(g,n)', () => msgSvc.getAioLatestMessages(g, n))
        || await tryCall('getLastMessageList({peerUid,chatType,count})', () => msgSvc.getLastMessageList({ peerUid: g, chatType: 2, count: n }))
        || await tryCall('getAioLatestMessages({peerUid,chatType,count})', () => msgSvc.getAioLatestMessages({ peerUid: g, chatType: 2, count: n }))
        || await tryCall('getMsgsBySeqAndCount(peerKey,n)', () => msgSvc.getMsgsBySeqAndCount(peerKey, '0', n, true));
        if (!result) return { status: 'failed', retcode: 1500, data: { attempts }, message: '群历史没有可用原生方法（见 data.attempts）' };
        const raw = result.value;
        if (raw && typeof raw === 'object' && raw.result !== undefined && Number(raw.result) !== 0) {
          return { status: 'failed', retcode: 1404, data: { attempts, nativeResult: raw.result, nativeMsg: String(raw.errMsg ?? '') }, message: '原生返回失败码，不是"没有历史"' };
        }
        const list = Array.isArray(raw) ? raw : (raw && (raw.messages ?? raw.msgList ?? raw.list)) || [];
        if (raw && typeof raw === 'object' && raw.msgList !== undefined && !Array.isArray(raw.msgList)) {
          attempts.push({ label: 'msgList-not-array', ok: false, error: typeof raw.msgList });
        }
        return { status: 'ok', retcode: 0, data: { attempts, count: Array.isArray(list) ? list.length : null, messages: list,
          raw_shape: raw && typeof raw === 'object' ? Object.keys(raw) : null,
          nativeResult: raw && typeof raw === 'object' ? (raw.result ?? null) : null,
          nativeMsg: raw && typeof raw === 'object' ? String(raw.errMsg ?? '') : null } };
      }
    }
    if (action.kind === 'rich_media') {
      // 私聊图只有 file_id / rkey，本机没有缓存文件：让 QQ 自己下载一次，再回报落地路径。
      const msgSvc = session.getMsgService();
      const a = action;
      // 下载目录：QQ 只在需要时把富媒体落盘，这里给它一个明确的目标目录，回来后自己核对文件。
      const fs = require('node:fs');
      const pathLib = require('node:path');
      const outDir = pathLib.join(process.env.TEMP || process.cwd(), 'openqq-rich');
      try { fs.mkdirSync(outDir, { recursive: true }); } catch { /* 目录建不了就走下面的候选 */ }
      const fileName = a.fileName || (a.fileUuid.slice(0, 32) + '.bin');
      const savePath = pathLib.join(outDir, fileName.replace(/[\\/:*?"<>|]/g, '_'));
      const base = { fileUuid: a.fileUuid, chatType: a.chatType, peerUid: a.peerUid, fileType: 0, fileName, needCreate: true };
      const candidates = [
        { label: 'downloadRichMedia(+savePath)', args: [{ ...base, savePath, saveFilePath: savePath, targetPath: savePath }] },
        { label: 'downloadRichMedia({fileUuid,chatType,peerUid,fileType:0})', args: [{ ...base }] },
        { label: 'downloadRichMedia({fileUuid,msgId,...})', args: [{ ...base, msgId: a.msgId }] },
        { label: 'downloadRichMedia(fileUuid)', args: [a.fileUuid] },
        { label: 'getRichMediaElement({fileUuid})', args: [{ fileUuid: a.fileUuid, chatType: a.chatType, peerUid: a.peerUid }] },
      ];
      const attempts = [];
      for (const c of candidates) {
        const method = c.label.startsWith('getRichMediaElement') ? 'getRichMediaElement' : 'downloadRichMedia';
        try {
          const value = await msgSvc[method](...c.args);
          attempts.push({ label: c.label, ok: true });
          // QQ 的下载是异步的：立刻看一次 savePath，没有就把候选全部跑一遍，最后由上层决定。
          let landed = '';
          try { if (fs.existsSync(savePath)) landed = savePath; } catch { /* 忽略 */ }
          const valuePath = value && typeof value === 'object' ? (value.filePath || value.savePath || value.path || '') : '';
          return { status: 'ok', retcode: 0, data: { attempts, via: c.label, result: value ?? null, savePath, landed, filePath: String(valuePath || landed || ''), shape: value && typeof value === 'object' ? Object.keys(value).slice(0, 20) : null } };
        } catch (error) { attempts.push({ label: c.label, ok: false, error: String(error && error.message ? error.message : error).slice(0, 180) }); }
      }
      return { status: 'failed', retcode: 1500, data: { attempts }, message: '富媒体下载没有可用原生方法（见 data.attempts）' };
    }
    if (action.kind === 'stranger') {
      const detail = await session.getProfileService().getUserDetailInfoByUin(action.uin);
      return { status: 'ok', retcode: 0, data: {
        user_id: String(action.uin),
        detail,
        raw_shape: detail && typeof detail === 'object' ? Object.keys(detail) : null,
      } };
    }
    if (action.kind === 'recent_face') {
      const msgSvc = session.getMsgService();
      // 两个名字共用 getRecentUsedFaceList。原来 get_recent_emoji_list 走的是 getRecentEmojiList，
      // 而它**在正式路径上会挂满 20 秒**（debug_call 里 14 秒也不返回），整条 IPC 判 1501 超时。
      // getRecentUsedFaceList 实测 5~40ms 回 {result:0, recentUsedFaceList:[...]}，两条都改用它。
      const method = 'getRecentUsedFaceList';
      const attempts = [];
      for (const args of [[{}], [20], []]) {
        if (typeof msgSvc[method] !== 'function') { attempts.push({ label: method, error: 'method missing' }); break; }
        try {
          const value = await msgSvc[method](...args);
          const list = Array.isArray(value) ? value : (value && (value.list ?? value.emojiInfoList ?? value.data)) || [];
          return { status: 'ok', retcode: 0, data: Array.isArray(list) ? list : [], meta: { method, args, shape: value && typeof value === 'object' ? Object.keys(value) : null } };
        } catch (error) { attempts.push({ label: method + '(' + JSON.stringify(args) + ')', error: String(error && error.message ? error.message : error).slice(0, 120) }); }
      }
      return { status: 'failed', retcode: 1404, data: { attempts }, message: method + ' 调用失败（见 data.attempts）' };
    }
    if (action.kind === 'fav_emoji') {
      const msgSvc = session.getMsgService();
      const n = action.count;
      const favCandidates = [
        [n, 0, 0, 0], [n, 0, false, false], [n, 0, 0, false], [n, 0, '', 0], [0, n, 0, 0],
        [{ count: n, startIndex: 0 }], [{ count: n }], [{ count: n, start: 0, pageSize: n }],
        [], [n], [n, 0], [n, 0, 0],
      ];
      let raw = null;
      let usedFavArgs = null;
      let lastFavError = null;
      for (const args of favCandidates) {
        try { raw = await msgSvc.fetchFavEmojiList(...args); usedFavArgs = args; break; } catch (error) { lastFavError = error; }
      }
      if (usedFavArgs === null) throw fail('fetchFavEmojiList 参数不匹配：' + (lastFavError && lastFavError.message), 1500);
      const toArray = (value) => {
        if (!value) return null;
        if (Array.isArray(value)) return value;
        if (value instanceof Map) return Array.from(value.values());
        if (value instanceof Set) return Array.from(value.values());
        return null;
      };
      const pickEmoji = (value, depth = 0) => {
        const direct = toArray(value);
        if (direct) return direct;
        if (!value || typeof value !== 'object' || depth > 3) return [];
        for (const key of ['emojiInfoList', 'emojiList', 'list', 'data', 'result']) {
          const got = pickEmoji(value[key], depth + 1);
          if (got.length) return got;
        }
        return [];
      };
      const describeType = (value) => {
        if (value === null || value === undefined) return String(value);
        if (Array.isArray(value)) return 'Array(' + value.length + ')';
        if (value instanceof Map) return 'Map(' + value.size + ')';
        const ctor = value && value.constructor ? value.constructor.name : typeof value;
        return ctor + (value && typeof value.size === 'number' ? '(size=' + value.size + ')' : '');
      };
      const list = pickEmoji(raw);
      // OneBot v11 expects the emoji list itself as `data`; diagnostics only ride along when the list is empty.
      return { status: 'ok', retcode: 0, data: list, ...(list.length ? {} : { message: 'fetchFavEmojiList 没有取到表情：args=' + JSON.stringify(usedFavArgs) + ' raw_shape=' + JSON.stringify(raw && typeof raw === 'object' ? Object.keys(raw).slice(0, 12) : null) + ' totalCnt=' + String(raw && raw.totalCnt) + ' emojiListType=' + String(describeType(raw && raw.emojiInfoList)) + ' resultType=' + String(describeType(raw && raw.result)) }) };
    }
    let timer;
    let tag;
    const cancelled = new Promise((_, reject) => {
      operation.cancel = () => { operation.active = false; reject(fail('会话或连接已关闭；已提交的发送结果未确认，请先查看 QQ，勿自动重试', 1502)); };
      timer = setTimeout(() => { operation.active = false; reject(fail('动作超时，已提交的发送结果未确认；请先查看 QQ，勿自动重试', 1501)); }, action.timeout ?? 15000);
    });
    operations.add(operation);
    const uidSteps = {
      convert: async uin => (await session.getUixConvertService().getUid([uin]))?.uidInfo?.get(uin),
      profile: async uin => (await session.getProfileService().getUidByUin('FriendsServiceImpl', [uin]))?.get(uin),
      group: async uin => (await session.getGroupService().getUidByUins([uin]))?.uids?.get(uin),
    };
    // Tries each source in turn and skips one that throws. Non-friends (group members, temp-chat peers) are often only known to the group service.
    const findUid = async (uin, order) => {
      for (const name of order) {
        ensure();
        let uid;
        try { uid = await uidSteps[name](uin); } catch { uid = undefined; }
        if (/^u_[\w-]+$/.test(uid ?? '')) return uid;
      }
      return undefined;
    };
    const needUid = async (uin, order, message) => {
      const uid = await findUid(uin, order);
      if (!uid) throw fail(message, 1500);
      return uid;
    };
    const memberName = async (group, uid) => {
      const infos = (await session.getGroupService().getMemberInfo(group, [uid], false))?.result?.infos;
      const info = infos instanceof Map ? infos.get(uid) : undefined;
      return info ? String(info.cardName || info.nick || '') : '';
    };
    // Group list entries arrive through the group listener; ask QQ to refresh, then wait for the update it triggers.
    const groupList = async refresh => {
      const cache = options.groups;
      if (!cache) throw fail('当前会话不支持获取群列表', 1500);
      if (refresh || cache.map.size === 0) {
        const since = cache.version;
        const result = await session.getGroupService().getGroupList(true);
        ensure();
        if (typeof result?.result === 'number' && result.result !== 0) throw fail('QQ 拒绝获取群列表：' + (result.errMsg || result.result), 1500);
        if (cache.version === since) await cache.waitForUpdate(since, 5000);
        ensure();
      }
      return [...cache.map.values()];
    };
    try {
      return await Promise.race([cancelled, (async () => {
        if (action.kind === 'get_login_info') return { user_id: Number(self.uin), nickname: '' };
        if (action.kind === 'get_status') return { online: true, good: true };
        if (action.kind === 'forward') {
          if (typeof options.expandForward !== 'function') throw fail('当前会话不支持获取合并转发', 1500);
          const messages = await options.expandForward(action.ref);
          ensure();
          return { self, forward: { ref: action.ref, messages } };
        }
        if (action.kind === 'get_msg') {
          if (typeof options.fetchMessage !== 'function') throw fail('当前会话不支持读取消息', 1500);
          const message = await options.fetchMessage(action.ref);
          ensure();
          return { self, message };
        }
        if (action.kind === 'get_image') {
          if (typeof options.resolveMedia !== 'function') throw fail('当前会话不支持获取图片', 1500);
          const media = await options.resolveMedia(action.key, 'image');
          ensure();
          return media;
        }
        if (admin.kinds.has(action.kind)) {
          return await admin.run(action, {
            session, ensure, groupList,
            friendList: async () => {
              if (typeof options.friendList !== 'function') throw fail('当前会话不支持获取好友列表', 1500);
              const list = await options.friendList();
              ensure();
              return list;
            },
            uidFor: uin => needUid(uin, ['convert', 'profile', 'group'], '无法把 QQ 号转换为 UID；未调用 QQ'),
            memberUid: (_group, uin) => needUid(uin, ['group', 'convert', 'profile'], '无法把 QQ 号转换为 UID；未调用 QQ'),
          });
        }
        let peerUid = action.target;
        if (action.chatType !== 2) peerUid = await needUid(action.target, ['convert', 'profile', 'group'], '无法把目标 QQ 号转换为 UID；未调用发送');
        ensure();
        const service = session.getMsgService();
        if (action.kind === 'input') {
          const result = await service.sendShowInputStatusReq(1, action.eventType, peerUid);
          ensure();
          if (result?.result !== undefined && result.result !== 0) throw fail('QQ 拒绝输入状态通知: ' + (result.errMsg ?? result.result), 1500);
          return null;
        }
        const time = session.getMSFService().getServerTime();
        if (typeof time !== 'string' || !/^[1-9]\d{0,19}$/.test(time)) throw fail('原生服务器时间无效，未调用发送', 1500);
        tag = service.generateMsgUniqueId(action.chatType, time);
        if (typeof tag !== 'string' || !/^[1-9]\d*$/.test(tag) || waiting.has(tag)) throw fail('原生发送关联标识无效或重复，未调用发送', 1500);
        // QQ preserves the caller's guildId tag on ordinary-chat send updates.
        if (action.kind !== 'send') throw fail('未处理的动作类型: ' + action.kind + '（内部错误，未调用 QQ）', 1404);
        const peer = { chatType: action.chatType, peerUid, guildId: tag };
        const acknowledged = new Promise(resolve => waiting.set(tag, { peer, resolve }));
        const elements = [];
        const reply = action.parts.find(part => part.type === 'reply');
        if (reply) {
          // Quoting across conversations is not possible in QQ; refuse before sending anything.
          if (reply.ref.chatType !== action.chatType || reply.ref.peerUid !== peerUid) throw fail('只能引用同一会话中的消息；未调用发送', 1400);
          let quoted = options.lookupRecent?.(reply.ref);
          if (!quoted?.msgSeq) {
            try {
              const found = (await service.getMsgsByMsgId({ chatType: reply.ref.chatType, peerUid, guildId: '' }, [reply.ref.msgId]))?.msgList
                ?.find(item => String(item.msgId) === reply.ref.msgId);
              if (found) quoted = { msgId: String(found.msgId), msgSeq: String(found.msgSeq ?? ''), clientSeq: String(found.clientSeq ?? ''), senderUin: String(found.senderUin ?? '') };
            } catch { /* reported below */ }
            ensure();
          }
          if (!quoted?.msgSeq) throw fail('引用的消息在 QQ 本地记录中找不到；未调用发送', 1404);
          // QQ requires the quote to be the first element.
          elements.push({ elementType: 7, elementId: '', replyElement: { replayMsgSeq: quoted.msgSeq, replayMsgId: quoted.msgId,
            senderUin: quoted.senderUin, senderUinStr: quoted.senderUin, replyMsgClientSeq: quoted.clientSeq } });
        }
        const build = createElementBuilder({ session, ensure, groupCode: action.target, memberName,
          memberUid: (_group, uin) => needUid(uin, ['group', 'convert', 'profile'], '无法把 @ 的 QQ 号转换为 UID；未调用发送') });
        for (const part of action.parts) {
          if (part.type === 'text' && part.text.length) elements.push({ elementType: 1, elementId: '',
            textElement: { content: part.text, atType: 0, atUid: '', atTinyId: '', atNtUid: '' } });
          else if (part.type === 'json') elements.push({ elementType: 10, elementId: '', arkElement: { bytesData: part.data, linkInfo: null, subElementType: null } });
          else if (typeof build[part.type] === 'function') elements.push(await build[part.type](part));
        }
        ensure();
        const result = await service.sendMsg('0', peer, elements, new Map());
        ensure();
        if (result?.result !== 0) throw fail('QQ 未接受发送: ' + (result?.errMsg ?? result?.result ?? '缺少结果'), 1500);
        const record = await acknowledged;
        ensure();
        if (record.sendStatus !== 2) throw fail('QQ 报告发送失败', 1500);
        if (!/^\d+$/.test(String(record.msgId)) || (typeof record.msgId === 'number' && !Number.isSafeInteger(record.msgId))) throw fail('QQ 回执消息 ID 无效，发送结果需在客户端确认', 1500);
        return { self, message: { chatType: peer.chatType, peerUid, msgId: String(record.msgId) } };
      })()]);
    } finally {
      operation.active = false;
      clearTimeout(timer);
      operations.delete(operation);
      if (tag && waiting.has(tag)) { waiting.get(tag).resolve({ sendStatus: 0 }); waiting.delete(tag); }
    }
  }
  function dispose() {
    disposed = true;
    for (const operation of operations) operation.cancel();
  }
  return { execute, observe, dispose };
}


// ==== COMPAT_ACTIONS ====
// 一批动作名 → 内核服务的启发式映射：按名字给内核方法打分，挑最像的那个调。
//
// 为什么保留它、而不是一律回「未实现」：
//   · 这些动作覆盖的是「读了就行」的查询（好友列表、群信息、历史消息、文件列表…），
//     内核里确实有对应方法，只是名字与 OneBot 的不一一对应。全部标未实现等于把这些能力白扔掉。
//   · 它不会假装成功：COMPAT_DENY 里的名字（实测会落到无关方法）和 nativeRefusal 认出的
//     失败文案都会变成明确的失败回执，不会返回「碰巧没报错」的假数据。
// 代价是「可能猜错服务」。所以凡是确认了正确方法的动作，都应当从这张表里移出去，
// 换成 NATIVE_OPS / OIDB_ACTIONS 里的显式条目；这张表是过渡态，不是终点。
const COMPAT_ACTIONS = new Set(["can_at_all","can_send_image","can_send_record","delete_custom_face","delete_essence_msg","delete_flash_file","delete_friend","delete_group_file","delete_group_file_folder","delete_group_folder","delete_group_tag","delete_msg","delete_qzone_msg","fetch_custom_face","fetch_custom_face_detail","fetch_emoji_like","fetch_face_entity","fetch_ptt_text","fetch_super_face_id","fetch_sys_faces","get_ai_characters","get_ai_record","get_clientkey","get_collection_list","get_cookies","get_credentials","get_csrf_token","get_doubt_friends_add_request","get_emoji_likes","get_essence_msg_list","get_file","get_fileset_id","get_fileset_info","get_flash_file_list","get_flash_file_url","get_forward_msg","get_friend_list","get_friend_msg_history","get_friends_with_category","get_group_admin_permissions","get_group_admin_settings","get_group_album_list","get_group_album_media_list","get_group_at_all_remain","get_group_detail_info","get_group_file_system_info","get_group_file_url","get_group_files_by_folder","get_group_honor_info","get_group_ignore_add_request","get_group_ignored_notifies","get_group_info","get_group_info_ex","get_group_list","get_group_member_info","get_group_member_list","get_group_msg_history","get_group_root_files","get_group_share_link","get_group_shut_list","get_group_signed_list","get_group_system_msg","get_group_tags","get_group_todo_list","get_image","get_login_info","get_mini_app_ark","get_msg","get_msg_emoji_likes","get_online_clients","get_private_file_url","get_profile_like","get_ptt_text","get_qun_album_list","get_qzone_feed_detail","get_qzone_feeds","get_qzone_home_feeds","get_qzone_msg_detail","get_qzone_msg_list","get_qzone_profile","get_recent_contact","get_record","get_record_text","get_rkey","get_rkey_server","get_share_link","get_status","get_stranger_info","get_unidirectional_friend_list","get_version_info","mark_group_msg_as_read","mark_msg_as_read","mark_private_msg_as_read","send_ark_share","send_custom_face","send_flash_msg","send_forward_msg","send_group_ai_record","send_group_ark_share","send_group_forward_msg","send_group_msg","send_group_sign","send_like","send_msg","send_packet","send_poke","send_private_forward_msg","send_private_msg","send_qzone_msg","send_to_new_members","set_diy_online_status","set_essence_msg","set_friend_add_request","set_friend_remark","set_friends_category","set_group_add_option","set_group_admin","set_group_ban","set_group_card","set_group_kick","set_group_leave","set_group_name","set_group_remark","set_group_special_title","set_group_whole_ban","set_input_status","set_msg_emoji_like","set_online_status","set_qq_avatar","set_qq_profile","set_self_longnick","upload_group_file","upload_private_file","upload_forward_msg"]);
// 启发式映射已知会猜错的：宁可明确报"待精确实现"，也不返回语义错误的数据。
const COMPAT_DENY = new Set([
  'get_credentials',         // 实测被映射到 getAutoReplyTextList（自动回复列表）
  'get_cookies',             // 需要原生 cookie 口，已在 qzone 分支单独实现
  'get_csrf_token',          // 同上（由 skey 算 g_tk）
  'get_qzone_feeds',
  'get_qzone_home_feeds',
  'get_qzone_msg_list',
  'get_qzone_profile',

  'get_profile_like',         // 已由 NATIVE_OPS 精确实现（ProfileLike.getBuddyProfileLike），这里只是兜底
  'get_group_share_link',   // 换到的是别的方法，语义不对
  'get_group_notice',       // 暂无精确映射
  'get_friend_msg_history', // 与 get_group_msg_history 混用会拿错会话
  'get_group_todo_list',    // 会匹到 getGroupList
  'fetch_sys_faces',        // 会匹到 fetchMarketEmoticonFaceImages（返回 None）
  'get_recent_contact',     // 已由 NATIVE_OPS 精确实现（RecentContact.getRecentContactList）
  'get_online_clients',     // 已由 NATIVE_OPS 精确实现（OnlineStatus.getOnlineFrdStatusInfos）
  // 下面这批是 全量实测抓出来的「调通了但返回的是别的接口的数据」——静默错数据比 1404 更坏，一律拉黑。
  'can_at_all',             // 落到 OnlineStatus 图标路径（返回值是 C:\...\OnlineStatus\...）
  'get_record',             // 同上，返回的是文件路径不是语音
  'get_record_text',        // 同上（真身应是 msg.translatePtt2Text，需 3 参）
  'get_share_link',         // 同上
  'get_collection_list',    // 落到 getAutoReplyTextList（返回 autoReplyList）
  'fetch_ptt_text',         // 同上
  'get_ptt_text',           // 同上（真身应是 msg.translatePtt2Text，需 3 参，要真实语音消息才验得了）
  'get_fileset_info',       // 落到群匿名信息（返回 isAnonymousChat/anonyId）
  'get_group_files_by_folder', // 落到 getGroupTagRecords（返回 tags 不是文件）
  // 第二批实测：这批全部落到 getGroupList / getBuddyList / getLastMessageList 等无关方法，
  // 只回一个 {result:0,errMsg:"success"} 空壳让人以为成功——比报错更坏，全部拉黑。
  'get_group_admin_permissions',   // → getGroupList
  'get_group_admin_settings',      // → getGroupList
  'get_group_album_list',          // → getGroupList
  'get_group_album_media_list',    // → getGroupList
  'get_group_file_url',            // → getGroupList
  'get_group_ignore_add_request',  // → getGroupList
  'get_group_root_files',          // → getGroupList
  'get_group_signed_list',         // → getGroupList
  'get_group_file_system_info',    // → 无 via、value=null
  'get_group_ignored_notifies',    // → getGroupNotifiesUnreadCount（只是未读数）
  'get_group_system_msg',          // → getGroupMsgLimitFreq（限频）
  'get_group_detail_info',         // → getGroupAuthDetailInfo（空壳）
  'get_group_info_ex',             // → GetGroupAllMemberNewExtInfo（回 "group code is 0"）
  'get_doubt_friends_add_request', // → getBuddyList
  'get_unidirectional_friend_list',// → getBuddyList
  'get_qun_album_list',            // → getLastMessageList
  'get_fileset_info',              // → 无 via、value=null
  'get_flash_file_list',           // → getNewOfflineFileList（离线文件，不是闪传）
]);
// 动作名 → 目标服务
function compatService(action, session) {
  const a = action;
  const has = name => typeof session[name] === 'function';
  if (a.includes('qzone')) return null; // 说说相关没有对应服务
  if (a.startsWith('get_group') || a.startsWith('set_group') || a.startsWith('delete_group')) return has('getGroupService') ? session.getGroupService() : null;
  if (a.startsWith('upload_group')) return has('getGroupService') ? session.getGroupService() : null;
  if (a.includes('profile') || a === 'get_stranger_info' || a === 'set_qq_profile' || a === 'set_qq_avatar' || a === 'set_self_longnick') return has('getProfileService') ? session.getProfileService() : null;
  if (a.includes('friend') || a.includes('buddy') || a === 'send_like') return has('getBuddyService') ? session.getBuddyService() : null;
  if (a.includes('rkey') || a.includes('cookies') || a.includes('clientkey') || a.includes('csrf')) return null; // 凭据类没有对应服务
  return has('getMsgService') ? session.getMsgService() : null;
}
// 用动作名里的词去匹配服务上的方法名
function compatCandidates(action, service) {
  const tokens = action.replace(/^(get|set|send|delete|fetch|upload|mark|can)_/, '').split('_').filter(Boolean);
  let names = [];
  for (let o = service; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) names = names.concat(Object.getOwnPropertyNames(o));
  names = Array.from(new Set(names)).filter(n => typeof service[n] === 'function');
  const score = n => {
    const lower = n.toLowerCase();
    let s = 0;
    for (const t of tokens) if (lower.includes(t.toLowerCase().slice(0, Math.max(3, t.length - 1)))) s += 1;
    if (/^(get|set|send|del|delete|fetch|upload|mark)/i.test(n) && n.toLowerCase().startsWith(action.split('_')[0])) s += 1;
    return s;
  };
  return names.filter(n => /^(get|fetch|can)/i.test(n)).map(n => ({ n, s: score(n) })).filter(x => x.s > 0).sort((a, b) => b.s - a.s).slice(0, 6).map(x => x.n);
}

module.exports = { validateAction, createActionHandler, normalizeParams, COMPAT_ACTIONS };
