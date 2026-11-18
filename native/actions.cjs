'use strict';

const { fail, identifier, nativeId } = require('./common.cjs');
const { parseCQ } = require('./cq.cjs');
const admin = require('./admin.cjs');
const { createElementBuilder } = require('./elements.cjs');

const MiB = 1024 * 1024;
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
  if (typeof params.message !== 'string' || params.auto_escape !== undefined) return request;
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
      case 'image': return { type: 'image', media: mediaRef(data.openqq_media, 'image'), summary: typeof data.summary === 'string' ? data.summary.slice(0, 64) : '' };
      case 'record': case 'video': case 'file': return { type: segment.type, media: mediaRef(data.openqq_media, segment.type) };
      default:
        throw fail(`当前发送支持 text、at、face、image、record、video、file、reply、json、dice、rps 消息段，暂不支持 ${typeof segment?.type === 'string' ? segment.type : '该消息段'}`);
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
  if (request.action === 'openqq_services') return { kind: 'services' };
  if (request.action === 'get_friend_list') return { kind: 'friend_list' };
  if (request.action === 'get_group_honor_info') throw fail('getGroupHonorList 的 groupUin/groupCode/group_id/位置参数全部回 errCode 20000 param(group_id) error，需要原生结构体，暂不实现', 1404);
  if (request.action === 'get_essence_msg_list') return { kind: 'essence', group: identifier(params.group_id, 'group_id') };
  if (request.action === 'send_poke') {
    return { kind: 'poke', target: identifier(params.user_id ?? params.group_id, 'user_id') };
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
  if (request.action === 'set_friend_add_request') {
    return { kind: 'friend_request', flag: String(params.flag ?? ''), approve: params.approve !== false, remark: String(params.remark ?? '') };
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
  if (request.action === 'get_image') {
    const raw = params.file ?? params.file_id;
    if (typeof raw !== 'string' || !raw.trim() || raw.length > 1024 || /[\u0000-\u001f]/.test(raw)) {
      throw fail('get_image 需要有效的 file 或 file_id');
    }
    return { kind: 'get_image', key: raw.trim() };
  }
  const managed = admin.validate(request, params);
  if (managed) return managed;
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

function createActionHandler(session, self, current, options = {}) {
  const operations = new Set();
  const waiting = new Map();
  let disposed = false;

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
          return { status: 'ok', retcode: 0, data: { action: action.action, via: name, value: value === undefined ? null : value } };
        } catch (error) {
          attempts.push({ name, error: String(error && error.message ? error.message : error).slice(0, 120) });
        }
      }
      return { status: 'failed', retcode: 1500, data: { action: action.action, attempts }, message: '群荣誉/精华没有可用原生方法（见 data.attempts）' };
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
        for (const args of argShapes) {
          try {
            const value = await target[name](...args);
            return { status: 'ok', retcode: 0, data: { action: action.action, via: name, args: args.length, value: value === undefined ? null : value } };
          } catch (error) {
            attempts.push({ name, argc: args.length, error: String(error && error.message ? error.message : error).slice(0, 120) });
          }
        }
      }
      return { status: 'failed', retcode: 1500, data: { action: action.action, candidates: names, attempts: attempts.slice(0, 8) }, message: '没有可用的原生方法（见 data.attempts）' };
    }
    if (action.kind === 'poke' || action.kind === 'group_history' || action.kind === 'friend_request' || action.kind === 'upload') {
      const attempts = [];
      const tryCall = async (label, fn) => {
        try { const value = await fn(); attempts.push({ label, ok: true }); return { value }; }
        catch (error) { attempts.push({ label, ok: false, error: String(error && error.message ? error.message : error).slice(0, 160) }); return null; }
      };
      if (action.kind === 'group_history') {
        const msgSvc = session.getMsgService();
        const g = action.group;
        const n = action.count;
        const result = await tryCall('getLastMessageList(g, n)', () => msgSvc.getLastMessageList(g, n))
          || await tryCall('getLastMessageList({group:g,count:n})', () => msgSvc.getLastMessageList({ groupCode: g, count: n }))
          || await tryCall('getAioLatestMessages(g,n)', () => msgSvc.getAioLatestMessages(g, n));
        if (!result) return { status: 'failed', retcode: 1500, data: { attempts }, message: '群历史没有可用原生方法（见 data.attempts）' };
        const raw = result.value;
        const list = Array.isArray(raw) ? raw : (raw && (raw.messages ?? raw.msgList ?? raw.list)) || [];
        return { status: 'ok', retcode: 0, data: { attempts, count: Array.isArray(list) ? list.length : null, messages: list, raw_shape: raw && typeof raw === 'object' ? Object.keys(raw) : null } };
      }
      if (action.kind === 'friend_request') {
        const buddy = session.getBuddyService();
        const result = await tryCall('approvalFriendRequest', () => buddy.approvalFriendRequest({ friendUid: action.flag, isAgree: action.approve, remark: action.remark }))
          || await tryCall('approvalDoubtBuddyReq', () => buddy.approvalDoubtBuddyReq({ reqUid: action.flag, isAgree: action.approve }))
          || await tryCall('setFriendAddRequest', () => buddy.setFriendAddRequest(action.flag, action.approve ? 1 : 2, action.remark));
        if (!result) return { status: 'failed', retcode: 1500, data: { attempts }, message: '好友请求没有可用原生方法（见 data.attempts）' };
        return { status: 'ok', retcode: 0, data: { attempts, result: result.value ?? null } };
      }
      if (action.kind === 'upload') {
        const msgSvc = session.getMsgService();
        const p = action.params || {};
        const result = await tryCall('uploadFile', () => msgSvc.uploadFile(p))
          || await tryCall('uploadGroupFile', () => session.getGroupService().uploadGroupFile(p))
          || await tryCall('uploadPrivateFile', () => session.getGroupService().uploadPrivateFile(p));
        if (!result) return { status: 'failed', retcode: 1500, data: { attempts }, message: '文件上传没有可用原生方法（见 data.attempts）' };
        return { status: 'ok', retcode: 0, data: { attempts, result: result.value ?? null } };
      }
      // poke：协议里是 elementType 8 的 grayTip，busiId '1061'，jsonStr.items 里放两个 uid（操作者 + 被戳者）。
      // 没有真实样本时按候选结构逐个试，并把 attempts 原样返回，这样一次重启就能把可能性试完。
      const msgSvc = session.getMsgService();
      // 注意：不能调 needUid —— 它定义在本函数更靠后的位置，在这里调用会踩 TDZ
      // （实测报 `Cannot access 'R' before initialization`）。所以就地做一次 uin→uid。
      const localUid = async (uin) => {
        try { const v = (await session.getUixConvertService().getUid([uin]))?.uidInfo?.get?.(uin); if (v) return v; } catch { /* 换下一种 */ }
        try { const v = (await session.getProfileService().getUidByUin('FriendsServiceImpl', [uin]))?.get?.(uin); if (v) return v; } catch { /* 换下一种 */ }
        try { const v = (await session.getGroupService().getUidByUins([uin]))?.uids?.get?.(uin); if (v) return v; } catch { /* 换下一种 */ }
        return '';
      };
      const targetUid = await localUid(String(action.target));
      const selfUid = self.uid || (await localUid(String(self.uin)));
      if (!targetUid) return { status: 'failed', retcode: 1500, data: { targetUid, selfUid }, message: '无法把被戳对象 QQ 号转换为 UID；未调用发送' };
      // 实测：sendMsg 的签名是 4 个参数（argc==4）：(msgId, peer, elements, attrs)。
      const peer = { chatType: 1, peerUid: targetUid, guildId: '' };
      const gray = (items, tip) => ({ elementType: 8, elementId: '',
        grayTipElement: { subElementType: tip ? 1 : 0, jsonGrayTipElement: { busiId: '1061', jsonStr: JSON.stringify({ busiId: '1061', ...(tip ? { tip } : {}), items }) } } });
      const items = [{ uid: selfUid }, { uid: targetUid }];
      const variants = [
        { label: 'sendMsg("", peer, [gray], Map)', fn: () => msgSvc.sendMsg('', peer, [gray(items)], new Map()) },
        { label: 'sendMsg("", peer, [gray], {})', fn: () => msgSvc.sendMsg('', peer, [gray(items)], {}) },
        { label: 'sendMsg(ts, peer, [gray], Map)', fn: () => msgSvc.sendMsg(String(Date.now()), peer, [gray(items)], new Map()) },
        { label: 'sendMsg("", peer, [gray tip=1], Map)', fn: () => msgSvc.sendMsg('', peer, [gray(items, 1)], new Map()) },
        { label: 'sendMsg(peer, [gray], Map, "")', fn: () => msgSvc.sendMsg(peer, [gray(items)], new Map(), '') },
      ];
      for (const v of variants) {
        const result = await tryCall(v.label, v.fn);
        if (result) return { status: 'ok', retcode: 0, data: { attempts, via: v.label, targetUid, selfUid } };
      }
      return { status: 'failed', retcode: 1500, data: { attempts, targetUid, selfUid }, message: '拍一拍没有可用原生方法（见 data.attempts）' };
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
    if (action.kind === 'friend_list') {
      // QQ NT: getBuddyList() 返回 { result: { data: [...] } } 一类的结构，形状不保证，逐层兜底取。
      const buddy = session.getBuddyService();
      const buddyArgs = [[false], [true], [0], [1]];
      let raw = null;
      let usedArgs = null;
      let lastBuddyError = null;
      for (const args of buddyArgs) {
        try { raw = await buddy.getBuddyList(...args); usedArgs = args; break; } catch (error) { lastBuddyError = error; }
      }
      if (usedArgs === null) throw fail('getBuddyList 参数不匹配：' + (lastBuddyError && lastBuddyError.message), 1500);
      const pick = value => (value && value.result && value.result.data) || (value && value.data) || value || [];
      const list = pick(raw);
      const arr = Array.isArray(list) ? list : (list?.buddies ?? list?.list ?? []);
      return { status: 'ok', retcode: 0, data: arr.map(item => ({
        user_id: (item?.uin ?? item?.uid ?? null),
        nickname: String(item?.nick ?? item?.nickname ?? ''),
        remark: String(item?.remark ?? item?.cardName ?? ''),
        raw_shape: item && typeof item === 'object' ? Object.keys(item).slice(0, 12) : null,
      })) };
    }
    if (action.kind === 'stranger') {
      const detail = await session.getProfileService().getUserDetailInfoByUin(action.uin);
      return { status: 'ok', retcode: 0, data: {
        user_id: String(action.uin),
        detail,
        raw_shape: detail && typeof detail === 'object' ? Object.keys(detail) : null,
      } };
    }
    if (action.kind === 'fav_emoji') {
      const msgSvc = session.getMsgService();
      const n = action.count;
      const favCandidates = [[n, 0, 0, 0], [n, 0, false, false], [n, 0, 0, false], [n, 0, '', 0], [0, n, 0, 0]];
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
      return { status: 'ok', retcode: 0, data: list, ...(list.length ? {} : { message: 'fetchFavEmojiList 没有取到表情：args=' + JSON.stringify(usedFavArgs) + ' raw_shape=' + JSON.stringify(raw && typeof raw === 'object' ? Object.keys(raw).slice(0, 12) : null) + ' emojiListType=' + String(describeType(raw && raw.emojiInfoList)) + ' resultType=' + String(describeType(raw && raw.result)) }) };
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
        if (action.kind === 'get_image') {
          if (typeof options.resolveMedia !== 'function') throw fail('当前会话不支持获取图片', 1500);
          const media = await options.resolveMedia(action.key, 'image');
          ensure();
          return media;
        }
        if (admin.kinds.has(action.kind)) {
          return await admin.run(action, {
            session, ensure, groupList,
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


// ==== COMPAT_ACTIONS (2026-11-18) ====
// SnowLuma 的动作表 → OpenQQ 原生服务的启发式映射。先保证"动作存在、有结构化回执"，再按真实调用精修。
const COMPAT_ACTIONS = new Set(["can_at_all","can_send_image","can_send_record","delete_custom_face","delete_essence_msg","delete_flash_file","delete_friend","delete_group_file","delete_group_file_folder","delete_group_folder","delete_group_tag","delete_msg","delete_qzone_msg","fetch_custom_face","fetch_custom_face_detail","fetch_emoji_like","fetch_face_entity","fetch_ptt_text","fetch_super_face_id","fetch_sys_faces","get_ai_characters","get_ai_record","get_clientkey","get_collection_list","get_cookies","get_credentials","get_csrf_token","get_doubt_friends_add_request","get_emoji_likes","get_essence_msg_list","get_file","get_fileset_id","get_fileset_info","get_flash_file_list","get_flash_file_url","get_forward_msg","get_friend_list","get_friend_msg_history","get_friends_with_category","get_group_admin_permissions","get_group_admin_settings","get_group_album_list","get_group_album_media_list","get_group_at_all_remain","get_group_detail_info","get_group_file_system_info","get_group_file_url","get_group_files_by_folder","get_group_honor_info","get_group_ignore_add_request","get_group_ignored_notifies","get_group_info","get_group_info_ex","get_group_list","get_group_member_info","get_group_member_list","get_group_msg_history","get_group_root_files","get_group_share_link","get_group_shut_list","get_group_signed_list","get_group_system_msg","get_group_tags","get_group_todo_list","get_image","get_login_info","get_mini_app_ark","get_msg","get_msg_emoji_likes","get_online_clients","get_private_file_url","get_profile_like","get_ptt_text","get_qun_album_list","get_qzone_feed_detail","get_qzone_feeds","get_qzone_home_feeds","get_qzone_msg_detail","get_qzone_msg_list","get_qzone_profile","get_recent_contact","get_record","get_record_text","get_rkey","get_rkey_server","get_share_link","get_status","get_stranger_info","get_unidirectional_friend_list","get_version_info","mark_group_msg_as_read","mark_msg_as_read","mark_private_msg_as_read","send_ark_share","send_custom_face","send_flash_msg","send_forward_msg","send_group_ai_record","send_group_ark_share","send_group_forward_msg","send_group_msg","send_group_sign","send_like","send_msg","send_packet","send_poke","send_private_forward_msg","send_private_msg","send_qzone_msg","send_to_new_members","set_diy_online_status","set_essence_msg","set_friend_add_request","set_friend_remark","set_friends_category","set_group_add_option","set_group_admin","set_group_ban","set_group_card","set_group_kick","set_group_leave","set_group_name","set_group_remark","set_group_special_title","set_group_whole_ban","set_input_status","set_msg_emoji_like","set_online_status","set_qq_avatar","set_qq_profile","set_self_longnick","upload_group_file","upload_private_file","upload_forward_msg"]);
// 启发式映射已知会猜错的：宁可明确报"待精确实现"，也不返回语义错误的数据。
const COMPAT_DENY = new Set([
  'get_group_todo_list',    // 会匹到 getGroupList
  'fetch_sys_faces',        // 会匹到 fetchMarketEmoticonFaceImages（返回 None）
  'get_recent_contact',     // 会匹到 getContactUnreadCnt（未读数不是最近会话）
  'get_online_clients',     // 会匹到 getOnLineDev（原生回 2001002 空）
]);
const COMPAT_ALIAS = {
  get_friends_with_category: 'get_friend_list',
  get_friend_msg_history: 'get_private_msg_history',
};
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
