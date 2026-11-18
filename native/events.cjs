'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { fail } = require('./common.cjs');
const { readSystemEvent } = require('./system.cjs');
const validUin = value => /^[1-9]\d*$/.test(String(value)) && Number.isSafeInteger(Number(value));
const now = () => Math.floor(Date.now() / 1000);
// Merged-forward expansion limits: nesting depth, messages per root and serialized size (IPC frames cap at 1 MiB).
const FORWARD_DEPTH = 3;
const FORWARD_LIMIT = 200;
const FORWARD_BYTES = 512 * 1024;
// A member who just joined or left is often unknown to every UID store until QQ pushes the refreshed member list.
const MEMBER_RETRY_MS = 1500;
const MEDIA_TIMEOUT_MS = 12000;

async function existingFile(filePath) {
  if (typeof filePath !== 'string' || !filePath) return undefined;
  try {
    const info = await fs.promises.stat(filePath);
    return info.isFile() && info.size > 0 ? filePath : undefined;
  } catch { return undefined; }
}

async function pickThumbPath(thumbPath) {
  const entries = thumbPath instanceof Map ? [...thumbPath.entries()]
    : thumbPath && typeof thumbPath === 'object' ? Object.entries(thumbPath) : [];
  entries.sort(([a], [b]) => (Number(a) === 0 ? -1 : Number(b) === 0 ? 1 : Number(b) - Number(a)));
  for (const [, candidate] of entries) {
    const ready = await existingFile(candidate);
    if (ready) return ready;
  }
  return undefined;
}

function createEventReceiver(session, self, report, current, { memberRetryMs = MEMBER_RETRY_MS, mediaTimeoutMs = MEDIA_TIMEOUT_MS } = {}) {
  const cache = new Map();
  const seenShapes = new Set();
  const members = new Map();
  const started = now();
  let friends;
  let syncing = true;
  // Groups QQ has told us about, for get_group_list / get_group_info. QQ answers a refresh through the group listener.
  const groups = { map: new Map(), version: 0 };
  const groupWaiters = new Set();
  groups.waitForUpdate = (since, ms) => new Promise(resolve => {
    const finish = () => { clearTimeout(timer); groupWaiters.delete(finish); resolve(); };
    const timer = setTimeout(finish, ms);
    groupWaiters.add(finish);
    if (groups.version !== since) finish();
  });
  function updateGroups(type, list) {
    if (!Array.isArray(list)) return;
    for (const item of list) {
      if (!item || !/^\d+$/.test(String(item.groupCode))) continue;
      if (type === 3) groups.map.delete(String(item.groupCode));
      else groups.map.set(String(item.groupCode), item);
    }
    groups.version++;
    for (const finish of [...groupWaiters]) finish();
  }
  const remember = (uid, uin) => {
    if (uid && validUin(uin)) cache.set(uid, String(uin));
    if (cache.size > 10000) cache.delete(cache.keys().next().value);
  };
  remember(self.uid, self.uin);

  const inflight = new Map();
  async function uin(uid, hint) {
    if (!current()) throw new Error('会话已失效');
    if (validUin(hint)) { remember(uid, hint); return String(hint); }
    if (validUin(uid)) return String(uid);
    if (typeof uid !== 'string' || !uid) throw new Error('事件缺少用户 UID');
    if (cache.has(uid)) return cache.get(uid);
    // NT UIDs are always "u_"-prefixed; anything else (e.g. the "0" placeholder) can never convert,
    // so fail fast instead of spending the 5-second lookup budget.
    if (!/^u_[\w-]+$/.test(uid)) throw new Error(`UID 格式无效：${uid.slice(0, 40)}`);
    // Bursts (a message with several @, a member leaving several groups) share one native lookup.
    if (inflight.has(uid)) return inflight.get(uid);
    const pending = lookup(uid).finally(() => inflight.delete(uid));
    inflight.set(uid, pending);
    return pending;
  }
  // Optional identities (operators, @ targets) degrade instead of discarding the whole event.
  async function optionalUin(uid, stage, hint) {
    try { return await uin(uid, hint); }
    catch (error) {
      if (!current()) throw error;
      emit({ type: 'event_error', stage, error: error.message + '，已按未知处理并继续上报' });
      return undefined;
    }
  }
  // The subject of a membership notice gets one delayed retry (member list pushes fill the cache meanwhile),
  // then degrades to unknown like an operator, so the join/leave itself is still reported.
  async function memberUin(uid, stage) {
    try { return await uin(uid); }
    catch (error) {
      if (!current()) throw error;
      await new Promise(resolve => setTimeout(resolve, memberRetryMs));
      return optionalUin(uid, stage);
    }
  }

  async function lookup(uid) {
    let timer;
    let finished = false;
    // Same fallback order as mature NTQQ bridges: strangers and members who just left a group
    // are often missing from the friend/profile store but still known to the group service.
    const lookups = [
      async () => (await session.getUixConvertService().getUin([uid]))?.uinInfo?.get(uid),
      async () => (await session.getProfileService().getUinByUid('FriendsServiceImpl', [uid]))?.get(uid),
      async () => (await session.getGroupService().getUinByUids([uid]))?.uins?.get(uid),
    ];
    const timeout = Symbol('timeout');
    let result;
    try {
      result = await Promise.race([
        (async () => {
          for (const lookup of lookups) {
            if (!current() || finished) return undefined;
            let value;
            try { value = await lookup(); } catch {}
            if (validUin(value)) return value;
          }
          return undefined;
        })(),
        new Promise(resolve => { timer = setTimeout(() => resolve(timeout), 5000); }),
      ]);
    } finally { finished = true; clearTimeout(timer); }
    if (result === timeout) throw new Error(`UID ${uid} 转 QQ 号超时（5 秒）`);
    if (!validUin(result)) throw new Error(`UID ${uid} 未能转换为 QQ 号（UixConvert/Profile/Group 均无映射）`);
    remember(uid, result);
    return String(result);
  }

  function emit(event) { if (current()) report(event); }
  function notice(event, key, time = now(), message) {
    emit({ type: 'notice', self, event, key, time, message });
  }
  async function batch(values, action, stage) {
    if (!Array.isArray(values)) throw new Error('事件列表必须为数组');
    await Promise.all(values.map(value => Promise.resolve().then(() => current() ? action(value) : undefined).catch(error => {
      emit({ type: 'event_error', stage, error: error.message });
    })));
  }
  function native(source, name, args) {
    // Unknown callbacks report structure once, never opaque network buffers or credentials.
    const key = `${source}/${name}`;
    if (seenShapes.has(key)) return;
    if (seenShapes.size >= 500) seenShapes.delete(seenShapes.values().next().value);
    seenShapes.add(key);
    const shape = value => value === null ? 'null' : Array.isArray(value) ? `array(${value.length})`
      : value instanceof Map ? `map(${value.size})` : typeof value === 'object' ? Object.keys(value).slice(0, 50) : typeof value;
    emit({ type: 'native_callback', source, event: name, argument_shapes: args.map(shape) });
  }

  // Reply sends need msgSeq/clientSeq of the quoted message; keep them for recently seen messages.
  const recent = new Map();
  function record(input, senderUin = input.senderUin) {
    if (!/^\d+$/.test(String(input?.msgId ?? ''))) return;
    recent.set(`${input.chatType}:${input.peerUid}:${input.msgId}`, { msgId: String(input.msgId), msgSeq: String(input.msgSeq ?? ''),
      clientSeq: String(input.clientSeq ?? ''), senderUin: String(senderUin ?? ''), senderUid: String(input.senderUid ?? '') });
    if (recent.size > 5000) recent.delete(recent.keys().next().value);
  }
  const lookupRecent = ref => recent.get(`${ref.chatType}:${ref.peerUid}:${ref.msgId}`);

  // Received rich-media index (for get_image) and download completion waiters (onRichMediaDownloadComplete).
  const mediaCache = new Map();
  const downloadWaiters = new Map();
  const inflightMedia = new Map();
  function cacheMediaKey(key, entry) {
    if (typeof key !== 'string' || !key) return;
    mediaCache.delete(key);
    mediaCache.set(key, entry);
    if (mediaCache.size > 5000) mediaCache.delete(mediaCache.keys().next().value);
  }
  function rememberMedia(element, ctx, msgId, resolvedPath) {
    const map = { 2: 'picElement', 3: 'fileElement', 4: 'pttElement', 5: 'videoElement' };
    const field = map[element?.elementType];
    const value = field ? element[field] : null;
    if (!value || typeof value !== 'object') return;
    const entry = {
      elementType: element.elementType,
      chatType: ctx.peer.chatType,
      peerUid: String(ctx.peer.peerUid),
      msgId: String(msgId ?? ''),
      elementId: String(element.elementId ?? ''),
      fileName: String(value.fileName ?? ''),
      md5: String(value.md5HexStr ?? value.fileMd5 ?? ''),
      fileUuid: String(value.fileUuid ?? ''),
      fileSize: Number(value.fileSize ?? 0) || 0,
      path: typeof resolvedPath === 'string' && resolvedPath ? resolvedPath : (typeof value.sourcePath === 'string' && value.sourcePath ? value.sourcePath : (typeof value.filePath === 'string' ? value.filePath : '')),
      url: typeof value.originImageUrl === 'string' && /^https?:\/\//.test(value.originImageUrl) ? value.originImageUrl : '',
      thumbPath: value.thumbPath,
    };
    cacheMediaKey(entry.fileName, entry);
    cacheMediaKey(entry.md5, entry);
    cacheMediaKey(entry.fileUuid, entry);
    cacheMediaKey(entry.path, entry);
    if (entry.msgId && entry.elementId) cacheMediaKey(`${entry.msgId}:${entry.elementId}`, entry);
  }
  function resolveDownloadNotify(notify) {
    if (!notify || typeof notify !== 'object') return;
    const key = `${notify.msgId ?? ''}:${notify.msgElementId ?? ''}`;
    const waiters = downloadWaiters.get(key);
    if (!waiters || !waiters.size) return;
    // Ignore thumbnail progress/completion while waiting for an original (thumbSize=0) download.
    if (notify.thumbSize !== undefined && Number(notify.thumbSize) !== 0) return;
    const errCode = notify.fileErrCode !== undefined && String(notify.fileErrCode) !== '' && String(notify.fileErrCode) !== '0';
    const failed = errCode || (notify.trasferStatus !== undefined && ![0, 2].includes(Number(notify.trasferStatus)));
    for (const waiter of [...waiters]) {
      if (failed) waiter.reject(new Error(notify.fileErrMsg || `QQ 富媒体下载失败 (${notify.fileErrCode || notify.trasferStatus})`));
      else waiter.resolve(typeof notify.filePath === 'string' ? notify.filePath : '');
    }
  }
  async function downloadPicture(entry) {
    const ready = await existingFile(entry.path);
    if (ready) return ready;
    const service = session.getMsgService?.();
    if (typeof service?.downloadRichMedia !== 'function' || !/^\d+$/.test(entry.msgId) || !entry.elementId) {
      return pickThumbPath(entry.thumbPath);
    }
    const inflightKey = `${entry.chatType}:${entry.peerUid}:${entry.msgId}:${entry.elementId}`;
    if (inflightMedia.has(inflightKey)) return inflightMedia.get(inflightKey);
    const task = (async () => {
      const waitKey = `${entry.msgId}:${entry.elementId}`;
      let timer;
      let waiter;
      const completed = new Promise((resolve, reject) => {
        waiter = {
          resolve: value => { clearTimeout(timer); waiters.delete(waiter); if (!waiters.size) downloadWaiters.delete(waitKey); resolve(value); },
          reject: error => { clearTimeout(timer); waiters.delete(waiter); if (!waiters.size) downloadWaiters.delete(waitKey); reject(error); },
        };
        let waiters = downloadWaiters.get(waitKey);
        if (!waiters) { waiters = new Set(); downloadWaiters.set(waitKey, waiters); }
        waiters.add(waiter);
        timer = setTimeout(() => waiter.reject(new Error('图片下载超时')), mediaTimeoutMs);
      });
      completed.catch(() => {});
      try {
        const result = await service.downloadRichMedia({
          fileModelId: '0',
          downSourceType: 0,
          triggerType: 1,
          msgId: entry.msgId,
          chatType: entry.chatType,
          peerUid: entry.peerUid,
          elementId: entry.elementId,
          thumbSize: 0,
          filePath: '',
          downloadType: 1,
        });
        if (!current()) throw new Error('会话已失效');
        if (result?.result !== undefined && result.result !== 0) {
          throw new Error(result.errMsg || `QQ 拒绝下载图片 (${result.result})`);
        }
        const already = await existingFile(entry.path);
        if (already) {
          waiter.resolve(already);
          return already;
        }
        const notifiedPath = await completed;
        const verified = await existingFile(notifiedPath) || await existingFile(entry.path);
        if (verified) { entry.path = verified; return verified; }
        throw new Error('QQ 下载完成但未生成图片文件');
      } catch (error) {
        waiter?.reject(error);
        throw error;
      } finally {
        clearTimeout(timer);
      }
    })().finally(() => inflightMedia.delete(inflightKey));
    inflightMedia.set(inflightKey, task);
    return task;
  }
  async function resolveMedia(key, kind) {
    if (typeof key !== 'string' || !key.trim()) throw fail('缺少图片标识 file', 1400);
    const trimmed = key.trim();
    const entry = mediaCache.get(trimmed) ?? mediaCache.get(path.basename(trimmed));
    if (!entry) throw fail('找不到对应的图片记录（仅支持本次运行期间收到的图片）', 1404);
    if (kind === 'image' && entry.elementType !== 2) throw fail('该标识不是图片', 1400);
    let localPath = await existingFile(entry.path);
    if (!localPath) {
      try { localPath = await downloadPicture(entry); }
      catch (error) {
        localPath = await pickThumbPath(entry.thumbPath);
        if (!localPath) throw fail(error.message, 1500);
      }
    }
    if (!localPath) throw fail('图片文件不存在或尚未下载', 1404);
    entry.path = localPath;
    cacheMediaKey(localPath, entry);
    const stat = await fs.promises.stat(localPath);
    return {
      file: localPath,
      file_name: entry.fileName || path.basename(localPath),
      file_size: stat.size || entry.fileSize,
      url: entry.url,
    };
  }

  // Merged forwards: QQ fetches the content with getMultiMsg(peer, rootMsgId, parentMsgId), where root is the
  // message in the chat and parent is the message that directly carries the (possibly nested) forward.
  async function multiMsg(peer, root, parent) {
    let timer;
    try {
      const result = await Promise.race([
        session.getMsgService().getMultiMsg({ chatType: peer.chatType, peerUid: peer.peerUid, guildId: '' }, root, parent),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('合并转发内容获取超时（8 秒）')), 8000); }),
      ]);
      if (result?.result !== undefined && result.result !== 0) throw new Error(`QQ 拒绝获取合并转发：${result.errMsg || result.result}`);
      if (!Array.isArray(result?.msgList)) throw new Error('合并转发内容结构未适配');
      return result.msgList;
    } finally { clearTimeout(timer); }
  }
  async function forwardMessages(ctx, parent) {
    const list = await multiMsg(ctx.peer, ctx.root, parent);
    const messages = [];
    for (const item of list) {
      if (!current()) throw new Error('会话已失效');
      if (ctx.budget.left-- <= 0) break;
      remember(item.senderUid, item.senderUin);
      let senderUin = '0';
      // Forwarded authors are often strangers; the nickname still identifies them, so a missing QQ number is not an error.
      try { senderUin = await uin(item.senderUid, item.senderUin); } catch (error) { if (!current()) throw error; }
      messages.push({ msgId: String(item.msgId ?? ''), msgTime: item.msgTime, senderUin, senderUid: item.senderUid,
        sendNickName: item.sendNickName, sendMemberName: item.sendMemberName,
        elements: await prepare(Array.isArray(item.elements) ? item.elements : [], { ...ctx, depth: ctx.depth + 1 }, String(item.msgId ?? '')) });
    }
    return messages;
  }
  async function expandForward(ref) {
    return forwardMessages({ peer: { chatType: ref.chatType, peerUid: ref.peerUid }, root: ref.root, depth: 0, budget: { left: FORWARD_LIMIT } }, ref.parent);
  }
  const forwardSize = value => JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? String(item) : item).length;

  async function prepare(elements, ctx, msgId) {
    return Promise.all(elements.map(async element => {
      const text = element.textElement;
      if (element.elementType === 1 && Number(text?.atType) === 2 && !validUin(text.atUid)) {
        // An unresolvable @ target keeps the native element (delivered as openqq_element) rather than losing the message.
        const target = await optionalUin(text.atNtUid, 'msg/at');
        return target ? { ...element, textElement: { ...text, atUid: target } } : element;
      }
      if (element.elementType === 2 && element.picElement) {
        const pic = element.picElement;
        if (ctx.skipDownload) {
          rememberMedia(element, ctx, msgId, pic.sourcePath);
          return element;
        }
        let resolved = await existingFile(pic.sourcePath);
        if (!resolved && typeof session.getMsgService?.()?.downloadRichMedia === 'function' && /^\d+$/.test(String(msgId)) && element.elementId) {
          const entry = {
            elementType: 2,
            chatType: ctx.peer.chatType,
            peerUid: String(ctx.peer.peerUid),
            msgId: String(msgId),
            elementId: String(element.elementId),
            fileName: String(pic.fileName ?? ''),
            md5: String(pic.md5HexStr ?? ''),
            fileUuid: String(pic.fileUuid ?? ''),
            fileSize: Number(pic.fileSize ?? 0) || 0,
            path: String(pic.sourcePath ?? ''),
            url: typeof pic.originImageUrl === 'string' && /^https?:\/\//.test(pic.originImageUrl) ? pic.originImageUrl : '',
            thumbPath: pic.thumbPath,
          };
          try {
            resolved = await downloadPicture(entry);
          } catch (error) {
            if (!current()) throw error;
            emit({ type: 'event_error', stage: 'msg/image', error: error.message + '，将继续上报消息' });
            resolved = await pickThumbPath(pic.thumbPath);
          }
          rememberMedia(element, ctx, msgId, resolved || '');
          return { ...element, picElement: { ...pic, sourcePath: resolved || '' } };
        }
        if (!resolved) resolved = await pickThumbPath(pic.thumbPath);
        rememberMedia(element, ctx, msgId, resolved || pic.sourcePath);
        return resolved ? { ...element, picElement: { ...pic, sourcePath: resolved } } : element;
      }
      if ([3, 4, 5].includes(element.elementType)) rememberMedia(element, ctx, msgId);
      const forward = element.multiForwardMsgElement;
      if (element.elementType === 16 && forward && /^\d+$/.test(msgId)) {
        const ref = { chatType: ctx.peer.chatType, peerUid: ctx.peer.peerUid, root: ctx.root, parent: msgId };
        let messages;
        if (ctx.depth < FORWARD_DEPTH) {
          try {
            messages = await forwardMessages(ctx, msgId);
            if (forwardSize(messages) > FORWARD_BYTES) {
              messages = undefined;
              emit({ type: 'event_error', stage: 'msg/forward', error: '合并转发内容超过 512 KiB，事件只携带 id，请用 get_forward_msg 获取' });
            }
          } catch (error) {
            if (!current()) throw error;
            emit({ type: 'event_error', stage: 'msg/forward', error: error.message + '，事件只携带 id，可稍后用 get_forward_msg 重试' });
          }
        }
        return { ...element, multiForwardMsgElement: { ...forward, openqq: { ...ref, ...(messages ? { messages } : {}) } } };
      }
      return element;
    }));
  }

  async function message(input, update = false) {
    if (![1, 2, 100].includes(input.chatType)) { native('msg', 'unsupported_chat', [input]); return; }
    remember(input.senderUid, input.senderUin);
    if (input.chatType !== 2) remember(input.peerUid, input.peerUin);
    const gray = input.elements?.find(element => element.elementType === 8)?.grayTipElement;
    const key = `${input.chatType}:${input.peerUid}:${input.msgId}`;
    const time = input.recallTime && Number(input.recallTime) > 0
      ? Math.floor(Number(input.recallTime) / (Number(input.recallTime) > 1e11 ? 1000 : 1)) : input.msgTime;
    if (gray?.revokeElement) {
      if (update && (!Number(input.recallTime) || Number(time) < started - 5)) return;
      const user = await uin(input.senderUid, input.senderUin);
      // Only group recalls carry an operator; a friend recall must not fail on an unused lookup.
      const operator = input.chatType === 2 ? await optionalUin(gray.revokeElement.operatorUid, 'msg/recall/operator',
        gray.revokeElement.isSelfOperate ? self.uin : undefined) : undefined;
      notice({ notice_type: input.chatType === 2 ? 'group_recall' : 'friend_recall', user_id: user,
        ...(input.chatType === 2 ? { group_id: input.peerUin ?? input.peerUid, operator_id: operator ?? 0,
          ...(operator ? {} : { openqq_operator_unknown: true }) } : {}),
      }, `recall:${key}`, time, input);
      return;
    }
    if (update) return;
    // Offline sync replays placeholder records with no elements; there is nothing to report.
    // Note each msgType once at debug level (type numbers only, never content) instead of warning per record.
    if (!Array.isArray(input.elements) || !input.elements.length) {
      native('msg', `empty_message(msgType=${Number(input.msgType)},subMsgType=${Number(input.subMsgType)})`, []);
      return;
    }
    if (gray && process.env.OPENQQ_GRAYTIP_DUMP !== '0' && !globalThis.__openqqGrayDumped) {
      globalThis.__openqqGrayDumped = true;
      try { console.error('[graytip-shape] ' + JSON.stringify(gray).slice(0, 2000)); } catch { /* best effort */ }
    }
    if (String(gray?.jsonGrayTipElement?.busiId) === '1061') {
      if (input.elements.length !== 1) throw new Error('戳一戳包含非预期的混合元素');
      let data;
      try { data = JSON.parse(gray.jsonGrayTipElement.jsonStr); } catch { throw new Error('戳一戳 JSON 无效'); }
      const users = Array.isArray(data?.items) ? data.items.filter(item => item?.uid) : [];
      if (users.length !== 2 || users.some(item => typeof item.uid !== 'string')) throw new Error('戳一戳缺少操作者或被戳者 UID');
      const [userUin, targetUin] = await Promise.all(users.map(item => uin(item.uid)));
      emit({ type: 'message', self, message: { ...input, poke: { userUin, targetUin } } });
      return;
    }
    if (input.chatType !== 2 && String(gray?.jsonGrayTipElement?.busiId) === '19324') {
      if (friends) friends.set(input.peerUid, input.peerUin);
      notice({ notice_type: 'friend_add', user_id: await uin(input.peerUid, input.peerUin) }, `friend-add:${key}`, input.msgTime);
      return;
    }
    if (gray?.groupElement && input.chatType === 2) {
      const group = gray.groupElement;
      const group_id = input.peerUin ?? input.peerUid;
      if (group.shutUp) {
        const ban = group.shutUp;
        const duration = Number(ban.duration);
        // user_id 0 means "whole group" in OneBot, so an unresolved member must still fail loudly;
        // only the operator may degrade.
        const operator = await optionalUin(ban.admin?.uid, 'msg/ban/operator');
        notice({ notice_type: 'group_ban', group_id,
          user_id: ban.member?.uid ? await uin(ban.member.uid) : 0,
          operator_id: operator ?? 0, ...(operator ? {} : { openqq_operator_unknown: true }), duration,
          sub_type: duration > 0 ? 'ban' : 'lift_ban',
        }, `ban:${key}`, input.msgTime);
        return;
      }
      if (group.type === 5) {
        notice({ notice_type: 'group_name', group_id, user_id: await uin(group.memberUid), group_name: String(group.groupName ?? '') }, key, input.msgTime);
        return;
      }
      // Membership changes use authoritative system pushes, which include the subtype and operator.
      if (group.type === 1) return;
    }
    if (gray) {
      notice({ notice_type: 'openqq_gray_tip', chat_type: input.chatType, peer_id: input.peerUin ?? input.peerUid,
        element: gray }, `gray:${key}`, input.msgTime);
      return;
    }
    const senderUin = await uin(input.senderUid, input.senderUin);
    record(input, senderUin);
    const elements = await prepare(input.elements ?? [], { peer: { chatType: input.chatType, peerUid: String(input.peerUid) },
      root: String(input.msgId), depth: 0, budget: { left: FORWARD_LIMIT }, skipDownload: String(senderUin) === self.uin }, String(input.msgId));
    emit({ type: 'message', self, message: { ...input, senderUin, elements } });
    if (input.chatType === 2) for (const element of elements) {
      const file = element.fileElement;
      if (element.elementType === 3 && file?.fileUuid) notice({ notice_type: 'group_upload', group_id: input.peerUin ?? input.peerUid,
        user_id: senderUin, file: { id: String(file.fileUuid), name: file.fileName, size: file.fileSize, busid: file.fileBizId ?? 0 },
      }, `upload:${key}:${element.elementId ?? file.fileUuid}`, input.msgTime);
    }
  }

  async function groupNotifies(notifies) {
    await batch(notifies, async item => {
      const group_id = item.group?.groupCode;
      const key = `group-notify:${item.seq}:${item.type}`;
      const rawTime = /^\d+$/.test(String(item.seq)) ? Number(BigInt(item.seq) / 1000000n) : 0;
      const time = rawTime > 0 ? rawTime : now();
      if ([1, 5, 7].includes(item.type) && item.status === 1) {
        emit({ type: 'request', self, key, time, event: { request_type: 'group', group_id,
          sub_type: item.type === 1 ? 'invite' : 'add', user_id: await uin(item.type === 1 ? item.user2?.uid : item.user1?.uid),
          // The flag carries everything set_group_add_request needs to answer this notification.
          comment: String(item.postscript ?? ''), flag: `g:${group_id}:${item.type}:${item.seq}`,
        } });
      } else native('group', 'onGroupNotifiesUpdated', [item]);
    }, 'group/notifies');
  }

  async function receive(source, name, args) {
    if (source === 'msg') {
      if (name === 'onNtMsgSyncStart' || name === 'onNtMsgSyncEnd') {
        syncing = name === 'onNtMsgSyncStart';
        emit({ type: 'sync_state', syncing });
        return;
      }
      if (['onRecvMsg', 'onRecvOnlineFileMsg', 'onMsgInfoListUpdate'].includes(name)) {
        await batch(args[0], value => message(value, name === 'onMsgInfoListUpdate'), name);
        return;
      }
      if (name === 'onRichMediaDownloadComplete') { resolveDownloadNotify(args[0]); return; }
      if (name === 'onRichMediaProgerssUpdate' || name === 'onRichMediaUploadComplete') return;
      if (name === 'onRecvSysMsg') {
        const event = readSystemEvent(args[0]);
        if (!event) { native(source, name, args); return; }
        const { user_uid, operator_uid, ...fields } = event.event;
        if (!user_uid && fields.openqq_reason !== 'disband') throw new Error('系统通知缺少成员 UID');
        const member = await memberUin(user_uid || self.uid, `${source}/${name}/member`);
        fields.user_id = member ?? 0;
        if (!member) fields.openqq_user_unknown = true;
        if (operator_uid) {
          // A missing operator mapping must not discard the membership change itself.
          const operator = await optionalUin(operator_uid, `${source}/${name}/operator`);
          fields.operator_id = operator ?? 0;
          if (!operator) fields.openqq_operator_unknown = true;
        } else if (fields.notice_type === 'group_decrease' && fields.sub_type === 'leave') {
          fields.operator_id = fields.user_id;
          if (!member) fields.openqq_operator_unknown = true;
        }
        if (fields.notice_type === 'group_decrease' && fields.sub_type === 'kick' && fields.user_id === self.uin) fields.sub_type = 'kick_me';
        notice(fields, event.key, event.time);
        return;
      }
      if (name === 'onInputStatusPush') {
        const value = args[0];
        if (!value || typeof value !== 'object') return;
        notice({ notice_type: 'notify', sub_type: 'input_status', user_id: await uin(value.fromUin),
          status_text: String(value.statusText ?? ''), event_type: value.eventType }, undefined);
        return;
      }
      if (name === 'onKickedOffLine') {
        emit({ type: 'offline', self_id: self.uin });
        notice({ notice_type: 'bot_offline', reason: String(args[0]?.tipsDesc ?? '') });
        return;
      }
    }
    if (source === 'group') {
      if (name === 'onGroupListUpdate') { updateGroups(args[0], args[1]); return; }
      if (name === 'onGroupNotifiesUpdated') return groupNotifies(args[1]);
      if (name === 'onGroupNotifiesUpdatedV2') return groupNotifies(args[2]);
      if (name === 'onGroupSingleScreenNotifies') return groupNotifies(args[2]);
      if (name === 'onMemberListChange') {
        // Member list pushes carry uid → uin pairs; caching them lets membership notices and mentions resolve.
        const infos = args[0]?.infos;
        if (!(infos instanceof Map)) { native(source, name, args); return; }
        for (const [uid, info] of infos) remember(uid, info?.uin);
        return;
      }
      if (name === 'onMemberInfoChange') {
        for (const [uid, info] of args[2] instanceof Map ? args[2] : []) {
          remember(uid, info.uin);
          const key = `${args[0]}:${uid}`;
          const previous = members.get(key);
          members.set(key, { cardName: info.cardName, memberSpecialTitle: info.memberSpecialTitle });
          if (members.size > 10000) members.delete(members.keys().next().value);
          if (previous && info.cardName !== undefined && previous.cardName !== undefined && info.cardName !== previous.cardName) {
            notice({ notice_type: 'group_card', group_id: args[0], user_id: await uin(uid, info.uin), card_old: previous.cardName, card_new: info.cardName });
          }
          if (previous && info.memberSpecialTitle !== undefined && previous.memberSpecialTitle !== undefined && info.memberSpecialTitle !== previous.memberSpecialTitle) {
            notice({ notice_type: 'notify', sub_type: 'title', group_id: args[0], user_id: await uin(uid, info.uin), title: info.memberSpecialTitle });
          }
        }
        return;
      }
    }
    if (source === 'buddy') {
      if (name === 'onBuddyReqChange') {
        await batch(args[0]?.buddyReqs, async req => {
          if (req.isInitiator || !req.isUnread || (req.isDecide && req.reqType !== 13)) return;
          emit({ type: 'request', self, time: req.reqTime, key: `friend:${req.friendUid}:${req.reqTime}`, event: {
            request_type: 'friend', user_id: await uin(req.friendUid), comment: String(req.extWords ?? ''), flag: `f:${req.friendUid}:${req.reqTime}`,
          } });
        }, 'buddy/requests');
        return;
      }
      if (name === 'onBuddyListChange') {
        if (!Array.isArray(args[0]) || args[0].some(category => !Array.isArray(category.buddyList))) throw new Error('好友列表回调结构未适配');
        const next = new Map();
        for (const category of args[0] ?? []) for (const buddy of category.buddyList ?? []) {
          remember(buddy.uid, buddy.uin);
          next.set(buddy.uid, buddy.uin);
        }
        if (friends && !syncing) {
          for (const [uid, hint] of next) if (!friends.has(uid)) notice({ notice_type: 'friend_add', user_id: await uin(uid, hint) });
          for (const [uid, hint] of friends) if (!next.has(uid)) notice({ notice_type: 'friend_delete', user_id: await uin(uid, hint) });
        }
        // The first complete list establishes a baseline; it is not a wave of new friends.
        friends = next;
        return;
      }
    }
    native(source, name, args);
  }
  // Services the action handler shares: forward fetching, quoted-message metadata, media cache and self-sent records.
  receive.expandForward = expandForward;
  receive.lookupRecent = lookupRecent;
  receive.resolveMedia = resolveMedia;
  receive.record = record;
  receive.groups = groups;
  return receive;
}

module.exports = { createEventReceiver };
