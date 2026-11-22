import { convertSegment, cqString } from './segments.mjs';

function integer(value, field, min = 0) {
  if ((typeof value !== 'string' && typeof value !== 'number') || !/^-?\d+$/.test(String(value)) || !Number.isSafeInteger(Number(value)) || Number(value) < min) {
    throw new Error(field + ' 不是有效的 OneBot 数值标识');
  }
  return Number(value);
}
const id = (value, field) => integer(value, field, 1);

// `idStore` (src/idstore.mjs) keeps the id mapping across restarts; without one the ids start again from 1.
export function createEventConverter({ mediaUrl, idStore } = {}) {
  const ids = new Map();
  const refs = new Map();
  const seen = new Map();
  let nextId = 1;
  if (idStore) {
    const saved = idStore.load();
    nextId = saved.nextId;
    for (const [key, id, ref] of saved.entries) { ids.set(key, id); if (ref) refs.set(id, ref); }
  }
  const keyOf = (selfId, message, nativeId = message.msgId) => {
    if (!/^\d+$/.test(String(nativeId)) || (typeof nativeId === 'number' && !Number.isSafeInteger(nativeId))) {
      throw new Error('原生消息标识无效或已丢失精度');
    }
    return [selfId, message.chatType, message.peerUid, nativeId].join(':');
  };
  // Every OneBot id maps back to the native reference actions need (reply quotes, get_forward_msg).
  function messageId(key, ref) {
    if (!ids.has(key)) {
      ids.set(key, nextId);
      if (ref) refs.set(nextId, ref);
      nextId++;
      idStore?.schedule(() => ({ nextId, entries: [...ids].map(([entryKey, id]) => [entryKey, id, refs.get(id)]) }));
    }
    // The mapping keeps the latest 10000 ids; older ones stop resolving (and are no longer written to the store).
    if (ids.size > 10000) {
      const [, oldest] = ids.entries().next().value;
      ids.delete(ids.keys().next().value);
      refs.delete(oldest);
    }
    return ids.get(key);
  }
  const messageRef = (selfId, message, nativeId = message.msgId) => messageId(keyOf(selfId, message, nativeId),
    { kind: 'message', selfId, chatType: message.chatType, peerUid: String(message.peerUid), msgId: String(nativeId),
      // forwardMsg 的 msgInfos 要「消息 ID + 序号」成对出现：只填 msgId 时内核按记录找不到配对条目。
      // 收到的原生消息自带 msgSeq，存进 ref 一起带下去（老记录没有就保持空串）。
      msgSeq: String(message.msgSeq ?? '') });
  function forwardId(selfId, ref) {
    if (![ref?.root, ref?.parent].every(value => /^\d+$/.test(String(value)))) throw new Error('合并转发标识无效');
    return messageId(['forward', selfId, ref.chatType, ref.peerUid, ref.root, ref.parent].join(':'),
      { kind: 'forward', selfId, chatType: ref.chatType, peerUid: String(ref.peerUid), root: String(ref.root), parent: String(ref.parent) });
  }
  // Forwarded messages become go-cqhttp/NapCat compatible nodes: sender, time and the segments as message/content.
  function forwardNodes(selfId, ref, messages) {
    return messages.map(item => {
      const segments = (item.elements ?? []).map(element => convertSegment(element,
        original => messageRef(selfId, ref, original), inner => forwardSegment(selfId, inner), mediaUrl));
      const userId = /^[1-9]\d*$/.test(String(item.senderUin)) && Number.isSafeInteger(Number(item.senderUin)) ? Number(item.senderUin) : 0;
      const nickname = String(item.sendMemberName || item.sendNickName || '');
      const time = /^\d+$/.test(String(item.msgTime)) ? Number(item.msgTime) : 0;
      return { time, message_type: ref.chatType === 2 ? 'group' : 'private', user_id: userId,
        sender: { user_id: userId, nickname }, message: segments, content: segments, raw_message: cqString(segments), message_format: 'array' };
    });
  }
  function forwardSegment(selfId, ref) {
    const data = { id: String(forwardId(selfId, ref)) };
    if (Array.isArray(ref.messages)) data.content = forwardNodes(selfId, ref, ref.messages);
    return { type: 'forward', data };
  }
  function messageEvent(self, message) {
    if (![1, 2, 100].includes(message.chatType)) return null;
    const selfId = id(self.uin, 'self_id');
    if (!Array.isArray(message.elements) || !message.elements.length) throw new Error('原生消息元素为空');
    const grayTips = message.elements.filter(element => element.elementType === 8);
    if (grayTips.length && !message.poke) throw new Error('尚未支持的灰条通知');
    const time = id(message.msgTime, 'time');
    const groupId = message.chatType === 2 ? id(message.peerUin ?? message.peerUid, 'group_id') : undefined;
    const key = keyOf(selfId, message);
    let event;
    if (message.poke) {
      if (message.elements.length !== 1 || grayTips.length !== 1 || String(grayTips[0].grayTipElement?.jsonGrayTipElement?.busiId) !== '1061') throw new Error('戳一戳缺少原生灰条标识');
      event = { post_type: 'notice', notice_type: 'notify', sub_type: 'poke',
        user_id: id(message.poke.userUin, 'user_id'), target_id: id(message.poke.targetUin, 'target_id') };
    } else {
      const senderId = id(message.senderUin, 'user_id');
      if (senderId === selfId) return null;
      const segments = message.elements.map(element => convertSegment(element, original => messageRef(selfId, message, original),
        ref => forwardSegment(selfId, ref), mediaUrl));
      event = { post_type: 'message', message_type: message.chatType === 2 ? 'group' : 'private',
        sub_type: message.chatType === 2 ? 'normal' : message.chatType === 100 ? 'group' : 'other',
        message_id: messageRef(selfId, message), user_id: senderId, message: segments, raw_message: cqString(segments),
        font: 0, sender: { user_id: senderId, nickname: String(message.sendNickName ?? '') },
      };
      if (message.chatType === 2) {
        event.sender.card = String(message.sendMemberName ?? '');
        event.anonymous = null;
      }
    }
    if (groupId !== undefined) event.group_id = groupId;
    return { event: { time, self_id: selfId, ...event }, key: key + ':' + event.post_type };
  }
  function convert(raw) {
    let result;
    if (raw.type === 'message') result = messageEvent(raw.self, raw.message);
    else if (raw.type === 'notice' || raw.type === 'request') {
      const selfId = id(raw.self.uin, 'self_id');
      const event = { ...raw.event };
      const type = event.notice_type ?? event.request_type;
      if (!type) throw new Error('事件缺少类型');
      if (['group_admin', 'group_increase', 'group_decrease', 'group_ban', 'group_recall', 'group_upload', 'group_card', 'group_name', 'group'].includes(type)) event.group_id = id(event.group_id, 'group_id');
      // 0 is valid for whole-group bans and for membership notices whose member could not be resolved (flagged).
      const unknownMember = event.openqq_user_unknown === true && ['group_increase', 'group_decrease', 'group_admin'].includes(type);
      if (!['openqq_native', 'openqq_gray_tip', 'bot_offline'].includes(type)) event.user_id = integer(event.user_id, 'user_id', type === 'group_ban' || unknownMember ? 0 : 1);
      if ('target_id' in event) event.target_id = id(event.target_id, 'target_id');
      if ('operator_id' in event) event.operator_id = integer(event.operator_id, 'operator_id');
      if (['group_increase', 'group_decrease', 'group_ban', 'group_recall'].includes(type) && !('operator_id' in event)) throw new Error('通知缺少 operator_id');
      const subtypes = { group_admin: ['set', 'unset'], group_increase: ['approve', 'invite'], group_decrease: ['leave', 'kick', 'kick_me'], group_ban: ['ban', 'lift_ban'], group: ['add', 'invite'] };
      if (Object.hasOwn(subtypes, type) && !subtypes[type].includes(event.sub_type)) throw new Error('事件 sub_type 无效');
      if (type === 'group_ban') event.duration = integer(event.duration, 'duration', -1);
      if (type === 'group_recall' || type === 'friend_recall') event.message_id = messageRef(selfId, raw.message);
      if (type === 'group_upload') {
        if (typeof event.file?.id !== 'string' || !event.file.id || typeof event.file.name !== 'string') throw new Error('群文件标识无效');
        event.file = { ...event.file, size: integer(event.file.size, 'file.size'), busid: integer(event.file.busid, 'file.busid') };
      }
      if (raw.type === 'request' && (!['friend', 'group'].includes(event.request_type) || typeof event.flag !== 'string' || !event.flag)) throw new Error('请求类型或 flag 无效');
      result = { event: { time: id(raw.time ?? Math.floor(Date.now() / 1000), 'time'), self_id: selfId, post_type: raw.type, ...event },
        key: raw.key ? [selfId, raw.type, raw.key].join(':') : undefined };
    } else return null;
    if (!result) return null;
    if (result.key) {
      if (seen.has(result.key)) return null;
      seen.set(result.key, true);
      if (seen.size > 10000) seen.delete(seen.keys().next().value);
    }
    return result.event;
  };
  // Writes the id mapping now (called on shutdown; otherwise it is written shortly after the last new id).
  convert.flush = () => idStore?.flush();
  convert.messageId = (self, message) => messageRef(id(self.uin, 'self_id'), message);
  // OneBot id → native reference (message or forward) seen in this run, or undefined.
  convert.resolve = value => {
    if ((typeof value !== 'string' && typeof value !== 'number') || !/^[1-9]\d*$/.test(String(value))) return undefined;
    return refs.get(Number(value));
  };
  // get_msg: the segments a received message would carry, for any sender (including ourselves).
  convert.messageResult = (self, message) => {
    const selfId = id(self.uin, 'self_id');
    if (![1, 2, 100].includes(message?.chatType)) throw new Error('原生消息的会话类型不受支持');
    if (!Array.isArray(message.elements) || !message.elements.length) throw new Error('原生消息元素为空');
    const segments = message.elements.map(element => convertSegment(element, original => messageRef(selfId, message, original),
      ref => forwardSegment(selfId, ref), mediaUrl));
    const senderId = /^[1-9]\d*$/.test(String(message.senderUin)) && Number.isSafeInteger(Number(message.senderUin)) ? Number(message.senderUin) : 0;
    const messageId = messageRef(selfId, message);
    const result = { time: id(message.msgTime, 'time'), message_type: message.chatType === 2 ? 'group' : 'private', message_id: messageId, real_id: messageId,
      user_id: senderId, sender: { user_id: senderId, nickname: String(message.sendNickName ?? '') }, message: segments, raw_message: cqString(segments), font: 0 };
    if (message.chatType === 2) {
      result.group_id = id(message.peerUin ?? message.peerUid, 'group_id');
      result.sender.card = String(message.sendMemberName ?? '');
    }
    return result;
  };
  convert.forwardResult = (self, forward) => {
    if (!forward?.ref || !Array.isArray(forward.messages)) throw new Error('合并转发回执无效');
    return { messages: forwardNodes(id(self.uin, 'self_id'), forward.ref, forward.messages) };
  };
  return convert;
}

export function createMessageConverter() {
  const convert = createEventConverter();
  return (self, message) => convert({ type: 'message', self, message });
}
