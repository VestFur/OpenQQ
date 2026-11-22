import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nativeEvents from '../native/events.cjs';
import nativeActions from '../native/actions.cjs';
import { createEventConverter } from '../src/onebot.mjs';
import { createIdStore } from '../src/idstore.mjs';
import { createMediaPreparer } from '../src/media.mjs';
import { dispatchAction } from '../src/actions.mjs';

const self = { uin: '123456', uid: 'u_self' };
const text = content => ({ elementType: 1, textElement: { content } });
const group = (overrides = {}) => ({ chatType: 2, msgId: '7001', msgSeq: '55', clientSeq: '9', msgTime: '1794470400', peerUid: '987654', peerUin: '987654',
  senderUid: 'u_actor', senderUin: '654321', sendNickName: 'actor', elements: [text('hi')], ...overrides });

function harness({ msgService = {} } = {}) {
  const raw = [];
  const store = new Map();
  const reactions = [];
  const session = {
    getUixConvertService: () => ({ getUin: async () => ({ uinInfo: new Map() }) }),
    getMsgService: () => ({
      async getMsgsByMsgId(_peer, ids) { return { result: 0, msgList: ids.map(id => store.get(id)).filter(Boolean) }; },
      async setMsgEmojiLikes(...args) { reactions.push(args); return { result: 0, errMsg: '' }; },
      ...msgService,
    }),
    getMSFService: () => ({ getServerTime: () => '1794470400' }),
  };
  const receive = nativeEvents.createEventReceiver(session, self, event => raw.push(event), () => true);
  const handler = nativeActions.createActionHandler(session, self, () => true, { fetchMessage: receive.fetchMessage, friendList: receive.friendList, lookupRecent: receive.lookupRecent, record: receive.record });
  const convert = createEventConverter();
  const channel = { request: request => handler.execute(request).then(data => ({ status: 'ok', retcode: 0, data }), error => ({ status: 'failed', retcode: error.retcode ?? 1500, data: null, message: error.message })) };
  return { raw, store, reactions, receive, handler, convert, channel };
}

test('get_friend_list answers from the list QQ pushed, with nicknames and remarks, and refuses before the first push', async () => {
  const h = harness();
  const before = await dispatchAction(h.channel, h.convert, { action: 'get_friend_list', echo: 1 });
  assert.equal(before.retcode, 1500);
  assert.match(before.message, /尚未同步/);

  await h.receive('buddy', 'onBuddyListChange', [[
    { categoryId: 0, categoryName: 'My friends', buddyList: [{ uid: 'u_a', uin: '111', nick: 'Alice', remark: 'Ali' }, { uid: 'u_b', uin: '222', nick: 'Bob', remark: '' }] },
    { categoryId: 1, categoryName: 'Work', buddyList: [{ uid: 'u_c', uin: '333', coreInfo: { nick: 'Cara', remark: 'boss' } }, { uid: 'u_unknown', nick: 'Ghost' }] },
  ]]);
  const response = await dispatchAction(h.channel, h.convert, { action: 'get_friend_list', echo: 2 });
  assert.equal(response.status, 'ok');
  assert.equal(response.echo, 2);
  assert.deepEqual(response.data, [
    { user_id: 111, nickname: 'Alice', remark: 'Ali' },
    { user_id: 222, nickname: 'Bob', remark: '' },
    { user_id: 333, nickname: 'Cara', remark: 'boss' },
  ], 'a friend whose QQ number cannot be resolved is left out');

  // A later push replaces the list.
  await h.receive('buddy', 'onBuddyListChange', [[{ categoryId: 0, categoryName: 'My friends', buddyList: [{ uid: 'u_b', uin: '222', nick: 'Bobby', remark: '' }] }]]);
  assert.deepEqual((await dispatchAction(h.channel, h.convert, { action: 'get_friend_list' })).data, [{ user_id: 222, nickname: 'Bobby', remark: '' }]);
});

test('set_msg_emoji_like reacts to a group message by its sequence number and validates what it is given', async () => {
  const h = harness();
  h.store.set('7001', group());
  await h.receive('msg', 'onRecvMsg', [[group()]]);
  const event = h.convert(h.raw.find(item => item.type === 'message'));
  const react = params => dispatchAction(h.channel, h.convert, { action: 'set_msg_emoji_like', params: { message_id: event.message_id, ...params } });

  const added = await react({ emoji_id: '76' });
  assert.deepEqual(added, { status: 'ok', retcode: 0, data: null });
  assert.deepEqual(h.reactions, [[{ chatType: 2, peerUid: '987654', guildId: '' }, '55', '76', '1', true]]);
  assert.equal((await react({ emoji_id: 128512, set: false })).status, 'ok');
  assert.deepEqual(h.reactions[1].slice(1), ['55', '128512', '2', false], 'emoji code points use the second type');
  assert.equal((await react({ emoji_id: '76', set: 'false' })).status, 'ok', 'string booleans from HTTP are understood');
  assert.equal(h.reactions[2][4], false);

  const count = h.reactions.length;
  for (const bad of [{ emoji_id: 'smile' }, { emoji_id: '' }, {}, { emoji_id: '-1' }, { emoji_id: '76', set: 'maybe' }]) {
    assert.equal((await react(bad)).retcode, 1400, JSON.stringify(bad));
  }
  assert.equal((await dispatchAction(h.channel, h.convert, { action: 'set_msg_emoji_like', params: { message_id: 4242, emoji_id: '76' } })).retcode, 1404);
  assert.equal(h.reactions.length, count, 'invalid requests never reach QQ');

  // The message must be in QQ's records, and QQ's refusal is reported.
  h.store.delete('7001');
  assert.equal((await react({ emoji_id: '76' })).retcode, 1404);
  h.store.set('7001', group());
  const refused = harness({ msgService: { async setMsgEmojiLikes() { return { result: 5, errMsg: 'denied' }; } } });
  refused.store.set('7001', group());
  await refused.receive('msg', 'onRecvMsg', [[group()]]);
  const refusedEvent = refused.convert(refused.raw.find(item => item.type === 'message'));
  const refusal = await dispatchAction(refused.channel, refused.convert, { action: 'set_msg_emoji_like', params: { message_id: refusedEvent.message_id, emoji_id: '76' } });
  assert.equal(refusal.retcode, 1500);
  assert.match(refusal.message, /denied/);
});

test('set_msg_emoji_like refuses private messages without calling QQ', async () => {
  const h = harness();
  const priv = { chatType: 1, msgId: '7100', msgSeq: '3', clientSeq: '1', msgTime: '1794470400', peerUid: 'u_friend', peerUin: '999', senderUid: 'u_friend', senderUin: '999', sendNickName: 'friend', elements: [text('hi')] };
  h.store.set('7100', priv);
  await h.receive('msg', 'onRecvMsg', [[priv]]);
  const event = h.convert(h.raw.find(item => item.type === 'message'));
  const response = await dispatchAction(h.channel, h.convert, { action: 'set_msg_emoji_like', params: { message_id: event.message_id, emoji_id: '76' } });
  assert.equal(response.retcode, 1400);
  assert.match(response.message, /群消息/);
  assert.equal(h.reactions.length, 0);
});

test('clean_cache sweeps OpenQQ\'s own temporary media left over from earlier runs', async t => {
  const root = await mkdtemp(join(tmpdir(), 'openqq-clean-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const media = createMediaPreparer({ dir: root });
  const old = join(root, 'old.tmp');
  const fresh = join(root, 'fresh.tmp');
  await writeFile(old, 'x'); await writeFile(fresh, 'y');
  const longAgo = new Date(Date.now() - 2 * 3600 * 1000);
  await utimes(old, longAgo, longAgo);
  const channel = { request: () => { throw new Error('never reaches QQ'); } };
  const response = await dispatchAction(channel, createEventConverter(), { action: 'clean_cache', echo: 'c' }, { media });
  assert.deepEqual(response, { status: 'ok', retcode: 0, data: null, echo: 'c' });
  await assert.rejects(stat(old), 'the stale file is gone');
  assert.ok((await stat(fresh)).isFile(), 'a file that may still be in use stays');
  assert.equal((await dispatchAction(channel, createEventConverter(), { action: 'clean_cache' })).status, 'ok', 'it also works without a media folder');
});

test('message ids survive a restart: the same message keeps its id, old ids still resolve and new ones continue the sequence', async t => {
  const root = await mkdtemp(join(tmpdir(), 'openqq-ids-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'run', 'ids.json');
  const message = (msgId, chatType = 2, peerUid = '987654') => ({ chatType, peerUid, msgId });

  const first = createEventConverter({ idStore: createIdStore(path, { delayMs: 60000 }) });
  const a = first.messageId(self, message('7001'));
  const b = first.messageId(self, message('7002'));
  const privateId = first.messageId(self, message('8001', 1, 'u_friend'));
  assert.deepEqual([a, b, privateId], [1, 2, 3]);
  first.flush();
  assert.equal(JSON.parse(await readFile(path, 'utf8')).nextId, 4);

  const second = createEventConverter({ idStore: createIdStore(path) });
  // msgSeq 现在跟着 ref 一起存（forwardMsg 的 msgInfos 要 msgId+msgSeq 成对）：
  // 这些 fixture 消息没带 msgSeq，存进 ref 的就是空串。
  assert.deepEqual(second.resolve(a), { kind: 'message', selfId: 123456, chatType: 2, peerUid: '987654', msgId: '7001', msgSeq: '' });
  assert.equal(second.resolve(privateId).peerUid, 'u_friend');
  assert.equal(second.messageId(self, message('7002')), b, 'a message seen before keeps its id');
  assert.equal(second.messageId(self, message('7003')), 4, 'new messages continue the sequence');
  assert.equal(second.resolve(999), undefined);

  // Forward ids are kept too, and an account switch does not mix the mappings up.
  const forward = second.forwardResult(self, { ref: { chatType: 2, peerUid: '987654', root: '7001', parent: '7001' }, messages: [] });
  assert.deepEqual(forward, { messages: [] });
  second.flush();
  const third = createEventConverter({ idStore: createIdStore(path) });
  assert.equal(third.messageId({ uin: '999999', uid: 'u_other' }, message('7001')), 5, 'another account gets its own id for the same chat and message');
  assert.equal(third.messageId(self, message('7001')), a);
});

test('the id store writes lazily, tolerates damage and keeps only identifiers', async t => {
  const root = await mkdtemp(join(tmpdir(), 'openqq-idstore-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'ids.json');

  assert.deepEqual(createIdStore(path).load(), { nextId: 1, entries: [] }, 'a missing file starts empty');
  await writeFile(path, '{ not json');
  assert.deepEqual(createIdStore(path).load(), { nextId: 1, entries: [] }, 'a damaged file starts empty');
  await writeFile(path, JSON.stringify({ version: 2, nextId: 5, entries: [] }));
  assert.deepEqual(createIdStore(path).load(), { nextId: 1, entries: [] }, 'an unknown version is ignored');
  await writeFile(path, JSON.stringify({ version: 1, nextId: 2, entries: [['ok', 9, { kind: 'message', chatType: 2, peerUid: 'g' }], ['bad id', 'x'], 'junk', ['bad ref', 3, { kind: 'other' }], [5, 4]] }));
  const loaded = createIdStore(path).load();
  assert.equal(loaded.nextId, 10, 'the next id is always above every stored id');
  assert.deepEqual(loaded.entries.map(entry => [entry[0], entry[1], entry[2]?.kind]), [['ok', 9, 'message'], ['bad ref', 3, undefined]]);

  const store = createIdStore(path, { delayMs: 20, limit: 3 });
  const writes = [];
  for (let i = 1; i <= 5; i++) store.schedule(() => { writes.push(i); return { nextId: i + 1, entries: Array.from({ length: i }, (_, n) => ['k' + n, n + 1]) }; });
  await new Promise(resolve => setTimeout(resolve, 120));
  assert.deepEqual(writes, [5], 'a burst of new ids costs one write with the latest state');
  const saved = JSON.parse(await readFile(path, 'utf8'));
  assert.deepEqual(saved.entries.map(entry => entry[0]), ['k2', 'k3', 'k4'], 'only the latest ids are kept');
  assert.equal(saved.entries.some(entry => entry.length > 3), false);

  const failing = createIdStore(join(root, 'ids.json', 'cannot-be-a-directory'), { delayMs: 1 });
  failing.schedule(() => ({ nextId: 2, entries: [['a', 1]] }));
  assert.doesNotThrow(() => failing.flush(), 'a failed write never throws into message delivery');
});
