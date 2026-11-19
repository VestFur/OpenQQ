import { test } from 'node:test';
import assert from 'node:assert/strict';
import nativeActions from '../native/actions.cjs';
import admin from '../native/admin.cjs';
import { createEventReceiver } from '../native/events.cjs';
import { createEventConverter } from '../src/onebot.mjs';
import { dispatchAction } from '../src/actions.mjs';

const self = { uin: '123456', uid: 'u_self' };

function fixture(t, overrides = {}) {
  const calls = [];
  const record = name => async (...args) => { calls.push([name, ...args]); return overrides[name]?.(...args) ?? { result: 0, errMsg: '' }; };
  const members = new Map([
    ['u_100', { uid: 'u_100', uin: '100', nick: '甲', cardName: '', role: 4, joinTime: '1700000000', lastSpeakTime: '1700000100', memberRealLevel: 12, memberSpecialTitle: '', shutUpTime: 0, isDelete: false }],
    ['u_200', { uid: 'u_200', uin: '200', nick: '乙', cardName: '乙的名片', role: 3, joinTime: '1700000200', lastSpeakTime: '0', memberRealLevel: 3, memberSpecialTitle: '头衔', shutUpTime: 60, isDelete: false }],
    ['u_300', { uid: 'u_300', uin: '300', nick: '已退', cardName: '', role: 2, isDelete: true }],
  ]);
  const cache = { map: new Map(), version: 0, waitForUpdate: async () => {} };
  const groupService = {
    getUidByUins: async uins => ({ uids: new Map(uins.map(uin => [uin, 'u_' + uin])) }),
    kickMember: record('kickMember'), setMemberShutUp: record('setMemberShutUp'), setGroupShutUp: record('setGroupShutUp'), modifyMemberRole: record('modifyMemberRole'),
    modifyMemberCardName: record('modifyMemberCardName'), modifyGroupName: record('modifyGroupName'), quitGroupV2: record('quitGroupV2'), destroyGroup: record('destroyGroup'),
    operateSysNotify: record('operateSysNotify'),
    getAllMemberList: async (group, force) => { calls.push(['getAllMemberList', group, force]); return overrides.members?.(force) ?? { errCode: 0, errMsg: '', result: { infos: members } }; },
    async getGroupList(force) {
      calls.push(['getGroupList', force]);
      if (overrides.groupList !== 'silent') {
        cache.map.set('1001', { groupCode: '1001', groupName: '甲群', memberCount: 12, maxMember: 200 });
        cache.map.set('1002', { groupCode: '1002', groupName: '乙群', memberCount: 3, maxMember: 500 });
        cache.version++;
      }
      return { result: 0, errMsg: '' };
    },
    ...overrides.groupService,
  };
  const session = {
    getGroupService: () => groupService,
    getBuddyService: () => ({ approvalFriendRequest: record('approvalFriendRequest') }),
    getMsgService: () => ({ recallMsg: record('recallMsg') }),
    getProfileService: () => ({ getUidByUin: async (_scope, uins) => new Map(uins.map(uin => [uin, 'u_' + uin])),
      getUserDetailInfoByUin: async uin => { calls.push(['getUserDetailInfoByUin', uin]); return overrides.detail?.(uin) ?? { result: 0, errMsg: '', detail: { uin, simpleInfo: { coreInfo: { nick: '路人' }, baseInfo: { sex: 2, age: 23 } } } }; } }),
    getProfileLikeService: () => ({ setBuddyProfileLike: record('setBuddyProfileLike') }),
    getUixConvertService: () => ({ getUid: async uins => ({ uidInfo: new Map(uins.map(uin => [uin, 'u_' + uin])) }) }),
    ...overrides.session,
  };
  const handler = nativeActions.createActionHandler(session, self, () => true, { groups: cache });
  t.after(() => handler.dispose());
  return { calls, handler, cache, groupService };
}

const ok = async (f, action, params) => f.handler.execute({ action, params });

test('group management actions call QQ with the converted UID and the right arguments', async t => {
  const f = fixture(t);
  assert.equal(await ok(f, 'set_group_kick', { group_id: 1001, user_id: 200, reject_add_request: true }), null);
  await ok(f, 'set_group_kick', { group_id: '1001', user_id: '200' });
  await ok(f, 'set_group_ban', { group_id: 1001, user_id: 200, duration: 600 });
  await ok(f, 'set_group_ban', { group_id: 1001, user_id: 200 });
  await ok(f, 'set_group_ban', { group_id: 1001, user_id: 200, duration: 0 });
  await ok(f, 'set_group_whole_ban', { group_id: 1001 });
  await ok(f, 'set_group_whole_ban', { group_id: 1001, enable: false });
  await ok(f, 'set_group_admin', { group_id: 1001, user_id: 200 });
  await ok(f, 'set_group_admin', { group_id: 1001, user_id: 200, enable: false });
  await ok(f, 'set_group_card', { group_id: 1001, user_id: 200, card: '新名片' });
  await ok(f, 'set_group_card', { group_id: 1001, user_id: 200 });
  await ok(f, 'set_group_name', { group_id: 1001, group_name: '新群名' });
  await ok(f, 'set_group_leave', { group_id: 1001 });
  await ok(f, 'set_group_leave', { group_id: 1001, is_dismiss: true });
  assert.deepEqual(f.calls, [
    ['kickMember', '1001', ['u_200'], true, ''], ['kickMember', '1001', ['u_200'], false, ''],
    ['setMemberShutUp', '1001', [{ uid: 'u_200', timeStamp: 600 }]], ['setMemberShutUp', '1001', [{ uid: 'u_200', timeStamp: 1800 }]], ['setMemberShutUp', '1001', [{ uid: 'u_200', timeStamp: 0 }]],
    ['setGroupShutUp', '1001', true], ['setGroupShutUp', '1001', false],
    ['modifyMemberRole', '1001', 'u_200', 3], ['modifyMemberRole', '1001', 'u_200', 2],
    ['modifyMemberCardName', '1001', 'u_200', '新名片'], ['modifyMemberCardName', '1001', 'u_200', ''],
    ['modifyGroupName', '1001', '新群名', false],
    ['quitGroupV2', { groupCode: '1001', needDeleteLocalMsg: false }], ['destroyGroup', '1001'],
  ]);
});

test('requests are answered through the flag the request event carried, and messages are recalled by native reference', async t => {
  const f = fixture(t);
  await ok(f, 'set_group_add_request', { flag: 'g:1001:7:1794470400000099', approve: true });
  await ok(f, 'set_group_add_request', { flag: 'g:1001:1:1794470400000100', sub_type: 'invite', approve: false, reason: '不合适' });
  await ok(f, 'set_friend_add_request', { flag: 'f:u_actor:1794470400' });
  await ok(f, 'set_friend_add_request', { flag: 'f:u_actor:1794470400', approve: false });
  await ok(f, 'delete_msg', { openqq_ref: { chatType: 2, peerUid: '1001', msgId: '9007199254741999' } });
  await ok(f, 'send_like', { user_id: 654321, times: 3 });
  await ok(f, 'send_like', { user_id: 654321 });
  assert.deepEqual(f.calls, [
    ['operateSysNotify', false, { operateType: 1, targetMsg: { seq: '1794470400000099', type: 7, groupCode: '1001', postscript: ' ' } }],
    ['operateSysNotify', false, { operateType: 2, targetMsg: { seq: '1794470400000100', type: 1, groupCode: '1001', postscript: '不合适' } }],
    ['approvalFriendRequest', { friendUid: 'u_actor', reqTime: '1794470400', accept: true }],
    ['approvalFriendRequest', { friendUid: 'u_actor', reqTime: '1794470400', accept: false }],
    ['recallMsg', { chatType: 2, peerUid: '1001', guildId: '0' }, ['9007199254741999']],
    ['setBuddyProfileLike', { friendUid: 'u_654321', sourceId: 71, doLikeCount: 3, doLikeTollCount: 0 }],
    ['setBuddyProfileLike', { friendUid: 'u_654321', sourceId: 71, doLikeCount: 1, doLikeTollCount: 0 }],
  ]);
});

test('invalid parameters are rejected before anything reaches QQ', async t => {
  const f = fixture(t);
  const bad = [
    ['set_group_kick', {}, /group_id/], ['set_group_kick', { group_id: 1 }, /user_id/], ['set_group_kick', { group_id: 'x', user_id: 1 }, /group_id/],
    ['set_group_kick', { group_id: 1, user_id: 2, reject_add_request: 'maybe' }, /reject_add_request/],
    ['set_group_ban', { group_id: 1, user_id: 2, duration: -1 }, /duration/], ['set_group_ban', { group_id: 1, user_id: 2, duration: 2592001 }, /duration/],
    ['set_group_ban', { group_id: 1, user_id: 2, duration: 1.5 }, /duration/], ['set_group_ban', { group_id: 1, user_id: 2, duration: 'abc' }, /duration/],
    ['set_group_card', { group_id: 1, user_id: 2, card: 'x'.repeat(61) }, /card/], ['set_group_card', { group_id: 1, user_id: 2, card: 'a\nb' }, /card/], ['set_group_card', { group_id: 1, user_id: 2, card: 5 }, /card/],
    ['set_group_name', { group_id: 1 }, /group_name/], ['set_group_name', { group_id: 1, group_name: '   ' }, /不能为空/], ['set_group_name', { group_id: 1, group_name: 'x'.repeat(49) }, /group_name/],
    ['set_group_add_request', { flag: '12345' }, /flag 无效/], ['set_group_add_request', {}, /flag 无效/], ['set_group_add_request', { flag: 'f:u_a:1' }, /flag 无效/],
    ['set_group_add_request', { flag: 'g:1:7:2', reason: 'x'.repeat(257) }, /reason/],
    ['set_friend_add_request', { flag: 'g:1:7:2' }, /flag 无效/], ['set_friend_add_request', { flag: 'f:bad:1' }, /flag 无效/], ['set_friend_add_request', { flag: 'f:u_a:1', approve: 'x' }, /approve/],
    ['delete_msg', {}, /message_id/], ['delete_msg', { openqq_ref: { chatType: 4, peerUid: 'x', msgId: '1' } }, /message_id/], ['delete_msg', { openqq_ref: { chatType: 2, peerUid: 'x', msgId: 'abc' } }, /message_id/],
    ['send_like', { user_id: 1, times: 0 }, /times/], ['send_like', { user_id: 1, times: 21 }, /times/],
    ['get_group_info', {}, /group_id/], ['get_group_member_info', { group_id: 1 }, /user_id/], ['get_stranger_info', {}, /user_id/],
  ];
  for (const [action, params, pattern] of bad) await assert.rejects(ok(f, action, params), pattern, action + ' ' + JSON.stringify(params));
  assert.deepEqual(f.calls, []);
  // set_group_special_title 已实现（OneBot v11 标准名 → OIDB 0x8fc_2 的 set_special_title），
  // 不再属于「尚未支持动作」，所以这里只保留仍未实现的那一个。
  await assert.rejects(f.handler.execute({ action: 'set_group_anonymous_ban', params: {} }), /尚未支持动作/);
});

test('refusals reported by QQ and unresolvable UIDs fail the action without pretending success', async t => {
  const f = fixture(t, { setMemberShutUp: () => ({ result: 5, errMsg: '没有权限' }), modifyMemberRole: () => ({ errCode: 9, errMsg: '', result: {} }),
    kickMember: () => undefined, operateSysNotify: () => undefined });
  await assert.rejects(ok(f, 'set_group_ban', { group_id: 1, user_id: 2, duration: 60 }), error => error.retcode === 1500 && /QQ 拒绝禁言：没有权限/.test(error.message));
  await assert.rejects(ok(f, 'set_group_admin', { group_id: 1, user_id: 2 }), error => error.retcode === 1500 && /QQ 拒绝设置管理员：9/.test(error.message));
  assert.equal(await ok(f, 'set_group_kick', { group_id: 1, user_id: 2 }), null, 'methods that resolve to nothing are treated as accepted');
  assert.equal(await ok(f, 'set_group_add_request', { flag: 'g:1:7:2' }), null);

  // every UID source (group service, friend/profile store, UixConvert) comes up empty
  const nobody = fixture(t, { groupService: { getUidByUins: async () => ({ uids: new Map() }) },
    session: { getUixConvertService: () => ({ getUid: async () => ({ uidInfo: new Map() }) }), getProfileService: () => ({ getUidByUin: async () => { throw new Error('store down'); } }) } });
  await assert.rejects(ok(nobody, 'set_group_kick', { group_id: 1, user_id: 2 }), /无法把 QQ 号转换为 UID/);
  assert.deepEqual(nobody.calls, [], 'nothing is sent to QQ when the member cannot be identified');
});

test('group queries map QQ\'s data to OneBot objects and refresh through the group listener', async t => {
  const f = fixture(t);
  assert.deepEqual(await ok(f, 'get_group_list', {}), [
    { group_id: 1001, group_name: '甲群', member_count: 12, max_member_count: 200 }, { group_id: 1002, group_name: '乙群', member_count: 3, max_member_count: 500 }]);
  assert.deepEqual(f.calls, [['getGroupList', true]]);
  assert.deepEqual(await ok(f, 'get_group_info', { group_id: 1002 }), { group_id: 1002, group_name: '乙群', member_count: 3, max_member_count: 500 });
  assert.equal(f.calls.length, 1, 'get_group_info answers from the cache once it is filled');
  await assert.rejects(ok(f, 'get_group_info', { group_id: 9 }), error => error.retcode === 1404);

  const list = await ok(f, 'get_group_member_list', { group_id: 1001 });
  assert.deepEqual(list.map(member => [member.user_id, member.nickname, member.card, member.role, member.title, member.level, member.join_time, member.shut_up_timestamp]), [
    [100, '甲', '', 'owner', '', '12', 1700000000, 0], [200, '乙', '乙的名片', 'admin', '头衔', '3', 1700000200, 60]]);
  assert.equal(list[0].group_id, 1001);
  assert.deepEqual(await ok(f, 'get_group_member_info', { group_id: 1001, user_id: 200 }).then(member => [member.user_id, member.card, member.role]), [200, '乙的名片', 'admin']);
  await assert.rejects(ok(f, 'get_group_member_info', { group_id: 1001, user_id: 300 }), error => error.retcode === 1404);
  await assert.rejects(ok(f, 'get_group_member_info', { group_id: 1001, user_id: 999 }), error => error.retcode === 1404);
  assert.ok(f.calls.some(call => call[0] === 'getAllMemberList' && call[2] === true), 'an unknown member triggers a forced refresh');
});

test('an unexpected member-list shape and a silent group-list refresh produce clear errors', async t => {
  const odd = fixture(t, { members: () => ({ errCode: 0, result: { infos: [] } }) });
  await assert.rejects(ok(odd, 'get_group_member_list', { group_id: 1 }), /结构未适配/);
  const refused = fixture(t, { members: () => ({ errCode: 4, errMsg: '无权限', result: {} }) });
  await assert.rejects(ok(refused, 'get_group_member_list', { group_id: 1 }), /QQ 拒绝获取群成员：无权限/);
  const silent = fixture(t, { groupList: 'silent' });
  assert.deepEqual(await ok(silent, 'get_group_list', {}), []);
  const bare = nativeActions.createActionHandler({}, self, () => true);
  t.after(() => bare.dispose());
  await assert.rejects(bare.execute({ action: 'get_group_list' }), /不支持获取群列表/);
});

test('the event receiver caches groups from onGroupListUpdate and wakes anyone waiting for an update', async () => {
  const receive = createEventReceiver({}, self, () => {}, () => true);
  const groups = receive.groups;
  assert.equal(groups.version, 0);
  const waited = groups.waitForUpdate(0, 1000);
  await receive('group', 'onGroupListUpdate', [1, [{ groupCode: '1001', groupName: 'A', memberCount: 1, maxMember: 200 }, { groupCode: 'bad', groupName: 'ignored' }, null]]);
  await waited;
  assert.deepEqual([...groups.map.keys()], ['1001']);
  assert.equal(groups.version, 1);
  await receive('group', 'onGroupListUpdate', [2, [{ groupCode: '1001', groupName: 'A2', memberCount: 2, maxMember: 200 }]]);
  assert.equal(groups.map.get('1001').groupName, 'A2');
  await receive('group', 'onGroupListUpdate', [3, [{ groupCode: '1001' }]]);
  assert.equal(groups.map.size, 0);
  await receive('group', 'onGroupListUpdate', [1, 'not a list']);
  assert.equal(groups.version, 3, 'a malformed update changes nothing');
  const started = Date.now();
  await groups.waitForUpdate(groups.version, 30);
  assert.ok(Date.now() - started >= 25, 'waits for the timeout when nothing arrives');
  assert.equal(await groups.waitForUpdate(0, 1000), undefined, 'returns at once when the cache already moved on');
});

test('delete_msg resolves a OneBot message_id to the native message, and unknown ids are reported as expired', async () => {
  const converter = createEventConverter();
  const id = converter.messageId(self, { chatType: 2, peerUid: '1001', msgId: '9007199254741999' });
  const calls = [];
  const channel = { async request(request, timeout) { calls.push({ request, timeout }); return { status: 'ok', retcode: 0, data: null }; } };
  const response = await dispatchAction(channel, converter, { action: 'delete_msg', params: { message_id: id }, echo: 'd' });
  assert.deepEqual([response.status, response.data, response.echo], ['ok', null, 'd']);
  assert.deepEqual(calls[0].request.params.openqq_ref, { chatType: 2, peerUid: '1001', msgId: '9007199254741999' });
  assert.equal(calls[0].timeout, 20000);
  const missing = await dispatchAction(channel, converter, { action: 'delete_msg', params: { message_id: 999 } });
  assert.deepEqual([missing.status, missing.retcode], ['failed', 1404]);
  const forged = await dispatchAction(channel, converter, { action: 'delete_msg', params: { message_id: id, openqq_ref: { chatType: 1, peerUid: 'u_victim', msgId: '1' } } });
  assert.deepEqual(calls.at(-1).request.params.openqq_ref, { chatType: 2, peerUid: '1001', msgId: '9007199254741999' }, 'a client-supplied native reference is replaced by the resolved one');
  assert.equal(forged.status, 'ok');
  assert.equal(calls.length, 2);
});

test('request flags produced by events can be answered by the matching actions', () => {
  assert.deepEqual(admin.GROUP_REQUEST.exec('g:987654:7:1794470400000099').slice(1), ['987654', '7', '1794470400000099']);
  assert.deepEqual(admin.FRIEND_REQUEST.exec('f:u_a-b_c:1794470400').slice(1), ['u_a-b_c', '1794470400']);
  assert.equal(admin.GROUP_REQUEST.test('g:98:7:1; drop'), false);
  assert.equal(admin.FRIEND_REQUEST.test('f:../x:1'), false);
});

test('get_stranger_info maps QQ profile data to OneBot and reports unknown users and refusals', async t => {
  const f = fixture(t);
  assert.deepEqual(await ok(f, 'get_stranger_info', { user_id: '654321' }), { user_id: 654321, nickname: '路人', sex: 'female', age: 23 });
  assert.deepEqual(f.calls, [['getUserDetailInfoByUin', '654321']]);
  const unknown = fixture(t, { detail: () => ({ result: 0, errMsg: '', detail: { simpleInfo: { coreInfo: { nick: 'x' }, baseInfo: { sex: 255, age: -1 } } } }) });
  assert.deepEqual(await ok(unknown, 'get_stranger_info', { user_id: 7 }), { user_id: 7, nickname: 'x', sex: 'unknown', age: 0 });
  const missing = fixture(t, { detail: () => ({ result: 0, errMsg: '' }) });
  await assert.rejects(ok(missing, 'get_stranger_info', { user_id: 8 }), error => error.retcode === 1404);
  const empty = fixture(t, { detail: () => ({ result: 0, errMsg: '', detail: { simpleInfo: { coreInfo: { nick: '' }, baseInfo: { sex: 0, age: 0 } } } }) });
  await assert.rejects(ok(empty, 'get_stranger_info', { user_id: 10 }), error => error.retcode === 1404);
  const refused = fixture(t, { detail: () => ({ result: 3, errMsg: '用户不存在' }) });
  await assert.rejects(ok(refused, 'get_stranger_info', { user_id: 9 }), error => error.retcode === 1500 && /QQ 拒绝获取用户资料：用户不存在/.test(error.message));
});
