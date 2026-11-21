import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const nativeDir = join(dirname(dirname(fileURLToPath(import.meta.url))), 'native');
const pb = require(join(nativeDir, 'pb-mini.cjs'));
const oidb = require(join(nativeDir, 'oidb-actions.cjs'));
const actions = require(join(nativeDir, 'actions.cjs'));

test('protobuf varints cover the boundaries and stay exact above 2^53', () => {
  assert.equal(pb.varint(0).toString('hex'), '00');
  assert.equal(pb.varint(1).toString('hex'), '01');
  assert.equal(pb.varint(127).toString('hex'), '7f');
  assert.equal(pb.varint(128).toString('hex'), '8001');
  assert.equal(pb.varint(300).toString('hex'), 'ac02');
  // 群号、msgId 这个量级必须精确：Number 在 2^53 以上会丢精度，所以字符串/BigInt 是唯一安全输入。
  assert.equal(pb.varint('9007199254740993').toString('hex'), '8180808080808010');
  assert.equal(pb.varint(9007199254740993n).toString('hex'), '8180808080808010');
  // 负数按 uint64 补码编码，而不是悄悄写 0。
  assert.equal(pb.varint(-1).toString('hex'), 'ffffffffffffffffff01');
});

test('protobuf encoder rejects invalid integers instead of writing zero', () => {
  for (const bad of [NaN, Infinity, 1.5, undefined, null, {}, [], 'abc', '']) {
    assert.throws(() => pb.varint(bad), TypeError, `应当拒绝 ${String(bad)}`);
  }
  assert.throws(() => pb.varint(Number.MAX_SAFE_INTEGER + 2), /安全整数/);
  assert.throws(() => pb.tag(-1, 0), RangeError);
  assert.throws(() => pb.tag(1, 9), RangeError);
});

test('field encoders produce the documented tags', () => {
  assert.equal(pb.tag(1, 2).toString('hex'), '0a');
  assert.equal(pb.tag(1, 0).toString('hex'), '08');
  assert.equal(pb.vint(2, 1).toString('hex'), '1001');
  assert.equal(pb.bytes(4, Buffer.from([1, 2])).toString('hex'), '22020102');
  assert.equal(pb.str(1, 'ab').toString('hex'), '0a026162');
});

test('encodeBySchema skips proto3 defaults and wraps nested messages', () => {
  const schema = {
    1: { name: 'groupUin', kind: 'varint' },
    2: { name: 'settings', kind: 'message', fields: { 1: { name: 'allow', kind: 'varint' } } },
    3: { name: 'name', kind: 'string' },
  };
  const encoded = oidb.encodeBySchema(schema, { groupUin: 1234, settings: { allow: 1 }, name: 'x' });
  assert.equal(encoded.toString('hex'), '08d209120208011a0178');
  // 0 / '' 不编码（proto3 默认值），和空对象一致。
  assert.equal(oidb.encodeBySchema(schema, { groupUin: 0, settings: {}, name: '' }).length, 0);
  // __raw 逃生口原样返回。
  const raw = Buffer.from([9, 9]);
  assert.equal(oidb.encodeBySchema(schema, { __raw: raw }), raw);
});

test('wrapOidbBase emits command/subCommand/errorCode/body and only adds reserved when asked', () => {
  const body = Buffer.from([0x08, 0x00]);
  assert.equal(oidb.wrapOidbBase(3795, 1, body).toString('hex'), '08d31d1001180022020800');
  assert.equal(oidb.wrapOidbBase(3795, 1, body, 1).toString('hex'), '08d31d10011800220208003801');
});

test('buildOidbPoke keeps the verified group shape', () => {
  assert.equal(
    pb.buildOidbPoke({ groupId: 1041147387, userId: 2975434328 }).toString('hex'),
    '08d31d10011800221008d88ce68a0b10fbcbbaf00328003000'
  );
});

test('download_file refuses every non-public target before it is executed', () => {
  const check = params => actions.validateAction({ action: 'download_file', params });
  for (const url of [
    'http://127.0.0.1:8080/x',
    'http://169.254.169.254/latest/meta-data/',
    'http://localhost/a',
    'http://foo.localhost/a',
    'http://service.internal/a',
    'http://10.1.2.3/a',
    'http://172.16.0.1/a',
    'http://192.168.1.1/a',
    'http://100.64.0.1/a',
    'http://0.0.0.0/a',
    'http://[::1]/a',
    'http://[fe80::1]/a',
    'file:///c:/windows/win.ini',
    'ftp://example.com/a',
    'http://user:pass@example.com/a',
  ]) {
    assert.throws(() => check({ url }), /download_file/, `应当拒绝 ${url}`);
  }
  const ok = check({ url: 'https://example.com/a', name: '../../evil.txt', headers: { Host: 'x', Referer: 'r' } });
  assert.equal(ok.kind, 'download_file');
  // basename 挡不住 '..'，所以文件名要单独净化，否则落盘路径会跳出 data/downloads。
  assert.equal(ok.name, '_.._evil.txt');
  // 会改变连接目标的头被丢掉，其余原样保留。
  assert.deepEqual(ok.headers, { Referer: 'r' });
  assert.equal(ok.maxBytes, 32 * 1024 * 1024);
  assert.throws(() => check({ url: 'https://example.com/a', max_bytes: 1e9 }), /max_bytes/);
  assert.throws(() => check({}), /url 或 base64/);
});

test('hot_reload_probe is not part of the action surface', () => {
  assert.throws(() => actions.validateAction({ action: 'hot_reload_probe', params: {} }), /尚未支持动作/);
});
