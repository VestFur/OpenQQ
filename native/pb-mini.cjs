'use strict';
// 极简 protobuf 编码器（2026-11-19）：群相册那批 trpc 命令要手搓 body，
// 只做最小集：varint / string / bytes / message，够用就行。
function varint(n) {
  const out = [];
  let v = Number(n);
  if (!Number.isFinite(v) || v < 0) v = 0;
  v = Math.floor(v);
  while (v > 127) { out.push((v & 127) | 128); v = Math.floor(v / 128); }
  out.push(v);
  return Buffer.from(out);
}
function tag(field, wire) { return varint((field << 3) | wire); }
function vint(field, n) { return Buffer.concat([tag(field, 0), varint(n)]); }
function str(field, s) {
  const b = Buffer.from(String(s == null ? '' : s), 'utf8');
  return Buffer.concat([tag(field, 2), varint(b.length), b]);
}
function bytes(field, b) {
  const buf = Buffer.isBuffer(b) ? b : Buffer.from(b || []);
  return Buffer.concat([tag(field, 2), varint(buf.length), buf]);
}
module.exports = { varint, tag, vint, str, bytes };
