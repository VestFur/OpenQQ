'use strict';
/**
 * SSO over pipe —— 复用 SnowLuma 注入组件提供的 SSO 发送通道。
 *
 * 背景（2026-11-19 逆向 + 实机验证，见 .botharness/逆向-SL发包机制.md）：
 *   SnowLuma 的 snowluma-win32-x64.dll 是自包含 hook 组件，注入 QQ 后会在
 *   \\.\pipe\mojo.<pid>.control 建一个命名管道，外部按 40 字节定长帧把
 *   {cmd, body} 递进去，由它在进程内调 QQ 真正的 SSO 发送链。
 *
 *   这个模块跑在 QQ 进程内（native/*.cjs），所以 process.pid 就是 QQ 的 pid。
 *
 * 帧格式（little-endian）：
 *   0  u32 magic = 0x31504851 ("QHP1")
 *   4  u16 version = 1
 *   6  u16 op
 *   8  u32 requestId
 *   12 i32 status
 *   16 u32 flags   (1=WantReply, 4=LoggedIn)
 *   20 u32 cmdLen  (<=0x1000)
 *   24 u32 msgLen  (<=0x10000)
 *   28 u32 bodyLen (<=0x1000000)
 *   32 u64 value0
 *   40.. cmd(utf8) + msg(utf8) + body(raw)
 *
 * op: 1=hello(dll→) 2=发包(node→) 3=ack 4=回包 5=错误 6=收包 7=登录态 0x11=ping
 */

const net = require('node:net');

const MAGIC = 0x31504851;
const OP_SEND = 2;
const OP_ACK = 3;
const OP_REPLY = 4;
const OP_ERROR = 5;
const OP_PING = 0x11;

const MAX_CMD = 0x1000;
const MAX_MSG = 0x10000;
const MAX_BODY = 0x1000000;

const DEFAULT_TIMEOUT_MS = 15000;

// ⚠️ 连接状态必须挂在 globalThis 上跨"热重载"复用。
// 原因：热重载会 delete require.cache 后重新 require 本模块，模块级的 socket 会变成新的 null，
// 而**旧 socket 不会被关闭** → dll 的 pipe server 只接受一个连接 → 新连接直接超时。
// 表现就是「每次 build 之后 SSO 全线 ETIMEDOUT，重启 QQ 才好」。
const G = globalThis.__oqSsoState || (globalThis.__oqSsoState = {
  socket: null, connecting: null, recvBuf: Buffer.alloc(0), seq: 0,
  pending: new Map(), lastError: '', loggedIn: false, uin: '0',
});
let socket = G.socket;
let connecting = G.connecting;
let recvBuf = G.recvBuf;
let seq = G.seq;
const pending = G.pending;
let lastError = G.lastError;
let loggedIn = G.loggedIn;
let uin = G.uin;

/** 把模块级状态同步回 globalThis（热重载后仍能复用同一个 socket） */
function __syncState() {
  G.socket = socket; G.connecting = connecting; G.recvBuf = recvBuf;
  G.seq = seq; G.lastError = lastError; G.loggedIn = loggedIn; G.uin = uin;
}

function pipeName(pid = process.pid) {
  return `\\\\.\\pipe\\mojo.${pid}.control`;
}

function buildFrame({ op, requestId = 0, status = 0, flags = 0, value0 = 0n, cmd = '', msg = '', body = Buffer.alloc(0) }) {
  const cmdBuf = Buffer.from(String(cmd), 'utf8');
  const msgBuf = Buffer.from(String(msg), 'utf8');
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body || []);
  if (cmdBuf.length > MAX_CMD) throw new Error(`cmd too long: ${cmdBuf.length} > ${MAX_CMD}`);
  if (msgBuf.length > MAX_MSG) throw new Error(`msg too long: ${msgBuf.length} > ${MAX_MSG}`);
  if (bodyBuf.length > MAX_BODY) throw new Error(`body too long: ${bodyBuf.length} > ${MAX_BODY}`);
  const h = Buffer.alloc(40);
  h.writeUInt32LE(MAGIC, 0);
  h.writeUInt16LE(1, 4);
  h.writeUInt16LE(op, 6);
  h.writeUInt32LE(requestId >>> 0, 8);
  h.writeInt32LE(status | 0, 12);
  h.writeUInt32LE(flags >>> 0, 16);
  h.writeUInt32LE(cmdBuf.length, 20);
  h.writeUInt32LE(msgBuf.length, 24);
  h.writeUInt32LE(bodyBuf.length, 28);
  h.writeBigUInt64LE(BigInt(value0), 32);
  return Buffer.concat([h, cmdBuf, msgBuf, bodyBuf]);
}

function settle(id, kind, payload) {
  const entry = pending.get(id);
  if (!entry) return;
  pending.delete(id);
  if (entry.timer) clearTimeout(entry.timer);
  if (kind === 'resolve') entry.resolve(payload);
  else entry.reject(payload);
}

function onFrame(frame) {
  switch (frame.op) {
    case 1: // hello
      lastError = '';
      break;
    case 7: // loginState
      loggedIn = frame.status === 1;
      uin = String(frame.value0);
      break;
    case OP_ACK: {
      // ack 一般只表示"已受理"，回包还在路上；但 ping（op 0x11）只有 ack 没有回包，
      // 所以带 ackOnly 标记的等待在收到 ack 时就结束。
      const entry = pending.get(frame.requestId);
      if (entry && entry.ackOnly) {
        pending.delete(frame.requestId);
        if (entry.timer) clearTimeout(entry.timer);
        entry.resolve({ status: 0, message: '', body: Buffer.alloc(0) });
      }
      break;
    }
    case OP_REPLY:
      settle(frame.requestId, 'resolve', {
        status: frame.status, message: frame.message, body: frame.body,
      });
      break;
    case OP_ERROR:
      settle(frame.requestId, 'resolve', {
        status: frame.status, message: frame.message, body: frame.body,
      });
      break;
    case 6: // 收到一个入站包
      break;
    default:
      break;
  }
}

function consume(chunk) {
  recvBuf = recvBuf.length ? Buffer.concat([recvBuf, chunk]) : chunk;
  while (recvBuf.length >= 40) {
    if (recvBuf.readUInt32LE(0) !== MAGIC) {
      lastError = 'bad magic on pipe, dropping connection';
      destroy();
      return;
    }
    const cl = recvBuf.readUInt32LE(20);
    const ml = recvBuf.readUInt32LE(24);
    const bl = recvBuf.readUInt32LE(28);
    const total = 40 + cl + ml + bl;
    if (recvBuf.length < total) return;
    const frame = {
      op: recvBuf.readUInt16LE(6),
      requestId: recvBuf.readUInt32LE(8),
      status: recvBuf.readInt32LE(12),
      flags: recvBuf.readUInt32LE(16),
      value0: recvBuf.readBigUInt64LE(32),
      cmd: recvBuf.subarray(40, 40 + cl).toString('utf8'),
      message: recvBuf.subarray(40 + cl, 40 + cl + ml).toString('utf8'),
      body: recvBuf.subarray(40 + cl + ml, total),
    };
    recvBuf = recvBuf.subarray(total);
    onFrame(frame);
  }
}

function destroy() {
  if (socket) {
    try { socket.destroy(); } catch { /* ignore */ }
    socket = null;
  }
  connecting = null;
  recvBuf = Buffer.alloc(0);
  for (const [id, entry] of pending) {
    if (entry.timer) clearTimeout(entry.timer);
    entry.reject(new Error('pipe closed'));
    pending.delete(id);
  }
}
  __syncState();

function ensureSocket() {
  if (socket && !socket.destroyed) return Promise.resolve(socket);
  if (connecting) return connecting;
  connecting = new Promise((resolve, reject) => {
    const name = pipeName();
    const s = net.connect(name);
    let settled = false;
    // ⚠️ 必须给 connect 加超时：管道"存在但 server 不 accept"时（dll 的 pipe server 被挂死），
    //    net.connect 既不触发 'connect' 也不触发 'error'，这个 Promise 会永远 pending。
    //    而 `connecting` 一直非 null → 后续所有 ensureSocket() 都返回这个永挂的 Promise
    //    → 表现为「一批动作集体 ETIMEDOUT，重启 QQ 才恢复」。这就是那个假死的真根因。
    const timer = setTimeout(() => {
      fail(Object.assign(new Error('pipe connect timeout'), { code: 'ETIMEDOUT' }));
    }, 5000);
    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      lastError = err.message;
      connecting = null;
      try { s.destroy(); } catch { /* ignore */ }
      reject(err);
    };
    s.once('error', fail);
    s.once('connect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      s.removeListener('error', fail);
      socket = s;
      connecting = null;
      recvBuf = Buffer.alloc(0);
      s.on('data', (chunk) => { try { consume(chunk); } catch (e) { lastError = String(e && e.message); destroy(); } });
      s.on('error', (e) => { lastError = String(e && e.message); destroy(); });
      s.on('close', () => { destroy(); });
      resolve(s);
      __syncState();
    });
  });
  return connecting;
}

/**
 * 发一个 SSO 包。
 * @param {string} cmd   例如 'OidbSvcTrpcTcp.0xed3_1'
 * @param {Buffer} body  原始 protobuf 字节
 * @param {object} opts  { wantReply=true, timeoutMs }
 * @returns {Promise<{status:number,message:string,body:Buffer}>}
 */
async function sendSso(cmd, body = Buffer.alloc(0), opts = {}) {
  const wantReply = opts.wantReply !== false;
  const timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs) : DEFAULT_TIMEOUT_MS;
  if (!cmd) throw new Error('cmd is required');
  const s = await ensureSocket();
  const id = ++seq;
  const flags = wantReply ? 1 : 0;
  const frame = buildFrame({ op: OP_SEND, requestId: id, flags, cmd, body });
  if (!wantReply) {
    s.write(frame);
    return { status: 0, message: 'sent', body: Buffer.alloc(0) };
  }
  const wait = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`sso pipe timeout after ${timeoutMs}ms (cmd=${cmd})`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
  });
  s.write(frame);
  return wait;
}

/** ping（op=0x11），返回 { ok, loggedIn, uin, error } */
async function ping(timeoutMs = 3000) {
  const s = await ensureSocket();
  const id = ++seq;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({ ok: false, loggedIn, uin, error: 'ping timeout' });
    }, timeoutMs);
    pending.set(id, {
      ackOnly: true,
      resolve: () => { clearTimeout(timer); resolve({ ok: true, loggedIn, uin, error: '' }); },
      reject: (e) => { clearTimeout(timer); resolve({ ok: false, loggedIn, uin, error: String(e && e.message) }); },
      timer,
    });
    s.write(buildFrame({ op: OP_PING, requestId: id }));
  });
}

// ---- 极简 protobuf 编码（够 OIDB 用）----
function pbVarint(n) {
  const out = [];
  let v = BigInt(n);
  if (v < 0n) v = BigInt.asUintN(64, v);
  while (v > 0x7fn) { out.push(Number(v & 0x7fn) | 0x80); v >>= 7n; }
  out.push(Number(v));
  return Buffer.from(out);
}
const pbTag = (num, wire) => pbVarint((num << 3) | wire);
const pbVarintField = (num, n) => Buffer.concat([pbTag(num, 0), pbVarint(n)]);
const pbBytesField = (num, buf) => Buffer.concat([pbTag(num, 2), pbVarint(buf.length), buf]);

/**
 * 构造拍一拍的 OIDB 包体（OidbBase 包 OidbPoke）。
 * OidbPoke { uin=1, groupUin=2, friendUin=5, ext=6 }  ← friendUin 是 5，不是 3
 * 群聊：uin=被拍的人, groupUin=群号, friendUin=0
 * 私聊：uin=对方,      groupUin=0,    friendUin=对方
 */
function buildOidbPoke({ groupId = 0, userId = 0 } = {}) {
  const g = BigInt(groupId || 0);
  const u = BigInt(userId || 0);
  const isGroup = g > 0n;
  const poke = Buffer.concat([
    pbVarintField(1, u),                       // uin：被拍的人
    pbVarintField(2, isGroup ? g : 0n),        // groupUin
    pbVarintField(5, isGroup ? 0n : u),        // friendUin
    pbVarintField(6, 0n),                      // ext
  ]);
  // OidbBase { command=1, subCommand=2, errorCode=3, body=4 }
  return Buffer.concat([
    pbVarintField(1, 3795), // 0xed3 SendPoke
    pbVarintField(2, 1),
    pbVarintField(3, 0),
    pbBytesField(4, poke),
  ]);
}

function status() {
  return {
    pipe: pipeName(),
    connected: Boolean(socket && !socket.destroyed),
    loggedIn,
    uin,
    pending: pending.size,
    lastError,
  };
}

module.exports = { sendSso, ping, status, pipeName, buildFrame, buildOidbPoke, pbVarint, pbVarintField, pbBytesField, OP_SEND, OP_PING, MAGIC };
