import { createConnection, createServer } from 'node:net';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { chmodSync, mkdtempSync, rmSync, statSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function allocateChannelPath() {
  if (process.platform === 'win32') {
    return { path: `\\\\.\\pipe\\openqq-${randomBytes(16).toString('hex')}`, ownedDir: null };
  }
  const base = tmpdir();
  const root = Buffer.byteLength(join(base, 'oqq-123456', 'ipc.sock')) <= 96 ? base : '/tmp';
  const dir = mkdtempSync(join(root, 'oqq-'));
  chmodSync(dir, 0o700);
  return { path: join(dir, 'ipc.sock'), ownedDir: dir };
}

// 固定端点：同一份安装每次启动都落到同一个地址，QQ 侧的 session.cjs 断线后才可能重连回来。
// seed 一般传项目目录，让同一台机器上的多份安装互不冲突。
export function persistentChannelPath(seed) {
  const id = createHash('sha256').update(String(seed)).digest('hex').slice(0, 10);
  if (process.platform === 'win32') return `\\\\.\\pipe\\openqq-${id}`;
  let base = tmpdir();
  const runtimeDir = process.env.XDG_RUNTIME_DIR;
  if (runtimeDir) { try { if (statSync(runtimeDir).isDirectory()) base = runtimeDir; } catch { /* 没这个目录就用 tmpdir */ } }
  const preferred = join(base, `openqq-${id}.sock`);
  // Unix domain socket 的 sun_path 上限通常是 104~108 字节，太长会 listen 失败，退到 /tmp。
  return Buffer.byteLength(preferred) <= 100 ? preferred : join('/tmp', `openqq-${id}.sock`);
}

// 上次异常退出可能留下 socket 文件。先探一下有没有人真的在听，确认没人再删，
// 避免把另一个正在服务的实例的端点删掉。
function clearStaleSocket(path) {
  try { if (!statSync(path).isSocket()) return Promise.resolve(false); } catch { return Promise.resolve(false); }
  return new Promise(resolve => {
    const probe = createConnection(path);
    probe.once('connect', () => { probe.destroy(); resolve(false); });
    probe.once('error', () => { try { unlinkSync(path); } catch { /* 删不掉就让 listen 报 EADDRINUSE */ } resolve(true); });
  });
}

export async function createNativeChannel(customPath, customToken) {
  const allocated = customPath ? { path: customPath, ownedDir: null } : allocateChannelPath();
  const path = allocated.path;
  const isWindowsPipe = process.platform === 'win32' || path.startsWith('\\\\.\\pipe\\');
  // 固定端点（调用方给了 customPath）可能残留上次的 socket 文件，listen 前先清掉。
  if (customPath && !isWindowsPipe) await clearStaleSocket(path);
  const events = new EventEmitter();
  const token = typeof customToken === 'string' && customToken.length >= 32 ? customToken : randomBytes(32).toString('hex');
  const sockets = new Set();
  let authenticated;
  const pending = new Map();
  function failPending() {
    for (const task of pending.values()) {
      clearTimeout(task.timer);
      task.reject(Object.assign(new Error('IPC 已断开；已提交的发送结果未确认，请勿自动重试'), { retcode: 1502 }));
    }
    pending.clear();
  }
  const server = createServer(socket => {
    sockets.add(socket);
    socket.setEncoding('utf8');
    socket.setTimeout(2000, () => socket.destroy());
    let buffer = '';
    let accepted = false;
    socket.on('error', () => socket.destroy());
    socket.on('close', () => {
      sockets.delete(socket);
      // 允许同一端点被下一次连接重新认证；否则 QQ 侧断线重连会被「已认证」挡掉。
      if (authenticated === socket) authenticated = null;
      if (accepted) { failPending(); events.emit('disconnected'); }
    });
    socket.on('data', chunk => {
      buffer += chunk;
      if (Buffer.byteLength(buffer) > 1024 * 1024) { socket.destroy(); return; }
      for (let end; (end = buffer.indexOf('\n')) !== -1;) {
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        try {
          const event = JSON.parse(line);
          if (!accepted) {
            const candidate = typeof event.token === 'string' ? Buffer.from(event.token) : Buffer.alloc(0);
            if (authenticated || event.type !== 'hello' || candidate.length !== token.length || !timingSafeEqual(candidate, Buffer.from(token)) || !Number.isSafeInteger(event.pid) || event.pid <= 0) {
              socket.destroy(); return;
            }
            accepted = true;
            authenticated = socket;
            socket.setTimeout(0);
            events.emit('connected', { pid: event.pid });
          } else if (event.type === 'action_result') {
            const task = pending.get(event.id);
            if (task) {
              clearTimeout(task.timer);
              pending.delete(event.id);
              task.resolve(event.response);
            }
          } else events.emit('event', event);
        } catch { socket.destroy(); return; }
      }
    });
  });
  server.maxConnections = 8;
  server.on('error', error => events.emit('failure', error));
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(path, resolve);
    });
    if (!isWindowsPipe) chmodSync(path, 0o600);
  } catch (error) {
    if (allocated.ownedDir) rmSync(allocated.ownedDir, { recursive: true, force: true });
    throw error;
  }
  return {
    events, path, token,
    request(request, timeoutMs = 20000) {
      return new Promise((resolve, reject) => {
        if (!authenticated?.writable || authenticated.destroyed) { reject(Object.assign(new Error('QQ 原生 IPC 尚未连接'), { retcode: 1502 })); return; }
        if (pending.size >= 32 || authenticated.writableLength > 1024 * 1024) { reject(Object.assign(new Error('动作队列已满，未提交'), { retcode: 1503 })); return; }
        const id = randomBytes(16).toString('hex');
        const frame = JSON.stringify({ type: 'action', id, request }) + '\n';
        if (Buffer.byteLength(frame) > 1024 * 1024) { reject(Object.assign(new Error('动作帧超过 1 MiB，未提交'), { retcode: 1400 })); return; }
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(Object.assign(new Error('IPC 动作超时；已提交的发送结果未确认，请勿自动重试'), { retcode: 1501 }));
        }, timeoutMs);
        pending.set(id, { resolve, reject, timer });
        authenticated.write(frame);
      });
    },
    async close() {
      failPending();
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
      if (allocated.ownedDir) rmSync(allocated.ownedDir, { recursive: true, force: true });
      else if (!isWindowsPipe) rmSync(path, { force: true });
    },
  };
}
