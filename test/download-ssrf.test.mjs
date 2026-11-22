// download_file 的 SSRF 防护现在全部在主进程的 media.mjs 下载器里：
//   · 字面 IP：download() 里 net.isIP + isBlockedAddress 直接拒绝（连请求都不发）；
//   · DNS 层：guarded lookup 把每个解析结果过 isBlockedAddress —— nip.io 这类
//     公共泛解析域名在解析之后被拒，这正是 review 指出的绕过方式；
//   · 凭据 / 非法 URL / base64 载荷在 resolveSource 与 download() 里各自校验。
// 这里测两层共用的事实函数 isBlockedAddress（字面层与 DNS 层判的都是它），
// 再用真实的 downloadFile 走一遍字面拒绝与 base64 落盘。
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { isBlockedAddress, createMediaPreparer } from '../src/media.mjs';

test('literal private targets are all recognized as blocked', () => {
  const rejected = [
    '0.0.0.1', '10.0.0.1', '100.64.0.1', '100.127.255.254', '127.0.0.1', '127.1.2.3',
    '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '::', '::1', 'fd00::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1',
  ];
  for (const address of rejected) {
    assert.ok(isBlockedAddress(address), `应该拦截 ${address}`);
  }
});

test('public addresses pass the block list', () => {
  for (const address of ['8.8.8.8', '1.1.1.1', '2606:4700::1111']) {
    assert.ok(!isBlockedAddress(address), `不该拦截 ${address}`);
  }
});

test('download_file refuses literal private urls before any request', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openqq-ssrf-'));
  try {
    const media = createMediaPreparer({ dir });
    for (const url of ['http://127.0.0.1:3999/panel', 'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.1/', 'http://192.168.1.1/', 'http://[::1]/', 'http://[fd00::1]/']) {
      await assert.rejects(() => media.downloadFile({ url }), /本机或内网/, `应该拒绝 ${url}`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('download_file refuses urls carrying credentials and non-http schemes', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openqq-ssrf-'));
  try {
    const media = createMediaPreparer({ dir });
    for (const url of ['http://user:pass@example.com/', 'ftp://example.com/file']) {
      await assert.rejects(() => media.downloadFile({ url }), /http\(s\)|下载地址/, `应该拒绝 ${url}`);
    }
    // file:// 在 download_file 语境里也不放行：media 的下载器只服务 http(s) / base64，
    // 一个本地绝对路径会被判为「不是绝对路径格式」而拒绝。
    await assert.rejects(() => media.downloadFile({ url: 'file:///etc/passwd' }), /绝对路径|地址/, '应该拒绝 file://');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('download_file requires url or base64, and base64 lands as a file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openqq-ssrf-'));
  try {
    const media = createMediaPreparer({ dir });
    await assert.rejects(() => media.downloadFile({}), /url 或 base64/);

    const payload = Buffer.from('hello openqq');
    const result = await media.downloadFile({ base64: payload.toString('base64'), name: 'greeting.txt' });
    assert.equal(result.name, 'greeting.txt');
    assert.equal(result.size, payload.length);
    assert.deepEqual(await readFile(result.file), payload);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('download_file name traversal is neutralized', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'openqq-ssrf-'));
  try {
    const media = createMediaPreparer({ dir });
    const payload = Buffer.from('x');
    const result = await media.downloadFile({ base64: payload.toString('base64'), name: '..\\..\\evil' });
    assert.notEqual(result.name, '..\\..\\evil');
    assert.ok(!result.name.includes('..'), `文件名不该保留 ..：${result.name}`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
