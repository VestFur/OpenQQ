import { readFile, stat } from 'node:fs/promises';
import { basename } from 'node:path';
import nativeActions from '../native/actions.cjs';

const fail = (message, retcode = 1400) => Object.assign(new Error(message), { retcode });
const sendActions = ['send_private_msg', 'send_group_msg', 'send_msg'];
const MAX_IMAGE_BASE64_BYTES = 16 * 1024 * 1024;

async function formatImageResult(data, mediaUrl) {
  const file = String(data?.file ?? '');
  const remoteUrl = typeof data?.url === 'string' && /^https?:\/\//.test(data.url) ? data.url : '';
  let size = Number(data?.file_size ?? 0) || 0;
  let exists = false;
  if (file) {
    try {
      const info = await stat(file);
      if (info.isFile()) { exists = true; size = info.size; }
    } catch { /* fallback below */ }
  }
  if (!exists && !remoteUrl) throw fail('图片文件不存在或尚未下载', 1404);
  const fileName = String(data?.file_name || (file ? basename(file) : '') || 'image');
  const url = remoteUrl || (exists && typeof mediaUrl === 'function' ? (mediaUrl(file, fileName) ?? '') : '');
  let base64;
  if (exists && size > 0 && size <= MAX_IMAGE_BASE64_BYTES) {
    try { base64 = (await readFile(file)).toString('base64'); } catch { /* best effort */ }
  }
  return { file, filename: fileName, file_name: fileName, size, file_size: size, url, ...(base64 ? { base64 } : {}) };
}

// OneBot ids are local to this process; translate them into the native references QQ needs before validation.
function resolveReferences(converter, request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) return request;
  const params = request.params;
  if (!params || typeof params !== 'object' || Array.isArray(params)) return request;
  if (request.action === 'get_forward_msg') {
    const ref = converter.resolve(params.id ?? params.message_id);
    if (!ref) throw fail('合并转发 id 不存在或已过期（仅支持本次运行期间收到的消息）', 1404);
    // A message id also works: QQ keys a top-level forward by the message that carries it.
    const forward = ref.kind === 'forward' ? ref : { chatType: ref.chatType, peerUid: ref.peerUid, root: ref.msgId, parent: ref.msgId };
    return { ...request, params: { ...params, openqq_ref: { chatType: forward.chatType, peerUid: forward.peerUid, root: forward.root, parent: forward.parent } } };
  }
  if (request.action === 'delete_msg') {
    const ref = converter.resolve(params.message_id);
    if (ref?.kind !== 'message') throw fail('message_id 不存在或已过期（仅支持本次运行期间收发过的消息）', 1404);
    return { ...request, params: { ...params, openqq_ref: { chatType: ref.chatType, peerUid: ref.peerUid, msgId: ref.msgId } } };
  }
  if (!sendActions.includes(request.action) || !Array.isArray(params.message)) return request;
  const message = params.message.map(segment => {
    if (segment?.type !== 'reply') return segment;
    const ref = converter.resolve(segment.data?.id);
    if (ref?.kind !== 'message') throw fail('引用的消息不存在或已过期（仅支持本次运行期间收发过的消息）', 1404);
    return { type: 'reply', data: { id: String(segment.data.id), openqq_ref: { chatType: ref.chatType, peerUid: ref.peerUid, msgId: ref.msgId } } };
  });
  return { ...request, params: { ...params, message } };
}

// Answers that need no QQ session. `can_send_*` is always yes because sending media is implemented here.
function localAnswer(request, options) {
  if (request?.action === 'get_version_info') {
    return { app_name: 'OpenQQ', app_version: options.version ?? '', protocol_version: 'v11' };
  }
  if (request?.action === 'can_send_image' || request?.action === 'can_send_record') return { yes: true };
  return undefined;
}

// `options.media` (see src/media.mjs) turns image / record / video / file segments into prepared local files.
export async function dispatchAction(channel, converter, request, options = {}) {
  let response;
  let release = async () => {};
  try {
    const local = localAnswer(request, options);
    if (local !== undefined) {
      response = { status: 'ok', retcode: 0, data: local };
    } else {
      let prepared = resolveReferences(converter, nativeActions.normalizeParams(request));
      if (options.media && sendActions.includes(prepared?.action) && prepared.params && typeof prepared.params === 'object') {
        const media = await options.media.prepare(prepared.params);
        prepared = { ...prepared, params: media.params };
        release = media.release;
      }
      const action = nativeActions.validateAction(prepared);
      response = await channel.request(prepared, (action.timeout ?? 15000) + 5000);
      if (!response || !['ok', 'failed'].includes(response.status) || !Number.isSafeInteger(response.retcode)) throw new Error('原生动作回执无效');
      if (response.status === 'ok' && response.retcode !== 0) throw new Error('原生动作回执状态不一致');
      // CUSTOM_ACTION_UNWRAP（2026-11-18）：native/actions.cjs 里自己实现的动作会返回**一整份 OneBot 回执**
      // （{status,retcode,data}），而通道会再把它塞进外层 data，于是上层看到 data.data，
      // 例如 fetch_custom_face_detail 的数组被埋在 data.data.data 里，桥只能报「data 不是数组」。
      // 这里把内层那份回执摊平：外层 status/retcode/message 用内层的，data 用内层的 data。
      if (response?.status === 'ok' && response.data && typeof response.data === 'object' && !Array.isArray(response.data)
          && typeof response.data.status === 'string' && Number.isSafeInteger(response.data.retcode)) {
        const inner = response.data;
        response = { status: inner.status, retcode: inner.retcode, data: inner.data ?? null, ...(inner.message ? { message: inner.message } : {}) };
      }
      if (response.status === 'ok' && action.kind === 'send') {
        response = { status: 'ok', retcode: 0, data: { message_id: converter.messageId(response.data.self, response.data.message) } };
      }
      if (response.status === 'ok' && action.kind === 'forward') {
        response = { status: 'ok', retcode: 0, data: converter.forwardResult(response.data.self, response.data.forward) };
      }
      if (response.status === 'ok' && action.kind === 'get_image') {
        response = { status: 'ok', retcode: 0, data: await formatImageResult(response.data, options.mediaUrl) };
      }
    }
  } catch (error) {
    // Diagnostics: a failed action used to keep only `message`, which hid where it came from.
    console.error('[dispatch] ' + (error?.stack ?? String(error)));
    response = { status: 'failed', retcode: error.retcode ?? 1500, data: null, message: error.message };
  } finally {
    await release();
  }
  return { ...response, ...(request && Object.hasOwn(request, 'echo') ? { echo: request.echo } : {}) };
}
