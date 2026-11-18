function numeric(value) { return /^\d+$/.test(String(value)) && Number.isSafeInteger(Number(value)); }
const text = value => typeof value === 'string' && value.length > 0;

function firstPath(value) {
  for (const candidate of [value.filePath, value.sourcePath]) {
    if (text(candidate)) return candidate;
  }
  const thumbs = value.thumbPath instanceof Map ? [...value.thumbPath.entries()]
    : value.thumbPath && typeof value.thumbPath === 'object' ? Object.entries(value.thumbPath) : [];
  thumbs.sort(([a], [b]) => (Number(a) === 0 ? -1 : Number(b) === 0 ? 1 : Number(b) - Number(a)));
  for (const [, candidate] of thumbs) {
    if (text(candidate)) return candidate;
  }
  return undefined;
}

export function convertSegment(element, replyId, forward, mediaUrl) {
  const fallback = () => ({ type: 'openqq_element', data: { element_type: element.elementType, element } });
  if (element.elementType === 1) {
    const value = element.textElement;
    if (typeof value?.content !== 'string') throw new Error('文本元素缺少 content');
    const at = Number(value.atType ?? 0);
    if (at === 0) return { type: 'text', data: { text: value.content } };
    if (at === 1) return { type: 'at', data: { qq: 'all' } };
    if (at === 2 && numeric(value.atUid) && Number(value.atUid) > 0) return { type: 'at', data: { qq: String(value.atUid) } };
    return fallback();
  }
  if (element.elementType === 6 && numeric(element.faceElement?.faceIndex)) {
    return { type: 'face', data: { id: String(element.faceElement.faceIndex) } };
  }
  const media = { 2: ['image', 'picElement'], 3: ['file', 'fileElement'], 4: ['record', 'pttElement'], 5: ['video', 'videoElement'] }[element.elementType];
  if (media) {
    const value = element[media[1]];
    if (!value) return fallback();
    // Diagnostics: OPENQQ_PTT_DUMP=1 dumps one real ptt element so the outgoing field set
    // can be matched exactly (QQ 原生层缺一个嵌套对象就只报 Could not convert undefined or null).
    if (element.elementType === 4 && process.env.OPENQQ_PTT_DUMP === '1' && !globalThis.__openqqPttDumped) {
      globalThis.__openqqPttDumped = true;
      try { console.error('[ptt-shape] ' + JSON.stringify(value).slice(0, 1500)); } catch { /* ignore */ }
    }
    const file = value.fileName || value.md5HexStr || value.fileUuid;
    if (!text(file)) return fallback();
    // QQ 客户端开过「语音转文字」时，pttElement.text 就是转写结果——入站直接透给上层，
    // 比另跑 STT 便宜得多；出站不需要它。
    const text = typeof value.text === 'string' ? value.text.trim() : '';
    const data = { file, ...(value.fileUuid ? { file_id: String(value.fileUuid) } : {}), ...(text ? { text } : {}) };
    const localPath = firstPath(value);
    if (localPath) data.path = localPath;
    if (text(value.originImageUrl) && /^https?:\/\//.test(value.originImageUrl)) data.url = value.originImageUrl;
    else if (localPath && typeof mediaUrl === 'function') {
      const served = mediaUrl(localPath, file);
      if (text(served)) data.url = served;
      else if (element.elementType === 2) data.file = localPath;
    }
    if (numeric(value.fileSize)) data.file_size = Number(value.fileSize);
    return { type: media[0], data };
  }
  if (element.elementType === 7 && element.replyElement) {
    const value = element.replyElement;
    const original = value.sourceMsgIdInRecords || value.replayMsgId;
    if (/^\d+$/.test(String(original)) && String(original) !== '0' && (typeof original !== 'number' || Number.isSafeInteger(original))) {
      return { type: 'reply', data: { id: String(replyId(original)) } };
    }
    return fallback();
  }
  if (element.elementType === 16 && element.multiForwardMsgElement?.openqq && forward) return forward(element.multiForwardMsgElement.openqq);
  if (element.elementType === 10 && text(element.arkElement?.bytesData)) return { type: 'json', data: { data: element.arkElement.bytesData } };
  if (element.elementType === 13 && text(element.structLongMsgElement?.xmlContent)) return { type: 'xml', data: { data: element.structLongMsgElement.xmlContent } };
  if (element.elementType === 11 && element.marketFaceElement) {
    const value = element.marketFaceElement;
    return { type: 'mface', data: { emoji_id: String(value.emojiId ?? ''), emoji_package_id: value.emojiPackageId, summary: String(value.faceName ?? '') } };
  }
  if (element.elementType === 14 && element.markdownElement) return { type: 'markdown', data: element.markdownElement };
  return fallback();
}

const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('[', '&#91;').replaceAll(']', '&#93;');
export function cqString(segments) {
  // A forward's expanded content stays in the array form; its CQ code carries only the id, as in go-cqhttp.
  return segments.map(segment => segment.type === 'text' ? escape(segment.data.text)
    : `[CQ:${segment.type}${Object.entries(segment.type === 'forward' ? { id: segment.data.id } : segment.data).map(([key, value]) => `,${key}=${escape(typeof value === 'object' ? JSON.stringify(value) : value).replaceAll(',', '&#44;')}`).join('')}]`).join('');
}
