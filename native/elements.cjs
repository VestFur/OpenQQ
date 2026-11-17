'use strict';

const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ELEMENT = { text: 1, pic: 2, file: 3, ptt: 4, video: 5, face: 6 };
const PIC_TYPE = { jpeg: 1000, png: 1001, webp: 1002, bmp: 1005, gif: 2000 };
const VIDEO_FORMAT = { mp4: 2, mov: 8 };
// Placeholder waveform QQ draws under a voice message; the real one is not needed for playback.
const WAVEFORM = [99, 75, 34, 50, 18, 85, 44, 82, 69, 35, 71, 36, 12, 30, 53, 18, 38, 62, 60, 21, 33, 35, 79, 82, 8, 28, 48, 74, 50, 27,
  39, 55, 14, 68, 54, 46, 11, 41, 52, 62, 12, 47, 18, 8, 85, 14, 26, 6, 21, 19];

function md5File(file) {
  return new Promise((resolve, reject) => {
    const hash = createHash('md5');
    fs.createReadStream(file).once('error', reject).on('data', chunk => hash.update(chunk)).once('end', () => resolve(hash.digest('hex')));
  });
}

// Copies a prepared local file into the folder QQ keeps its rich media in, and returns where QQ expects it.
async function stage(service, source, elementType, fileName, method = 'getRichMediaFilePathForGuild') {
  const md5 = await md5File(source);
  const target = service[method]({ md5HexStr: md5, fileName, elementType, elementSubType: 0, thumbSize: 0,
    needCreate: true, downloadType: 1, file_uuid: '' });
  if (typeof target !== 'string' || !target) throw new Error('QQ 没有返回富媒体存放路径');
  await fs.promises.mkdir(path.dirname(target), { recursive: true });
  await fs.promises.copyFile(source, target);
  return { md5, target, size: (await fs.promises.stat(target)).size };
}

const base = (elementType, key, value) => ({ elementType, elementId: '', [key]: value });

function createElementBuilder({ session, ensure, groupCode, memberUid, memberName }) {
  const service = () => session.getMsgService();
  return {
    async at(part) {
      if (part.target === 'all') return base(ELEMENT.text, 'textElement', { content: '@全体成员', atType: 1, atUid: '0', atTinyId: '', atNtUid: '' });
      const uid = await memberUid(groupCode, part.target);
      ensure();
      const name = part.name || await memberName(groupCode, uid).catch(() => '') || part.target;
      ensure();
      return base(ELEMENT.text, 'textElement', { content: '@' + name, atType: 2, atUid: part.target, atTinyId: '', atNtUid: uid });
    },
    face(part) {
      return base(ELEMENT.face, 'faceElement', { faceIndex: part.id, faceType: part.id >= 222 ? 2 : 1 });
    },
    dice() {
      return base(ELEMENT.face, 'faceElement', { faceIndex: 358, faceType: 3, faceText: '[骰子]', packId: '1', stickerId: '33', sourceType: 1, stickerType: 2, surpriseId: '' });
    },
    rps() {
      return base(ELEMENT.face, 'faceElement', { faceIndex: 359, faceType: 3, faceText: '[包剪锤]', packId: '1', stickerId: '34', sourceType: 1, stickerType: 2, surpriseId: '' });
    },
    async image(part) {
      const media = part.media;
      const staged = await stage(service(), media.path, ELEMENT.pic, media.name);
      ensure();
      return base(ELEMENT.pic, 'picElement', { md5HexStr: staged.md5, fileSize: staged.size, picWidth: media.width, picHeight: media.height, fileName: media.name,
        sourcePath: staged.target, original: true, picType: PIC_TYPE[media.format] ?? PIC_TYPE.png, picSubType: 0, fileUuid: '', fileSubId: '', thumbFileSize: 0, summary: part.summary });
    },
    async record(part) {
      const media = part.media;
      const md5 = await md5File(media.path);
      const fileName = md5 + '.amr';
      // 语音要按 mobile-send 的登记路径落盘；部分版本的 guild 路径会拒绝 elementType 4。
      let staged, mobileError;
      try { staged = await stage(service(), media.path, ELEMENT.ptt, fileName, 'getRichMediaFilePathForMobileQQSend'); }
      catch (error) { mobileError = error; }
      if (!staged) {
        try { staged = await stage(service(), media.path, ELEMENT.ptt, fileName); }
        catch (error) { throw new Error('语音文件登记失败：mobile=' + (mobileError && mobileError.message) + '；guild=' + error.message); }
      }
      ensure();
      // The field set mirrors a pttElement QQ itself produced. QQ enumerates the keys of the nested `otherBusinessInfo`
      // while sending, so leaving it out fails with only "Cannot convert undefined or null to object" (issue #7).
      return base(ELEMENT.ptt, 'pttElement', { fileName: md5 + '.amr', filePath: staged.target, md5HexStr: staged.md5, fileSize: String(staged.size), duration: media.duration,
        formatType: 1, voiceType: 0, voiceChangeType: 0, canConvert2Text: false, autoConvertText: 0, waveAmplitudes: WAVEFORM, playState: 0,
        fileId: 0, fileUuid: '', fileSubId: '', fileBizId: null, storeID: 1, text: '', translateStatus: 0, transferStatus: 0, progress: 0, invalidState: 0,
        import_rich_media_context: null, otherBusinessInfo: { aiVoiceInfo: null, aiVoiceType: 0 }, isInApplicationDataPath: null });
    },
    async video(part) {
      const media = part.media;
      const staged = await stage(service(), media.path, ELEMENT.video, media.name);
      ensure();
      // QQ looks for the cover in a sibling "Thumb" folder of the "Ori" folder holding the video.
      const separator = path.sep;
      const folder = path.dirname(staged.target);
      const thumbFolder = folder.includes(`${separator}Ori`) ? folder.replace(`${separator}Ori`, `${separator}Thumb`) : path.join(folder, 'Thumb');
      await fs.promises.mkdir(thumbFolder, { recursive: true });
      const thumbTarget = path.join(thumbFolder, `${staged.md5}_0.png`);
      await fs.promises.copyFile(media.thumb.path, thumbTarget);
      const thumbMd5 = await md5File(thumbTarget);
      ensure();
      return base(ELEMENT.video, 'videoElement', { fileName: media.name, filePath: staged.target, videoMd5: staged.md5, thumbMd5, fileTime: media.duration,
        thumbPath: new Map([[0, thumbTarget]]), thumbSize: media.thumb.size, thumbWidth: media.thumb.width, thumbHeight: media.thumb.height,
        fileWidth: media.width, fileHeight: media.height, fileSize: String(staged.size), fileFormat: VIDEO_FORMAT[media.format] ?? VIDEO_FORMAT.mp4 });
    },
    async file(part) {
      const media = part.media;
      const staged = await stage(service(), media.path, ELEMENT.file, media.name);
      ensure();
      return base(ELEMENT.file, 'fileElement', { fileMd5: staged.md5, fileName: media.name, filePath: staged.target, fileSize: String(staged.size) });
    },
  };
}

module.exports = { createElementBuilder, md5File };
