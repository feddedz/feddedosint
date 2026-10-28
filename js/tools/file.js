import { h, getJSON, card, kv, ext, grid, muted, badge, copyBtn, linkGroups, sha256, fmtNum } from '../util.js';
import { md5 } from '../md5.js';
import { getKey, hasKey } from '../store.js';
import { extractEntities, entityCards, countAll } from './extract.js';

// File signatures ("magic bytes"). test(b) gets the first bytes as a Uint8Array.
const at = (b, off, ...bytes) => bytes.every((x, i) => b[off + i] === x);
const str = (b, off, s) => [...s].every((c, i) => b[off + i] === c.charCodeAt(0));
const SIGS = [
  ['Windows executable (PE)', ['exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'efi'], b => at(b, 0, 0x4d, 0x5a)],
  ['ELF executable (Linux / Unix)', ['', 'so', 'elf', 'bin', 'o'], b => at(b, 0, 0x7f, 0x45, 0x4c, 0x46)],
  ['Mach-O executable (macOS)', ['', 'dylib', 'bundle'], b => at(b, 0, 0xcf, 0xfa, 0xed, 0xfe) || at(b, 0, 0xce, 0xfa, 0xed, 0xfe) || at(b, 0, 0xfe, 0xed, 0xfa, 0xcf)],
  ['Java class / Mach-O fat binary', ['class', ''], b => at(b, 0, 0xca, 0xfe, 0xba, 0xbe)],
  ['PDF document', ['pdf'], b => str(b, 0, '%PDF')],
  ['ZIP archive (also docx / xlsx / pptx / jar / apk)', ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odt', 'ods', 'epub', 'xpi', 'ipa', 'whl', 'nupkg', 'vsix'], b => at(b, 0, 0x50, 0x4b, 0x03, 0x04) || at(b, 0, 0x50, 0x4b, 0x05, 0x06)],
  ['Legacy Office / OLE (doc, xls, ppt, msg, msi)', ['doc', 'xls', 'ppt', 'msg', 'msi', 'pub', 'vsd'], b => at(b, 0, 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)],
  ['RTF document', ['rtf', 'doc'], b => str(b, 0, '{\\rtf')],
  ['RAR archive', ['rar'], b => str(b, 0, 'Rar!')],
  ['7-Zip archive', ['7z'], b => at(b, 0, 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)],
  ['GZIP compressed', ['gz', 'tgz'], b => at(b, 0, 0x1f, 0x8b)],
  ['XZ compressed', ['xz'], b => at(b, 0, 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)],
  ['BZIP2 compressed', ['bz2'], b => str(b, 0, 'BZh')],
  ['CAB archive', ['cab'], b => str(b, 0, 'MSCF')],
  ['ISO disk image', ['iso'], b => str(b, 0x8001, 'CD001')],
  ['Windows shortcut (LNK)', ['lnk'], b => at(b, 0, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00)],
  ['SQLite database', ['sqlite', 'db', 'sqlite3'], b => str(b, 0, 'SQLite format 3')],
  ['PNG image', ['png'], b => at(b, 0, 0x89, 0x50, 0x4e, 0x47)],
  ['JPEG image', ['jpg', 'jpeg', 'jfif'], b => at(b, 0, 0xff, 0xd8, 0xff)],
  ['GIF image', ['gif'], b => str(b, 0, 'GIF8')],
  ['WebP image', ['webp'], b => str(b, 0, 'RIFF') && str(b, 8, 'WEBP')],
  ['WAV audio', ['wav'], b => str(b, 0, 'RIFF') && str(b, 8, 'WAVE')],
  ['AVI video', ['avi'], b => str(b, 0, 'RIFF') && str(b, 8, 'AVI ')],
  ['BMP image', ['bmp'], b => str(b, 0, 'BM')],
  ['TIFF image', ['tif', 'tiff', 'dng', 'nef', 'cr2'], b => str(b, 0, 'II*\0') || str(b, 0, 'MM\0*')],
  ['ICO icon', ['ico'], b => at(b, 0, 0x00, 0x00, 0x01, 0x00)],
  ['MP4 / QuickTime / HEIC', ['mp4', 'm4a', 'm4v', 'mov', 'heic', 'heif', '3gp'], b => str(b, 4, 'ftyp')],
  ['MP3 audio', ['mp3'], b => str(b, 0, 'ID3') || at(b, 0, 0xff, 0xfb)],
  ['OGG media', ['ogg', 'oga', 'ogv', 'opus'], b => str(b, 0, 'OggS')],
  ['FLAC audio', ['flac'], b => str(b, 0, 'fLaC')],
  ['WebAssembly', ['wasm'], b => at(b, 0, 0x00, 0x61, 0x73, 0x6d)],
  ['Script with shebang', ['sh', 'bash', 'zsh', 'py', 'pl', 'rb', 'js', 'mjs', 'php', 'lua', ''], b => str(b, 0, '#!')],
  ['XML / SVG', ['xml', 'svg', 'plist', 'xaml'], b => str(b, 0, '<?xml')],
  ['HTML document', ['html', 'htm', 'hta'], b => /^\s*<(!doctype html|html|head|script)/i.test(String.fromCharCode(...b.subarray(0, 64)))],
];

function identify(b, name) {
  const ext = (name.includes('.') ? name.split('.').pop() : '').toLowerCase();
  const sig = SIGS.find(([, , t]) => { try { return t(b); } catch { return false; } });
  if (!sig) return { type: null, ext, mismatch: false };
  const mismatch = !!ext && !sig[1].includes(ext);
  return { type: sig[0], ext, mismatch, expected: sig[1].filter(Boolean) };
}

function entropy(b) {
  if (!b.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < b.length; i++) counts[b[i]]++;
  let e = 0;
  for (const c of counts) if (c) { const p = c / b.length; e -= p * Math.log2(p); }
  return e;
}

// Printable ASCII and UTF-16LE strings, like the classic `strings` tool.
function strings(b, min = 5, cap = 6000) {
  const out = [];
  let cur = '';
  for (let i = 0; i < b.length && out.length < cap; i++) {
    const c = b[i];
    if ((c >= 0x20 && c < 0x7f) || c === 9) cur += String.fromCharCode(c);
    else { if (cur.length >= min) out.push(cur); cur = ''; }
  }
  if (cur.length >= min) out.push(cur);
  let wide = '';
  for (let i = 0; i + 1 < b.length && out.length < cap; i += 2) {
    const c = b[i];
    if (b[i + 1] === 0 && ((c >= 0x20 && c < 0x7f) || c === 9)) wide += String.fromCharCode(c);
    else { if (wide.length >= min) out.push(wide); wide = ''; }
  }
  return [...new Set(out)];
}

const MACHINE = { 0x14c: 'x86 (32-bit)', 0x8664: 'x86-64', 0x1c0: 'ARM', 0x1c4: 'ARM Thumb-2', 0xaa64: 'ARM64', 0x200: 'IA-64' };
const SUBSYSTEM = { 1: 'native / driver', 2: 'Windows GUI', 3: 'Windows console', 9: 'Windows CE', 10: 'EFI application', 11: 'EFI boot driver', 12: 'EFI runtime driver', 14: 'Xbox', 16: 'boot application' };

function parsePE(b) {
  if (b.length < 0x40 || !at(b, 0, 0x4d, 0x5a)) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const pe = dv.getUint32(0x3c, true);
  if (pe + 24 > b.length || dv.getUint32(pe, true) !== 0x00004550) return null;
  const nsec = dv.getUint16(pe + 6, true), optSize = dv.getUint16(pe + 20, true), chars = dv.getUint16(pe + 22, true);
  const opt = pe + 24, magic = opt + 2 <= b.length ? dv.getUint16(opt, true) : 0;
  const secOff = opt + optSize, sections = [];
  for (let i = 0; i < Math.min(nsec, 64); i++) {
    const o = secOff + i * 40;
    if (o + 40 > b.length) break;
    const name = String.fromCharCode(...b.subarray(o, o + 8)).replace(/\0+$/, '');
    const rawSize = dv.getUint32(o + 16, true), rawPtr = dv.getUint32(o + 20, true);
    sections.push({ name, size: rawSize, entropy: rawPtr < b.length ? entropy(b.subarray(rawPtr, Math.min(b.length, rawPtr + rawSize))) : 0 });
  }
  return {
    machine: MACHINE[dv.getUint16(pe + 4, true)] || `0x${dv.getUint16(pe + 4, true).toString(16)}`,
    compiled: dv.getUint32(pe + 8, true),
    kind: chars & 0x2000 ? 'DLL' : 'executable',
    format: magic === 0x20b ? 'PE32+ (64-bit)' : magic === 0x10b ? 'PE32 (32-bit)' : 'unknown',
    subsystem: opt + 70 <= b.length ? SUBSYSTEM[dv.getUint16(opt + 68, true)] : null,
    sections,
  };
}

const ELF_MACHINE = { 3: 'x86', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64', 40: 'ARM', 62: 'x86-64', 183: 'AArch64', 243: 'RISC-V' };
const ELF_TYPE = { 1: 'relocatable', 2: 'executable', 3: 'shared object / PIE', 4: 'core dump' };
function parseELF(b) {
  if (b.length < 20 || !at(b, 0, 0x7f, 0x45, 0x4c, 0x46)) return null;
  const le = b[5] === 1, dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return { bits: b[4] === 2 ? '64-bit' : '32-bit', endian: le ? 'little-endian' : 'big-endian',
    type: ELF_TYPE[dv.getUint16(16, le)] || 'other', machine: ELF_MACHINE[dv.getUint16(18, le)] || `machine ${dv.getUint16(18, le)}` };
}

const entTone = e => (e > 7.2 ? 'bad' : e > 6.5 ? 'warn' : 'muted');
const entText = e => (e > 7.2 ? 'very high — compressed, encrypted or packed' : e > 6.5 ? 'high' : e > 4 ? 'normal for code / binary data' : 'low — mostly text or padding');

function lookupLinks(hash) {
  const kind = { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' }[hash.length];
  return linkGroups([{ group: 'reputation (hash lookup only — nothing is uploaded)', items: [
    ['VirusTotal', `https://www.virustotal.com/gui/file/${hash}`],
    ['MalwareBazaar', kind === 'sha256' ? `https://bazaar.abuse.ch/sample/${hash}/` : `https://bazaar.abuse.ch/browse.php?search=${kind}%3A${hash}`],
    ['Hybrid Analysis', `https://www.hybrid-analysis.com/search?query=${hash}`],
    ['Triage', `https://tria.ge/s?q=${kind}%3A${hash}`],
    ['Kaspersky OpenTIP', `https://opentip.kaspersky.com/${hash}/`],
    ['AlienVault OTX', `https://otx.alienvault.com/indicator/file/${hash}`],
    ['Google', `https://www.google.com/search?q=%22${hash}%22`],
  ] }]);
}

// Optional live VirusTotal verdict, if the user saved a key. VT may refuse browser requests.
function vtCard(hash) {
  if (!hasKey('virustotal')) return null;
  const body = h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'asking VirusTotal…');
  const el = card('virustotal verdict', {}, body);
  getJSON(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': getKey('virustotal') } })
    .then(r => {
      if (r.status === 404) return body.replaceWith(muted('VirusTotal has never seen this file.'));
      const s = r.data?.data?.attributes?.last_analysis_stats;
      if (!r.ok || !s) throw 0;
      const bad = (s.malicious || 0) + (s.suspicious || 0);
      body.replaceWith(kv([
        ['detections', badge(`${bad} / ${bad + (s.undetected || 0) + (s.harmless || 0)} engines`, bad ? 'bad' : 'ok')],
        ['name', r.data.data.attributes.meaningful_name],
        ['type', r.data.data.attributes.type_description],
      ]));
    })
    .catch(() => body.replaceWith(muted('VirusTotal did not allow a direct browser request — use the link below.')));
  return el;
}

function hashMode(hash) {
  const kind = { 32: 'MD5 (or imphash)', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512' }[hash.length];
  return grid(
    card('hash', { wide: true }, kv([['value', h('code', { class: 'wrap small' }, hash)], ['type', kind || 'unknown length']]), lookupLinks(hash)),
    vtCard(hash),
  );
}

async function analyse(file) {
  const buf = new Uint8Array(await file.arrayBuffer());
  const head = buf.subarray(0, 0x9000);
  const id = identify(head, file.name);
  const [s256, sha1buf] = await Promise.all([sha256(buf), crypto.subtle.digest('SHA-1', buf)]);
  const s1 = [...new Uint8Array(sha1buf)].map(x => x.toString(16).padStart(2, '0')).join('');
  const m5 = buf.length <= 256 * 1024 * 1024 ? md5(buf) : null;
  const ent = entropy(buf);
  const pe = parsePE(buf), elf = parseELF(buf);
  const strs = strings(buf.subarray(0, 16 * 1024 * 1024));
  const ents = extractEntities(strs.join('\n'), 300);

  const strList = h('div', { class: 'strings' });
  const renderStrings = term => strList.replaceChildren(...strs.filter(s => !term || s.toLowerCase().includes(term)).slice(0, 400)
    .map(s => h('div', { class: 'mono small wrap' }, s)));
  renderStrings('');

  return [
    id.mismatch ? h('div', { class: 'verdict bad' }, `⚠ extension .${id.ext} does not match the real content (${id.type}) — a common disguise`) : null,
    grid(
      card('file', {}, kv([
        ['name', file.name], ['size', `${fmtNum(file.size)} bytes`],
        ['real type', id.type ? badge(id.type, id.mismatch ? 'bad' : 'ok') : 'unknown / plain data'],
        ['browser mime', file.type || '—'],
        ['modified', file.lastModified ? new Date(file.lastModified).toISOString().slice(0, 19).replace('T', ' ') : null],
        ['entropy', [badge(`${ent.toFixed(2)} / 8`, entTone(ent)), ' ', h('span', { class: 'muted small' }, entText(ent))]],
      ])),
      card('hashes', { actions: copyBtn(() => `md5  ${m5 || '-'}\nsha1 ${s1}\nsha256 ${s256}`, 'copy') }, kv([
        ['md5', m5 ? h('code', { class: 'wrap small' }, m5) : 'skipped (file too large)'],
        ['sha-1', h('code', { class: 'wrap small' }, s1)],
        ['sha-256', h('code', { class: 'wrap small' }, s256)],
      ]), lookupLinks(s256)),
      vtCard(s256),
      pe ? card('windows executable', { wide: true }, kv([
        ['format', `${pe.format} · ${pe.kind}`], ['cpu', pe.machine], ['subsystem', pe.subsystem],
        ['compile time', pe.compiled ? `${new Date(pe.compiled * 1000).toISOString().slice(0, 10)} (can be faked)` : null],
        ['packer hint', pe.sections.some(s => /upx/i.test(s.name)) ? badge('UPX packed', 'warn')
          : pe.sections.some(s => s.entropy > 7.2) ? badge('high-entropy section — possibly packed', 'warn') : null],
      ]), h('table', { class: 'records' }, h('tbody', {}, pe.sections.map(s => h('tr', {},
        h('td', { class: 'type' }, s.name || '(blank)'), h('td', {}, `${fmtNum(s.size)} bytes`),
        h('td', {}, badge(s.entropy.toFixed(2), entTone(s.entropy)))))))) : null,
      elf ? card('elf binary', {}, kv([['class', elf.bits], ['byte order', elf.endian], ['type', elf.type], ['cpu', elf.machine]])) : null,
      card(`strings · ${fmtNum(strs.length)}`, { wide: true, collapsed: strs.length > 0 && countAll(ents) > 0, actions: copyBtn(() => strs.join('\n'), 'copy') },
        h('input', { class: 'filter', placeholder: 'filter strings…', oninput: e => renderStrings(e.target.value.trim().toLowerCase()) }), strList),
    ),
    countAll(ents) ? h('div', { class: 'grid' }, entityCards(ents, { title: 'indicators in strings' })) : null,
  ];
}

function dropzone(results) {
  const input = h('input', { type: 'file', hidden: true });
  const zone = h('label', { class: 'drop' }, input,
    h('strong', {}, 'drop any file or click to choose'),
    h('span', { class: 'muted' }, 'Analysed locally: real type, hashes, entropy, strings, executable headers. The file is never uploaded.'));
  const handle = async file => {
    if (!file) return;
    results.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'analysing ', file.name, '…'));
    try { results.replaceChildren(...(await analyse(file)).filter(Boolean)); }
    catch (e) { results.replaceChildren(muted(`could not read that file: ${e.message}`)); }
  };
  input.addEventListener('change', () => handle(input.files[0]));
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('over'); handle(e.dataTransfer.files[0]); });
  return zone;
}

export default {
  id: 'file',
  label: 'file',
  placeholder: 'md5 / sha-1 / sha-256 hash — or drop a file below',
  intro: 'Static triage for any file — real type, hashes, entropy, strings and executable headers — or look up a hash.',
  examples: ['44d88612fea8a8f36de82e1278abb02f'],
  allowEmpty: true,

  run(raw) {
    const q = raw.trim().toLowerCase();
    if (q && !/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^[a-f0-9]{128}$/.test(q)) throw new Error('enter an MD5, SHA-1, SHA-256 or SHA-512 hash');
    const results = h('div');
    return [dropzone(results), results, q ? hashMode(q) : null];
  },
};
