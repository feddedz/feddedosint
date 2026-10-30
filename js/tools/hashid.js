import { h, card, grid, muted, badge, ext, pivot, copyBtn } from '../util.js';

// Identify the likely type of a hash / token from its length and character set, and offer the right
// lookup. Fully offline — the hash never leaves the browser (lookups are one-click, opt-in links).

const HEX = s => /^[a-f0-9]+$/i.test(s);
const B64 = s => /^[A-Za-z0-9+/]+={0,2}$/.test(s);

function identify(h) {
  const out = [];
  const len = h.length;
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(h)) out.push(['bcrypt', 'strong', true]);
  if (/^\$argon2(id|i|d)\$/.test(h)) out.push(['Argon2', 'strong', true]);
  if (/^\$6\$/.test(h)) out.push(['sha512crypt ($6$)', 'strong', true]);
  if (/^\$5\$/.test(h)) out.push(['sha256crypt ($5$)', 'strong', true]);
  if (/^\$1\$/.test(h)) out.push(['md5crypt ($1$)', 'weak', true]);
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(h)) out.push(['JWT (JSON Web Token)', '', false, 'jwt']);
  if (HEX(h)) {
    if (len === 32) out.push(['MD5', 'file/password', true], ['NTLM', 'password', true], ['MD4', '', false]);
    if (len === 40) out.push(['SHA-1', 'file/password', true], ['MySQL 4.1+ (*HEX)', '', false]);
    if (len === 56) out.push(['SHA-224', '', false]);
    if (len === 64) out.push(['SHA-256', 'file/password', true], ['SHA3-256', '', false], ['BLAKE2s', '', false]);
    if (len === 96) out.push(['SHA-384', '', false]);
    if (len === 128) out.push(['SHA-512', 'file/password', true], ['SHA3-512', '', false], ['Whirlpool', '', false]);
    if (len === 8) out.push(['CRC-32 / Adler-32', '', false]);
    if (len === 16) out.push(['MySQL323 / half-MD5', '', false]);
  }
  if (!HEX(h) && B64(h) && len % 4 === 0) out.push(['Base64-encoded data', '', false, 'b64']);
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(h)) out.push(['UUID / GUID', '', false]);
  return out;
}

export default {
  id: 'hashid',
  label: 'hashid',
  placeholder: 'paste a hash or token to identify',
  intro: 'Identifies the likely hash or token type from its format (MD5, SHA family, NTLM, bcrypt, Argon2, JWT, base64, UUID…), and points you to the right lookup. Offline.',
  examples: ['5f4dcc3b5aa765d61d8327deb882cf99', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'],

  run(raw) {
    const hash = (raw || '').trim();
    if (!hash) throw new Error('paste a hash or token');
    const matches = identify(hash);
    if (!matches.length) {
      return card('unrecognized', { wide: true }, muted(`“${hash.slice(0, 40)}${hash.length > 40 ? '…' : ''}” (${hash.length} chars) doesn’t match a known hash/token format.`));
    }

    const special = matches.find(m => m[3] === 'jwt') ? 'jwt' : matches.find(m => m[3] === 'b64') ? 'b64' : null;
    const rows = matches.filter(m => !m[3]).map(([name, use, crackable]) => h('tr', {},
      h('td', {}, h('strong', {}, name)),
      h('td', {}, use ? badge(use, use === 'strong' ? 'ok' : use === 'weak' ? 'bad' : 'muted') : null),
      h('td', { class: 'muted small' }, crackable ? 'common password/file hash' : 'checksum / non-secret')));

    const looksFileHash = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(hash);
    const lookups = card('lookups', { wide: true },
      muted('Opt-in external lookups (sends the hash to that service):'),
      h('div', { class: 'chips' }, [
        looksFileHash ? h('span', { class: 'chip' }, ext(`https://www.virustotal.com/gui/search/${hash}`, 'VirusTotal (file hash)')) : null,
        looksFileHash ? h('span', { class: 'chip' }, pivot('file', hash, 'file tool')) : null,
        h('span', { class: 'chip' }, ext(`https://hashes.com/en/decrypt/hash`, 'hashes.com')),
        special === 'jwt' ? h('span', { class: 'chip' }, pivot('utils', hash, 'decode JWT (utils)')) : null,
        special === 'b64' ? h('span', { class: 'chip' }, pivot('transform', '', 'decode in transform')) : null,
      ].filter(Boolean)));

    const header = card('hash identification', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, badge(`${hash.length} chars`, 'muted'), copyBtn(() => hash, 'copy')) },
      special === 'jwt' ? muted('This is a JWT — three base64url parts. Decode it to read the header & claims (don’t trust unsigned ones).') : null,
      h('table', { class: 'records' }, h('tbody', {}, rows)));

    return grid(header, lookups);
  },
};
