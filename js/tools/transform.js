import { h, card, grid, muted, badge, copyBtn, sha256 } from '../util.js';
import { md5 } from '../md5.js';

// A CyberChef-style transform pipeline: stack operations (encode/decode/hash/case/reverse) and see
// the output update live. Fully offline — nothing leaves the browser.

const enc = new TextEncoder();
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

async function sha1Hex(str) {
  const d = await crypto.subtle.digest('SHA-1', enc.encode(str));
  return toHex(d);
}

// Each op: name + an (async) string -> string function.
const OPS = {
  'base64 encode': s => btoa(unescape(encodeURIComponent(s))),
  'base64 decode': s => decodeURIComponent(escape(atob(s.trim()))),
  'url encode': s => encodeURIComponent(s),
  'url decode': s => decodeURIComponent(s),
  'hex encode': s => [...enc.encode(s)].map(b => b.toString(16).padStart(2, '0')).join(''),
  'hex decode': s => { const h2 = s.replace(/[^0-9a-f]/gi, ''); const b = new Uint8Array(h2.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h2.substr(i * 2, 2), 16); return new TextDecoder().decode(b); },
  'binary encode': s => [...enc.encode(s)].map(b => b.toString(2).padStart(8, '0')).join(' '),
  'binary decode': s => { const bits = s.replace(/[^01]/g, ''); const b = new Uint8Array(bits.length / 8); for (let i = 0; i < b.length; i++) b[i] = parseInt(bits.substr(i * 8, 8), 2); return new TextDecoder().decode(b); },
  rot13: s => s.replace(/[a-z]/gi, c => String.fromCharCode((c.toLowerCase() <= 'm' ? 13 : -13) + c.charCodeAt(0))),
  reverse: s => [...s].reverse().join(''),
  uppercase: s => s.toUpperCase(),
  lowercase: s => s.toLowerCase(),
  'strip whitespace': s => s.replace(/\s+/g, ''),
  md5: s => toHex(md5(enc.encode(s))),
  'sha-1': s => sha1Hex(s),
  'sha-256': s => sha256(s),
};
const OP_NAMES = Object.keys(OPS);

async function apply(input, pipeline) {
  let v = input, err = null;
  for (const op of pipeline) {
    try { v = await OPS[op](v); } catch (e) { err = `step "${op}" failed: ${e.message}`; break; }
  }
  return { v, err };
}

export default {
  id: 'transform',
  label: 'transform',
  placeholder: '',
  intro: 'A chainable transform pipeline — stack encode/decode/hash/case operations and watch the output update. Fully offline.',
  examples: [],
  noInput: true,
  noTrack: true,

  run() {
    let pipeline = [];
    const input = h('textarea', { class: 'bigtext', rows: '4', placeholder: 'input text…', spellcheck: 'false' });
    const output = h('textarea', { class: 'bigtext', rows: '4', readonly: 'true', spellcheck: 'false' });
    const chips = h('div', { class: 'chips' });
    const errBox = h('div', {});

    const refresh = async () => {
      chips.replaceChildren(...(pipeline.length ? pipeline.map((op, i) => {
        const x = h('span', { class: 'chip', style: 'cursor:pointer' }, `${i + 1}. ${op}`, h('span', { class: 'muted' }, ' ✕'));
        x.onclick = () => { pipeline.splice(i, 1); refresh(); };
        return x;
      }) : [h('span', { class: 'muted small' }, 'no operations — add some below. Click a step to remove it.')]));
      const { v, err } = await apply(input.value, pipeline);
      output.value = err ? '' : v;
      errBox.replaceChildren(err ? h('p', { class: 'error small' }, err) : null);
    };

    input.addEventListener('input', refresh);
    const sel = h('select', { class: 'filter' }, h('option', { value: '' }, 'add operation…'), ...OP_NAMES.map(n => h('option', { value: n }, n)));
    sel.onchange = () => { if (sel.value) { pipeline.push(sel.value); sel.value = ''; refresh(); } };
    const clear = h('button', { class: 'mini ghost', type: 'button' }, 'clear'); clear.onclick = () => { pipeline = []; refresh(); };

    // quick-add buttons for the common ops
    const quick = ['base64 encode', 'base64 decode', 'url decode', 'hex decode', 'rot13', 'sha-256'].map(op => {
      const b = h('button', { class: 'mini', type: 'button' }, op); b.onclick = () => { pipeline.push(op); refresh(); }; return b;
    });

    refresh();
    return grid(
      card('input', { wide: true }, input),
      card('pipeline', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, sel, clear) },
        chips, errBox, h('div', { class: 'row wrap', style: 'gap:6px;margin-top:8px' }, quick)),
      card('output', { wide: true, actions: copyBtn(() => output.value, 'copy') }, output));
  },
};
