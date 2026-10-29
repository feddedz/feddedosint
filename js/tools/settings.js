import { h, card, grid, muted, ext, badge } from '../util.js';
import { KEY_DEFS, getKey, setKey, hasKey, settings, setSetting, applyTheme, clearGraph, clearRecent } from '../store.js';
import * as be from '../backend.js';

function backendCard() {
  const status = h('span', {}, badge('checking…', 'muted'));
  be.health(true).then(info => {
    if (!info) return status.replaceChildren(badge('unreachable', 'bad'));
    status.replaceChildren(badge('connected', 'ok'), ' ', h('span', { class: 'muted small' }, `AI ${info.ai ? 'ready (' + info.model + ')' : 'off'}`));
  });
  return card('backend', { wide: true, actions: status },
    muted('Everyone uses the shared feddedosint backend: GitHub sign-in, approvals, the AI and the proxies.'),
    h('p', { class: 'muted small' }, be.BACKEND));
}

function keyRow(def) {
  const input = h('input', {
    class: 'filter', type: 'password', value: getKey(def.id), placeholder: 'paste key…', spellcheck: 'false', autocomplete: 'off',
  });
  const state = h('span', {}, hasKey(def.id) ? badge('set', 'ok') : badge('empty', 'muted'));
  const save = h('button', { class: 'mini', type: 'button' }, 'save');
  save.onclick = () => { setKey(def.id, input.value); state.replaceChildren(input.value.trim() ? badge('set', 'ok') : badge('empty', 'muted')); save.textContent = 'saved'; setTimeout(() => (save.textContent = 'save'), 1000); };
  const show = h('button', { class: 'mini ghost', type: 'button' }, 'show');
  show.onclick = () => { input.type = input.type === 'password' ? 'text' : 'password'; show.textContent = input.type === 'password' ? 'show' : 'hide'; };
  return h('div', { class: 'keyrow' },
    h('div', { class: 'keymeta' }, h('strong', {}, def.name), ' ', state,
      h('div', { class: 'muted small' }, def.hint, ' · ', ext(def.url, 'get a key'))),
    h('div', { class: 'row' }, input, show, save));
}

export default {
  id: 'settings',
  label: 'settings',
  placeholder: '',
  intro: '',
  examples: [],
  allowEmpty: true,
  noInput: true,

  run() {
    const s = settings();

    // theme
    const themeBtns = ['dark', 'light'].map(t => {
      const b = h('button', { class: 'seg' + (s.theme === t ? ' on' : ''), type: 'button' }, t);
      b.onclick = () => { setSetting('theme', t); applyTheme(); [...b.parentElement.children].forEach(x => x.classList.toggle('on', x === b)); };
      return b;
    });

    const graphToggle = h('button', { class: 'seg' + (s.graph ? ' on' : ''), type: 'button' }, s.graph ? 'recording' : 'paused');
    graphToggle.onclick = () => { const on = !settings().graph; setSetting('graph', on); graphToggle.textContent = on ? 'recording' : 'paused'; graphToggle.classList.toggle('on', on); };

    const clearBtn = (label, fn) => { const b = h('button', { class: 'mini', type: 'button' }, label); b.onclick = () => { fn(); b.textContent = 'done'; setTimeout(() => (b.textContent = label), 1000); }; return b; };

    return grid(
      backendCard(),

      card('api keys', { wide: true },
        muted('Keys are stored only in this browser (localStorage) and are sent only to their own service. Each one unlocks richer live data.'),
        h('div', { class: 'keylist' }, KEY_DEFS.map(keyRow))),

      card('appearance', {},
        h('div', { class: 'setrow' }, h('span', {}, 'theme'), h('div', { class: 'segset' }, themeBtns)),
        muted('The UI is designed dark-first; light is available for bright rooms.')),

      card('investigation graph', {},
        h('div', { class: 'setrow' }, h('span', {}, 'recording'), h('div', { class: 'segset' }, graphToggle)),
        muted('When on, every entity you open is added to the graph and pivots are linked.')),

      card('your data', { wide: true },
        muted('Nothing here is ever uploaded. Clear whatever you like, whenever you like.'),
        h('div', { class: 'row wrap' },
          clearBtn('clear graph', clearGraph),
          clearBtn('clear search history', () => clearRecent()),
          clearBtn('clear everything', () => { try { localStorage.clear(); } catch {} applyTheme(); }))),

      card('about', { wide: true },
        muted('feddedosint is a members-only OSINT toolkit. Most queries go straight from your browser to the public services shown in each result; sign-in, the AI and the proxies run on the shared backend.'),
        h('p', { class: 'muted small' }, 'For lawful, ethical research only. Respect privacy and each service’s terms.')),
    );
  },
};
