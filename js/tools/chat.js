import { h, card, muted, mdLite, pivot, ext } from '../util.js';
import * as ai from '../ai.js';
import * as be from '../backend.js';
import { graph, getCase, currentUser } from '../store.js';
import { extractEntities, KINDS } from './extract.js';

const SYSTEM = `You are the research assistant inside feddedosint, a client-side OSINT toolkit.
Help the investigator plan and interpret open-source, public-data research: domains, IPs, ASNs,
certificates, emails, usernames, breaches (exposure checks only), geolocation, files and CVEs.
Be concise and practical. Suggest concrete next lookups and search-engine queries. When you name a
domain, IP, email, URL, hash or CVE, write it plainly so the interface can link it.
Only assist with lawful, ethical, public-source investigation; never help access private systems,
crack credentials, or de-anonymise or harass a private individual.`;

// Conversation persists while the tab is open (per page load).
let history = [];

function contextBlock() {
  const g = graph(), c = getCase();
  const byTool = {};
  for (const n of Object.values(g.nodes)) (byTool[n.tool] ||= []).push(n.value);
  const lines = Object.entries(byTool).map(([t, vs]) => `${t}: ${vs.slice(0, 12).join(', ')}${vs.length > 12 ? ` (+${vs.length - 12})` : ''}`);
  const parts = [];
  if (lines.length) parts.push('Entities in the current investigation graph:\n' + lines.join('\n'));
  if (c.notes?.trim()) parts.push('Investigator notes:\n' + c.notes.trim().slice(0, 1200));
  return parts.join('\n\n');
}

function entityChips(text) {
  const ents = extractEntities(text, 40);
  const rows = KINDS.filter(k => ents[k.id]?.length && ['domain', 'ip', 'email', 'url', 'cve', 'md5', 'sha1', 'sha256', 'btc', 'eth'].includes(k.id))
    .flatMap(k => ents[k.id].map(v => pivot(k.tool, v)));
  if (!rows.length) return null;
  return h('div', { class: 'chipflow' }, h('span', { class: 'muted small' }, 'open:'), ...rows.slice(0, 16));
}

function bubble(role, node) {
  return h('div', { class: 'msg ' + role }, h('div', { class: 'msg-role muted small' }, role === 'user' ? 'you' : 'assistant'), node);
}

const SUGGEST = [
  'Plan an investigation of the domain example.com',
  'What do SPF, DKIM and DMARC tell me about a sender?',
  'Explain what these open ports suggest: 22, 443, 3389',
  'Summarise what I have in my investigation graph so far',
];

export default {
  id: 'chat',
  label: 'chat',
  placeholder: '',
  intro: 'An AI research assistant that can see your investigation and help plan, interpret and pivot.',
  examples: [],
  allowEmpty: true,
  noInput: true,
  noTrack: true,

  async run() {
    if (!be.backendConfigured()) {
      return card('ai not set up', { wide: true },
        muted('The chat uses your Gemini key through the Cloudflare Worker, so the key is never exposed in the browser.'),
        h('p', {}, 'Add your Worker URL in ', pivot('settings', 'backend', 'Settings'), ' and sign in on the ', pivot('account', '', 'account'), ' tab.'),
        h('p', { class: 'muted small' }, 'setup guide: ', ext('https://github.com/feddedz/feddedosint/blob/main/worker/README.md', 'worker/README.md')));
    }
    const info = await be.health(true);
    if (!info?.ai) return card('ai unavailable', { wide: true }, muted('The backend is connected but no AI model is configured on it (set GEMINI_KEY and AI_MODEL on the Worker).'));
    if (!be.isLoggedIn()) return card('sign in to chat', { wide: true },
      muted('The AI is for signed-in users so it uses the owner’s key safely.'), h('p', {}, 'Go to the ', pivot('account', '', 'account'), ' tab to sign up or log in.'));

    const log = h('div', { class: 'chatlog' });
    const render = () => {
      log.replaceChildren(...history.flatMap(m => {
        const body = m.role === 'assistant' ? mdLite(m.text) : h('div', {}, m.text);
        const nodes = [bubble(m.role, body)];
        if (m.role === 'assistant') { const chips = entityChips(m.text); if (chips) nodes.push(chips); }
        return nodes;
      }));
      log.scrollTop = log.scrollHeight;
    };

    const ta = h('textarea', { class: 'chatinput', rows: 2, placeholder: 'ask anything — Enter to send, Shift+Enter for a new line', spellcheck: 'false' });
    const ctxToggle = h('button', { class: 'seg on', type: 'button', title: 'include your graph & notes as context' }, 'context: on');
    let useCtx = true;
    ctxToggle.onclick = () => { useCtx = !useCtx; ctxToggle.textContent = 'context: ' + (useCtx ? 'on' : 'off'); ctxToggle.classList.toggle('on', useCtx); };
    const send = h('button', { class: 'primary', type: 'button' }, 'send');
    const clear = h('button', { class: 'mini ghost', type: 'button' }, 'clear');
    clear.onclick = () => { history = []; render(); };

    async function submit() {
      const text = ta.value.trim();
      if (!text || send.disabled) return;
      ta.value = '';
      history.push({ role: 'user', text });
      render();
      send.disabled = true;
      const pending = bubble('assistant', h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'thinking…'));
      log.append(pending); log.scrollTop = log.scrollHeight;
      try {
        const ctx = useCtx ? contextBlock() : '';
        const system = SYSTEM + (ctx ? `\n\nCurrent investigation context:\n${ctx}` : '');
        const reply = await ai.ask({ system, messages: ai.toContents(history), temperature: 0.5, maxOutputTokens: 1600 });
        history.push({ role: 'assistant', text: reply || '(no reply)' });
      } catch (e) {
        history.push({ role: 'assistant', text: '⚠ ' + (e.message || 'request failed') });
      } finally {
        send.disabled = false;
        render();
        ta.focus();
      }
    }
    send.onclick = submit;
    ta.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); } });

    if (!history.length) {
      log.append(h('div', { class: 'chatempty' },
        muted(`Signed in as ${currentUser()?.username}. Ask me to plan an investigation, interpret a result, or suggest the next lookup.`),
        h('div', { class: 'chipflow' }, ...SUGGEST.map(s => {
          const b = h('button', { class: 'chip', type: 'button' }, s);
          b.onclick = () => { ta.value = s; submit(); };
          return b;
        }))));
    } else render();

    return h('div', { class: 'chatwrap' },
      log,
      h('div', { class: 'chatbar' }, ta, h('div', { class: 'chatbtns' }, ctxToggle, clear, send)));
  },
};
