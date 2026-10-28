import { h, card, muted, mdLite, pivot, badge } from '../util.js';
import { icon } from '../icons.js';
import * as ai from '../ai.js';
import * as be from '../backend.js';
import { graph, getCase, currentUser, trackNode } from '../store.js';
import { extractEntities, KINDS } from './extract.js';
import { aiGateMessage } from '../gate.js';

const SYSTEM = `You are the research assistant inside feddedosint, a client-side OSINT toolkit.
Help the investigator plan and interpret open-source, public-data research: domains, IPs, ASNs,
certificates, emails, usernames, breaches (exposure checks only), geolocation, files and CVEs.
Be concise and practical. Suggest concrete next lookups and search-engine queries. When you name a
domain, IP, email, URL, hash or CVE, write it plainly so the interface can link it.
Only assist with lawful, ethical, public-source investigation; never help access private systems,
crack credentials, or de-anonymise or harass a private individual.`;

// The F/O mark, used as the assistant avatar.
const MARK = `<svg viewBox="0 0 100 100" aria-hidden="true"><rect width="100" height="100" rx="26" fill="#0a0a0c"/><path d="M60 24 L40 80" stroke="#3a3a40" stroke-width="5" stroke-linecap="round"/><g fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="9"><path d="M30 28 V72 M30 28 H52 M30 49 H48" stroke="#f3f3f4"/><circle cx="66" cy="58" r="15" stroke="#6f6f77"/></g></svg>`;

// Conversation + UI state persist while the tab is open.
let history = [];
let nextId = 1;
const pinned = new Set();
let autoSpeak = false;

const synth = typeof speechSynthesis !== 'undefined' ? speechSynthesis : null;
let speakingId = null;
const stripMd = t => t.replace(/```[\s\S]*?```/g, ' code block ').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/[#*`_>|]/g, '').replace(/\n{2,}/g, '. ').replace(/\s+/g, ' ').trim();

function contextBlock() {
  const g = graph(), c = getCase();
  const byTool = {};
  for (const n of Object.values(g.nodes)) (byTool[n.tool] ||= []).push(n.value);
  const lines = Object.entries(byTool).map(([t, vs]) => `${t}: ${vs.slice(0, 15).join(', ')}${vs.length > 15 ? ` (+${vs.length - 15})` : ''}`);
  const parts = [];
  if (lines.length) parts.push('Entities in the current investigation graph:\n' + lines.join('\n'));
  if (c.notes?.trim()) parts.push('Investigator notes:\n' + c.notes.trim().slice(0, 1500));
  return parts.join('\n\n');
}

function entityChips(text) {
  const ents = extractEntities(text, 40);
  const rows = KINDS.filter(k => ents[k.id]?.length && ['domain', 'ip', 'email', 'url', 'cve', 'md5', 'sha1', 'sha256', 'btc', 'eth'].includes(k.id))
    .flatMap(k => ents[k.id].map(v => pivot(k.tool, v)));
  if (!rows.length) return null;
  return h('div', { class: 'chipflow' }, h('span', { class: 'muted small' }, 'open'), ...rows.slice(0, 16));
}

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
        h('p', {}, 'Add your Worker URL in ', pivot('settings', 'backend', 'Settings'), ' and sign in on the ', pivot('account', '', 'account'), ' tab.'));
    }
    const info = await be.health(true);
    if (!info?.ai) return card('ai unavailable', { wide: true }, muted('The backend is connected but no AI model is configured on it.'));
    const g = aiGateMessage();
    if (g) return card(g.title, { wide: true }, muted(g.body), g.action);

    const log = h('div', { class: 'chatlog' });
    const pinStrip = h('div', { class: 'pinstrip' });
    const ta = h('textarea', { class: 'chatinput', rows: 1, placeholder: 'ask anything — Enter to send, Shift+Enter for a new line', spellcheck: 'false' });

    // ---- text to speech ----
    const speak = (id, text) => {
      if (!synth) return;
      synth.cancel();
      if (speakingId === id) { speakingId = null; renderLog(); return; }
      const u = new SpeechSynthesisUtterance(stripMd(text));
      u.rate = 1.02;
      u.onend = u.onerror = () => { if (speakingId === id) { speakingId = null; renderLog(); } };
      speakingId = id;
      try { synth.speak(u); } catch { speakingId = null; }
      renderLog();
    };

    const iconBtn = (ic, title, on, active) => {
      const b = h('button', { class: 'msgbtn' + (active ? ' active' : ''), type: 'button', title });
      b.innerHTML = icon(ic);
      b.addEventListener('click', on);
      return b;
    };

    function msgNode(m) {
      const avatar = h('div', { class: 'msg-av ' + m.role });
      if (m.role === 'assistant') avatar.innerHTML = MARK;
      else { const u = currentUser(); if (u?.avatar) avatar.append(h('img', { src: u.avatar, alt: '', referrerpolicy: 'no-referrer' })); else avatar.textContent = (u?.login || 'you')[0].toUpperCase(); }

      const body = m.role === 'assistant' ? mdLite(m.text) : h('div', { class: 'plain' }, m.text);
      const tools = h('div', { class: 'msgtools' },
        iconBtn('copy', 'copy', async () => { try { await navigator.clipboard.writeText(m.text); flash('copied'); } catch {} }),
        iconBtn('pin', pinned.has(m.id) ? 'unpin' : 'pin', () => { pinned.has(m.id) ? pinned.delete(m.id) : pinned.add(m.id); renderLog(); }, pinned.has(m.id)),
        synth && m.role === 'assistant' ? iconBtn(speakingId === m.id ? 'stop' : 'speaker', 'read aloud', () => speak(m.id, m.text), speakingId === m.id) : null);

      const bubble = h('div', { class: 'bubble' }, body, tools);
      const col = h('div', { class: 'msg-main' }, bubble);
      if (m.role === 'assistant') { const chips = entityChips(m.text); if (chips) col.append(chips); }
      return h('div', { class: 'msg ' + m.role }, avatar, col);
    }

    function renderLog() {
      // pinned strip
      const pins = history.filter(m => pinned.has(m.id));
      pinStrip.replaceChildren(...(pins.length ? [
        h('div', { class: 'pinhead muted small' }, spanIcon('pin'), ` ${pins.length} pinned`),
        h('div', { class: 'pinitems' }, pins.map(m => {
          const chip = h('button', { class: 'pinchip', type: 'button', title: 'jump to message' }, (m.role === 'assistant' ? '◆ ' : 'you: ') + stripMd(m.text).slice(0, 70));
          chip.onclick = () => { const el = log.querySelector(`[data-mid="${m.id}"]`); el?.scrollIntoView({ behavior: 'smooth', block: 'center' }); el?.classList.add('flashmsg'); setTimeout(() => el?.classList.remove('flashmsg'), 1200); };
          return chip;
        })),
      ] : []));
      pinStrip.classList.toggle('on', pins.length > 0);

      if (!history.length) { log.replaceChildren(emptyState()); return; }
      log.replaceChildren(...history.map(m => { const n = msgNode(m); n.dataset.mid = m.id; return n; }));
      if (pendingNode) log.append(pendingNode);
      log.scrollTop = log.scrollHeight;
    }

    let pendingNode = null;
    const spanIcon = ic => { const s = h('span', { class: 'ico' }); s.innerHTML = icon(ic); return s; };
    const toast = h('div', { class: 'chattoast' });
    const flash = msg => { toast.textContent = msg; toast.classList.add('on'); setTimeout(() => toast.classList.remove('on'), 1100); };

    // ---- send ----
    async function send(text) {
      text = (text ?? ta.value).trim();
      if (!text || sendBtn.disabled) return;
      ta.value = ''; autoGrow();
      const m = { id: nextId++, role: 'user', text };
      history.push(m);
      renderLog();
      sendBtn.disabled = true;
      pendingNode = h('div', { class: 'msg assistant' }, (() => { const a = h('div', { class: 'msg-av assistant' }); a.innerHTML = MARK; return a; })(),
        h('div', { class: 'msg-main' }, h('div', { class: 'bubble' }, h('div', { class: 'typing' }, h('span'), h('span'), h('span')))));
      log.append(pendingNode); log.scrollTop = log.scrollHeight;
      try {
        const ctx = contextBlock();
        const system = SYSTEM + (ctx ? `\n\nCurrent investigation context:\n${ctx}` : '');
        const reply = await ai.ask({ system, messages: ai.toContents(history), temperature: 0.5, maxOutputTokens: 1800 });
        const am = { id: nextId++, role: 'assistant', text: reply || '(no reply)' };
        history.push(am);
        if (autoSpeak && reply) setTimeout(() => speak(am.id, reply), 120);
      } catch (e) {
        history.push({ id: nextId++, role: 'assistant', text: '⚠ ' + (e.message || 'request failed') });
      } finally {
        pendingNode = null;
        sendBtn.disabled = false;
        renderLog();
        ta.focus();
      }
    }

    // ---- actions menu ----
    const fill = prefix => { ta.value = prefix; autoGrow(); ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); menu.classList.remove('open'); };
    const act = text => { menu.classList.remove('open'); send(text); };
    function addMentioned() {
      const last = [...history].reverse().find(m => m.role === 'assistant');
      if (!last) return flash('nothing to add');
      const ents = extractEntities(last.text, 60);
      let n = 0;
      for (const k of KINDS) for (const v of ents[k.id] || []) { trackNode(k.tool, v); n++; }
      flash(n ? `added ${n} to graph` : 'no entities found');
      menu.classList.remove('open');
    }
    function exportChat() {
      const md = history.map(m => `**${m.role === 'assistant' ? 'assistant' : 'you'}:**\n\n${m.text}`).join('\n\n---\n\n');
      const a = h('a', { href: URL.createObjectURL(new Blob([md], { type: 'text/markdown' })), download: 'feddedosint-chat.md' });
      document.body.append(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      menu.classList.remove('open');
    }
    const ACTIONS = [
      { group: 'attach context', items: [
        { icon: 'graph', label: 'attach graph', run: () => act('Give an overview of everything in my investigation graph — the entities and how they connect — and highlight the most interesting leads.') },
        { icon: 'case', label: 'attach case notes', run: () => act('Based on my case notes and graph, what should I prioritise next?') },
        { icon: 'overview', label: 'use recent searches', run: () => act('Looking at what I’ve searched recently, suggest connections or leads I might have missed.') },
      ] },
      { group: 'analyze the case', items: [
        { icon: 'engine', label: 'summarize', run: () => act('Summarise my current investigation so far in a few sentences.') },
        { icon: 'pivot', label: 'next steps', run: () => act('What are the best next OSINT steps for my current investigation? Be specific and concrete.') },
        { icon: 'graph', label: 'find connections', run: () => act('Find and explain the most likely connections between the entities in my graph.') },
        { icon: 'cve', label: 'risk assessment', run: () => act('Give a defensive security assessment of the infrastructure in my graph, with prioritised actions.') },
        { icon: 'headers', label: 'find contradictions', run: () => act('Point out any contradictions, uncertainties or weak assumptions in my current findings.') },
        { icon: 'records', label: 'build timeline', run: () => act('Build a timeline of the entities and events in my investigation.') },
        { icon: 'file', label: 'draft report', run: () => act('Write a concise, source-aware intelligence report in markdown (with sections) from my current investigation.') },
      ] },
      { group: 'templates (edit, then send)', items: [
        { icon: 'overview', label: 'analyze entity', run: () => fill('Analyze this and suggest pivots: ') },
        { icon: 'extract', label: 'extract IOCs', run: () => fill('Extract every indicator (domains, IPs, hashes, emails, CVEs) from this text:\n\n') },
        { icon: 'dorks', label: 'build a dork', run: () => fill('Build a precise Google search query to find: ') },
        { icon: 'cve', label: 'explain a CVE', run: () => fill('Explain this CVE, its impact and how to defend against it: ') },
      ] },
      { group: 'this chat', items: [
        { icon: 'graph', label: 'add mentioned to graph', run: addMentioned },
        { icon: 'export', label: 'export chat (.md)', run: exportChat },
        { icon: 'speaker', label: 'read last reply', run: () => { const m = [...history].reverse().find(x => x.role === 'assistant'); menu.classList.remove('open'); if (m) speak(m.id, m.text); } },
        { icon: 'trash', label: 'clear chat', run: () => { history = []; pinned.clear(); menu.classList.remove('open'); renderLog(); } },
      ] },
    ];
    const menu = h('div', { class: 'actionmenu' }, ACTIONS.map(grp => h('div', { class: 'actgroup' },
      h('div', { class: 'acthead muted small' }, grp.group),
      h('div', { class: 'actitems' }, grp.items.map(it => {
        const b = h('button', { class: 'actitem', type: 'button' });
        b.innerHTML = icon(it.icon) + `<span>${it.label}</span>`;
        b.addEventListener('click', it.run);
        return b;
      })))));

    // ---- bar controls ----
    const actionsBtn = h('button', { class: 'barbtn', type: 'button', title: 'actions' });
    actionsBtn.innerHTML = icon('wand') + '<span>actions</span>';
    actionsBtn.onclick = e => { e.stopPropagation(); menu.classList.toggle('open'); };
    document.addEventListener('click', () => menu.classList.remove('open'));
    menu.addEventListener('click', e => e.stopPropagation());

    const speakToggle = h('button', { class: 'barbtn', type: 'button', title: 'read replies aloud' });
    const paintSpeak = () => { speakToggle.innerHTML = icon(autoSpeak ? 'speaker' : 'stop') + `<span>read aloud: ${autoSpeak ? 'on' : 'off'}</span>`; speakToggle.classList.toggle('on', autoSpeak); };
    speakToggle.onclick = () => { autoSpeak = !autoSpeak; if (!autoSpeak && synth) synth.cancel(); paintSpeak(); };
    if (!synth) speakToggle.style.display = 'none';
    paintSpeak();

    const sendBtn = h('button', { class: 'primary sendbtn', type: 'button' });
    sendBtn.innerHTML = icon('pivot') + '<span>send</span>';
    sendBtn.onclick = () => send();

    function autoGrow() { ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, 180) + 'px'; }
    ta.addEventListener('input', autoGrow);
    ta.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });

    function emptyState() {
      const SUGGEST = ['Plan an investigation of github.com', 'What do SPF, DKIM and DMARC tell me?', 'Summarise my investigation graph', 'Draft a report from my current case'];
      return h('div', { class: 'chatempty' },
        h('div', { class: 'welcome' }, (() => { const a = h('div', { class: 'welcome-av' }); a.innerHTML = MARK; return a; })(),
          h('div', {}, h('strong', {}, `Hi ${currentUser()?.login || ''} 👋`), muted('I can see your investigation graph and notes. Ask me to plan, interpret or pivot — or use the actions menu.'))),
        h('div', { class: 'chipflow' }, ...SUGGEST.map(s => { const b = h('button', { class: 'suggchip', type: 'button' }, s); b.onclick = () => send(s); return b; })));
    }

    renderLog();
    autoGrow();
    return h('div', { class: 'chatwrap' },
      pinStrip,
      log,
      h('div', { class: 'chatbar' },
        h('div', { class: 'barrow' }, h('div', { class: 'barleft' }, actionsBtn, speakToggle, menu), badge(info.model || 'ai', 'muted')),
        h('div', { class: 'inputrow' }, ta, sendBtn)),
      toast);
  },
};
