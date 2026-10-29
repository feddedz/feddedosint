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

const MARK = `<svg viewBox="0 0 100 100" aria-hidden="true"><rect width="100" height="100" rx="26" fill="#0a0a0c"/><path d="M60 24 L40 80" stroke="#3a3a40" stroke-width="5" stroke-linecap="round"/><g fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="9"><path d="M30 28 V72 M30 28 H52 M30 49 H48" stroke="#f3f3f4"/><circle cx="66" cy="58" r="15" stroke="#6f6f77"/></g></svg>`;

// ---- state (persists while the tab is open; the request keeps running in the background) ----
let history = [];       // { id, role, text, thoughts? }
let nextId = 1;
const pinned = new Set();
let autoSpeak = false;
let active = null;      // in-flight stream: { id, controller, thoughts, answer }
let view = null;        // { log, render } for the currently mounted chat

const synth = typeof speechSynthesis !== 'undefined' ? speechSynthesis : null;
let speakingId = null;

const stripMd = t => (t || '').replace(/```[\s\S]*?```/g, ' code block ').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/[#*`_>|]/g, '').replace(/\n{2,}/g, '. ').replace(/\s+/g, ' ').trim();
const spanIcon = ic => { const s = h('span', { class: 'ico' }); s.innerHTML = icon(ic); return s; };

function renderIfMounted() { if (view?.log?.isConnected) view.render(); }
let rafPending = false;
function scheduleRender() { if (rafPending) return; rafPending = true; requestAnimationFrame(() => { rafPending = false; renderIfMounted(); }); }
function busy(on) { document.querySelector('.navitem[data-tool="chat"]')?.classList.toggle('busy', on); }

function speak(id, text) {
  if (!synth) return;
  synth.cancel();
  if (speakingId === id) { speakingId = null; renderIfMounted(); return; }
  const u = new SpeechSynthesisUtterance(stripMd(text));
  u.rate = 1.02;
  u.onend = u.onerror = () => { if (speakingId === id) { speakingId = null; renderIfMounted(); } };
  speakingId = id;
  try { synth.speak(u); } catch { speakingId = null; }
  renderIfMounted();
}

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

const avatarEl = role => {
  const a = h('div', { class: 'msg-av ' + role });
  if (role === 'assistant') a.innerHTML = MARK;
  else { const u = currentUser(); if (u?.avatar) a.append(h('img', { src: u.avatar, alt: '', referrerpolicy: 'no-referrer' })); else a.textContent = (u?.login || 'you')[0].toUpperCase(); }
  return a;
};

function iconBtn(ic, title, on, activeState) {
  const b = h('button', { class: 'msgbtn' + (activeState ? ' active' : ''), type: 'button', title });
  b.innerHTML = icon(ic);
  b.addEventListener('click', on);
  return b;
}

function thoughtsBlock(text, live) {
  return h('details', { class: 'thoughts' + (live ? ' live' : ''), ...(live ? { open: true } : {}) },
    h('summary', {}, spanIcon('wand'), h('span', { class: 'muted small' }, live ? 'thinking…' : 'thought process')),
    h('div', { class: 'thoughttext' }, text));
}

function msgNode(m, flash) {
  const body = [];
  if (m.role === 'assistant') {
    if (m.thoughts) body.push(thoughtsBlock(m.thoughts, false));
    body.push(mdLite(m.text));
  } else {
    body.push(h('div', { class: 'plain' }, m.text));
  }
  const tools = h('div', { class: 'msgtools' },
    iconBtn('copy', 'copy', async () => { try { await navigator.clipboard.writeText(m.text); } catch {} }),
    iconBtn('pin', pinned.has(m.id) ? 'unpin' : 'pin', () => { pinned.has(m.id) ? pinned.delete(m.id) : pinned.add(m.id); renderIfMounted(); }, pinned.has(m.id)),
    synth && m.role === 'assistant' ? iconBtn(speakingId === m.id ? 'stop' : 'speaker', 'read aloud', () => speak(m.id, m.text), speakingId === m.id) : null);
  const bubble = h('div', { class: 'bubble' }, ...body, tools);
  const col = h('div', { class: 'msg-main' }, bubble);
  if (m.role === 'assistant') { const chips = entityChips(m.text); if (chips) col.append(chips); }
  const node = h('div', { class: 'msg ' + m.role + (flash ? ' flashmsg' : '') }, avatarEl(m.role), col);
  node.dataset.mid = m.id;
  return node;
}

function streamingNode() {
  const body = [];
  if (active.thoughts) body.push(thoughtsBlock(active.thoughts, true));
  if (active.answer) body.push(mdLite(active.answer));
  else if (!active.thoughts) body.push(h('div', { class: 'typing' }, h('span'), h('span'), h('span')));
  const stop = h('button', { class: 'stopbtn', type: 'button' }, spanIcon('stop'), h('span', {}, 'stop'));
  stop.onclick = () => active?.controller.abort();
  const bubble = h('div', { class: 'bubble streaming' }, ...body, h('div', { class: 'streamfoot' }, stop));
  return h('div', { class: 'msg assistant' }, avatarEl('assistant'), h('div', { class: 'msg-main' }, bubble));
}

// ---- streaming send (runs independent of the DOM so it survives tab switches) ----
async function startSend(text) {
  text = (text || '').trim();
  if (!text || active) return;
  history.push({ id: nextId++, role: 'user', text });
  active = { id: nextId++, controller: new AbortController(), thoughts: '', answer: '' };
  busy(true);
  renderIfMounted();
  try {
    const ctx = contextBlock();
    const system = SYSTEM + (ctx ? `\n\nCurrent investigation context:\n${ctx}` : '');
    const answer = await be.aiStream(
      { system, messages: ai.toContents(history), temperature: 0.5, maxOutputTokens: 1800 },
      {
        signal: active.controller.signal,
        onThought: d => { active.thoughts += d; scheduleRender(); },
        onText: (d, full) => { active.answer = full; scheduleRender(); },
      });
    history.push({ id: active.id, role: 'assistant', text: answer || active.answer || '(no reply)', thoughts: active.thoughts });
    if (autoSpeak && (answer || active.answer)) { const id = active.id; setTimeout(() => speak(id, answer || ''), 100); }
  } catch (e) {
    if (e.name === 'AbortError') {
      const partial = active.answer.trim();
      history.push({ id: active.id, role: 'assistant', text: (partial ? partial + '\n\n' : '') + '_(stopped)_', thoughts: active.thoughts });
    } else {
      history.push({ id: active.id, role: 'assistant', text: '⚠ ' + (e.message || 'request failed'), thoughts: active.thoughts });
    }
  } finally {
    active = null;
    busy(false);
    renderIfMounted();
  }
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
    const info = await be.health(true);
    if (!info?.ai) return card('ai unavailable', { wide: true }, muted('The backend is connected but no AI model is configured on it.'));
    const g = aiGateMessage();
    if (g) return card(g.title, { wide: true }, muted(g.body), g.action);

    const log = h('div', { class: 'chatlog' });
    const pinStrip = h('div', { class: 'pinstrip' });
    const ta = h('textarea', { class: 'chatinput', rows: 1, placeholder: 'ask anything — Enter to send, Shift+Enter for a new line', spellcheck: 'false' });

    function render() {
      const pins = history.filter(m => pinned.has(m.id));
      pinStrip.replaceChildren(...(pins.length ? [
        h('div', { class: 'pinhead muted small' }, spanIcon('pin'), ` ${pins.length} pinned`),
        h('div', { class: 'pinitems' }, pins.map(m => {
          const chip = h('button', { class: 'pinchip', type: 'button' }, (m.role === 'assistant' ? '◆ ' : 'you: ') + stripMd(m.text).slice(0, 70));
          chip.onclick = () => { const el = log.querySelector(`[data-mid="${m.id}"]`); el?.scrollIntoView({ behavior: 'smooth', block: 'center' }); el?.classList.add('flashmsg'); setTimeout(() => el?.classList.remove('flashmsg'), 1200); };
          return chip;
        })),
      ] : []));
      pinStrip.classList.toggle('on', pins.length > 0);

      if (!history.length && !active) { log.replaceChildren(emptyState()); return; }
      const nearBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 80;
      log.replaceChildren(...history.map(m => msgNode(m)));
      if (active) log.append(streamingNode());
      if (nearBottom) log.scrollTop = log.scrollHeight;
    }
    view = { log, render };

    // ---- actions menu ----
    const fill = prefix => { ta.value = prefix; autoGrow(); ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); menu.classList.remove('open'); };
    const act = text => { menu.classList.remove('open'); startSend(text); };
    const flash = (() => { const t = h('div', { class: 'chattoast' }); return { el: t, show: msg => { t.textContent = msg; t.classList.add('on'); setTimeout(() => t.classList.remove('on'), 1100); } }; })();
    function addMentioned() {
      const last = [...history].reverse().find(m => m.role === 'assistant');
      menu.classList.remove('open');
      if (!last) return flash.show('nothing to add');
      const ents = extractEntities(last.text, 60);
      let n = 0;
      for (const k of KINDS) for (const v of ents[k.id] || []) { trackNode(k.tool, v); n++; }
      flash.show(n ? `added ${n} to graph` : 'no entities found');
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
        { icon: 'trash', label: 'clear chat', run: () => { if (active) active.controller.abort(); history = []; pinned.clear(); menu.classList.remove('open'); render(); } },
      ] },
    ];
    const menu = h('div', { class: 'actionmenu' }, ACTIONS.map(grp => h('div', { class: 'actgroup' },
      h('div', { class: 'acthead muted small' }, grp.group),
      h('div', { class: 'actitems' }, grp.items.map(it => { const b = h('button', { class: 'actitem', type: 'button' }); b.innerHTML = icon(it.icon) + `<span>${it.label}</span>`; b.addEventListener('click', it.run); return b; })))));

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
    const doSend = () => { const t = ta.value.trim(); if (!t || active) return; ta.value = ''; autoGrow(); startSend(t); };
    sendBtn.onclick = doSend;

    function autoGrow() { ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, 180) + 'px'; }
    ta.addEventListener('input', autoGrow);
    ta.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend(); } });

    function emptyState() {
      const SUGGEST = ['Plan an investigation of github.com', 'What do SPF, DKIM and DMARC tell me?', 'Summarise my investigation graph', 'Draft a report from my current case'];
      return h('div', { class: 'chatempty' },
        h('div', { class: 'welcome' }, (() => { const a = h('div', { class: 'welcome-av' }); a.innerHTML = MARK; return a; })(),
          h('div', {}, h('strong', {}, `Hi ${currentUser()?.login || ''} 👋`), muted('I can see your investigation graph and notes, I stream my thinking live, and I keep working if you switch tabs. Use the actions menu for shortcuts.'))),
        h('div', { class: 'chipflow' }, ...SUGGEST.map(s => { const b = h('button', { class: 'suggchip', type: 'button' }, s); b.onclick = () => startSend(s); return b; })));
    }

    render();
    autoGrow();
    return h('div', { class: 'chatwrap' },
      pinStrip,
      log,
      h('div', { class: 'chatbar' },
        h('div', { class: 'barrow' }, h('div', { class: 'barleft' }, actionsBtn, speakToggle, menu), badge(info.model || 'ai', 'muted')),
        h('div', { class: 'inputrow' }, ta, sendBtn)),
      flash.el);
  },
};
