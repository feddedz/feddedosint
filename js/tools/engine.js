import { h, card, grid, muted, badge, ext, pivot, copyBtn, mdLite, fmtDate } from '../util.js';
import { classify } from './overview.js';
import { collect, canon, canCollect } from '../collect.js';
import { trackNode, trackEdge, getCase, setCase } from '../store.js';
import * as ai from '../ai.js';
import * as be from '../backend.js';
import { aiGateMessage } from '../gate.js';
import { posture, rank, toneOf } from '../risk.js';

const SCOPES = {
  quick: { nodes: 12, depth: 1, concurrency: 4, label: 'quick' },
  standard: { nodes: 32, depth: 2, concurrency: 4, label: 'standard' },
  deep: { nodes: 64, depth: 3, concurrency: 5, label: 'deep' },
};
let scopeKey = 'standard';

const AN_SYSTEM = `You are a defensive OSINT analyst. You are given evidence collected from public sources
about internet infrastructure. Using ONLY that evidence (never invent facts), write a report in Markdown:
## Summary — 3-5 sentences on what this infrastructure is and who appears to run it.
## Key findings — bullets, each ending with the source in brackets, e.g. [DNS], [RDAP], [Shodan].
## Security observations — exposure a defender should note (open management ports, old software, weak mail auth, etc.), framed for defence.
## Uncertainties & contradictions — anything unverified, ambiguous, or conflicting in the evidence.
## Recommended next steps — concrete further lookups.
Be concise. Do not speculate about private individuals.`;

function reportMarkdown(seed, visited, evidence) {
  const byTool = {};
  for (const v of visited) (byTool[v.tool] ||= []).push(v.value);
  return [
    `# Investigation: ${seed}`, '',
    `_Autonomous run, ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC — ${visited.length} entities, ${evidence.length} evidence items._`, '',
    '## Entities', '',
    ...Object.entries(byTool).map(([t, vs]) => `- **${t}** (${vs.length}): ${vs.join(', ')}`), '',
    '## Evidence', '',
    ...evidence.map(e => `- ${e.claim} [${e.source}]`), '',
  ].join('\n');
}

async function investigate(container, seed, statusEl, logEl) {
  const scope = SCOPES[scopeKey];
  const types = classify(seed);
  const start = types.find(canCollect);
  if (!start) {
    statusEl.replaceChildren(badge('cannot start', 'bad'));
    logEl.append(h('div', muted(`"${seed}" is a ${types[0]} — the engine expands domains, IPs, URLs, emails and ASNs. Use the ${types[0]} tool directly, or give it a domain / IP / URL.`)));
    return;
  }

  const seen = new Set([canon(start, seed)]);
  const queue = [{ tool: start, value: seed, depth: 0 }];
  const visited = [], evidence = [], findings = [];
  const log = (node, text, tone) => {
    if (!container.isConnected) return;
    logEl.append(h('div', { class: 'step' }, badge(node, tone || 'muted'), h('span', {}, text)));
    logEl.scrollTop = logEl.scrollHeight;
  };
  trackNode(start, seed);

  while (queue.length && visited.length < scope.nodes && container.isConnected) {
    const batch = queue.splice(0, scope.concurrency);
    statusEl.replaceChildren(h('span', { class: 'spin' }), h('span', { class: 'muted small' }, ` ${visited.length}/${scope.nodes} examined · ${queue.length} queued`));
    await Promise.all(batch.map(async node => {
      const res = await collect(node.tool, node.value);
      if (!container.isConnected) return;
      visited.push(node);
      evidence.push(...res.evidence);
      findings.push(...(res.findings || []));
      log(node.tool, `${node.value} — ${res.summary}`, res.ok ? 'ok' : 'warn');
      for (const nb of res.neighbors) {
        trackEdge(node.tool, node.value, nb.tool, nb.value);
        const c = canon(nb.tool, nb.value);
        if (seen.has(c)) continue;
        seen.add(c);
        if (node.depth < scope.depth && canCollect(nb.tool) && visited.length + queue.length < scope.nodes) {
          queue.push({ tool: nb.tool, value: nb.value, depth: node.depth + 1 });
        }
      }
    }));
  }
  if (!container.isConnected) return;

  statusEl.replaceChildren(badge(`done · ${visited.length} entities`, 'ok'));
  const md = reportMarkdown(seed, visited, evidence);

  // Entity + evidence cards (always available, no AI needed).
  const byTool = {};
  for (const v of visited) (byTool[v.tool] ||= []).push(v.value);
  const entityCard = card('entities', { wide: true, actions: copyBtn(md, 'copy report') },
    Object.entries(byTool).map(([t, vs]) => h('div', { class: 'casegroup' },
      h('h4', {}, `${t} · ${vs.length}`),
      h('div', { class: 'chipflow' }, vs.map(v => pivot(t, v))))));
  const evidenceCard = card(`evidence · ${evidence.length}`, { wide: true },
    evidence.length ? h('div', { class: 'breach-list' }, evidence.map(e => h('div', { class: 'breach-item' },
      h('div', {}, e.claim), h('div', { class: 'muted small' }, 'source: ', e.url ? ext(e.url, e.source) : e.source, ' · ', fmtDate(e.at)))))
      : muted('no structured evidence gathered.'));
  const p = posture(findings);
  const riskCard = card('risk posture', { wide: true, actions: badge(`${p.score}/100 · ${p.sev}`, toneOf(p.sev)) },
    findings.length
      ? h('table', { class: 'records' }, h('tbody', {}, rank(findings).map(f => h('tr', {},
          h('td', {}, badge(f.sev, toneOf(f.sev))),
          h('td', {}, h('strong', {}, f.title), h('div', { class: 'muted small' }, f.why))))))
      : muted('No exposure findings surfaced from the public collectors.'));
  const pivotsCard = card('visualise', {},
    h('p', {}, 'This run was added to your ', pivot('graph', '', 'investigation graph'), ' and can be plotted on the ', pivot('map', '', 'map'), '.'),
    h('p', { class: 'muted small' }, 'click any entity above to pivot into its full tool.'));

  const resultWrap = h('div');
  container.append(grid(riskCard, entityCard, evidenceCard, pivotsCard), resultWrap);

  // AI analysis layered on top, if available.
  if (be.isLoggedIn() && await ai.available().catch(() => false)) {
    const aiCard = card('ai analysis', { wide: true }, h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'reasoning over the evidence…'));
    resultWrap.append(aiCard);
    const slot = aiCard.querySelector('.body');
    try {
      const context = `Seed: ${seed}\n\nRisk posture: ${p.score}/100 (${p.sev})\nFindings:\n${rank(findings).slice(0, 20).map(f => `- [${f.sev}] ${f.title}: ${f.why}`).join('\n') || '(none)'}\n\nEntities:\n${Object.entries(byTool).map(([t, vs]) => `${t}: ${vs.join(', ')}`).join('\n')}\n\nEvidence:\n${evidence.slice(0, 80).map(e => `- ${e.claim} [${e.source}]`).join('\n') || '(none)'}`;
      const reply = await ai.ask({ system: AN_SYSTEM, prompt: context, temperature: 0.3, maxOutputTokens: 2000 });
      slot.replaceChildren(mdLite(reply));
    } catch (e) {
      slot.replaceChildren(muted('AI analysis unavailable: ' + (e.message || 'failed') + '. The evidence above still stands on its own.'));
    }
  } else {
    resultWrap.append(card('ai analysis', { wide: true },
      muted('Connect the backend and sign in to add an AI written, evidence-cited analysis on top of these findings.'),
      h('p', { class: 'muted small' }, pivot('settings', 'backend', 'set up backend'), ' · ', pivot('account', '', 'sign in'))));
  }

  // Note the run in the case file.
  const c = getCase();
  if (c.title === 'untitled investigation') setCase({ title: `investigation: ${seed}` });
}

export default {
  id: 'engine',
  label: 'engine',
  placeholder: 'domain, IP, URL, email or ASN to investigate automatically',
  intro: 'Point it at one thing and it investigates outward across public sources — resolving, pivoting, gathering cited evidence and building the graph — then writes it up.',
  examples: ['github.com', '1.1.1.1'],
  noTrack: true,

  run(seed) {
    seed = seed.trim();
    if (!seed) throw new Error('enter a domain, IP, URL, email or ASN');
    const g = aiGateMessage();
    if (g) return card(g.title, { wide: true }, muted(g.body), g.action);

    const scopeSel = h('div', { class: 'segset' }, Object.entries(SCOPES).map(([k, s]) => {
      const b = h('button', { class: 'seg' + (k === scopeKey ? ' on' : ''), type: 'button' }, s.label);
      b.onclick = () => { scopeKey = k; [...scopeSel.children].forEach(x => x.classList.toggle('on', x === b)); };
      return b;
    }));
    const statusEl = h('span', {});
    const logEl = h('div', { class: 'enginelog' });
    const rerun = h('button', { class: 'primary', type: 'button' }, 'investigate');

    const container = h('div');
    const head = card('autonomous investigation', { wide: true, actions: [h('span', { class: 'muted small' }, 'scope'), scopeSel, rerun] },
      h('div', { class: 'row-between' }, h('div', {}, h('strong', {}, seed)), statusEl),
      muted('Follows public-infrastructure links (DNS, RDAP, hosting, Shodan exposure, ASN) outward within a budget. Defensive, public-source only.'),
      logEl);

    const body = h('div');
    container.append(head, body);

    const start = () => {
      body.replaceChildren(); logEl.replaceChildren();
      // Wait until the container is mounted so the isConnected guards hold.
      requestAnimationFrame(() => investigate(body, seed, statusEl, logEl).catch(e => {
        if (body.isConnected) body.append(card('investigation error', { wide: true }, muted(e?.message || 'failed')));
      }));
    };
    rerun.onclick = start;
    start();
    return container;
  },
};
