import { h, card, grid, muted, badge, ext, pivot, copyBtn, mdLite, fmtDate, fmtNum } from '../util.js';
import { classify } from './overview.js';
import { collect, canon, canCollect } from '../collect.js';
import { trackNode, trackEdge } from '../store.js';
import { posture, rank, toneOf, bandOf } from '../risk.js';
import * as ai from '../ai.js';
import * as be from '../backend.js';

// The analyst engine: builds a relationship graph over public infrastructure, propagates risk
// across it, clusters likely-related assets, and separates what it reports into three tiers —
// CONFIRMED FACTS, PROBABLE RELATIONSHIPS, and SPECULATIVE PREDICTIONS — each with its evidence.
// Infrastructure / organisations only; never private individuals (see CLAUDE.md §9).

const SCOPES = {
  quick: { nodes: 14, depth: 1, concurrency: 4, label: 'quick' },
  standard: { nodes: 36, depth: 2, concurrency: 5, label: 'standard' },
  deep: { nodes: 70, depth: 3, concurrency: 6, label: 'deep' },
};
let scopeKey = 'standard';

// Edges along which risk realistically spreads (shared hosting, provider, DNS, routing).
const PROP_REL = /resolves to|hosted|host|announced|nameserver|mail server|reverse|operator|hostname/i;
const SNAP_KEY = 'feddedosint.analyst';
const readSnaps = () => { try { return JSON.parse(localStorage.getItem(SNAP_KEY)) || {}; } catch { return {}; } };
const writeSnaps = o => { try { localStorage.setItem(SNAP_KEY, JSON.stringify(o)); } catch {} };

const CONF = { high: ['high', 'bad'], medium: ['medium', 'warn'], low: ['low', 'muted'] };

const AN_SYSTEM = `You are a defensive infrastructure-intelligence analyst. You are given evidence and findings
collected from public sources about internet infrastructure and organisations. Using ONLY that evidence
(never invent facts, never profile private individuals), output Markdown with exactly these sections:
## Situation — 2-4 sentences: what this infrastructure is and who appears to operate it.
## Likely scenarios — 3 bullets of what may develop next. Start each with (high) / (medium) / (low) confidence, then the scenario, then the supporting evidence in brackets.
## What a defender should watch — concrete signals to monitor.
Keep it tight and clearly separate fact from inference.`;

async function analyse(container, seed, statusEl, logEl, resultSlot) {
  const scope = SCOPES[scopeKey];
  const types = classify(seed);
  const start = types.find(canCollect);
  if (!start) { statusEl.replaceChildren(badge('cannot start', 'bad')); resultSlot.replaceChildren(card('unsupported seed', { wide: true }, muted(`"${seed}" is a ${types[0]}. The analyst reasons over infrastructure — give it a domain, IP, URL, ASN or email.`))); return; }

  const seen = new Set([canon(start, seed)]);
  const queue = [{ tool: start, value: seed, depth: 0 }];
  const nodes = new Map();           // id -> {id,tool,value,depth,facts,findings,summary}
  const edges = [];                  // {from,to,rel}
  const evidence = [];
  const log = (t, text, tone) => { if (!container.isConnected) return; logEl.append(h('div', { class: 'step' }, badge(t, tone || 'muted'), h('span', {}, text))); logEl.scrollTop = logEl.scrollHeight; };
  trackNode(start, seed);

  while (queue.length && nodes.size < scope.nodes && container.isConnected) {
    const batch = queue.splice(0, scope.concurrency);
    statusEl.replaceChildren(h('span', { class: 'spin' }), h('span', { class: 'muted small' }, ` ${nodes.size}/${scope.nodes} mapped · ${queue.length} queued`));
    await Promise.all(batch.map(async node => {
      const res = await collect(node.tool, node.value);
      if (!container.isConnected) return;
      const id = canon(node.tool, node.value);
      const findings = (res.findings || []).map(f => ({ ...f, nodeId: id }));
      nodes.set(id, { id, tool: node.tool, value: node.value, depth: node.depth, facts: res.facts || [], findings, summary: res.summary });
      evidence.push(...(res.evidence || []));
      log(node.tool, `${node.value} — ${res.summary}`, res.ok ? 'ok' : 'warn');
      for (const nb of (res.neighbors || [])) {
        const to = canon(nb.tool, nb.value);
        edges.push({ from: id, to, rel: nb.rel || 'linked', toTool: nb.tool, toValue: nb.value });
        trackEdge(node.tool, node.value, nb.tool, nb.value);
        if (seen.has(to)) continue;
        seen.add(to);
        if (node.depth < scope.depth && canCollect(nb.tool) && nodes.size + queue.length < scope.nodes) queue.push({ tool: nb.tool, value: nb.value, depth: node.depth + 1 });
      }
    }));
  }
  if (!container.isConnected) return;
  statusEl.replaceChildren(badge(`done · ${nodes.size} entities`, 'ok'));

  // ---- risk propagation ----
  const base = {}; for (const n of nodes.values()) base[n.id] = posture(n.findings).score;
  const prop = { ...base }; const contrib = {};
  for (const e of edges) {
    if (!PROP_REL.test(e.rel) || !nodes.has(e.from) || !nodes.has(e.to)) continue;
    for (const [a, b] of [[e.from, e.to], [e.to, e.from]]) {
      const add = Math.round(0.3 * base[b]);
      if (add >= 8) { prop[a] = Math.min(100, (prop[a] || 0) + add); (contrib[a] ||= []).push({ via: nodes.get(b).value, add }); }
    }
  }
  const allFindings = [...nodes.values()].flatMap(n => n.findings);
  const overall = posture(allFindings);

  // ---- clustering (probable same-operator / shared infra) ----
  const hostMap = {};            // ip -> [domain values]
  const asnMap = {};             // asn value -> [ip values]
  for (const e of edges) {
    if (/resolves to|^host$|hostname/i.test(e.rel) && nodes.get(e.from)?.tool === 'domain') (hostMap[e.toValue] ||= []).push(nodes.get(e.from).value);
    if (/announced/i.test(e.rel)) (asnMap[e.toValue] ||= []).push(nodes.get(e.from)?.value);
  }
  const sharedHosts = Object.entries(hostMap).filter(([, ds]) => new Set(ds).size >= 2).map(([ip, ds]) => ({ ip, domains: [...new Set(ds)] }));

  // ---- anomalies / patterns ----
  const anomalies = [];
  for (const sh of sharedHosts) if (sh.domains.length >= 3) anomalies.push({ sev: 'medium', text: `${sh.domains.length} domains resolve to ${sh.ip} — shared hosting or a related cluster.` });
  for (const n of nodes.values()) {
    const reg = n.facts.find(f => f[0] === 'registered')?.[1];
    if (reg) { const age = (Date.now() - new Date(reg)) / 86400000; if (age >= 0 && age < 90) anomalies.push({ sev: 'low', text: `${n.value} was registered ${Math.round(age)} day(s) ago — recently created asset.` }); }
  }

  // ---- predictions (speculative, forward-looking) ----
  const preds = [];
  const push = (conf, text, refs) => preds.push({ conf, text, refs: refs || [] });
  for (const f of rank(allFindings)) {
    const who = f.detail?.host || f.detail?.ip || f.detail?.domain || '';
    if (f.kind === 'takeover') push('high', `${who}: subdomain takeover is possible until the dangling record is removed — an attacker could serve content from your domain.`, [f.title]);
    else if (f.kind === 'sensitive-service') push(f.score >= 85 ? 'high' : 'medium', `${who}: the exposed ${f.detail.service} is a likely target for scanning, brute-force or direct compromise.`, [f.title]);
    else if (f.kind === 'cve-cluster' || f.kind === 'cve') push(f.score >= 80 ? 'high' : 'medium', `${who}: known-vulnerable software raises the odds of opportunistic exploitation.`, [f.title]);
    else if (f.kind === 'weak-mail') push('medium', `${who}: the domain can likely be spoofed in phishing until DMARC is enforced (p=reject).`, [f.title]);
  }
  // risk-propagation scenario
  const topProp = [...nodes.values()].map(n => ({ n, p: prop[n.id] || 0, b: base[n.id] || 0 })).filter(x => x.p > x.b && x.p >= 40).sort((a, b) => b.p - a.p)[0];
  if (topProp) push('medium', `A compromise of ${(contrib[topProp.n.id] || []).map(c => c.via).join(', ') || 'a connected host'} could cascade to ${topProp.n.value} and the assets sharing that infrastructure (risk propagation).`, ['propagation']);
  if (!preds.length) push('low', 'No material forward risks were inferred from the public signals gathered — surface looks clean from the outside.', []);

  // ---- temporal: diff against the last run of this seed ----
  const seedId = canon(start, seed);
  const snaps = readSnaps();
  const prev = snaps[seedId];
  const curEntities = [...nodes.keys()].sort();
  const curFindings = [...new Set(allFindings.map(f => f.title))].sort();
  let temporal = null;
  if (prev) {
    const newE = curEntities.filter(x => !prev.entities.includes(x));
    const goneE = prev.entities.filter(x => !curEntities.includes(x));
    const newF = curFindings.filter(x => !prev.findings.includes(x));
    const goneF = prev.findings.filter(x => !curFindings.includes(x));
    temporal = { at: prev.at, newE, goneE, newF, goneF };
  }
  snaps[seedId] = { at: Date.now(), entities: curEntities, findings: curFindings };
  writeSnaps(snaps);

  // ============ render ============
  const tierBadge = t => badge(t, t === 'fact' ? 'ok' : t === 'probable' ? 'warn' : 'muted');
  const row = (b, body) => h('div', { class: 'step' }, b, h('span', {}, body));

  // posture + propagation
  const propRows = [...nodes.values()].map(n => ({ n, b: base[n.id] || 0, p: prop[n.id] || 0 })).filter(x => x.b > 0 || x.p > 0).sort((a, b) => b.p - a.p).slice(0, 12);
  const postureCard = card('risk posture & propagation', { wide: true, actions: badge(`${overall.score}/100 · ${overall.sev}`, toneOf(overall.sev)) },
    muted('Each asset\'s own exposure (base), and its risk after accounting for the exposure of the infrastructure it shares (propagated).'),
    propRows.length ? h('table', { class: 'datatable' },
      h('thead', {}, h('tr', {}, ['asset', 'base', 'propagated', 'why'].map(c => h('th', {}, c)))),
      h('tbody', {}, propRows.map(x => h('tr', {},
        h('td', {}, pivot(x.n.tool, x.n.value, x.n.value)),
        h('td', {}, badge(String(x.b), toneOf(bandOf(x.b)))),
        h('td', {}, badge(String(x.p), toneOf(bandOf(x.p)))),
        h('td', { class: 'small muted' }, (contrib[x.n.id] || []).map(c => `+${c.add} via ${c.via}`).join('; ') || '—')))))
      : muted('No exposure surfaced from the public collectors.'));

  // relationships / clusters
  const relCard = card('relationships', { wide: true, actions: pivot('graph', '', 'open graph') },
    muted(`${nodes.size} entities, ${edges.length} links mapped and added to your investigation graph.`),
    sharedHosts.length
      ? sharedHosts.map(sh => h('div', { class: 'casegroup' }, h('h4', {}, tierBadge('probable'), ` shared host ${sh.ip}`),
          h('div', { class: 'chipflow' }, [pivot('ip', sh.ip, sh.ip), ...sh.domains.map(d => pivot('domain', d, d))])))
      : muted('No shared-infrastructure clusters among the mapped assets.'));

  // tiered assessment
  const facts = evidence.slice(0, 60);
  const probable = [
    ...sharedHosts.map(sh => `${sh.domains.slice(0, 4).join(', ')}${sh.domains.length > 4 ? '…' : ''} likely related — they share host ${sh.ip}.`),
    ...Object.entries(asnMap).filter(([, ips]) => new Set(ips.filter(Boolean)).size >= 2).map(([asn, ips]) => `${[...new Set(ips.filter(Boolean))].slice(0, 4).join(', ')} are announced by the same network (${asn}) — same operator or provider.`),
    ...anomalies.map(a => a.text),
  ];
  const assessCard = card('assessment — fact · probable · speculative', { wide: true },
    h('div', { class: 'casegroup' }, h('h4', {}, tierBadge('fact'), ` confirmed facts · ${facts.length}`),
      facts.length ? h('div', { class: 'enginelog' }, facts.map(e => row(badge(e.source, 'ok'), [e.claim, e.url ? [' ', ext(e.url, 'src')] : null]))) : muted('none')),
    h('div', { class: 'casegroup' }, h('h4', {}, tierBadge('probable'), ` probable relationships · ${probable.length}`),
      probable.length ? probable.map(t => row(tierBadge('probable'), t)) : muted('none inferred')),
    h('div', { class: 'casegroup' }, h('h4', {}, tierBadge('speculative'), ` speculative predictions · ${preds.length}`),
      preds.map(p => row(badge(...CONF[p.conf]), [p.text, p.refs.length ? h('span', { class: 'muted small' }, ' — evidence: ' + p.refs.join(', ')) : null]))));

  // temporal
  const temporalCard = card('temporal — what changed', { wide: true },
    temporal
      ? h('div', {}, muted(`since the last run (${fmtDate(temporal.at)}):`),
          [['new assets', temporal.newE.map(x => x.split(':')[1])], ['new findings', temporal.newF], ['resolved findings', temporal.goneF], ['assets gone', temporal.goneE.map(x => x.split(':')[1])]]
            .filter(([, arr]) => arr.length).map(([label, arr]) => row(badge(`${arr.length}`, label.startsWith('new finding') ? 'bad' : label.startsWith('resolved') ? 'ok' : 'warn'), `${label}: ${arr.slice(0, 10).join(', ')}`)),
          (!temporal.newE.length && !temporal.newF.length && !temporal.goneF.length && !temporal.goneE.length) ? muted('no changes since the last run.') : null)
      : muted('Baseline captured. Re-run this seed later to see what changed (new subdomains, new exposure, resolved issues).'));

  const reportMd = [`# Analyst report: ${seed}`, '', `_${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC · posture ${overall.score}/100 (${overall.sev}) · ${nodes.size} entities_`, '',
    '## Confirmed facts', ...facts.map(e => `- ${e.claim} [${e.source}]`), '',
    '## Probable relationships', ...probable.map(t => `- ${t}`), '',
    '## Speculative predictions', ...preds.map(p => `- (${p.conf}) ${p.text}`), ''].join('\n');

  const result = h('div');
  resultSlot.replaceChildren(grid(postureCard, relCard, assessCard, temporalCard,
    card('export', {}, copyBtn(reportMd, 'copy full report'))), result);

  // ---- AI scenario layer (optional) ----
  if (be.isLoggedIn() && await ai.available().catch(() => false)) {
    const aiCard = card('ai scenario analysis', { wide: true }, h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'projecting scenarios from the evidence…'));
    result.append(aiCard);
    const slot = aiCard.querySelector('.body');
    try {
      const ctx = `Seed: ${seed}\nPosture: ${overall.score}/100 (${overall.sev})\n\nConfirmed facts:\n${facts.slice(0, 50).map(e => `- ${e.claim} [${e.source}]`).join('\n') || '(none)'}\n\nProbable relationships:\n${probable.join('\n') || '(none)'}\n\nFindings:\n${rank(allFindings).slice(0, 20).map(f => `- [${f.sev}] ${f.title}: ${f.why}`).join('\n') || '(none)'}`;
      slot.replaceChildren(mdLite(await ai.ask({ system: AN_SYSTEM, prompt: ctx, temperature: 0.4, maxOutputTokens: 1400 })));
    } catch (e) { slot.replaceChildren(muted('AI layer unavailable: ' + (e.message || 'failed') + '. The tiered assessment above stands on its own.')); }
  }
}

export default {
  id: 'analyst',
  label: 'analyst',
  placeholder: 'domain, IP, ASN, URL or email to analyse',
  intro: 'The flagship engine: maps how infrastructure and organisations connect, propagates risk across those links, clusters related assets, tracks change over time, and separates confirmed facts from probable relationships and speculative predictions — every conclusion cited. Infrastructure only, authorized targets.',
  examples: ['github.com', '1.1.1.1'],
  noTrack: true,

  run(seed) {
    seed = seed.trim();
    if (!seed) throw new Error('enter a domain, IP, ASN, URL or email');

    const scopeSel = h('div', { class: 'segset' }, Object.entries(SCOPES).map(([k, s]) => {
      const b = h('button', { class: 'seg' + (k === scopeKey ? ' on' : ''), type: 'button' }, s.label);
      b.onclick = () => { scopeKey = k; [...scopeSel.children].forEach(x => x.classList.toggle('on', x === b)); };
      return b;
    }));
    const statusEl = h('span', {});
    const logEl = h('div', { class: 'enginelog' });
    const rerun = h('button', { class: 'primary', type: 'button' }, 'analyse');
    const resultSlot = h('div');
    const container = h('div');

    const head = card('intelligence analyst', { wide: true, actions: [h('span', { class: 'muted small' }, 'scope'), scopeSel, rerun] },
      h('div', { class: 'row-between' }, h('div', {}, h('strong', {}, seed)), statusEl),
      muted('Expands public-infrastructure links (DNS, RDAP, hosting, Shodan, ASN), then analyses them: risk propagation, clustering, prediction, temporal change. Public sources only; never profiles private individuals.'),
      logEl);
    container.append(head, resultSlot);

    const start = () => {
      resultSlot.replaceChildren(); logEl.replaceChildren();
      requestAnimationFrame(() => analyse(container, seed, statusEl, logEl, resultSlot).catch(e => {
        if (resultSlot.isConnected) resultSlot.append(card('analyst error', { wide: true }, muted(e?.message || 'failed')));
      }));
    };
    rerun.onclick = start;
    start();
    return container;
  },
};
