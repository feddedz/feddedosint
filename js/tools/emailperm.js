import { h, card, grid, muted, badge, ext, pivot, copyBtn, normDomain } from '../util.js';

// Email permutator: from a person's name and a domain, generate the common corporate email formats
// and give one-click verification pivots. For your own organisation or authorized research
// (recruiting, sales, your own account recovery) — it generates candidates, it doesn't confirm them.

// Build the standard permutations from first/last/domain.
function permutations(first, last, domain) {
  const f = first[0] || '', l = last[0] || '';
  const fl = first, ll = last;
  const set = new Set([
    fl, ll, `${fl}.${ll}`, `${fl}${ll}`, `${f}${ll}`, `${f}.${ll}`, `${fl}${l}`, `${fl}.${l}`,
    `${ll}${fl}`, `${ll}.${fl}`, `${ll}${f}`, `${ll}.${f}`, `${f}${l}`, `${fl}_${ll}`, `${ll}_${fl}`, `${fl}-${ll}`,
  ].filter(x => x && !x.startsWith('.') && !x.endsWith('.')));
  return [...set].map(local => `${local}@${domain}`);
}

export default {
  id: 'emailperm',
  label: 'emailperm',
  placeholder: 'First Last @ company.com   (e.g. "jane doe example.com")',
  intro: 'Generates the common corporate email formats from a name + domain, with verification pivots. For your own org or authorized research — generates candidates, doesn’t confirm them.',
  examples: ['jane doe example.com'],

  run(raw) {
    const input = (raw || '').trim().toLowerCase();
    if (!input) throw new Error('enter: first last domain.com');
    // Parse "first last domain" (domain is the token containing a dot).
    const tokens = input.split(/[\s,]+/).filter(Boolean);
    const domTok = tokens.find(t => t.includes('.'));
    const domain = domTok ? (normDomain(domTok) || domTok.replace(/^@/, '')) : '';
    const names = tokens.filter(t => t !== domTok).map(t => t.replace(/[^a-z-]/g, ''));
    if (!domain || names.length < 1) throw new Error('enter a first name, last name and a domain — e.g. "jane doe example.com"');
    const first = names[0], last = names[1] || '';

    const emails = permutations(first, last, domain);

    const rows = emails.map(e => h('tr', {},
      h('td', { class: 'small' }, e),
      h('td', {}, h('div', { class: 'row', style: 'gap:6px;justify-content:flex-end' },
        pivot('email', e, 'check'),
        ext(`https://hunter.io/email-verifier/${encodeURIComponent(e)}`, 'verify')))));

    return grid(
      card('email permutations', { wide: true, actions: copyBtn(() => emails.join('\n'), 'copy all') },
        muted(`${emails.length} candidate addresses for ${first}${last ? ' ' + last : ''} @ ${domain}. These are guesses from common formats — verify before use.`),
        h('table', { class: 'records' }, h('tbody', {}, rows))),
      card('tips', {},
        muted('Find the org’s real pattern first: one known address (from a press page, a git commit, LinkedIn) tells you which format they use, then only that row matters.'),
        h('p', { class: 'muted small' }, 'bulk formats & confidence: ', ext('https://hunter.io/', 'Hunter.io'), ' · ', ext('https://www.email-format.com/', 'email-format.com'))));
  },
};
