import { h, card, grid, muted, badge, ext, pivot, copyBtn, dns, normDomain, isIP } from '../util.js';

// Full DNS record dump for a domain over DoH — A/AAAA, CNAME, NS, MX, SOA, TXT, CAA, plus mail-auth
// (SPF, DMARC, and common DKIM selectors). Public DNS, client-side.

const TYPES = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'SOA', 'TXT', 'CAA'];
const DKIM_SELECTORS = ['google', 'default', 'selector1', 'selector2', 'k1', 'mail', 's1', 'dkim'];
const pivotFor = (type, data) => {
  if (type === 'A' || type === 'AAAA') return pivot('ip', data, data);
  if (type === 'NS' || type === 'CNAME') return pivot('domain', data.replace(/\.$/, ''), data);
  if (type === 'MX') return pivot('domain', data.replace(/^\d+\s+/, '').replace(/\.$/, ''), data);
  return data;
};

export default {
  id: 'dns',
  label: 'dns',
  placeholder: 'example.com  (full DNS record dump)',
  intro: 'Every DNS record for a domain — A/AAAA, CNAME, NS, MX, SOA, TXT, CAA — plus mail authentication (SPF, DMARC, common DKIM selectors). Public DNS.',
  examples: ['example.com', 'cloudflare.com'],

  async run(raw) {
    const d = normDomain(raw) || raw.trim().toLowerCase();
    if (!d || !d.includes('.')) throw new Error('enter a domain, e.g. example.com');

    const results = await Promise.all(TYPES.map(t => dns(d, t).catch(() => [])));
    const byType = Object.fromEntries(TYPES.map((t, i) => [t, results[i]]));
    const [dmarc, ...dkims] = await Promise.all([
      dns(`_dmarc.${d}`, 'TXT').catch(() => []),
      ...DKIM_SELECTORS.map(s => dns(`${s}._domainkey.${d}`, 'TXT').catch(() => [])),
    ]);

    const total = Object.values(byType).reduce((n, a) => n + a.length, 0);
    const recordCards = TYPES.filter(t => byType[t].length).map(t => card(`${t} (${byType[t].length})`, { wide: t === 'TXT' },
      h('table', { class: 'records' }, h('tbody', {}, byType[t].map(r => h('tr', {},
        h('td', { class: 'small', style: 'word-break:break-all' }, pivotFor(t, r.data)),
        h('td', { class: 'muted small' }, r.ttl != null ? `ttl ${r.ttl}` : '')))))));

    // Mail auth summary.
    const spf = (byType.TXT || []).find(r => /^v=spf1/i.test(r.data));
    const dmarcRec = dmarc.find(r => /^v=DMARC1/i.test(r.data));
    const dkimFound = DKIM_SELECTORS.map((s, i) => [s, dkims[i].find(r => /v=DKIM1|k=rsa|p=/i.test(r.data))]).filter(([, r]) => r);
    const authRow = (label, ok, detail) => h('tr', {}, h('td', {}, badge(label, ok ? 'ok' : 'warn')), h('td', { class: 'small', style: 'word-break:break-all' }, ok ? detail : h('span', { class: 'muted' }, 'not found')));
    const mail = card('mail authentication', { wide: true },
      h('table', { class: 'records' }, h('tbody', {},
        authRow('SPF', !!spf, spf?.data),
        authRow('DMARC', !!dmarcRec, dmarcRec?.data),
        authRow('DKIM', dkimFound.length > 0, dkimFound.map(([s]) => s).join(', ') + ' selector(s)'))),
      !dmarcRec ? muted('No DMARC record — the domain is easier to spoof. Consider publishing one.') : null);

    const header = card('dns records', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, badge(`${total} records`, 'ok'),
        copyBtn(() => TYPES.flatMap(t => byType[t].map(r => `${t}\t${r.data}`)).join('\n'), 'copy all')) },
      muted(`All DNS records for ${d}.`),
      h('div', { class: 'row wrap', style: 'gap:6px;margin-top:6px' }, pivot('domain', d, 'domain intel'), pivot('cert', d, 'certificates'), pivot('whois', d, 'whois')));

    return grid(header, mail, ...recordCards);
  },
};
