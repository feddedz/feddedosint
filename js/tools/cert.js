import { h, card, grid, muted, badge, ext, pivot, copyBtn, getJSON, normDomain, fmtDate } from '../util.js';

// Certificate-transparency history for a domain, from crt.sh. Every certificate ever logged for the
// name and its subdomains — a rich source of subdomain discovery, issuer history and expiry tracking.
// Public CT logs, fetched client-side.

export default {
  id: 'cert',
  label: 'cert',
  placeholder: 'example.com  (certificate transparency history)',
  intro: 'Certificate-transparency history from crt.sh — subdomains from SANs, issuers, and certificate timeline/expiry. Public CT logs.',
  examples: ['example.com'],

  async run(raw) {
    const domain = normDomain(raw) || raw.trim().toLowerCase();
    if (!domain || !domain.includes('.')) throw new Error('enter a domain, e.g. example.com');

    const r = await getJSON(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, { timeout: 30000 }).catch(() => null);
    if (!r?.ok || !Array.isArray(r.data)) {
      return card('no CT data', { wide: true }, muted(`crt.sh returned nothing for ${domain} (it may be busy — try again), or check it `), h('p', {}, ext(`https://crt.sh/?q=${encodeURIComponent(domain)}`, 'on crt.sh')));
    }
    const rows = r.data;
    if (!rows.length) return card('no certificates', { wide: true }, muted(`No certificates logged for ${domain}.`));

    const subs = new Set(), issuers = {};
    let earliest = Infinity, latest = 0, soonest = null;
    const now = Date.now();
    for (const c of rows) {
      String(c.name_value || '').split('\n').forEach(n => { n = n.trim().toLowerCase().replace(/^\*\./, ''); if (n.endsWith(domain)) subs.add(n); });
      const iss = (c.issuer_name || '').match(/O=([^,]+)/)?.[1] || c.issuer_name || 'unknown';
      issuers[iss] = (issuers[iss] || 0) + 1;
      const nb = Date.parse(c.not_before), na = Date.parse(c.not_after);
      if (nb) earliest = Math.min(earliest, nb);
      if (na) { latest = Math.max(latest, na); if (na > now && (!soonest || na < soonest)) soonest = na; }
    }
    const subList = [...subs].sort();
    const issList = Object.entries(issuers).sort((a, b) => b[1] - a[1]);
    const recent = [...rows].sort((a, b) => Date.parse(b.not_before) - Date.parse(a.not_before)).slice(0, 25);

    const sc = (n, l) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' }, String(n)), h('div', { class: 'statlbl muted small' }, l));
    const summary = card('certificate transparency', { wide: true, actions: badge(`${rows.length} certs`, 'ok') },
      muted(`Certificates logged for ${domain} and its subdomains.`),
      h('div', { class: 'statrow' },
        sc(rows.length, 'certificates'), sc(subList.length, 'subdomains'), sc(issList.length, 'issuers'),
        sc(earliest !== Infinity ? new Date(earliest).getUTCFullYear() : '—', 'first seen'),
        sc(soonest ? Math.max(0, Math.round((soonest - now) / 86400000)) : '—', 'days to expiry')),
      soonest && soonest - now < 21 * 86400000 ? h('p', {}, badge('expiring soon', 'warn'), ` next certificate expires ${fmtDate(soonest)}`) : null);

    const subCard = card(`subdomains (${subList.length})`, { wide: true, collapsed: subList.length > 60 },
      muted('Hostnames seen in certificate SANs — a strong subdomain source.'),
      h('p', {}, copyBtn(() => subList.join('\n'), 'copy all')),
      h('div', { class: 'chips' }, subList.slice(0, 400).map(s => h('span', { class: 'chip' }, pivot('recon', s, s)))));

    const issCard = card('issuers', {}, h('table', { class: 'records' }, h('tbody', {}, issList.slice(0, 15).map(([i, n]) =>
      h('tr', {}, h('td', { class: 'small' }, i), h('td', { class: 'muted small' }, `${n}`))))));

    const recentCard = card('recent certificates', { wide: true, collapsed: true },
      h('table', { class: 'records' }, h('tbody', {}, recent.map(c => h('tr', {},
        h('td', { class: 'muted small' }, (c.not_before || '').slice(0, 10)),
        h('td', { class: 'small', style: 'word-break:break-all' }, (c.name_value || '').split('\n')[0]),
        h('td', { class: 'muted small' }, (c.issuer_name || '').match(/O=([^,]+)/)?.[1] || ''))))));

    return grid(summary, subCard, issCard, recentCard);
  },
};
