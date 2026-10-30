import { h, card, grid, muted, badge, ext, pivot, copyBtn, getJSON, normDomain, isIP, vcard, rdapEntity, rdapEvent, fmtDate } from '../util.js';

// Registration details for a domain or IP via RDAP (structured WHOIS) — registrar, creation / expiry
// dates, domain age, status flags, nameservers, DNSSEC. Public RDAP data, client-side.

const days = ms => Math.round(ms / 86400000);

export default {
  id: 'whois',
  label: 'whois',
  placeholder: 'example.com or an IP  (registration / RDAP)',
  intro: 'Registration details via RDAP (structured WHOIS) — registrar, creation & expiry, domain age, status, nameservers and DNSSEC. Public data.',
  examples: ['example.com', '8.8.8.8'],

  async run(raw) {
    const input = raw.trim();
    if (!input) throw new Error('enter a domain or IP');
    const ipMode = isIP(input);
    const target = ipMode ? input : (normDomain(input) || input);
    const r = await getJSON(`https://rdap.org/${ipMode ? 'ip' : 'domain'}/${encodeURIComponent(target)}`, { timeout: 20000 }).catch(() => null);
    if (!r?.ok || !r.data) {
      return card('no RDAP data', { wide: true }, muted(`RDAP returned nothing for ${target}.`), h('p', {}, ext(`https://rdap.org/${ipMode ? 'ip' : 'domain'}/${target}`, 'open RDAP')));
    }
    const d = r.data;
    const rows = [];

    if (ipMode) {
      rows.push(['range', d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : d.handle]);
      rows.push(['name', d.name]);
      rows.push(['type', d.type]);
      rows.push(['country', d.country]);
      const org = vcard(rdapEntity(d.entities, 'registrant') || rdapEntity(d.entities, 'administrative'));
      if (org.fn) rows.push(['organization', org.fn]);
    } else {
      const reg = vcard(rdapEntity(d.entities, 'registrar'));
      const created = rdapEvent(d, 'registration');
      const expires = rdapEvent(d, 'expiration');
      const changed = rdapEvent(d, 'last changed');
      rows.push(['domain', d.ldhName || target]);
      if (reg.fn) rows.push(['registrar', reg.fn]);
      if (created) { rows.push(['created', created.slice(0, 10)]); rows.push(['age', `${days(Date.now() - Date.parse(created))} days`]); }
      if (changed) rows.push(['updated', changed.slice(0, 10)]);
      if (expires) rows.push(['expires', expires.slice(0, 10)]);
      if (d.secureDNS) rows.push(['DNSSEC', d.secureDNS.delegationSigned ? 'signed' : 'unsigned']);
    }

    const created = rdapEvent(d, 'registration');
    const expires = rdapEvent(d, 'expiration');
    const young = created && (Date.now() - Date.parse(created)) < 90 * 86400000;
    const expSoon = expires && (Date.parse(expires) - Date.now()) < 30 * 86400000 && Date.parse(expires) > Date.now();

    const kvTable = h('table', { class: 'records' }, h('tbody', {}, rows.filter(([, v]) => v).map(([k, v]) =>
      h('tr', {}, h('td', { class: 'muted small' }, k), h('td', {}, String(v))))));

    const statuses = (d.status || []);
    const statusCard = statuses.length ? card('status', {}, h('div', { class: 'chips' }, statuses.map(s => h('span', { class: 'chip' }, s)))) : null;

    const ns = (d.nameservers || []).map(n => n.ldhName).filter(Boolean);
    const nsCard = ns.length ? card('nameservers', {}, h('div', { class: 'chips' }, ns.map(n => h('span', { class: 'chip' }, pivot('domain', n.toLowerCase(), n))))) : null;

    const flags = [young ? badge('recently registered', 'warn') : null, expSoon ? badge('expiring soon', 'warn') : null].filter(Boolean);
    const header = card('registration', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, ...flags, copyBtn(() => rows.map(([k, v]) => `${k}: ${v}`).join('\n'), 'copy')) },
      kvTable,
      young ? muted('Recently registered domains are disproportionately used for phishing/abuse — weigh that in context.') : null,
      h('div', { class: 'row wrap', style: 'gap:6px;margin-top:6px' }, pivot(ipMode ? 'ip' : 'domain', target, ipMode ? 'IP intel' : 'domain intel'), !ipMode ? pivot('dns', target, 'DNS records') : null, !ipMode ? pivot('typosquat', target, 'brand lookalikes') : null));

    return grid(header, statusCard, nsCard);
  },
};
