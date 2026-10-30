import { h, card, grid, muted, badge, ext, pivot, dns, getJSON, isIP, normDomain } from '../util.js';

// Reputation check for an IP or domain: GreyNoise (is it a known internet scanner / benign crawler?),
// Shodan InternetDB exposure, and one-click lookups across the major reputation/blocklist services.
// Public data, client-side. Useful for triaging an IP in a log, or checking your own host's standing.

const LINKS = ip => [
  ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${ip}`],
  ['AbuseIPDB', `https://www.abuseipdb.com/check/${ip}`],
  ['Shodan', `https://www.shodan.io/host/${ip}`],
  ['GreyNoise', `https://viz.greynoise.io/ip/${ip}`],
  ['Censys', `https://search.censys.io/hosts/${ip}`],
  ['Spamhaus', `https://check.spamhaus.org/results/?query=${ip}`],
  ['Pulsedive', `https://pulsedive.com/indicator/?ioc=${ip}`],
  ['Talos', `https://talosintelligence.com/reputation_center/lookup?search=${ip}`],
];

export default {
  id: 'reputation',
  label: 'reputation',
  placeholder: 'an IP or domain to check reputation',
  intro: 'Reputation triage for an IP or domain — GreyNoise scanner classification, Shodan exposure, and one-click lookups across the major reputation / blocklist services.',
  examples: ['1.1.1.1', '8.8.8.8'],

  async run(raw) {
    const input = raw.trim();
    if (!input) throw new Error('enter an IP or domain');
    let ip = input, resolvedFrom = null;
    if (!isIP(input)) {
      const d = normDomain(input) || input;
      const a = await dns(d, 'A').catch(() => []);
      if (!a.length) throw new Error(`could not resolve ${d}`);
      ip = a[0].data; resolvedFrom = d;
    }

    const cards = [];

    // GreyNoise community API (no key) — classifies noisy scanners vs benign crawlers vs unknown.
    const gn = await getJSON(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, { timeout: 12000 }).catch(() => null);
    if (gn?.ok && gn.data) {
      const d = gn.data;
      const cls = d.classification || 'unknown';
      const tone = cls === 'malicious' ? 'bad' : cls === 'benign' ? 'ok' : 'muted';
      cards.push(card('GreyNoise', { actions: badge(cls, tone) },
        d.noise ? muted(`${ip} is a known internet scanner${d.name && d.name !== 'unknown' ? ` — ${d.name}` : ''}. ${d.riot ? 'Also in RIOT (common business service).' : ''}`)
          : muted(d.message || `${ip} is not seen scanning by GreyNoise.`),
        h('p', { class: 'muted small' }, 'last seen: ', d.last_seen || 'n/a', ' · ', ext(d.link || `https://viz.greynoise.io/ip/${ip}`, 'details'))));
    }

    // Shodan InternetDB exposure.
    const idb = await getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`).catch(() => null);
    if (idb?.ok && idb.data) {
      const d = idb.data;
      cards.push(card('exposure (Shodan)', {},
        d.ports?.length ? h('p', {}, 'open ports: ', h('strong', {}, d.ports.join(', '))) : muted('no open ports seen'),
        d.vulns?.length ? h('p', {}, badge(`${d.vulns.length} CVE(s)`, 'warn'), ' ', d.vulns.slice(0, 8).map((v, i) => h('span', {}, i ? ', ' : '', pivot('cve', v, v)))) : null,
        d.tags?.length ? h('p', { class: 'muted small' }, 'tags: ', d.tags.join(', ')) : null));
    }

    const header = card('reputation', { wide: true, actions: resolvedFrom ? badge(`${resolvedFrom} → ${ip}`, 'muted') : badge(ip, 'muted') },
      muted(`Reputation and exposure signals for ${ip}${resolvedFrom ? ` (resolved from ${resolvedFrom})` : ''}. Combine with the manual lookups below.`),
      h('div', { class: 'row wrap', style: 'gap:6px;margin-top:6px' }, pivot('ip', ip, 'full IP intel'), pivot('sweep', ip, 'network sweep')));

    const linksCard = card('reputation & blocklist services', { wide: true },
      muted('Open this IP in each — handy for confirming a finding across sources.'),
      h('div', { class: 'chips' }, LINKS(ip).map(([n, u]) => h('span', { class: 'chip' }, ext(u, n)))));

    return grid(header, ...cards, linksCard);
  },
};
