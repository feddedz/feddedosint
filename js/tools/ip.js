import {
  h, getJSON, dns, isIP, isIPv4, reverseName, card, asyncCard, kv, ext, pivot, linkGroups, grid, muted,
  vcard, rdapEntity, rdapEvent, fmtDate, flag,
} from '../util.js';
import { getKey, hasKey } from '../store.js';

const PRIVATE = [
  [/^10\./, 'private (RFC 1918)'], [/^192\.168\./, 'private (RFC 1918)'], [/^172\.(1[6-9]|2\d|3[01])\./, 'private (RFC 1918)'],
  [/^127\./, 'loopback'], [/^169\.254\./, 'link-local'], [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, 'carrier-grade NAT'],
  [/^0\./, 'unspecified'], [/^(22[4-9]|23\d)\./, 'multicast'],
  [/^(::1|::)$/, 'loopback / unspecified'], [/^f[cd]/i, 'unique local (private)'], [/^fe[89ab]/i, 'link-local'],
];

function mapEmbed(lat, lon) {
  const d = 0.08;
  const src = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - d},${lat - d / 2},${lon + d},${lat + d / 2}&layer=mapnik&marker=${lat},${lon}`;
  return h('div', { class: 'map' }, h('iframe', { src, loading: 'lazy', title: 'approximate location', referrerpolicy: 'no-referrer' }));
}

export default {
  id: 'ip',
  label: 'ip',
  placeholder: 'IPv4 / IPv6 — leave empty for your own',
  intro: 'Geolocation, ASN & ISP, reverse DNS, open ports & known CVEs (Shodan InternetDB) and network ownership (RDAP).',
  examples: ['1.1.1.1', '8.8.8.8'],
  allowEmpty: true,

  async run(raw) {
    let ip = raw.trim().replace(/^\[|\]$/g, '');
    if (!ip) {
      const r = await getJSON('https://api64.ipify.org?format=json').catch(() => null);
      ip = r?.data?.ip;
      if (!ip) throw new Error('could not detect your IP — enter one manually');
      history.replaceState(null, '', `#ip/${encodeURIComponent(ip)}`);
    }
    if (!isIP(ip)) throw new Error('that is not a valid IPv4 or IPv6 address');
    const reserved = PRIVATE.find(([re]) => re.test(ip))?.[1];
    if (reserved) return muted(`${ip} is a ${reserved} address — it is not routable on the internet, so there is nothing to look up.`);
    const enc = encodeURIComponent(ip);

    return grid(
      asyncCard('location & network', async () => {
        const r = await getJSON(`https://ipwho.is/${enc}`);
        const g = r.data;
        if (!g?.success) throw new Error(g?.message || `HTTP ${r.status}`);
        const c = g.connection || {};
        return [
          kv([
            ['ip', h('span', { class: 'mono' }, g.ip, ' ', h('span', { class: 'muted' }, g.type))],
            ['location', [flag(g.country_code), [g.city, g.region, g.country].filter(Boolean).join(', ')].join(' ')],
            ['coordinates', g.latitude != null && pivot('geo', `${g.latitude},${g.longitude}`, `${g.latitude}, ${g.longitude}`)],
            ['postal', g.postal],
            ['timezone', g.timezone?.id && `${g.timezone.id} (UTC${g.timezone.utc})`],
            ['asn', c.asn && ext(`https://bgp.he.net/AS${c.asn}`, `AS${c.asn}`)],
            ['org', c.org],
            ['isp', c.isp !== c.org ? c.isp : null],
            ['domain', c.domain && pivot('domain', c.domain)],
          ]),
          g.latitude != null ? mapEmbed(g.latitude, g.longitude) : null,
          muted('IP geolocation is approximate — usually the ISP’s location, not the person’s.'),
        ];
      }, { wide: true }),

      asyncCard('reverse dns', async () => {
        const ptr = await dns(reverseName(ip), 'PTR');
        return ptr.length
          ? h('div', {}, ptr.map(p => h('div', {}, pivot('domain', p.data))))
          : muted('no PTR record.');
      }),

      asyncCard('exposure (shodan internetdb)', async () => {
        const r = await getJSON(`https://internetdb.shodan.io/${enc}`);
        if (r.status === 404) return muted('no open ports or services seen by Shodan.');
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const x = r.data;
        const tags = (list, cls = 'tag') => list.length ? h('div', { class: 'tags' }, list.map(t => h('span', { class: cls }, t))) : null;
        return kv([
          ['open ports', tags(x.ports.map(String))],
          ['hostnames', x.hostnames.map(n => h('div', {}, pivot('domain', n)))],
          ['tags', tags(x.tags)],
          ['software', x.cpes.map(c => h('div', { class: 'mono wrap' }, c))],
          ['vulns', x.vulns.length ? h('div', { class: 'tags' }, x.vulns.slice(0, 40).map(v =>
            ext(`https://nvd.nist.gov/vuln/detail/${v}`, v))) : null],
        ]);
      }),

      // Richer data when the user has saved their own keys in Settings.
      hasKey('shodan') ? asyncCard('shodan host', async () => {
        const r = await getJSON(`https://api.shodan.io/shodan/host/${enc}?key=${encodeURIComponent(getKey('shodan'))}&minify=true`);
        if (r.status === 404) return muted('Shodan has no data on this host.');
        if (r.status === 401 || r.status === 403) throw new Error('Shodan rejected the key — check it in Settings');
        if (!r.ok || !r.data) throw new Error(`HTTP ${r.status}`);
        const x = r.data;
        return kv([
          ['organization', x.org], ['isp', x.isp], ['os', x.os],
          ['ports', (x.ports || []).length ? h('div', { class: 'tags' }, x.ports.map(p => h('span', { class: 'tag' }, String(p)))) : null],
          ['hostnames', (x.hostnames || []).map(n => h('div', {}, pivot('domain', n)))],
          ['domains', (x.domains || []).map(n => h('div', {}, pivot('domain', n)))],
          ['tags', (x.tags || []).join(', ')],
          ['vulns', (x.vulns || []).length ? h('div', { class: 'tags' }, x.vulns.slice(0, 30).map(v => pivot('cve', v))) : null],
          ['last seen', x.last_update?.slice(0, 10)],
        ]);
      }) : null,

      hasKey('ipinfo') ? asyncCard('ipinfo', async () => {
        const r = await getJSON(`https://ipinfo.io/${enc}/json?token=${encodeURIComponent(getKey('ipinfo'))}`);
        if (r.status === 401 || r.status === 403) throw new Error('IPinfo rejected the token — check it in Settings');
        if (!r.ok || !r.data) throw new Error(`HTTP ${r.status}`);
        const x = r.data;
        return kv([
          ['hostname', x.hostname && pivot('domain', x.hostname)],
          ['location', [x.city, x.region, x.country].filter(Boolean).join(', ')],
          ['coordinates', x.loc && pivot('geo', x.loc)],
          ['org', x.org], ['postal', x.postal], ['timezone', x.timezone],
          ['anycast', x.anycast ? 'yes' : null],
          ['privacy', x.privacy ? Object.entries(x.privacy).filter(([, v]) => v === true).map(([k]) => k).join(', ') || 'none detected' : null],
        ]);
      }) : null,

      asyncCard('ownership (rdap)', async () => {
        const r = await getJSON(`https://rdap.org/ip/${enc}`);
        if (!r.ok || !r.data) throw new Error(`HTTP ${r.status}`);
        const x = r.data;
        const reg = vcard(rdapEntity(x.entities, 'registrant'));
        const abuse = vcard(rdapEntity(x.entities, 'abuse'));
        return kv([
          ['network', x.name],
          ['range', x.startAddress && `${x.startAddress} – ${x.endAddress}`],
          ['cidr', (x.cidr0_cidrs || []).map(c => `${c.v4prefix || c.v6prefix}/${c.length}`).join(', ')],
          ['owner', [reg.fn, reg.org].filter(Boolean).join(' — ')],
          ['country', x.country && `${flag(x.country)} ${x.country}`],
          ['abuse', abuse.email && pivot('email', abuse.email)],
          ['registered', rdapEvent(x, 'registration') && fmtDate(rdapEvent(x, 'registration'))],
          ['handle', x.handle],
        ]);
      }),

      card('pivot further', { wide: true }, linkGroups([
        { group: 'reputation', items: [
          ['AbuseIPDB', `https://www.abuseipdb.com/check/${enc}`], ['GreyNoise', `https://viz.greynoise.io/ip/${enc}`],
          ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${enc}`], ['AlienVault OTX', `https://otx.alienvault.com/indicator/ip/${enc}`],
          ['Cisco Talos', `https://talosintelligence.com/reputation_center/lookup?search=${enc}`], ['Spur (VPN/proxy)', `https://spur.us/context/${enc}`],
        ] },
        { group: 'infrastructure', items: [
          ['Shodan', `https://www.shodan.io/host/${enc}`], ['Censys', `https://search.censys.io/hosts/${enc}`],
          ['IPinfo', `https://ipinfo.io/${enc}`], ['Hurricane Electric BGP', `https://bgp.he.net/ip/${enc}`],
          ['urlscan.io', `https://urlscan.io/ip/${enc}`],
          ...(isIPv4(ip) ? [['ViewDNS reverse IP', `https://viewdns.info/reverseip/?host=${enc}&t=1`]] : []),
        ] },
      ])),
    );
  },
};
