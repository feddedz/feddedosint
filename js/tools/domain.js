import {
  h, getJSON, dns, normDomain, card, asyncCard, kv, ext, pivot, linkGroups, copyBtn, grid, muted,
  vcard, rdapEntity, rdapEvent, fmtDate, flag,
} from '../util.js';

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'default', 'k1', 'k2', 's1', 's2', 'mail', 'dkim', 'mandrill', 'zoho', 'protonmail'];

// Fingerprints in MX / SPF / TXT records that reveal which services a domain uses.
const FINGERPRINTS = [
  [/google\.com|googlemail|_spf\.google|google-site-verification/i, 'Google Workspace'],
  [/outlook\.com|protection\.outlook|spf\.protection|^MS=/i, 'Microsoft 365'],
  [/protonmail|proton\.ch|protonmail-verification/i, 'Proton Mail'],
  [/zoho/i, 'Zoho'],
  [/messagingengine|fastmail/i, 'Fastmail'],
  [/mimecast/i, 'Mimecast'],
  [/pphosted|proofpoint/i, 'Proofpoint'],
  [/barracuda/i, 'Barracuda'],
  [/icloud\.com|apple-domain-verification/i, 'Apple'],
  [/mailgun/i, 'Mailgun'],
  [/sendgrid/i, 'SendGrid'],
  [/mandrillapp|mcsv\.net|mailchimp/i, 'Mailchimp'],
  [/amazonses|amazon-ses/i, 'Amazon SES'],
  [/sparkpost/i, 'SparkPost'],
  [/postmark/i, 'Postmark'],
  [/hubspot/i, 'HubSpot'],
  [/salesforce|exacttarget/i, 'Salesforce'],
  [/zendesk/i, 'Zendesk'],
  [/freshdesk/i, 'Freshdesk'],
  [/atlassian-domain-verification/i, 'Atlassian'],
  [/facebook-domain-verification/i, 'Meta'],
  [/docusign/i, 'DocuSign'],
  [/stripe-verification/i, 'Stripe'],
  [/zoom-domain-verification|ZOOM_verify/i, 'Zoom'],
  [/slack-domain-verification/i, 'Slack'],
  [/adobe-idp-site-verification|adobe-sign-verification/i, 'Adobe'],
  [/dropbox-domain-verification/i, 'Dropbox'],
  [/notion-domain-verification/i, 'Notion'],
  [/openai-domain-verification/i, 'OpenAI'],
  [/anthropic-domain-verification/i, 'Anthropic'],
  [/cisco-ci-domain-verification|webex/i, 'Cisco Webex'],
  [/yandex-verification/i, 'Yandex'],
  [/globalsign|_globalsign-domain-verification/i, 'GlobalSign'],
  [/have-i-been-pwned-verification/i, 'Have I Been Pwned'],
  [/cloudflare/i, 'Cloudflare'],
  [/awsdns/i, 'AWS Route 53'],
  [/azure-dns/i, 'Azure DNS'],
  [/domaincontrol\.com/i, 'GoDaddy DNS'],
  [/registrar-servers\.com/i, 'Namecheap DNS'],
  [/vercel-dns|vercel/i, 'Vercel'],
  [/netlify/i, 'Netlify'],
  [/github\.io|_github-pages-challenge/i, 'GitHub Pages'],
];

export function fingerprint(strings) {
  const hits = new Set();
  for (const s of strings) for (const [re, name] of FINGERPRINTS) if (re.test(s)) hits.add(name);
  return [...hits];
}

function hostLink(value) {
  // MX data is "10 mail.example.com"; keep the priority, pivot on the host.
  const m = value.match(/^(\d+)\s+(.+)$/);
  return m ? [m[1] + ' ', pivot('domain', m[2])] : pivot('domain', value);
}

function recordValue(type, value) {
  if (type === 'A' || type === 'AAAA') return pivot('ip', value);
  if (type === 'NS' || type === 'CNAME' || type === 'MX') return hostLink(value);
  return h('span', { class: 'mono wrap' }, value);
}

export default {
  id: 'domain',
  label: 'domain',
  placeholder: 'domain or URL',
  intro: 'DNS, WHOIS (RDAP), mail security, detected services, hosting, certificate-transparency subdomains and archive history.',
  examples: ['github.com', 'example.org'],

  run(raw) {
    const d = normDomain(raw);
    if (!d) throw new Error('that does not look like a domain');

    const cache = new Map();
    const q = (name, type) => {
      const key = `${name}|${type}`;
      if (!cache.has(key)) cache.set(key, dns(name, type).catch(() => []));
      return cache.get(key);
    };
    const enc = encodeURIComponent(d);

    return grid(
      asyncCard('dns records', async () => {
        const results = await Promise.all(TYPES.map(t => q(d, t)));
        const rows = TYPES.flatMap((t, i) => results[i].map(r => [t, r]));
        if (!rows.length) return muted('no records — the domain may not exist or not resolve.');
        return h('table', { class: 'records' },
          h('tbody', {}, rows.map(([t, r]) => h('tr', {},
            h('td', { class: 'type' }, t), h('td', {}, recordValue(t, r.data)), h('td', { class: 'ttl muted' }, r.ttl)))));
      }, { wide: true }),

      asyncCard('registration (rdap)', async () => {
        const r = await getJSON(`https://rdap.org/domain/${enc}`);
        if (r.status === 404) return muted('no RDAP record — the TLD may not support RDAP, or the domain is unregistered.');
        if (!r.ok || !r.data) throw new Error(`HTTP ${r.status}`);
        const x = r.data;
        const registrar = rdapEntity(x.entities, 'registrar');
        const abuse = vcard(rdapEntity(registrar?.entities, 'abuse'));
        const registrant = vcard(rdapEntity(x.entities, 'registrant'));
        const created = rdapEvent(x, 'registration');
        const ageYears = created ? ((Date.now() - new Date(created)) / 3.156e10).toFixed(1) : null;
        return kv([
          ['registrar', vcard(registrar).fn],
          ['registered', created && `${fmtDate(created)} (${ageYears} yrs)`],
          ['expires', rdapEvent(x, 'expiration') && fmtDate(rdapEvent(x, 'expiration'))],
          ['updated', rdapEvent(x, 'last changed') && fmtDate(rdapEvent(x, 'last changed'))],
          ['registrant', [registrant.fn, registrant.org].filter(Boolean).join(' — ')],
          ['registrant email', registrant.email && pivot('email', registrant.email)],
          ['abuse contact', abuse.email && pivot('email', abuse.email)],
          ['status', (x.status || []).join(', ')],
          ['dnssec', x.secureDNS ? (x.secureDNS.delegationSigned ? 'signed' : 'unsigned') : null],
          ['nameservers', (x.nameservers || []).map(n => n.ldhName?.toLowerCase()).filter(Boolean)
            .map(n => h('div', {}, pivot('domain', n)))],
        ]);
      }),

      asyncCard('mail security', async () => {
        const [mx, txt, dmarc] = await Promise.all([q(d, 'MX'), q(d, 'TXT'), q(`_dmarc.${d}`, 'TXT')]);
        const spf = txt.find(r => /^v=spf1/i.test(r.data))?.data;
        const dm = dmarc.find(r => /^v=DMARC1/i.test(r.data))?.data;
        const policy = dm?.match(/;\s*p=(\w+)/i)?.[1];
        const selectors = await Promise.all(DKIM_SELECTORS.map(async s => ((await q(`${s}._domainkey.${d}`, 'TXT')).length ? s : null)));
        const spoofable = !spf || !dm || policy === 'none';
        return kv([
          ['mx', mx.length ? mx.map(r => h('div', {}, hostLink(r.data))) : 'none — domain does not receive mail'],
          ['spf', spf ? h('span', { class: 'mono wrap' }, spf) : 'missing'],
          ['dmarc', dm ? h('span', { class: 'mono wrap' }, dm) : 'missing'],
          ['dkim selectors', selectors.filter(Boolean).join(', ') || 'none of the common ones'],
          ['spoofing', spoofable ? 'likely possible (weak or missing SPF/DMARC)' : `protected (DMARC p=${policy})`],
        ]);
      }),

      asyncCard('detected services', async () => {
        const [mx, txt, ns, cname] = await Promise.all([q(d, 'MX'), q(d, 'TXT'), q(d, 'NS'), q(d, 'CNAME')]);
        const all = [...mx, ...txt, ...ns, ...cname].map(r => r.data);
        const found = fingerprint(all);
        return found.length
          ? h('div', { class: 'tags' }, found.map(f => h('span', { class: 'tag' }, f)))
          : muted('no known service fingerprints in DNS.');
      }),

      asyncCard('hosting', async () => {
        const a = await q(d, 'A');
        const ip = a[0]?.data || (await q(d, 'AAAA'))[0]?.data;
        if (!ip) return muted('no A/AAAA record.');
        const r = await getJSON(`https://ipwho.is/${encodeURIComponent(ip)}`);
        const g = r.data?.success ? r.data : null;
        return kv([
          ['ip', pivot('ip', ip)],
          ['asn', g?.connection?.asn && `AS${g.connection.asn}`],
          ['org', g?.connection?.org || g?.connection?.isp],
          ['location', g && [flag(g.country_code), [g.city, g.country].filter(Boolean).join(', ')].join(' ')],
          ['other ips', a.slice(1).map(r => h('div', {}, pivot('ip', r.data)))],
        ]);
      }),

      asyncCard('archive history', async () => {
        const [first, latest] = await Promise.all([
          getJSON(`https://web.archive.org/cdx/search/cdx?url=${enc}&output=json&limit=1&fl=timestamp`).catch(() => null),
          getJSON(`https://archive.org/wayback/available?url=${enc}`).catch(() => null),
        ]);
        const ts = first?.data?.[1]?.[0];
        const snap = latest?.data?.archived_snapshots?.closest;
        const fmt = t => `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}`;
        if (!ts && !snap) throw new Error('wayback machine did not respond');
        return kv([
          ['first capture', ts && ext(`https://web.archive.org/web/${ts}/${d}`, fmt(ts))],
          ['latest capture', snap && ext(snap.url.replace(/^http:/, 'https:'), fmt(snap.timestamp))],
          ['all captures', ext(`https://web.archive.org/web/*/${d}*`, 'browse calendar')],
        ]);
      }),

      subdomainsCard(d, enc),

      card('pivot further', { wide: true }, linkGroups([
        { group: 'reputation & scanning', items: [
          ['VirusTotal', `https://www.virustotal.com/gui/domain/${enc}`], ['urlscan.io', `https://urlscan.io/domain/${enc}`],
          ['Shodan', `https://www.shodan.io/search?query=hostname%3A${enc}`], ['Censys', `https://search.censys.io/search?resource=hosts&q=${enc}`],
          ['AlienVault OTX', `https://otx.alienvault.com/indicator/domain/${enc}`],
        ] },
        { group: 'dns & infrastructure', items: [
          ['SecurityTrails', `https://securitytrails.com/domain/${enc}/dns`], ['DNSDumpster', 'https://dnsdumpster.com/'],
          ['crt.sh', `https://crt.sh/?q=${enc}`], ['ViewDNS reverse IP', `https://viewdns.info/reverseip/?host=${enc}&t=1`],
          ['MXToolbox', `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${enc}`], ['BuiltWith', `https://builtwith.com/${enc}`],
          ['who.is', `https://who.is/whois/${enc}`],
        ] },
        { group: 'content', items: [
          ['Wayback Machine', `https://web.archive.org/web/*/${enc}`], ['archive.today', `https://archive.ph/${enc}`],
          ['Google site:', `https://www.google.com/search?q=site%3A${enc}`], ['GitHub code', `https://github.com/search?q=%22${enc}%22&type=code`],
          ['Hunter emails', `https://hunter.io/search/${enc}`], ['Similarweb', `https://www.similarweb.com/website/${enc}/`],
        ] },
      ])),
    );
  },
};

function subdomainsCard(d, enc) {
  let names = [];
  const actions = copyBtn(() => names.join('\n'), 'copy');
  return asyncCard('subdomains (certificate transparency)', async () => {
    const r = await getJSON(`https://crt.sh/?q=%25.${enc}&output=json`, { timeout: 45000 });
    if (!r.ok || !Array.isArray(r.data)) throw new Error(r.status === 404 ? 'no certificates found' : `crt.sh HTTP ${r.status} (it is often overloaded — retry in a bit)`);
    const set = new Set();
    for (const row of r.data) {
      for (const n of String(row.name_value).toLowerCase().split('\n')) {
        const clean = n.trim().replace(/^\*\./, '');
        if (clean === d || clean.endsWith('.' + d)) set.add(clean);
      }
    }
    names = [...set].sort((a, b) => a.split('.').reverse().join('.').localeCompare(b.split('.').reverse().join('.')));
    if (!names.length) return muted('no certificates found.');
    const list = h('div', { class: 'sublist' });
    const render = filter => {
      const shown = names.filter(n => n.includes(filter)).slice(0, 600);
      list.replaceChildren(...shown.map(n => pivot('domain', n)));
    };
    render('');
    const filter = h('input', { class: 'filter', placeholder: `filter ${names.length} names…`, oninput: e => render(e.target.value.trim().toLowerCase()) });
    return [h('div', { class: 'row' }, filter, actions), list,
      names.length > 600 ? muted('showing the first 600 matches — use the filter or copy for the full list.') : null];
  }, { wide: true });
}
