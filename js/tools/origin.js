import { h, card, grid, muted, badge, ext, pivot, copyBtn, getJSON, dns, normDomain } from '../util.js';
import * as be from '../backend.js';

// Published Cloudflare IPv4 ranges — IPs inside these are the CDN edge, not the origin.
const CF_RANGES = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
  '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
  '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'];
const CDN_HINT = /cloudflare|fastly|akamai|incapsula|imperva|sucuri|cloudfront|edgecast|stackpath|bunnycdn|keycdn|cdn77|limelight|azureedge|googleusercontent/i;

// Subdomains that commonly point straight at the origin, bypassing the CDN.
const ORIGIN_SUBS = ['origin', 'origin-www', 'www-origin', 'direct', 'direct-connect', 'cpanel', 'whm', 'webmail',
  'mail', 'email', 'smtp', 'imap', 'pop', 'ftp', 'sftp', 'ssh', 'dev', 'development', 'staging', 'stage', 'test',
  'uat', 'vpn', 'remote', 'server', 'srv', 'host', 'backend', 'api', 'admin', 'portal', 'ns1', 'ns2', 'gw', 'mx',
  'mx1', 'old', 'legacy', 'corp', 'internal', 'dashboard', 'db', 'app'];

const toInt = ip => ip.split('.').reduce((n, o) => ((n * 256) + Number(o)) >>> 0, 0);
function inCidr(ip, cidr) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
  const [b, p] = cidr.split('/'); const m = p === '0' ? 0 : (0xffffffff << (32 - +p)) >>> 0;
  return ((toInt(ip) & m) >>> 0) === ((toInt(b) & m) >>> 0);
}
const isCF = ip => CF_RANGES.some(c => inCidr(ip, c));

async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, async () => {
    while (i < items.length) { const idx = i++; const r = await fn(items[idx]).catch(() => null); onEach(items[idx], r); }
  }));
}

export default {
  id: 'origin',
  label: 'origin',
  placeholder: 'domain behind a CDN (e.g. example.com)',
  intro: 'Tries to find the real origin server IP hiding behind a CDN/WAF (Cloudflare, Fastly…) — from certificate-transparency subdomains, origin-style hostnames, MX and SPF leakage. Classic CDN-bypass recon on targets you\'re authorized to test.',
  examples: ['example.com'],

  run(raw) {
    const d = normDomain(raw) || raw.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!d || !/\./.test(d)) throw new Error('enter a domain like example.com');
    const hasBackend = be.backendConfigured() && be.isApproved();

    const summary = h('span', { class: 'muted small' }, 'resolving front…');
    const verdict = h('div', { class: 'risklist' });
    const tbody = h('tbody');
    const candidates = new Map();            // ip -> {ip, sources:Set, ports, hostnames, vulns}
    const addCand = (ip, source) => { if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || isCF(ip)) return false; const c = candidates.get(ip) || { ip, sources: new Set() }; c.sources.add(source); candidates.set(ip, c); return true; };
    const exportCSV = () => ['ip,sources,ports,hostnames', ...[...candidates.values()].map(c => [c.ip, [...c.sources].join('; '), (c.ports || []).join('|'), (c.hostnames || []).join('|')].map(x => `"${x}"`).join(','))].join('\n');

    (async () => {
      // 1) what's the front? resolve apex + detect CDN
      const frontA = (await dns(d, 'A').catch(() => [])).map(r => r.data);
      let cdn = frontA.some(isCF) ? 'Cloudflare' : null;
      if (hasBackend) {
        const r = await be.fetchUrl(`https://${d}`).catch(() => null);
        const hdr = Object.entries(r?.data?.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
        if (!cdn) { const m = hdr.match(CDN_HINT); if (m) cdn = m[0]; }
        if (/cf-ray/i.test(hdr)) cdn = 'Cloudflare';
      }
      verdict.append(h('div', { class: 'riskrow' }, badge(cdn ? 'CDN' : 'direct', cdn ? 'warn' : 'ok'),
        h('span', {}, cdn ? `${d} fronts through ${cdn} (edge IPs: ${frontA.join(', ') || '—'}). Hunting the origin…` : `${d} resolves directly to ${frontA.join(', ') || '—'} — no CDN detected; that is likely the origin.`)));
      if (!cdn) frontA.forEach(ip => addCand(ip, 'direct A record'));

      // 2) gather leads
      summary.textContent = 'enumerating subdomains + origin hostnames…';
      const names = new Map();                 // host -> source
      // crt.sh subdomains
      try {
        const r = await getJSON(`https://crt.sh/?q=%25.${encodeURIComponent(d)}&output=json`, { timeout: 45000 });
        if (r.ok && Array.isArray(r.data)) for (const row of r.data) String(row.name_value || '').split('\n').forEach(n => {
          n = n.trim().toLowerCase().replace(/^\*\./, ''); if ((n.endsWith('.' + d) || n === d) && !names.has(n)) names.set(n, 'CT subdomain ' + n);
        });
      } catch { /* continue */ }
      for (const s of ORIGIN_SUBS) names.set(`${s}.${d}`, `origin-style host ${s}.${d}`);
      // SPF ip4: ranges + MX
      const txt = await dns(d, 'TXT').catch(() => []);
      const spf = txt.map(r => r.data).find(v => /^v=spf1/i.test(v));
      if (spf) for (const m of spf.matchAll(/ip4:(\d+\.\d+\.\d+\.\d+)/g)) addCand(m[1], 'SPF ip4 leak');
      const mx = await dns(d, 'MX').catch(() => []);
      for (const r of mx) names.set(r.data.replace(/^\d+\s+/, '').replace(/\.$/, ''), 'MX host');

      // 3) resolve everything, keep non-CDN IPs
      const hosts = [...names.keys()].slice(0, 160);
      summary.textContent = `resolving ${hosts.length} leads…`;
      let done = 0;
      await pool(hosts, 24, h2 => dns(h2, 'A').catch(() => []), (host, recs) => {
        done++;
        for (const r of (recs || [])) addCand(r.data, names.get(host));
        if (done % 12 === 0 || done === hosts.length) summary.textContent = `resolving ${done}/${hosts.length} · ${candidates.size} candidate origin IP(s)`;
      });

      if (!candidates.size) { summary.textContent = `done — no non-CDN origin candidates found for ${d}.`; verdict.append(h('div', { class: 'riskrow' }, badge('note', 'ok'), h('span', {}, 'Every lead resolves back into the CDN — origin is well hidden.'))); return; }

      // 4) enrich candidates with Shodan exposure + confidence
      summary.textContent = `checking ${candidates.size} candidate origins…`;
      await pool([...candidates.keys()], 12, ip => getJSON(`https://internetdb.shodan.io/${ip}`, { timeout: 12000 }).then(r => (r.ok && r.status !== 404 ? r.data : null)), (ip, data) => {
        const c = candidates.get(ip);
        if (data) { c.ports = data.ports || []; c.hostnames = data.hostnames || []; c.vulns = data.vulns || []; }
      });

      const rank = c => {
        let s = 0;
        if ([...c.sources].some(x => /SPF|MX/.test(x))) s += 2;
        if ((c.hostnames || []).some(hn => hn.includes(d.split('.').slice(-2).join('.')))) s += 3;
        if ((c.ports || []).includes(443) || (c.ports || []).includes(80)) s += 2;
        if ([...c.sources].some(x => /direct A/.test(x))) s += 4;
        return s;
      };
      const ranked = [...candidates.values()].sort((a, b) => rank(b) - rank(a));
      for (const c of ranked) {
        const conf = rank(c) >= 5 ? ['high', 'bad'] : rank(c) >= 2 ? ['medium', 'warn'] : ['low', 'muted'];
        tbody.append(h('tr', {},
          h('td', {}, pivot('ip', c.ip, c.ip), ' ', pivot('map', c.ip, 'map')),
          h('td', {}, badge(conf[0], conf[1])),
          h('td', { class: 'small' }, (c.ports || []).length ? (c.ports || []).slice(0, 8).join(', ') : muted('—')),
          h('td', { class: 'small muted' }, [...c.sources].slice(0, 2).join('; ')),
          h('td', { class: 'small muted' }, (c.hostnames || []).slice(0, 2).join(', '))));
      }
      const best = ranked.filter(c => rank(c) >= 5);
      if (best.length) verdict.append(h('div', { class: 'riskrow' }, badge('high', 'bad'),
        h('span', {}, `likely origin${best.length > 1 ? 's' : ''}: `, ...best.slice(0, 3).flatMap((c, i) => [i ? ', ' : '', pivot('ip', c.ip, c.ip)]), ` — try requesting the site directly with Host: ${d} to confirm the CDN bypass.`)));

      summary.textContent = `done — ${candidates.size} candidate origin IP(s), ${best.length} high-confidence`;
    })();

    return grid(
      card('origin finder', { wide: true, actions: h('div', { class: 'actions' }, summary, copyBtn(exportCSV, 'csv')) },
        muted(`Looks for the real server behind ${d}'s CDN using only public data (CT logs, DNS, SPF, MX, Shodan). A CDN only protects hostnames that point at it — a single subdomain resolving to the origin defeats it. Authorized targets only.`),
        verdict),
      card('candidate origins', { wide: true }, h('table', { class: 'datatable' },
        h('thead', {}, h('tr', {}, ['IP', 'confidence', 'open ports', 'found via', 'reverse DNS'].map(c => h('th', {}, c)))), tbody)),
    );
  },
};
