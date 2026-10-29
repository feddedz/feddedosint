import { h, card, grid, muted, badge, ext, pivot, copyBtn, getJSON, isIP } from '../util.js';

// Bulk exposure sweep over an ASN or CIDR. Expands the block to host IPs, queries Shodan's free
// InternetDB per host (browser-accessible, no key), and aggregates open ports, known CVEs and
// sensitive services — the kind of fleet-wide view you want over your own address space.
// Public data, client-side. Capped so a browser run stays reasonable.

const SENSITIVE = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 135: 'MSRPC', 139: 'NetBIOS', 445: 'SMB', 1433: 'MSSQL',
  1521: 'Oracle', 2049: 'NFS', 2375: 'Docker', 2376: 'Docker', 3306: 'MySQL', 3389: 'RDP',
  5432: 'Postgres', 5601: 'Kibana', 5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis', 6443: 'Kubernetes API',
  9200: 'Elasticsearch', 9300: 'Elasticsearch', 10250: 'Kubelet', 11211: 'Memcached', 15672: 'RabbitMQ',
  27017: 'MongoDB', 27018: 'MongoDB',
};

const toInt = ip => ip.split('.').reduce((n, o) => (n * 256 + Number(o)) >>> 0, 0) >>> 0;
const fromInt = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');

// Expand an IPv4 CIDR to a capped list of host addresses.
function cidrHosts(cidr, cap) {
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  if (!isIP(base) || base.includes(':') || !(bits >= 0 && bits <= 32)) throw new Error('enter an IPv4 CIDR like 192.0.2.0/24');
  const size = bits >= 31 ? (1 << (32 - bits)) : (1 << (32 - bits));
  const net = toInt(base) & (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
  const first = bits <= 30 ? net + 1 : net;            // skip network address for /0../30
  const last = bits <= 30 ? net + size - 2 : net + size - 1; // skip broadcast
  const hosts = [];
  for (let n = first >>> 0; n <= (last >>> 0) && hosts.length < cap; n++) hosts.push(fromInt(n >>> 0));
  return { hosts, total: Math.max(0, last - first + 1) };
}

async function asnPrefixes(asn) {
  const n = String(asn).replace(/^as/i, '');
  const r = await getJSON(`https://api.bgpview.io/asn/${n}/prefixes`, { timeout: 20000 }).catch(() => null);
  const v4 = r?.data?.data?.ipv4_prefixes || [];
  return v4.map(p => p.prefix).filter(Boolean);
}

async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  const run = async () => { while (i < items.length) { const idx = i++; const r = await fn(items[idx]).catch(() => null); onEach?.(items[idx], r); } };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, run));
}

async function probe(ip) {
  const r = await getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { timeout: 9000 }).catch(() => null);
  if (!r?.ok || !r.data) return null;
  const d = r.data;
  if (!(d.ports?.length || d.vulns?.length || d.hostnames?.length)) return null;
  return { ip, ports: (d.ports || []).sort((a, b) => a - b), vulns: d.vulns || [], hostnames: d.hostnames || [] };
}

export default {
  id: 'sweep',
  label: 'sweep',
  placeholder: 'AS13335  or  192.0.2.0/24  (bulk exposure sweep)',
  intro: 'Fleet-wide exposure: expands an ASN or CIDR to hosts and pulls open ports & CVEs per IP from Shodan InternetDB. For address space you own or are authorized to assess.',
  examples: ['192.0.2.0/24', 'AS13335'],

  async run(raw) {
    const input = raw.trim();
    if (!input) throw new Error('enter an ASN (AS13335) or an IPv4 CIDR (192.0.2.0/24)');

    const CAP = 512; // host cap for a browser run
    let hosts = [], total = 0, scopeLabel = '';

    if (/^as?\d+$/i.test(input) || /^\d{1,7}$/.test(input)) {
      const prefixes = await asnPrefixes(input);
      if (!prefixes.length) throw new Error('no IPv4 prefixes found for that ASN (or BGPView is busy)');
      scopeLabel = `AS${input.replace(/^as/i, '')} — ${prefixes.length} IPv4 prefix(es)`;
      for (const pfx of prefixes) {
        if (hosts.length >= CAP) break;
        try { const { hosts: hs, total: t } = cidrHosts(pfx, CAP - hosts.length); hosts.push(...hs); total += t; } catch {}
      }
    } else if (input.includes('/')) {
      const { hosts: hs, total: t } = cidrHosts(input, CAP);
      hosts = hs; total = t; scopeLabel = `${input} — ${t.toLocaleString('en-US')} host address(es)`;
    } else if (isIP(input)) {
      hosts = [input]; total = 1; scopeLabel = input;
    } else {
      throw new Error('enter an ASN (AS13335) or an IPv4 CIDR (192.0.2.0/24)');
    }

    const live = [];
    await pool(hosts, 12, probe, (_, r) => r && live.push(r));
    live.sort((a, b) => toInt(a.ip) - toInt(b.ip));

    // Aggregate.
    const portHist = {};
    const cveSet = new Set();
    const findings = []; // {ip, port, service} sensitive exposures
    for (const hostRec of live) {
      for (const p of hostRec.ports) { portHist[p] = (portHist[p] || 0) + 1; if (SENSITIVE[p]) findings.push({ ip: hostRec.ip, port: p, service: SENSITIVE[p] }); }
      for (const v of hostRec.vulns) cveSet.add(v);
    }
    const topPorts = Object.entries(portHist).sort((a, b) => b[1] - a[1]).slice(0, 24);

    const sc = (n, l, warn) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' + (warn && n ? ' warn' : '') }, typeof n === 'number' ? n.toLocaleString('en-US') : n), h('div', { class: 'statlbl muted small' }, l));
    const summary = card('sweep', { wide: true, actions: badge(`${live.length} live / ${hosts.length} scanned`, live.length ? 'ok' : 'muted') },
      muted(`${scopeLabel}. Scanned ${hosts.length.toLocaleString('en-US')}${total > hosts.length ? ` of ${total.toLocaleString('en-US')} (capped at ${CAP})` : ''} host(s) against Shodan InternetDB.`),
      h('div', { class: 'statrow' },
        sc(live.length, 'hosts with exposure'),
        sc(Object.keys(portHist).length, 'distinct ports'),
        sc(findings.length, 'sensitive services', true),
        sc(cveSet.size, 'known CVEs', true),
        sc(hosts.length, 'scanned')),
      h('p', { class: 'row wrap', style: 'gap:6px;margin-top:8px' },
        live.length ? copyBtn(() => live.map(x => x.ip).join('\n'), 'copy live IPs') : null,
        live.length ? pivot('map', live.slice(0, 50).map(x => x.ip).join(', '), 'plot on map') : null));

    const findCard = findings.length ? card(`sensitive services (${findings.length})`, { wide: true },
      muted('Management and data-store ports exposed to the internet — review each on assets you own.'),
      h('table', { class: 'records' }, h('tbody', {}, findings.sort((a, b) => toInt(a.ip) - toInt(b.ip)).slice(0, 300).map(f =>
        h('tr', {},
          h('td', {}, badge(f.service, 'bad')),
          h('td', {}, pivot('ip', f.ip, f.ip)),
          h('td', { class: 'muted small' }, `port ${f.port}`)))))) : null;

    const cveCard = cveSet.size ? card(`known CVEs (${cveSet.size})`, { wide: true, collapsed: cveSet.size > 30 },
      muted('CVEs Shodan associates with software seen on these hosts.'),
      h('div', { class: 'chips' }, [...cveSet].sort().slice(0, 200).map(v => h('span', { class: 'chip' }, pivot('cve', v, v))))) : null;

    const portsCard = topPorts.length ? card('open-port distribution', {},
      muted('Most common open ports across the live hosts.'),
      h('table', { class: 'records' }, h('tbody', {}, topPorts.map(([p, n]) =>
        h('tr', {},
          h('td', {}, SENSITIVE[p] ? badge(SENSITIVE[p], 'warn') : badge('port', 'muted')),
          h('td', {}, String(p)),
          h('td', { class: 'muted small' }, `${n} host${n === 1 ? '' : 's'}`)))))) : null;

    const hostCard = live.length ? card(`live hosts (${live.length})`, { wide: true, collapsed: live.length > 40 },
      h('table', { class: 'records' }, h('tbody', {}, live.slice(0, 500).map(hostRec =>
        h('tr', {},
          h('td', {}, pivot('ip', hostRec.ip, hostRec.ip)),
          h('td', { class: 'small' }, hostRec.ports.map(p => SENSITIVE[p] ? h('span', {}, badge(String(p), 'warn'), ' ') : h('span', { class: 'muted' }, p + ' ')).flat()),
          h('td', { class: 'muted small' }, hostRec.vulns.length ? `${hostRec.vulns.length} CVE(s)` : '', hostRec.hostnames[0] ? ` ${hostRec.hostnames[0]}` : ''))))) ) : null;

    if (!live.length) return grid(summary, card('nothing exposed', { wide: true }, muted('No hosts in this block returned open ports, CVEs or hostnames from InternetDB. That often means a clean or well-firewalled block — or the range is unrouted.')));
    return grid(summary, findCard, cveCard, portsCard, hostCard);
  },
};
