// Structured OSINT collection: given an entity, return facts, neighbour entities to
// pivot to, and cited evidence. Used by the autonomous engine and the AI chat so both
// work from the same evidence model. Everything comes from public sources.

import { getJSON, dns, reverseName, isIP, normDomain, registrable, rdapEntity, rdapEvent, vcard } from './util.js';

const ev = (claim, source, url) => ({ claim, source, url, at: Date.now() });
const uniq = arr => [...new Set(arr)];

async function collectDomain(d) {
  const facts = [], neighbors = [], evidence = [];
  const [a, aaaa, mx, ns, txt] = await Promise.all([
    dns(d, 'A').catch(() => []), dns(d, 'AAAA').catch(() => []), dns(d, 'MX').catch(() => []),
    dns(d, 'NS').catch(() => []), dns(d, 'TXT').catch(() => []),
  ]);
  for (const r of a) { facts.push(['A', r.data]); neighbors.push({ tool: 'ip', value: r.data, rel: 'resolves to' }); }
  for (const r of aaaa) { facts.push(['AAAA', r.data]); neighbors.push({ tool: 'ip', value: r.data, rel: 'resolves to' }); }
  if (a.length || aaaa.length) evidence.push(ev(`${d} resolves to ${uniq([...a, ...aaaa].map(r => r.data)).join(', ')}`, 'DNS', `https://dns.google/resolve?name=${d}&type=A`));
  for (const r of mx) { const host = r.data.replace(/^\d+\s+/, ''); facts.push(['MX', r.data]); neighbors.push({ tool: 'domain', value: host, rel: 'mail server' }); }
  for (const r of ns) { facts.push(['NS', r.data]); neighbors.push({ tool: 'domain', value: r.data, rel: 'nameserver' }); }
  const spf = txt.find(r => /^v=spf1/i.test(r.data));
  if (spf) facts.push(['SPF', spf.data]);

  const r = await getJSON(`https://rdap.org/domain/${encodeURIComponent(d)}`).catch(() => null);
  if (r?.ok && r.data) {
    const reg = vcard(rdapEntity(r.data.entities, 'registrar'));
    const created = rdapEvent(r.data, 'registration');
    if (reg.fn) { facts.push(['registrar', reg.fn]); evidence.push(ev(`${d} is registered through ${reg.fn}`, 'RDAP', `https://rdap.org/domain/${d}`)); }
    if (created) { facts.push(['registered', created.slice(0, 10)]); evidence.push(ev(`${d} was registered on ${created.slice(0, 10)}`, 'RDAP', `https://rdap.org/domain/${d}`)); }
  }
  const summary = `${d}: ${a.length + aaaa.length} address(es), ${mx.length} mail server(s), ${ns.length} nameserver(s)`;
  return { ok: true, summary, facts, neighbors, evidence };
}

async function collectIP(ip) {
  const facts = [], neighbors = [], evidence = [];
  const g = await getJSON(`https://ipwho.is/${encodeURIComponent(ip)}`).catch(() => null);
  if (g?.data?.success) {
    const d = g.data, loc = [d.city, d.country].filter(Boolean).join(', ');
    facts.push(['location', loc], ['org', d.connection?.org || d.connection?.isp]);
    if (d.connection?.asn) { facts.push(['ASN', `AS${d.connection.asn}`]); neighbors.push({ tool: 'asn', value: `AS${d.connection.asn}`, rel: 'announced by' }); }
    if (d.connection?.domain) neighbors.push({ tool: 'domain', value: d.connection.domain, rel: 'operator domain' });
    evidence.push(ev(`${ip} geolocates to ${loc} (${d.connection?.org || 'unknown org'})`, 'ipwho.is', `https://ipwho.is/${ip}`));
  }
  const ptr = await dns(reverseName(ip), 'PTR').catch(() => []);
  for (const r of ptr) { facts.push(['PTR', r.data]); neighbors.push({ tool: 'domain', value: r.data, rel: 'reverse DNS' }); }

  const idb = await getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`).catch(() => null);
  if (idb?.ok && idb.data?.ports) {
    if (idb.data.ports.length) { facts.push(['open ports', idb.data.ports.join(', ')]); evidence.push(ev(`${ip} has ${idb.data.ports.length} port(s) seen open by Shodan: ${idb.data.ports.join(', ')}`, 'Shodan InternetDB', `https://internetdb.shodan.io/${ip}`)); }
    for (const v of (idb.data.vulns || []).slice(0, 20)) neighbors.push({ tool: 'cve', value: v, rel: 'potentially vulnerable to' });
    for (const hn of (idb.data.hostnames || [])) neighbors.push({ tool: 'domain', value: hn, rel: 'hostname' });
    if (idb.data.vulns?.length) facts.push(['known CVEs', idb.data.vulns.slice(0, 10).join(', ')]);
  }
  return { ok: true, summary: `${ip}: ${facts.find(f => f[0] === 'location')?.[1] || 'location unknown'}`, facts, neighbors, evidence };
}

async function collectASN(input) {
  const n = String(input).replace(/^as/i, '');
  const r = await getJSON(`https://api.bgpview.io/asn/${n}`).catch(() => null);
  const facts = [], neighbors = [], evidence = [];
  const d = r?.data?.data;
  if (d) {
    facts.push(['name', d.name], ['description', d.description_short], ['country', d.country_code]);
    evidence.push(ev(`AS${n} is ${d.name} (${d.description_short || ''}), ${d.country_code || ''}`, 'BGPView', `https://bgpview.io/asn/${n}`));
    if (d.website) { const dom = normDomain(d.website); if (dom) neighbors.push({ tool: 'domain', value: dom, rel: 'operator website' }); }
  }
  const pre = await getJSON(`https://api.bgpview.io/asn/${n}/prefixes`).catch(() => null);
  const v4 = pre?.data?.data?.ipv4_prefixes || [];
  if (v4.length) facts.push(['IPv4 prefixes', `${v4.length} announced`]);
  return { ok: !!d, summary: d ? `AS${n}: ${d.name}` : `AS${n}: not found`, facts, neighbors, evidence };
}

async function collectURL(u) {
  try {
    const url = new URL(/^https?:\/\//i.test(u) ? u : 'http://' + u);
    const host = url.hostname;
    const neighbors = [{ tool: isIP(host) ? 'ip' : 'domain', value: host, rel: 'host of URL' }];
    return { ok: true, summary: `URL on ${host}`, facts: [['host', host], ['path', url.pathname]], neighbors, evidence: [] };
  } catch { return { ok: false, summary: 'invalid URL', facts: [], neighbors: [], evidence: [] }; }
}

async function collectEmail(e) {
  const domain = e.split('@')[1];
  if (!domain) return { ok: false, summary: 'invalid email', facts: [], neighbors: [], evidence: [] };
  const mx = await dns(domain, 'MX').catch(() => []);
  return {
    ok: true, summary: `email on ${domain}`,
    facts: [['domain', domain], ['accepts mail', mx.length ? 'yes' : 'no MX']],
    neighbors: [{ tool: 'domain', value: domain, rel: 'email domain' }],
    evidence: [],
  };
}

const COLLECTORS = { domain: collectDomain, ip: collectIP, asn: collectASN, url: collectURL, email: collectEmail };
export const canCollect = tool => tool in COLLECTORS;

export async function collect(tool, value) {
  const fn = COLLECTORS[tool];
  if (!fn) return { ok: false, summary: `${tool} not auto-collectable`, facts: [], neighbors: [], evidence: [] };
  try { return await fn(value); }
  catch (e) { return { ok: false, summary: `failed: ${e.message}`, facts: [], neighbors: [], evidence: [] }; }
}

// Canonicalise a value so the same entity is not visited twice.
export function canon(tool, value) {
  let v = String(value).trim().toLowerCase().replace(/\.$/, '');
  if (tool === 'domain') v = v.replace(/^\*\./, '');
  if (tool === 'asn') v = 'as' + v.replace(/^as/i, '');
  return `${tool}:${v}`;
}

export const registrableOf = host => (isIP(host) ? host : registrable(host));
