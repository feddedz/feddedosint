import { h, card, grid, muted, badge, ext, pivot, dns, getJSON, isIP, normDomain } from '../util.js';
import { watches, addWatch, removeWatch, isWatched, saveSnapshot } from '../store.js';

// Change monitoring for infrastructure you own or are authorized to watch. Takes a snapshot of a
// domain or IP — certificate-transparency subdomains, DNS records, open ports and known CVEs —
// and on the next check diffs it against the last one, so new exposure surfaces as an alert.
// All public-source, client-side; snapshots live in this browser only.

const rerender = () => window.dispatchEvent(new HashChangeEvent('hashchange'));

async function snapshotDomain(d) {
  const [a, aaaa, mx, ns, txt] = await Promise.all([
    dns(d, 'A').catch(() => []), dns(d, 'AAAA').catch(() => []), dns(d, 'MX').catch(() => []),
    dns(d, 'NS').catch(() => []), dns(d, 'TXT').catch(() => []),
  ]);
  const ips = [...a, ...aaaa].map(r => r.data);
  // Certificate-transparency subdomains (crt.sh).
  let subs = [];
  const ct = await getJSON(`https://crt.sh/?q=${encodeURIComponent('%.' + d)}&output=json`, { timeout: 25000 }).catch(() => null);
  if (ct?.ok && Array.isArray(ct.data)) {
    const set = new Set();
    for (const row of ct.data) String(row.name_value || '').split('\n').forEach(n => {
      n = n.trim().toLowerCase().replace(/^\*\./, '');
      if (n.endsWith(d)) set.add(n);
    });
    subs = [...set].sort();
  }
  // Exposure per resolved IP.
  const ports = {}, vulns = {};
  await Promise.all(ips.map(async ip => {
    const r = await getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`).catch(() => null);
    if (r?.ok && r.data) { ports[ip] = (r.data.ports || []).sort((x, y) => x - y); vulns[ip] = (r.data.vulns || []).sort(); }
  }));
  return {
    at: Date.now(),
    a: a.map(r => r.data).sort(), aaaa: aaaa.map(r => r.data).sort(),
    mx: mx.map(r => r.data).sort(), ns: ns.map(r => r.data).sort(),
    spf: (txt.find(r => /^v=spf1/i.test(r.data))?.data) || '',
    subs, ports, vulns,
  };
}

async function snapshotIP(ip) {
  const ptr = await dns(ip.includes(':') ? ip : ip.split('.').reverse().join('.') + '.in-addr.arpa', 'PTR').catch(() => []);
  const r = await getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`).catch(() => null);
  const d = r?.ok ? r.data : {};
  return {
    at: Date.now(),
    ptr: ptr.map(x => x.data).sort(),
    ports: { [ip]: (d.ports || []).sort((x, y) => x - y) },
    vulns: { [ip]: (d.vulns || []).sort() },
    hostnames: (d.hostnames || []).sort(),
    cpes: (d.cpes || []).sort(),
  };
}

const snapshot = (tool, value) => (tool === 'ip' ? snapshotIP(value) : snapshotDomain(value));

// Flatten a snapshot into a set of comparable "key: item" lines, so diffing is a set difference.
function flatten(snap) {
  const out = [];
  const add = (label, arr) => (arr || []).forEach(v => out.push(`${label}: ${v}`));
  add('A', snap.a); add('AAAA', snap.aaaa); add('MX', snap.mx); add('NS', snap.ns);
  add('PTR', snap.ptr); add('hostname', snap.hostnames); add('subdomain', snap.subs);
  if (snap.spf) out.push(`SPF: ${snap.spf}`);
  for (const [ip, ps] of Object.entries(snap.ports || {})) (ps || []).forEach(p => out.push(`port ${ip}:${p}`));
  for (const [ip, vs] of Object.entries(snap.vulns || {})) (vs || []).forEach(v => out.push(`CVE ${ip}: ${v}`));
  return new Set(out);
}

function diff(prev, next) {
  const a = flatten(prev), b = flatten(next);
  const added = [...b].filter(x => !a.has(x));
  const removed = [...a].filter(x => !b.has(x));
  return { added, removed };
}

// Severity for an alert line, so new ports/CVEs rise to the top.
const sev = line => /^CVE/.test(line) ? 3 : /^port/.test(line) ? 2 : /^subdomain|^hostname|^A:|^AAAA:/.test(line) ? 1 : 0;

function alertRows(lines, kind) {
  return lines.sort((x, y) => sev(y) - sev(x)).map(line => {
    // Make the entity pivotable where we can.
    const m = line.match(/^(?:CVE [^:]+: )(CVE-\d{4}-\d+)$/i) || line.match(/^subdomain: (.+)$/) || line.match(/^(?:A|AAAA|PTR): (.+)$/) || line.match(/^hostname: (.+)$/);
    let entity = null;
    if (/^CVE/.test(line) && m) entity = pivot('cve', m[1], m[1]);
    else if (/^subdomain|^hostname/.test(line) && m) entity = pivot('recon', m[1], m[1]);
    else if (/^(A|AAAA|PTR)/.test(line) && m) entity = pivot('ip', m[1], m[1]);
    return h('tr', {},
      h('td', {}, badge(kind, kind === 'new' ? (sev(line) >= 2 ? 'bad' : 'warn') : 'muted')),
      h('td', { class: 'small', style: 'word-break:break-all' }, entity || line.replace(/^[^:]+: /, '')),
      h('td', { class: 'muted small' }, line.split(':')[0]));
  });
}

function snapshotSummary(snap, tool) {
  const rows = [];
  if (tool === 'ip') {
    const ip = Object.keys(snap.ports || {})[0];
    rows.push(['open ports', (snap.ports?.[ip] || []).join(', ') || 'none seen']);
    if (snap.vulns?.[ip]?.length) rows.push(['known CVEs', snap.vulns[ip].length]);
    if (snap.hostnames?.length) rows.push(['hostnames', snap.hostnames.length]);
    if (snap.ptr?.length) rows.push(['PTR', snap.ptr.join(', ')]);
  } else {
    rows.push(['subdomains (CT)', snap.subs?.length || 0]);
    rows.push(['A/AAAA', [...(snap.a || []), ...(snap.aaaa || [])].join(', ') || 'none']);
    if (snap.mx?.length) rows.push(['mail servers', snap.mx.length]);
    const totalPorts = Object.values(snap.ports || {}).reduce((n, p) => n + p.length, 0);
    const totalV = Object.values(snap.vulns || {}).reduce((n, v) => n + v.length, 0);
    rows.push(['open ports (all IPs)', totalPorts]);
    if (totalV) rows.push(['known CVEs', totalV]);
  }
  return h('table', { class: 'records' }, h('tbody', {}, rows.map(([k, v]) =>
    h('tr', {}, h('td', { class: 'muted small' }, k), h('td', {}, String(v))))));
}

function watchlistCard() {
  const list = watches();
  if (!list.length) {
    return card('watchlist', { wide: true },
      muted('Nothing watched yet. Run a domain or IP above, then “watch” it — each re-check diffs against the last snapshot and flags new subdomains, ports and CVEs.'));
  }
  const rows = list.map(w => {
    const open = h('a', { class: 'mini', href: `#monitor/${encodeURIComponent(w.value)}` }, 'check now');
    const rm = h('button', { class: 'mini ghost', type: 'button' }, 'remove');
    rm.onclick = () => { removeWatch(w.id); rerender(); };
    return h('tr', {},
      h('td', {}, h('strong', {}, w.value), ' ', badge(w.tool, 'muted')),
      h('td', { class: 'muted small' }, w.checked ? 'last checked ' + new Date(w.checked).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'never checked'),
      h('td', {}, h('div', { class: 'row', style: 'gap:6px;justify-content:flex-end' }, open, rm)));
  });
  return card(`watchlist (${list.length})`, { wide: true },
    muted('Targets you are monitoring. Open each to take a fresh snapshot and see what changed.'),
    h('table', { class: 'records' }, h('tbody', {}, rows)));
}

export default {
  id: 'monitor',
  label: 'monitor',
  placeholder: 'example.com or 1.2.3.4  (domain/IP to snapshot & watch)',
  intro: 'Snapshot a domain or IP’s public footprint — CT subdomains, DNS, open ports and CVEs — and get change alerts on every re-check. For assets you own or are authorized to monitor.',
  examples: ['example.com', '1.1.1.1'],
  allowEmpty: true,

  async run(raw) {
    if (!raw || !raw.trim()) return grid(watchlistCard());

    const input = raw.trim();
    const tool = isIP(input) ? 'ip' : 'domain';
    const value = tool === 'ip' ? input : (normDomain(input) || input);
    const id = `${tool}:${value}`;
    const prior = watches().find(w => w.id === id)?.snapshot || null;

    const next = await snapshot(tool, value);
    if (prior) saveSnapshot(id, next);

    // Watch / unwatch control.
    const watched = isWatched(tool, value);
    const watchBtn = h('button', { class: watched ? 'mini ghost' : 'mini', type: 'button' }, watched ? 'watching ✓ — unwatch' : 'watch this');
    watchBtn.onclick = () => {
      if (isWatched(tool, value)) removeWatch(id);
      else { addWatch(tool, value); saveSnapshot(id, next); }
      rerender();
    };

    const head = card('snapshot', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, badge(tool, 'muted'), watchBtn) },
      muted(`Public footprint of ${value} as of ${new Date(next.at).toISOString().slice(0, 16).replace('T', ' ')} UTC. ${watched ? 'This target is on your watchlist.' : 'Watch it to track changes over time.'}`),
      snapshotSummary(next, tool));

    let changeCard;
    if (!prior) {
      changeCard = card('baseline', { wide: true },
        muted(watched
          ? 'First snapshot saved as the baseline. Re-check later and anything new — a fresh subdomain, a newly open port, a new CVE — shows up here as an alert.'
          : 'This is a first look. Add it to your watchlist to save a baseline, then future checks will diff against it.'));
    } else {
      const { added, removed } = diff(prior, next);
      if (!added.length && !removed.length) {
        changeCard = card('changes', { wide: true, actions: badge('no change', 'ok') },
          muted('Nothing changed since the last snapshot.'));
      } else {
        changeCard = card('changes since last check', { wide: true, actions: badge(`${added.length} new · ${removed.length} gone`, added.length ? 'bad' : 'warn') },
          added.length ? muted(`${added.length} new item(s) — new exposure to review.`) : null,
          h('table', { class: 'records' }, h('tbody', {}, [...alertRows(added, 'new'), ...alertRows(removed, 'gone')])));
      }
    }

    const pivots = card('dig deeper', {},
      h('div', { class: 'row wrap', style: 'gap:6px' },
        pivot('recon', value, 'full recon'),
        pivot(tool, value, `${tool} detail`),
        pivot('engine', value, 'autonomous engine')));

    return grid(head, changeCard, pivots, watchlistCard());
  },
};
