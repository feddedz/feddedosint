import { h, card, kv, grid, badge, copyBtn, pivot, linkGroups, isIPv4, expandIPv6, fmtNum } from '../util.js';

// ---------- IPv4 ----------
const toInt = ip => ip.split('.').reduce((n, o) => (n * 256) + Number(o), 0);
const toIP = n => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
const maskOf = p => (p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0);
const bin = n => n.toString(2).padStart(32, '0').match(/.{8}/g).join('.');

const RANGES4 = [
  ['10.0.0.0/8', 'private (RFC 1918)'], ['172.16.0.0/12', 'private (RFC 1918)'], ['192.168.0.0/16', 'private (RFC 1918)'],
  ['100.64.0.0/10', 'carrier-grade NAT'], ['127.0.0.0/8', 'loopback'], ['169.254.0.0/16', 'link-local'],
  ['192.0.2.0/24', 'documentation (TEST-NET-1)'], ['198.51.100.0/24', 'documentation (TEST-NET-2)'], ['203.0.113.0/24', 'documentation (TEST-NET-3)'],
  ['224.0.0.0/4', 'multicast'], ['240.0.0.0/4', 'reserved'], ['0.0.0.0/8', 'this network'],
];
const within4 = (n, cidr) => { const [b, p] = cidr.split('/'); const m = maskOf(+p); return ((n & m) >>> 0) === ((toInt(b) & m) >>> 0); };

function v4(ip, p) {
  const n = toInt(ip), mask = maskOf(p);
  const net = (n & mask) >>> 0, bcast = (net | (~mask >>> 0)) >>> 0;
  const size = 2 ** (32 - p);
  const hosts = p >= 31 ? size : size - 2;
  const first = p >= 31 ? net : net + 1, last = p >= 31 ? bcast : bcast - 1;
  const o1 = n >>> 24;
  const cls = o1 < 128 ? 'A' : o1 < 192 ? 'B' : o1 < 224 ? 'C' : o1 < 240 ? 'D (multicast)' : 'E (reserved)';
  const kind = RANGES4.find(([c]) => within4(n, c))?.[1] || 'public';
  const cidr = `${toIP(net)}/${p}`;
  const octets = Math.floor(p / 8);
  const rev = toIP(net).split('.').slice(0, Math.max(1, octets)).reverse().join('.') + '.in-addr.arpa';

  const splitInput = h('input', { class: 'filter', type: 'number', min: p, max: 32, value: Math.min(p + 2, 32), style: 'max-width:90px' });
  const splitList = h('div', { class: 'sublist' });
  const renderSplit = () => {
    const np = Math.max(p, Math.min(32, Number(splitInput.value) || p));
    const count = 2 ** (np - p), step = 2 ** (32 - np);
    splitList.replaceChildren(...Array.from({ length: Math.min(count, 256) }, (_, i) => h('div', {},
      pivot('cidr', `${toIP(net + i * step)}/${np}`))),
    count > 256 ? h('div', { class: 'muted small' }, `…and ${fmtNum(count - 256)} more`) : null);
  };
  splitInput.addEventListener('input', renderSplit);
  renderSplit();

  return grid(
    card('subnet', { actions: copyBtn(cidr, 'copy cidr') }, kv([
      ['cidr', h('code', {}, cidr)],
      ['network', pivot('ip', toIP(net))],
      ['broadcast', h('code', {}, toIP(bcast))],
      ['usable hosts', `${toIP(first)} – ${toIP(last)}`],
      ['host count', fmtNum(hosts)],
      ['type', badge(kind, kind === 'public' ? 'ok' : 'muted')],
      ['class', cls],
    ])),
    card('masks', {}, kv([
      ['netmask', h('code', {}, toIP(mask))],
      ['wildcard', h('code', {}, toIP(~mask >>> 0))],
      ['mask (binary)', h('code', { class: 'small' }, bin(mask))],
      ['address (binary)', h('code', { class: 'small' }, bin(n))],
      ['reverse zone', h('code', { class: 'small' }, rev)],
    ])),
    card('neighbours', {}, kv([
      ['previous', net - size >= 0 ? pivot('cidr', `${toIP(net - size)}/${p}`) : null],
      ['next', bcast + 1 <= 0xffffffff ? pivot('cidr', `${toIP(bcast + 1)}/${p}`) : null],
      ['parent', p > 0 ? pivot('cidr', `${toIP((net & maskOf(p - 1)) >>> 0)}/${p - 1}`) : null],
    ])),
    card('split', { wide: true }, h('div', { class: 'row' }, h('span', { class: 'muted small' }, 'split into /'), splitInput), splitList),
    kind === 'public' ? card('routing', { wide: true }, h('p', {}, pivot('asn', toIP(first), 'who announces this range (ASN) →')), linkGroups([{ items: [
      ['bgp.he.net', `https://bgp.he.net/net/${cidr}`],
      ['RIPEstat', `https://stat.ripe.net/app/launchpad/S1_${encodeURIComponent(cidr)}`],
      ['Shodan (net:)', `https://www.shodan.io/search?query=net%3A${encodeURIComponent(cidr)}`],
      ['Censys', `https://search.censys.io/search?resource=hosts&q=ip%3A${encodeURIComponent(cidr)}`],
    ] }])) : null,
  );
}

// ---------- IPv6 ----------
const big6 = full => BigInt('0x' + full.replace(/:/g, ''));
function fmt6(n) {
  const groups = n.toString(16).padStart(32, '0').match(/.{4}/g).map(g => g.replace(/^0+(?=.)/, ''));
  // compress the longest run of zero groups (2+) into "::"
  let best = [-1, 0], cur = [-1, 0];
  groups.forEach((g, i) => {
    if (g === '0') { cur = cur[0] < 0 ? [i, 1] : [cur[0], cur[1] + 1]; if (cur[1] > best[1]) best = [...cur]; }
    else cur = [-1, 0];
  });
  if (best[1] < 2) return groups.join(':');
  return groups.slice(0, best[0]).join(':') + '::' + groups.slice(best[0] + best[1]).join(':');
}

function v6(ip, p) {
  const full = expandIPv6(ip);
  const n = big6(full), all = (1n << 128n) - 1n;
  const mask = p === 0 ? 0n : (all << BigInt(128 - p)) & all;
  const net = n & mask, last = net | (~mask & all);
  const size = 1n << BigInt(128 - p);
  const sizeText = p >= 64 ? fmtNum(Number(size)) : `2^${128 - p}`;
  return grid(
    card('subnet', { actions: copyBtn(`${fmt6(net)}/${p}`, 'copy cidr') }, kv([
      ['cidr', h('code', {}, `${fmt6(net)}/${p}`)],
      ['first', h('code', { class: 'wrap' }, fmt6(net))],
      ['last', h('code', { class: 'wrap' }, fmt6(last))],
      ['addresses', sizeText],
      ['/64 subnets', p <= 64 ? (p >= 32 ? fmtNum(2 ** (64 - p)) : `2^${64 - p}`) : '—'],
      ['expanded', h('code', { class: 'wrap small' }, full)],
    ])),
    card('look further', {}, h('p', {}, pivot('asn', fmt6(net === n ? net + 1n : n), 'who announces this range (ASN) →')), linkGroups([{ items: [
      ['bgp.he.net', `https://bgp.he.net/net/${fmt6(net)}/${p}`],
    ] }])),
  );
}

export default {
  id: 'cidr',
  label: 'subnet',
  placeholder: 'CIDR (10.0.0.0/22, 2001:db8::/48) or IP + mask',
  intro: 'Subnet calculator for IPv4 and IPv6 — ranges, masks, neighbours and splits. Runs offline.',
  examples: ['192.168.10.77/21', '104.16.0.0/13', '2001:db8:abcd::/48'],

  run(raw) {
    let s = raw.trim();
    if (!s) throw new Error('enter a CIDR like 10.0.0.0/24');
    // "a.b.c.d 255.255.255.0" -> prefix length
    const masked = s.match(/^(\S+)\s+(\d+\.\d+\.\d+\.\d+)$/);
    if (masked && isIPv4(masked[2])) {
      const m = toInt(masked[2]);
      const p = bin(m).replace(/\./g, '').indexOf('0');
      if (p >= 0 && ((m << p) >>> 0) !== 0) throw new Error('that netmask is not contiguous');
      s = `${masked[1]}/${p < 0 ? 32 : p}`;
    }
    const [ip, pre] = s.split('/');
    if (isIPv4(ip)) {
      const p = pre === undefined ? 32 : Number(pre);
      if (!Number.isInteger(p) || p < 0 || p > 32) throw new Error('IPv4 prefix must be 0–32');
      return v4(ip, p);
    }
    if (expandIPv6(ip || '')) {
      const p = pre === undefined ? 128 : Number(pre);
      if (!Number.isInteger(p) || p < 0 || p > 128) throw new Error('IPv6 prefix must be 0–128');
      return v6(ip, p);
    }
    throw new Error('not a valid IPv4 or IPv6 address');
  },
};

export { fmt6 };
