import { h, getJSON, isIP, asyncCard, kv, ext, pivot, grid, muted, badge, copyBtn, flag } from '../util.js';

// Resolve an input to an ASN number: "AS13335", "13335", or an IP address.
async function resolveASN(input) {
  const m = input.match(/^(?:as)?(\d{1,10})$/i);
  if (m) return Number(m[1]);
  if (isIP(input)) {
    const r = await getJSON(`https://api.bgpview.io/ip/${encodeURIComponent(input)}`);
    const pre = r.data?.data?.prefixes?.[0];
    if (pre?.asn?.asn) return pre.asn.asn;
    throw new Error('no ASN found for that IP');
  }
  throw new Error('enter an ASN (e.g. AS13335) or an IP address');
}

export default {
  id: 'asn',
  label: 'asn',
  placeholder: 'AS number or IP (e.g. AS13335)',
  intro: 'Explore an autonomous system — who operates it, its address space (prefixes), peers and upstreams.',
  examples: ['AS13335', 'AS15169'],

  async run(raw) {
    const input = raw.trim();
    if (!input) throw new Error('enter an ASN or IP');
    const asn = await resolveASN(input);

    const info = getJSON(`https://api.bgpview.io/asn/${asn}`);

    return grid(
      asyncCard('autonomous system', async () => {
        const r = await info;
        const d = r.data?.data;
        if (!d) throw new Error('ASN not found');
        return [
          kv([
            ['asn', h('strong', {}, `AS${asn}`)],
            ['name', d.name],
            ['description', d.description_short],
            ['country', d.country_code && `${flag(d.country_code)} ${d.country_code}`],
            ['website', d.website && ext(d.website, d.website)],
            ['registry', d.rir_allocation?.rir_name],
            ['allocated', d.rir_allocation?.date_allocated?.slice(0, 10)],
            ['abuse', (d.email_contacts || []).map(e => pivot('email', e)).flatMap((x, i) => i ? [', ', x] : [x])],
            ['looking glass', d.looking_glass && ext(d.looking_glass, 'open')],
          ]),
          h('div', { class: 'links' }, [
            ['bgp.he.net', `https://bgp.he.net/AS${asn}`],
            ['PeeringDB', `https://www.peeringdb.com/asn/${asn}`],
            ['RIPEstat', `https://stat.ripe.net/app/launchpad/S1_${asn}`],
            ['BGPView', `https://bgpview.io/asn/${asn}`],
          ].map(([n, u]) => ext(u, n))),
        ];
      }, { wide: true }),

      asyncCard('prefixes (address space)', async () => {
        const r = await getJSON(`https://api.bgpview.io/asn/${asn}/prefixes`);
        const d = r.data?.data;
        if (!d) throw new Error('could not load prefixes');
        const v4 = d.ipv4_prefixes || [], v6 = d.ipv6_prefixes || [];
        const list = [...v4, ...v6];
        if (!list.length) return muted('no announced prefixes.');
        const box = h('div', { class: 'sublist' });
        const render = term => box.replaceChildren(...list.filter(p => p.prefix.includes(term)).slice(0, 400)
          .map(p => h('div', {}, pivot('ip', p.prefix.split('/')[0], p.prefix),
            p.name ? h('span', { class: 'muted small' }, ` ${p.name}`) : null)));
        render('');
        return [
          h('div', { class: 'row' },
            h('input', { class: 'filter', placeholder: `filter ${v4.length} IPv4 · ${v6.length} IPv6…`, oninput: e => render(e.target.value.trim()) }),
            copyBtn(() => list.map(p => p.prefix).join('\n'), 'copy')),
          box,
        ];
      }, { wide: true }),

      asyncCard('peers & upstreams', async () => {
        const r = await getJSON(`https://api.bgpview.io/asn/${asn}/peers`);
        const peers = r.data?.data?.ipv4_peers || [];
        if (!peers.length) return muted('no peer data.');
        return h('div', { class: 'tags' }, peers.slice(0, 60).map(p =>
          h('a', { class: 'badge muted', href: `#asn/AS${p.asn}`, title: p.name }, `AS${p.asn}`)));
      }, { wide: true }),
    );
  },
};
