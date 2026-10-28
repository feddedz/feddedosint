import { h, getText, card, asyncCard, kv, grid, muted, badge, copyBtn, linkGroups } from '../util.js';

export default {
  id: 'mac',
  label: 'mac',
  placeholder: 'MAC / BSSID (any format)',
  intro: 'Identify the maker of a network device from its MAC address, spot randomised addresses, and see every format.',
  examples: ['3C:22:FB:12:34:56', 'f0-9f-c2-00-00-01'],

  run(raw) {
    const hex = raw.trim().replace(/[^0-9a-f]/gi, '').toUpperCase();
    if (hex.length !== 12) throw new Error('a MAC address has 12 hex digits, e.g. 3C:22:FB:12:34:56');
    const pairs = hex.match(/../g);
    const mac = pairs.join(':');
    const first = parseInt(pairs[0], 16);
    const local = !!(first & 0x02), multicast = !!(first & 0x01);

    // Modified EUI-64 link-local IPv6 address derived from this MAC (SLAAC, without privacy extensions).
    const eui = [(first ^ 0x02).toString(16).padStart(2, '0'), pairs[1], pairs[2], 'ff', 'fe', pairs[3], pairs[4], pairs[5]].join('').toLowerCase();
    const ll6 = `fe80::${eui.slice(0, 4).replace(/^0+(?=.)/, '')}:${eui.slice(4, 8).replace(/^0+(?=.)/, '')}:${eui.slice(8, 12).replace(/^0+(?=.)/, '')}:${eui.slice(12).replace(/^0+(?=.)/, '')}`;

    return grid(
      card('address', { actions: copyBtn(mac, 'copy') }, kv([
        ['mac', h('code', {}, mac)],
        ['oui (maker prefix)', h('code', {}, pairs.slice(0, 3).join(':'))],
        ['administration', local ? badge('locally administered — likely randomised / private', 'warn') : badge('globally unique (burned-in)', 'ok')],
        ['cast', multicast ? badge('multicast / group', 'warn') : 'unicast'],
      ])),

      local ? card('vendor', {}, muted('Locally administered addresses are made up by the device (phones and laptops randomise their Wi-Fi MAC for privacy), so there is no manufacturer to look up.'))
        : asyncCard('vendor', async () => {
          const r = await getText(`https://api.macvendors.com/${encodeURIComponent(mac)}`);
          if (r.status === 404) return muted('no manufacturer registered for this prefix.');
          if (!r.ok) throw new Error(r.status === 429 ? 'rate limited — wait a second and retry' : `HTTP ${r.status}`);
          return h('div', { class: 'verdict ok' }, r.text.trim());
        }),

      card('formats', { wide: true }, kv([
        ['colon', h('code', {}, mac)],
        ['hyphen', h('code', {}, pairs.join('-'))],
        ['cisco', h('code', {}, hex.toLowerCase().match(/..../g).join('.'))],
        ['bare', h('code', {}, hex)],
        ['eui-64 ipv6', h('code', {}, ll6)],
      ])),

      card('look further', { wide: true }, linkGroups([{ items: [
        ['MAC Lookup', `https://maclookup.app/search/result?mac=${mac}`],
        ['macaddress.io', `https://macaddress.io/lookup/${mac}`],
        ['Wireshark OUI', 'https://www.wireshark.org/tools/oui-lookup.html'],
        ['WiGLE (Wi-Fi BSSID)', `https://wigle.net/search?netid=${encodeURIComponent(mac)}`],
      ] }])),
    );
  },
};
