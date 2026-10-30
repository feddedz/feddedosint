import { h, card, grid, muted, badge, ext, pivot, copyBtn, normDomain } from '../util.js';
import * as be from '../backend.js';

// Fetches a site's well-known / conventional files through the proxy — robots.txt, sitemaps,
// security.txt, humans.txt, ads.txt, .well-known/* — and surfaces what they reveal: disallowed
// paths (often the interesting ones), sitemap URLs, and a security contact. Authorized recon.

const TARGETS = [
  { p: '/robots.txt', name: 'robots.txt' },
  { p: '/sitemap.xml', name: 'sitemap.xml' },
  { p: '/security.txt', name: 'security.txt' },
  { p: '/.well-known/security.txt', name: '.well-known/security.txt' },
  { p: '/humans.txt', name: 'humans.txt' },
  { p: '/ads.txt', name: 'ads.txt' },
  { p: '/.well-known/change-password', name: '.well-known/change-password' },
  { p: '/.well-known/openid-configuration', name: 'openid-configuration' },
];

async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  const run = async () => { while (i < items.length) { const idx = i++; const r = await fn(items[idx]).catch(() => null); onEach?.(items[idx], r); } };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, run));
}

export default {
  id: 'wellknown',
  label: 'wellknown',
  placeholder: 'example.com  (robots / sitemap / security.txt / .well-known)',
  intro: 'Pulls a site’s conventional files — robots.txt, sitemaps, security.txt, .well-known — and surfaces disallowed paths, sitemap URLs and a security contact. Authorized recon.',
  examples: ['example.com'],

  async run(raw) {
    const host = normDomain(raw) || raw.trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (!host) throw new Error('enter a host, e.g. example.com');
    if (!(be.backendConfigured() && be.isApproved())) {
      return card('sign-in needed', { wide: true }, muted('This fetches files through the backend proxy, so it needs an approved sign-in.'), h('p', {}, pivot('account', '', 'sign in')));
    }
    const origin = `https://${host}`;

    const found = [];
    await pool(TARGETS, 5, async t => {
      const r = await be.fetchUrl(origin + t.p).catch(() => null);
      const d = r?.data;
      if (d?.status === 200 && (d.body || '').trim() && !/<html/i.test((d.body || '').slice(0, 200))) return { ...t, body: d.body, url: d.finalUrl || origin + t.p };
      return null;
    }, (_, hit) => { if (hit) found.push(hit); });

    if (!found.length) return card('nothing found', { wide: true }, muted(`None of the conventional files returned content for ${host}.`));

    const cards = [];

    // robots.txt → disallowed paths (recon signal) + referenced sitemaps.
    const robots = found.find(f => f.name === 'robots.txt');
    if (robots) {
      const disallow = [...robots.body.matchAll(/^\s*Disallow:\s*(\S+)/gim)].map(m => m[1]).filter(p => p && p !== '/');
      const sitemaps = [...robots.body.matchAll(/^\s*Sitemap:\s*(\S+)/gim)].map(m => m[1]);
      cards.push(card('robots.txt', { wide: true },
        disallow.length ? h('div', {}, muted('Disallowed paths — often where the interesting stuff is:'),
          h('div', { class: 'chips' }, [...new Set(disallow)].slice(0, 120).map(p => h('span', { class: 'chip' }, ext(origin + p, p)))),
          h('p', {}, copyBtn(() => [...new Set(disallow)].map(p => origin + p).join('\n'), 'copy paths'))) : muted('No Disallow entries.'),
        sitemaps.length ? h('p', { class: 'small' }, 'sitemaps: ', ...sitemaps.flatMap((s, i) => [i ? ' · ' : '', ext(s, s)])) : null));
    }

    // security.txt → contact.
    const sec = found.find(f => f.name.includes('security.txt'));
    if (sec) {
      const contact = [...sec.body.matchAll(/^\s*Contact:\s*(\S+)/gim)].map(m => m[1]);
      cards.push(card('security.txt', {}, muted('Vulnerability-disclosure contact(s):'),
        contact.length ? h('div', { class: 'chips' }, contact.map(c => h('span', { class: 'chip' }, /@/.test(c) ? pivot('email', c.replace(/^mailto:/, ''), c) : ext(c, c)))) : muted('(no Contact line)')));
    }

    // sitemap.xml → URL count + sample.
    const sm = found.find(f => f.name === 'sitemap.xml');
    if (sm) {
      const urls = [...sm.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]);
      cards.push(card('sitemap.xml', { wide: true, collapsed: urls.length > 40 },
        muted(`${urls.length} URL(s) listed.`),
        h('p', {}, copyBtn(() => urls.join('\n'), 'copy urls')),
        h('div', { style: 'display:flex;flex-direction:column;gap:3px' }, urls.slice(0, 120).map(u => h('div', { class: 'small', style: 'word-break:break-all' }, ext(u, u))))));
    }

    const others = found.filter(f => !['robots.txt', 'sitemap.xml'].includes(f.name) && !f.name.includes('security.txt'));
    for (const o of others) cards.push(card(o.name, { collapsed: true }, h('pre', { class: 'notespre small' }, o.body.slice(0, 2000))));

    const header = card('well-known files', { wide: true, actions: badge(`${found.length} found`, 'ok') },
      muted(`Conventional files present on ${host}: `), h('p', {}, h('div', { class: 'chips' }, found.map(f => h('span', { class: 'chip' }, ext(f.url, f.name))))));

    return grid(header, ...cards);
  },
};
