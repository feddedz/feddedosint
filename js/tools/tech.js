import { h, card, grid, muted, badge, ext, pivot, copyBtn, normDomain } from '../util.js';
import * as be from '../backend.js';

// Fingerprints a single site's stack from its response headers and body — CMS, framework, server,
// CDN, analytics — through the backend proxy. Authorized recon; one target at a time.

const TECH = [
  [h => /wp-content|wp-includes/i.test(h.body), 'WordPress', 'cms'],
  [h => /drupal/i.test(h.body) || /x-drupal/i.test(h.hdr), 'Drupal', 'cms'],
  [h => /joomla/i.test(h.body), 'Joomla', 'cms'],
  [h => /x-shopify|cdn\.shopify/i.test(h.all), 'Shopify', 'ecommerce'],
  [h => /wix\.com|x-wix/i.test(h.all), 'Wix', 'builder'],
  [h => /squarespace/i.test(h.body), 'Squarespace', 'builder'],
  [h => /ghost/i.test(h.body), 'Ghost', 'cms'],
  [h => /__NEXT_DATA__|\/_next\//.test(h.body), 'Next.js', 'framework'],
  [h => /data-reactroot|react(?:-dom)?\.production/i.test(h.body), 'React', 'framework'],
  [h => /ng-version=|angular/i.test(h.body), 'Angular', 'framework'],
  [h => /data-v-[0-9a-f]{8}|__vue__|__nuxt/i.test(h.body), 'Vue / Nuxt', 'framework'],
  [h => /gatsby/i.test(h.body), 'Gatsby', 'framework'],
  [h => /x-powered-by:\s*express/i.test(h.hdr), 'Express', 'backend'],
  [h => /x-powered-by.*php|phpsessid/i.test(h.all), 'PHP', 'backend'],
  [h => /x-aspnet-version|asp\.net|__viewstate/i.test(h.all), 'ASP.NET', 'backend'],
  [h => /laravel_session/i.test(h.hdr), 'Laravel', 'backend'],
  [h => /csrftoken|django/i.test(h.all), 'Django', 'backend'],
  [h => /phusion|passenger|_rails/i.test(h.all), 'Ruby on Rails', 'backend'],
  [h => /cloudflare/i.test(h.hdr), 'Cloudflare', 'cdn'],
  [h => /x-amz-cf-id|cloudfront/i.test(h.hdr), 'AWS CloudFront', 'cdn'],
  [h => /x-vercel/i.test(h.hdr), 'Vercel', 'host'],
  [h => /x-nf-request-id|netlify/i.test(h.hdr), 'Netlify', 'host'],
  [h => /x-github-request|github\.io/i.test(h.hdr), 'GitHub Pages', 'host'],
  [h => /fastly/i.test(h.hdr), 'Fastly', 'cdn'],
  [h => /akamai/i.test(h.hdr), 'Akamai', 'cdn'],
  [h => /server:\s*nginx/i.test(h.hdr), 'nginx', 'server'],
  [h => /server:\s*apache/i.test(h.hdr), 'Apache', 'server'],
  [h => /server:\s*(microsoft-)?iis/i.test(h.hdr), 'IIS', 'server'],
  [h => /server:\s*litespeed/i.test(h.hdr), 'LiteSpeed', 'server'],
  [h => /server:\s*caddy/i.test(h.hdr), 'Caddy', 'server'],
  [h => /google-analytics|gtag\(|googletagmanager/i.test(h.body), 'Google Analytics', 'analytics'],
  [h => /hotjar/i.test(h.body), 'Hotjar', 'analytics'],
  [h => /cloudflareinsights/i.test(h.body), 'Cloudflare Analytics', 'analytics'],
  [h => /jquery/i.test(h.body), 'jQuery', 'library'],
  [h => /bootstrap/i.test(h.body), 'Bootstrap', 'library'],
  [h => /tailwind/i.test(h.body), 'Tailwind', 'library'],
  [h => /recaptcha|hcaptcha/i.test(h.body), 'CAPTCHA', 'security'],
  [h => /stripe\.com\/v3|js\.stripe/i.test(h.body), 'Stripe', 'payments'],
];

export default {
  id: 'tech',
  label: 'tech',
  placeholder: 'example.com  (website technology fingerprint)',
  intro: 'Fingerprints a site’s stack — CMS, framework, server, CDN, analytics — from its headers and body. Authorized recon, one target at a time.',
  examples: ['example.com'],

  async run(raw) {
    const host = normDomain(raw) || raw.trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (!host) throw new Error('enter a host, e.g. example.com');
    if (!(be.backendConfigured() && be.isApproved())) {
      return card('sign-in needed', { wide: true }, muted('This fetches the site through the backend proxy, so it needs an approved sign-in.'), h('p', {}, pivot('account', '', 'sign in')));
    }
    const origin = `https://${host}`;
    let r = await be.fetchUrl(origin).catch(() => null);
    if (!r?.ok || !r.data?.status) r = await be.fetchUrl(`http://${host}`).catch(() => null);
    const d = r?.data;
    if (!d?.status) return card('unreachable', { wide: true }, muted(`Couldn’t reach ${origin} through the proxy.`));

    const hdr = Object.entries(d.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n').toLowerCase();
    const body = (d.body || '').slice(0, 200000);
    const ctx = { hdr, body: body.toLowerCase(), all: (hdr + body).toLowerCase() };
    const hits = TECH.filter(([fn]) => fn(ctx)).map(([, name, cat]) => ({ name, cat }));

    const byCat = {};
    for (const t of hits) (byCat[t.cat] ||= []).push(t.name);

    const server = (d.headers?.server) || '—';
    const title = (/<title[^>]*>([\s\S]{0,160}?)<\/title>/i.exec(d.body || '') || [])[1]?.replace(/\s+/g, ' ').trim() || '';

    const header = card('technology', { wide: true, actions: badge(`${hits.length} detected`, hits.length ? 'ok' : 'muted') },
      h('p', {}, h('strong', {}, host), ' · ', badge(`HTTP ${d.status}`, 'muted'), ' · server: ', h('code', {}, server)),
      title ? muted(`title: ${title}`) : null,
      hits.length ? h('div', { class: 'chips' }, hits.map(t => h('span', { class: 'chip' }, t.name))) : muted('No known technologies fingerprinted from the response.'),
      h('div', { class: 'row wrap', style: 'gap:6px;margin-top:8px' }, pivot('assess', host, 'vuln assessment'), pivot('recon', host, 'attack surface'), pivot('favicon', host, 'favicon pivot'), pivot('wellknown', host, 'well-known files')));

    const catCards = Object.entries(byCat).map(([c, names]) => card(c, {}, h('div', { class: 'chips' }, names.map(n => h('span', { class: 'chip' }, n)))));

    return grid(header, ...catCards);
  },
};
