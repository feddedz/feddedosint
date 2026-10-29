import { h, card, grid, muted, badge, ext, pivot, copyBtn, normDomain } from '../util.js';
import * as be from '../backend.js';
import { faviconHash, b64ToBytes } from '../mmh3.js';

// Favicon-hash pivot. Fetches a site's favicon (through the backend proxy, for the raw bytes),
// computes the Shodan mmh3 hash, and builds a `http.favicon.hash:` pivot — the classic way to find
// every other host serving the same favicon (shared panels, mirrored infra, a product's fleet).
// Public data; the byte fetch goes through your approved backend.

const SHODAN = hash => `https://www.shodan.io/search?query=${encodeURIComponent('http.favicon.hash:' + hash)}`;

// Find a favicon URL from page HTML, else fall back to /favicon.ico at the origin.
function faviconURL(pageUrl, html) {
  const origin = new URL(pageUrl).origin;
  const m = /<link[^>]+rel=["']?[^"'>]*icon[^"'>]*["']?[^>]*>/gi;
  let best = '';
  for (const tag of html.match(m) || []) {
    const href = /href=["']?([^"'>\s]+)/i.exec(tag);
    if (href) { best = href[1]; break; }
  }
  if (!best) return `${origin}/favicon.ico`;
  try { return new URL(best, pageUrl).href; } catch { return `${origin}/favicon.ico`; }
}

export default {
  id: 'favicon',
  label: 'favicon',
  placeholder: 'example.com or https://example.com  (favicon → Shodan hash)',
  intro: 'Computes a site’s Shodan favicon hash and pivots to every other host serving the same icon — great for finding mirrored panels and a product’s whole fleet.',
  examples: ['example.com'],
  noTrack: true,

  async run(raw) {
    const input = raw.trim();
    if (!input) throw new Error('enter a site, e.g. example.com');
    const pageUrl = /^https?:\/\//i.test(input) ? input : `https://${normDomain(input) || input.replace(/\/.*$/, '')}`;

    if (!(be.backendConfigured() && be.isApproved())) {
      return card('sign-in needed', { wide: true },
        muted('The favicon hash needs the raw icon bytes, fetched through the backend proxy — so this needs an approved sign-in.'),
        h('p', {}, pivot('account', '', 'sign in')));
    }

    // 1) Get the page HTML to locate the favicon link.
    const page = await be.fetchUrl(pageUrl).catch(() => null);
    const html = page?.data?.body || '';
    const icoUrl = faviconURL(page?.data?.finalUrl || pageUrl, html);

    // 2) Fetch the favicon bytes (base64) through the proxy.
    const r = await be.fetchBytes(icoUrl).catch(() => null);
    if (!r?.ok || !r.data?.b64) {
      return card('no favicon', { wide: true },
        muted(`Couldn’t fetch a favicon for ${pageUrl}.`),
        h('p', { class: 'muted small' }, 'tried: ', ext(icoUrl, icoUrl), r?.data?.error ? ` — ${r.data.error}` : ''));
    }
    const bytes = b64ToBytes(r.data.b64);
    if (!bytes.length) return card('empty favicon', { wide: true }, muted(`The favicon at ${icoUrl} was empty.`));

    const hash = faviconHash(bytes);
    const ct = r.data.contentType || 'image/x-icon';
    const dataUri = `data:${ct};base64,${r.data.b64}`;

    return grid(
      card('favicon hash', { wide: true, actions: badge(`${bytes.length} bytes`, 'muted') },
        h('div', { class: 'row', style: 'gap:14px;align-items:center' },
          h('img', { src: dataUri, alt: '', width: '48', height: '48', style: 'border:1px solid var(--line);border-radius:8px;background:#fff;padding:3px' }),
          h('div', {},
            h('div', {}, h('strong', { style: 'font-size:18px' }, String(hash))),
            h('div', { class: 'muted small' }, 'Shodan mmh3 favicon hash for ', ext(icoUrl, new URL(icoUrl).hostname + new URL(icoUrl).pathname)))),
        h('p', { class: 'row wrap', style: 'gap:6px;margin-top:10px' },
          copyBtn(() => String(hash), 'copy hash'),
          ext(SHODAN(hash), 'search Shodan for this favicon'),
          copyBtn(() => `http.favicon.hash:${hash}`, 'copy shodan query'))),
      card('what this does', {},
        muted('Any host whose favicon hashes to this number is likely running the same application or belongs to the same operator — a strong pivot for mapping infrastructure you own or are investigating with authorization.'),
        h('p', { class: 'muted small' }, 'Also works in Censys: ', ext(`https://search.censys.io/search?resource=hosts&q=${encodeURIComponent('services.http.response.favicons.md5_hash') }`, 'favicon search'))),
    );
  },
};
