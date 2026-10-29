import { h, card, grid, muted, badge, ext, pivot, copyBtn, getText, normDomain } from '../util.js';

// Harvest every URL the Internet Archive has seen for a host, via the Wayback CDX API.
// Public archive data, fetched straight from the browser. Great for finding forgotten
// endpoints, old admin panels, leaked paths, parameters and file types on your own sites.

const CDX = 'https://web.archive.org/cdx/search/cdx';

// Interesting path / extension signals worth flagging in the results.
const JUICY = [
  [/\.(sql|bak|old|backup|tar|gz|zip|rar|7z|dump)(\?|$)/i, 'backup/archive'],
  [/\.(env|git|svn|htaccess|htpasswd|DS_Store)(\?|$)/i, 'config/vcs'],
  [/\.(log|txt|csv|json|xml|yaml|yml|ini|conf|cfg)(\?|$)/i, 'data/config'],
  [/\.(pem|key|crt|cer|pfx|p12|ppk)(\?|$)/i, 'key/cert'],
  [/(admin|login|signin|dashboard|console|manage|cpanel|phpmyadmin|wp-admin)/i, 'admin'],
  [/(api|graphql|rest|v1|v2|swagger|openapi|\.wsdl)/i, 'api'],
  [/(upload|file|download|attachment|export|backup|dump)/i, 'file op'],
  [/(token|apikey|api_key|secret|password|passwd|auth|key=)/i, 'secret param'],
  [/(test|dev|staging|debug|internal|private|tmp|temp)/i, 'non-prod'],
  [/\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh|do|action)(\?|$)/i, 'dynamic'],
];

const tagOf = url => JUICY.find(([re]) => re.test(url))?.[1] || null;

export default {
  id: 'wayback',
  label: 'wayback',
  placeholder: 'example.com  (host to harvest archived URLs for)',
  intro: 'Pull every URL the Internet Archive has recorded for a host — forgotten endpoints, old panels, parameters and risky file types. Public archive data.',
  examples: ['example.com', 'github.com'],

  async run(raw) {
    const host = normDomain(raw) || raw.trim().replace(/^https?:\/\//i, '').split('/')[0];
    if (!host) throw new Error('enter a host, e.g. example.com');

    // collapse=urlkey dedupes; limit keeps it browser-friendly. Includes subdomains (*.host).
    const q = new URLSearchParams({
      url: `*.${host}/*`, output: 'json', fl: 'original,timestamp,statuscode,mimetype',
      collapse: 'urlkey', limit: '6000',
    });
    const r = await getText(`${CDX}?${q}`, { timeout: 30000 }).catch(() => null);
    if (!r?.ok || !r.text?.trim()) {
      return card('no archive data', { wide: true },
        muted(`The Wayback CDX API returned nothing for ${host}. It may have no captures, or the API is busy — try again, or check it `),
        h('p', {}, ext(`https://web.archive.org/web/*/${host}/*`, 'on web.archive.org')));
    }

    let rows;
    try { rows = JSON.parse(r.text); } catch { throw new Error('could not parse the archive response'); }
    const header = rows.shift(); // ['original','timestamp','statuscode','mimetype']
    const seen = new Set();
    const urls = [];
    for (const [url, ts, status, mime] of rows) {
      if (!url || seen.has(url)) continue;
      seen.add(url);
      urls.push({ url, ts, status, mime, tag: tagOf(url) });
    }
    if (!urls.length) return card('no archived urls', { wide: true }, muted(`No captures recorded for ${host}.`));

    const flagged = urls.filter(u => u.tag);
    const hosts = new Set(urls.map(u => { try { return new URL(u.url).hostname; } catch { return null; } }).filter(Boolean));
    const params = new Set();
    for (const u of urls) { try { new URL(u.url).searchParams.forEach((_, k) => params.add(k)); } catch {} }

    const summary = card('harvest', { wide: true, actions: badge(`${urls.length} urls`, 'ok') },
      h('div', { class: 'statrow' },
        stat(urls.length, 'archived urls'),
        stat(hosts.size, 'hostnames'),
        stat(flagged.length, 'flagged', flagged.length ? 'warn' : 'muted'),
        stat(params.size, 'url parameters')),
      h('p', { class: 'row wrap', style: 'gap:6px;margin-top:10px' },
        copyBtn(() => urls.map(u => u.url).join('\n'), 'copy all urls'),
        copyBtn(() => flagged.map(u => u.url).join('\n'), 'copy flagged'),
        copyBtn(() => [...params].sort().join('\n'), 'copy parameters'),
        ext(`https://web.archive.org/web/*/${host}/*`, 'open on archive.org')));

    const hostCard = card('hostnames seen in the archive', {},
      muted('Subdomains the archive has URLs for — pivot each into recon or dns.'),
      h('div', { class: 'chips' }, [...hosts].sort().slice(0, 120).map(hn =>
        h('span', { class: 'chip' }, pivot('recon', hn, hn)))));

    const flagCard = flagged.length ? card(`flagged urls (${flagged.length})`, { wide: true, collapsed: flagged.length > 60 },
      muted('Paths and extensions worth a closer look on your own assets — backups, configs, keys, admin panels, secret-looking parameters.'),
      urlTable(flagged.slice(0, 300))) : null;

    const allCard = card(`all urls (${urls.length})`, { wide: true, collapsed: true },
      urlTable(urls.slice(0, 1500)),
      urls.length > 1500 ? muted(`Showing the first 1500. Use “copy all urls” for the full ${urls.length}.`) : null);

    const paramCard = params.size ? card(`url parameters (${params.size})`, { collapsed: params.size > 40 },
      muted('Every query-string key ever seen — a map of the app’s inputs (test these only on assets you own).'),
      h('div', { class: 'chips' }, [...params].sort().map(p => h('span', { class: 'chip' }, p)))) : null;

    return grid(summary, flagCard, hostCard, paramCard, allCard);
  },
};

function stat(n, label, tone) {
  return h('div', { class: 'statcell' },
    h('div', { class: 'statnum' + (tone === 'warn' && n ? ' warn' : '') }, String(n)),
    h('div', { class: 'statlbl muted small' }, label));
}

function fmtTs(ts) {
  if (!ts || ts.length < 8) return '';
  return `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
}

function urlTable(items) {
  return h('table', { class: 'records' }, h('tbody', {}, items.map(u => h('tr', {},
    h('td', {}, u.tag ? badge(u.tag, 'warn') : badge(fmtTs(u.ts) || '—', 'muted')),
    h('td', { class: 'small', style: 'word-break:break-all' },
      ext(`https://web.archive.org/web/${u.ts}/${u.url}`, u.url)),
    h('td', { class: 'muted small' }, u.status || '')))));
}
