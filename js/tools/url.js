import { h, getJSON, card, asyncCard, kv, ext, pivot, grid, muted, badge, copyBtn, linkGroups, defang, refang, registrable, isIP, rdapEvent, fmtDate } from '../util.js';
import { getKey, hasKey } from '../store.js';

const SHORTENERS = new Set(['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
  'rb.gy', 'tiny.cc', 'lnkd.in', 't.ly', 'bl.ink', 'short.io', 's.id', 'v.gd', 'qrco.de', 'tr.ee', 'dub.sh', 'x.co', 'trib.al']);
// TLDs that show up disproportionately in abuse reports. A hint, never proof.
const RISKY_TLD = new Set(['zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'link', 'work', 'support', 'rest', 'fit',
  'country', 'kim', 'cam', 'quest', 'buzz', 'icu', 'monster', 'sbs', 'cfd', 'lol', 'online', 'site']);
const REDIRECT_KEYS = /^(url|u|redirect|redirect_uri|redirect_url|next|return|returnurl|return_to|continue|dest|destination|target|goto|link|r|q)$/i;

const b64url = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const safeDecode = s => { try { return decodeURIComponent(s); } catch { return s; } };

export default {
  id: 'url',
  label: 'url',
  placeholder: 'full URL (defanged is fine)',
  intro: 'Break a link apart, flag phishing tricks, follow embedded redirects, check domain age and past scans.',
  examples: ['https://example.com/login?next=https%3A%2F%2Fevil.example.net%2F'],

  run(raw) {
    let input = refang(raw.trim());
    if (!input) throw new Error('enter a URL');
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) input = 'http://' + input;
    let u;
    try { u = new URL(input); } catch { throw new Error('that is not a valid URL'); }
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const base = isIP(host) ? host : registrable(host);
    const params = [...u.searchParams.entries()];

    // Red flags, worst first.
    const flags = [];
    if (u.username || u.password) flags.push(['bad', `contains credentials-style text before "@" (${u.username}…) — the real host is ${host}`]);
    if (isIP(host)) flags.push(['bad', 'host is a raw IP address instead of a domain']);
    if (host.split('.').some(l => l.startsWith('xn--'))) flags.push(['bad', 'internationalised (punycode) domain — check for look-alike characters']);
    if (SHORTENERS.has(host)) flags.push(['warn', 'link shortener — the destination is hidden']);
    if (RISKY_TLD.has(host.split('.').pop())) flags.push(['warn', `.${host.split('.').pop()} is a TLD often seen in abuse reports`]);
    if (u.protocol === 'http:') flags.push(['warn', 'not encrypted (http)']);
    if (host.split('.').length > 4) flags.push(['warn', `many subdomain levels (${host.split('.').length}) — sometimes used to hide the real domain`]);
    if (/(login|signin|verify|account|secure|update|wallet|bank|password|auth)/i.test(u.pathname + u.hostname) && !isIP(host))
      flags.push(['muted', 'uses account / login wording — confirm it is the real site']);
    if (input.length > 200) flags.push(['muted', `long URL (${input.length} chars)`]);
    if (u.port && !['80', '443'].includes(u.port)) flags.push(['warn', `non-standard port ${u.port}`]);
    const nested = params.filter(([k, v]) => REDIRECT_KEYS.test(k) && /^(https?:)?\/\//i.test(v));
    if (nested.length) flags.push(['warn', `embedded redirect to ${nested.map(([, v]) => v).join(', ')}`]);

    const enc = encodeURIComponent(u.href);
    return grid(
      card('anatomy', { wide: true, actions: copyBtn(defang(u.href), 'copy defanged') }, kv([
        ['scheme', u.protocol.replace(':', '')],
        ['host', isIP(host) ? pivot('ip', host) : pivot('domain', host)],
        ['registrable', !isIP(host) && host !== base ? pivot('domain', base) : null],
        ['port', u.port],
        ['path', u.pathname !== '/' && h('code', { class: 'wrap small' }, safeDecode(u.pathname))],
        ['fragment', u.hash && h('code', { class: 'wrap small' }, u.hash)],
        ['defanged', h('code', { class: 'wrap small' }, defang(u.href))],
      ])),

      params.length ? card(`query parameters · ${params.length}`, { wide: true },
        h('table', { class: 'records' }, h('tbody', {}, params.map(([k, v]) => h('tr', {},
          h('td', { class: 'type' }, k),
          h('td', {}, /^(https?:)?\/\//i.test(v) ? pivot('url', v) : h('span', { class: 'mono wrap' }, v))))))) : null,

      card(`findings · ${flags.length}`, { wide: true }, flags.length
        ? h('div', { class: 'findings' }, flags.map(([t, text]) => h('div', { class: 'finding' },
          badge(t === 'muted' ? 'info' : t === 'warn' ? 'warning' : 'red flag', t), h('span', {}, text))))
        : muted('no structural red flags. That alone does not make a link safe.')),

      !isIP(host) ? asyncCard('domain age', async () => {
        const r = await getJSON(`https://rdap.org/domain/${encodeURIComponent(base)}`);
        if (!r.ok || !r.data) throw new Error(r.status === 404 ? 'no RDAP record for this domain' : `HTTP ${r.status}`);
        const created = rdapEvent(r.data, 'registration');
        if (!created) return muted('registration date not published.');
        const days = Math.floor((Date.now() - new Date(created)) / 864e5);
        return kv([
          ['registered', `${fmtDate(created)}`],
          ['age', badge(days < 30 ? `${days} days — very new` : days < 365 ? `${days} days` : `${(days / 365).toFixed(1)} years`,
            days < 30 ? 'bad' : days < 180 ? 'warn' : 'ok')],
        ]);
      }) : null,

      asyncCard('past scans (urlscan.io)', async () => {
        const q = encodeURIComponent(isIP(host) ? `ip:${host}` : `domain:${host}`);
        const r = await getJSON(`https://urlscan.io/api/v1/search/?q=${q}&size=8`,
          hasKey('urlscan') ? { headers: { 'API-Key': getKey('urlscan') } } : {});
        if (!r.ok) throw new Error(`urlscan returned HTTP ${r.status}`);
        const res = r.data?.results || [];
        if (!res.length) return muted('never scanned on urlscan.io.');
        return h('div', { class: 'shots' }, res.map(x => ext(`https://urlscan.io/result/${x._id}/`,
          h('img', { src: x.screenshot, alt: '', loading: 'lazy', referrerpolicy: 'no-referrer', onerror: e => e.target.remove() }),
          h('span', { class: 'small' }, (x.task?.url || '').slice(0, 60)),
          h('span', { class: 'muted small' }, `${fmtDate(x.task?.time)} · ${x.page?.country || '—'} · ${x.page?.ip || ''}`))));
      }, { wide: true }),

      card('check reputation', { wide: true }, linkGroups([
        { group: 'scanners', items: [
          ['urlscan.io', `https://urlscan.io/search/#${encodeURIComponent(isIP(host) ? 'ip:' + host : 'domain:' + host)}`],
          ['VirusTotal', `https://www.virustotal.com/gui/url/${b64url(u.href)}`],
          ['Google Safe Browsing', `https://transparencyreport.google.com/safe-browsing/search?url=${enc}`],
          ['URLhaus', `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(host)}`],
          ['PhishTank', 'https://phishtank.org/'],
        ] },
        { group: 'history & expansion', items: [
          ['Wayback Machine', `https://web.archive.org/web/*/${u.href}`],
          ['unshorten.me', `https://unshorten.me/s/${u.href}`],
          ['archive.today', `https://archive.ph/${u.href}`],
        ] },
      ])),
    );
  },
};
