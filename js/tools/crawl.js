import { h, card, grid, muted, badge, ext, copyBtn } from '../util.js';
import * as be from '../backend.js';

// Secrets worth surfacing from live HTML + JavaScript.
const SECRETS = [
  [/AKIA[0-9A-Z]{16}/g, 'AWS access key'],
  [/AIza[0-9A-Za-z_\-]{35}/g, 'Google API key'],
  [/ya29\.[0-9A-Za-z_\-]+/g, 'Google OAuth token'],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/g, 'Slack token'],
  [/sk_live_[0-9A-Za-z]{16,}/g, 'Stripe live key'],
  [/gh[pousr]_[0-9A-Za-z]{30,}/g, 'GitHub token'],
  [/eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g, 'JWT'],
  [/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, 'private key'],
  [/firebaseio\.com|firebaseapp\.com/g, 'Firebase'],
  [/(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token|bearer)["'`\s:=]{1,6}["'`]([A-Za-z0-9_\-]{16,64})["'`]/gi, 'generic secret'],
];
const ENDPOINTS = /["'`](\/(?:api|v\d|rest|graphql|internal|admin|auth|oauth|user|account|upload|download|file|payment|billing)[A-Za-z0-9_\-/.{}:]*)["'`]/g;
const uniq = a => [...new Set(a)];

export default {
  id: 'crawl',
  label: 'crawl',
  placeholder: 'URL or domain (e.g. https://example.com)',
  intro: 'Live page recon: fetches a page through the backend and maps its real attack surface — links, forms & their inputs (injection points), JavaScript, emails, comments, and leaked keys/endpoints in the live code. Authorized targets only.',
  examples: ['https://example.com'],

  run(raw) {
    let target = raw.trim();
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target.replace(/^\/+/, '');
    let base;
    try { base = new URL(target); } catch { throw new Error('enter a valid URL or domain'); }
    if (!(be.backendConfigured() && be.isApproved())) {
      return grid(card('live crawl', { wide: true }, muted('This fetches live pages through the backend proxy, so it needs an approved sign-in. Connect the backend in settings.')));
    }

    const summary = h('span', { class: 'muted small' }, 'fetching page…');
    const sLinks = h('span', {}, '0'), sForms = h('span', {}, '0'), sJS = h('span', {}, '0'), sSecret = h('span', {}, '0');
    const findings = h('div', { class: 'risklist' });
    const formsBox = h('div', {});
    const jsBox = h('div', { class: 'livelist' });
    const linksBox = h('div', {});
    const stat = (l, el) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' }, el), h('div', { class: 'statlbl muted small' }, l));
    const host = base.hostname;

    const scanText = (text, where) => {
      let n = 0;
      for (const [re, label] of SECRETS) { const m = text.match(re); if (m) { n += uniq(m).length; for (const v of uniq(m).slice(0, 2)) findings.append(h('div', { class: 'riskrow' }, badge('high', 'bad'), h('span', {}, `${label} in ${where}: `, h('code', { class: 'small' }, String(v).slice(0, 60))))); } }
      return n;
    };

    (async () => {
      const r = await be.fetchUrl(base.href).catch(() => null);
      if (!r?.ok || !r.data?.body) { summary.textContent = 'could not fetch the page (' + (r?.data?.error || `HTTP ${r?.data?.status || '?'}`) + ').'; return; }
      const html = r.data.body;
      const doc = new DOMParser().parseFromString(html, 'text/html');

      // links
      const links = uniq([...doc.querySelectorAll('a[href]')].map(a => { try { return new URL(a.getAttribute('href'), base).href; } catch { return null; } }).filter(Boolean));
      const internal = links.filter(u => { try { return new URL(u).hostname === host; } catch { return false; } });
      const external = links.filter(u => !internal.includes(u));
      sLinks.textContent = links.length;

      // forms = injection surface
      const forms = [...doc.querySelectorAll('form')];
      sForms.textContent = forms.length;
      if (forms.length) {
        formsBox.append(card('forms — input/injection surface', { wide: true, collapsed: forms.length > 6 }, forms.map(f => {
          let action = f.getAttribute('action') || '(self)'; try { action = new URL(action, base).href; } catch {}
          const method = (f.getAttribute('method') || 'GET').toUpperCase();
          const inputs = [...f.querySelectorAll('input,textarea,select')].map(i => i.getAttribute('name') || i.getAttribute('type') || '?');
          const hasPass = [...f.querySelectorAll('input[type=password]')].length;
          const hasFile = [...f.querySelectorAll('input[type=file]')].length;
          return h('div', { class: 'riskrow' }, badge(method, method === 'POST' ? 'warn' : 'muted'),
            h('span', {}, ext(action, action.slice(0, 70)), ' — ', h('span', { class: 'muted small' }, inputs.join(', ') || 'no named inputs'),
              hasPass ? badge('login', 'bad') : null, hasFile ? badge('upload', 'bad') : null));
        })));
        if (forms.some(f => (f.getAttribute('method') || 'GET').toUpperCase() === 'GET' && f.querySelector('input')))
          findings.append(h('div', { class: 'riskrow' }, badge('note', 'warn'), h('span', {}, 'GET form(s) with inputs — parameters land in the URL (reflected-XSS / logging surface).')));
      }

      // emails + comments
      const emails = uniq((html.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || []).filter(e => !/\.(png|jpg|gif|svg|webp)$/i.test(e)));
      const comments = (html.match(/<!--([\s\S]*?)-->/g) || []).map(c => c.slice(4, -3).trim()).filter(c => c.length > 8 && !/^\[if|googleoff|endif/i.test(c));

      // inline + external JS secrets/endpoints
      let secretCount = scanText(html, 'page HTML');
      const scripts = uniq([...doc.querySelectorAll('script[src]')].map(s => { try { return new URL(s.getAttribute('src'), base).href; } catch { return null; } }).filter(Boolean));
      sJS.textContent = scripts.length;
      const inlineEps = uniq([...html.matchAll(ENDPOINTS)].map(m => m[1]));

      summary.textContent = `scanning ${Math.min(scripts.length, 25)} scripts…`;
      let i = 0;
      await Promise.all([0, 1, 2, 3].map(async () => {
        while (i < Math.min(scripts.length, 25)) {
          const u = scripts[i++];
          const jr = await be.fetchUrl(u).catch(() => null);
          const text = jr?.data?.body || ''; if (!text) continue;
          const found = [];
          for (const [re, label] of SECRETS) { const m = text.match(re); if (m) found.push([label, uniq(m).slice(0, 2)]); }
          const eps = uniq([...text.matchAll(ENDPOINTS)].map(m => m[1])).slice(0, 25);
          secretCount += scanText(text, u.split('/').pop());
          if (found.length || eps.length) jsBox.append(h('div', { class: 'liverow ' + (found.length ? 'found' : '') },
            h('span', { class: 'dot ' + (found.length ? 'found' : 'none') }), h('div', { class: 'avatar' }),
            h('div', { class: 'main' }, ext(u, u.replace(/^https?:\/\//, '').slice(0, 80)),
              found.map(([l, v]) => h('div', { class: 'small' }, badge(l, 'bad'), ' ', h('code', { class: 'small' }, v.join(', ').slice(0, 100)))),
              eps.length ? h('div', { class: 'small muted' }, 'endpoints: ' + eps.join('  ').slice(0, 280)) : null)));
          sSecret.textContent = secretCount;
        }
      }));

      // render secondary cards
      if (inlineEps.length) jsBox.append(h('div', { class: 'small muted', style: 'margin-top:6px' }, 'inline endpoints: ' + inlineEps.join('  ').slice(0, 400)));
      if (!jsBox.children.length) jsBox.append(muted('no secrets or endpoints found in the scripts.'));
      linksBox.append(card(`links (${internal.length} internal · ${external.length} external)`, { wide: true, collapsed: true, actions: copyBtn(() => links.join('\n'), 'copy') },
        h('div', { class: 'links col' }, internal.slice(0, 200).map(u => ext(u, u)))));
      if (emails.length) linksBox.append(card(`emails (${emails.length})`, { wide: true, collapsed: true, actions: copyBtn(() => emails.join('\n'), 'copy') }, h('div', { class: 'links col' }, emails.map(e => ext('mailto:' + e, e)))));
      if (comments.length) linksBox.append(card(`HTML comments (${comments.length})`, { wide: true, collapsed: true }, comments.slice(0, 40).map(c => h('pre', { class: 'json small' }, c.slice(0, 300)))));
      if (emails.length) findings.append(h('div', { class: 'riskrow' }, badge('note', 'warn'), h('span', {}, `${emails.length} email address(es) exposed in the page.`)));
      if (!findings.children.length) findings.append(h('div', { class: 'riskrow' }, badge('note', 'ok'), h('span', {}, 'no secrets, risky forms or leaked emails found on this page.')));

      summary.textContent = `done — ${links.length} links · ${forms.length} forms · ${scripts.length} scripts · ${secretCount} secret(s)`;
    })();

    return grid(
      card('live crawl', { wide: true, actions: summary },
        muted(`Fetches ${base.href} through the backend and maps its live attack surface. Does not crawl beyond the page. Authorized targets only.`),
        h('div', { class: 'statrow4' }, stat('links', sLinks), stat('forms', sForms), stat('scripts', sJS), stat('secrets', sSecret))),
      card('findings', { wide: true }, findings),
      formsBox,
      card('JavaScript — secrets & endpoints', { wide: true }, jsBox),
      linksBox,
    );
  },
};
