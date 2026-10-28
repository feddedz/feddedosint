import { h, dns, sha256, card, asyncCard, kv, ext, pivot, linkGroups, grid, muted } from '../util.js';
import { fingerprint } from './domain.js';

const FREE = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com',
  'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.de', 'gmx.net', 'web.de',
  'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'tutanota.com', 'tuta.io', 'fastmail.com', 'hey.com', 'qq.com', '163.com']);

const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'sharklasers.com', '10minutemail.com',
  'temp-mail.org', 'tempmail.com', 'tempmail.net', 'throwawaymail.com', 'yopmail.com', 'yopmail.net', 'getnada.com', 'nada.email',
  'trashmail.com', 'dispostable.com', 'maildrop.cc', 'mintemail.com', 'mohmal.com', 'emailondeck.com', 'fakeinbox.com',
  'mailnesia.com', 'mytemp.email', 'tempail.com', 'tempr.email', 'discard.email', 'spamgourmet.com', 'mailcatch.com',
  'burnermail.io', 'inboxkitten.com', 'mail.tm', 'tmail.ws', 'emailfake.com', '33mail.com', 'anonaddy.me', 'simplelogin.com',
  'duck.com', 'relay.firefox.com', 'mozmail.com', 'privaterelay.appleid.com']);

const RELAY = new Set(['duck.com', 'mozmail.com', 'relay.firefox.com', 'privaterelay.appleid.com', 'simplelogin.com', 'anonaddy.me', '33mail.com']);

export default {
  id: 'email',
  label: 'email',
  placeholder: 'name@example.com',
  intro: 'Gravatar profile, mail provider & domain security, disposable/relay detection, breach and account-discovery pivots.',
  examples: ['test@example.com'],

  run(raw) {
    const email = raw.trim().toLowerCase();
    const m = email.match(/^([^\s@]+)@([a-z0-9.-]+\.[a-z]{2,})$/i);
    if (!m) throw new Error('that does not look like an email address');
    const [, local, domain] = m;
    const enc = encodeURIComponent(email);
    const base = local.split('+')[0];
    const kind = RELAY.has(domain) ? 'privacy relay / alias — the real inbox is hidden'
      : DISPOSABLE.has(domain) ? 'disposable / temporary inbox'
      : FREE.has(domain) ? 'free webmail provider' : 'custom / organisation domain';

    return grid(
      card('overview', {}, kv([
        ['address', h('span', { class: 'mono' }, email)],
        ['local part', [pivot('username', base), base !== local ? h('span', { class: 'muted' }, `  (+tag: ${local.slice(base.length + 1)})`) : null]],
        ['domain', pivot('domain', domain)],
        ['type', kind],
      ])),

      asyncCard('gravatar', async () => {
        const hash = await sha256(email);
        return new Promise(resolve => {
          const img = h('img', { src: `https://gravatar.com/avatar/${hash}?d=404&s=240`, alt: 'gravatar', referrerpolicy: 'no-referrer' });
          img.onload = () => resolve([h('div', { class: 'gravatar' }, img),
            ext(`https://gravatar.com/${hash}`, 'open gravatar profile')]);
          img.onerror = () => resolve(muted('no gravatar for this address.'));
        });
      }),

      asyncCard('mail domain', async () => {
        const [mx, txt, dmarc] = await Promise.all([
          dns(domain, 'MX'), dns(domain, 'TXT').catch(() => []), dns(`_dmarc.${domain}`, 'TXT').catch(() => []),
        ]);
        const services = fingerprint([...mx, ...txt].map(r => r.data));
        const spf = txt.some(r => /^v=spf1/i.test(r.data));
        const dm = dmarc.find(r => /^v=DMARC1/i.test(r.data))?.data;
        return kv([
          ['accepts mail', mx.length ? 'yes' : 'no MX records — this address cannot receive mail'],
          ['mx', mx.map(r => h('div', { class: 'mono' }, r.data))],
          ['provider', services.join(', ')],
          ['spf / dmarc', `${spf ? 'spf ✓' : 'spf ✗'} · ${dm ? `dmarc ✓ (p=${dm.match(/;\s*p=(\w+)/i)?.[1] || '?'})` : 'dmarc ✗'}`],
        ]);
      }),

      card('pivot further', { wide: true },
        muted('Use responsibly — only research people or organisations you are authorised to look into.'),
        linkGroups([
          { group: 'verification & exposure', items: [
            ['Have I Been Pwned', 'https://haveibeenpwned.com/'], ['Hunter verify', `https://hunter.io/email-verifier/${enc}`],
          ] },
          { group: 'public footprint', items: [
            ['GitHub commits', `https://github.com/search?q=${enc}&type=commits`], ['GitHub users', `https://github.com/search?q=${enc}&type=users`],
            ['PGP keyserver', `https://keys.openpgp.org/search?q=${enc}`],
          ] },
          { group: 'search', items: [
            ['Google', `https://www.google.com/search?q=%22${enc}%22`], ['Bing', `https://www.bing.com/search?q=%22${enc}%22`],
            ['DuckDuckGo', `https://duckduckgo.com/?q=%22${enc}%22`], ['Pastes', `https://www.google.com/search?q=%22${enc}%22+site%3Apastebin.com`],
          ] },
        ])),
    );
  },
};
