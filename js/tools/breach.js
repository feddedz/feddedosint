import { h, getJSON, getText, card, asyncCard, kv, ext, pivot, grid, muted, badge, copyBtn, fmtNum, fmtDate } from '../util.js';
import { getKey, hasKey } from '../store.js';

const td = new TextEncoder();
async function sha1Hex(text) {
  const buf = await crypto.subtle.digest('SHA-1', td.encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

const strength = pw => {
  let s = 0;
  if (pw.length >= 8) s++; if (pw.length >= 12) s++; if (pw.length >= 16) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++; if (/[^\w]/.test(pw)) s++;
  return ['very weak', 'weak', 'weak', 'fair', 'good', 'strong', 'very strong'][Math.min(s, 6)];
};

// Password exposure via k-anonymity: only the first 5 chars of the SHA-1 hash ever leave the browser.
async function checkPassword(pw) {
  const hash = await sha1Hex(pw);
  const prefix = hash.slice(0, 5), suffix = hash.slice(5);
  const r = await getText(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } });
  if (!r.ok) throw new Error(`Pwned Passwords returned HTTP ${r.status}`);
  const line = r.text.split('\n').find(l => l.split(':')[0].trim() === suffix);
  const count = line ? parseInt(line.split(':')[1], 10) : 0;
  return { count, hash, strength: strength(pw) };
}

function passwordCard(pw) {
  return asyncCard('password exposure', async () => {
    const { count, hash, strength } = await checkPassword(pw);
    const seen = count > 0;
    return [
      h('div', { class: 'verdict ' + (seen ? 'bad' : 'ok') },
        seen ? `⚠ found in known breaches ${fmtNum(count)} times` : '✓ not found in any known breach'),
      kv([
        ['strength', badge(strength, /strong|good/.test(strength) ? 'ok' : 'warn')],
        ['sha-1', h('code', { class: 'wrap small' }, hash)],
        ['sent to server', h('code', {}, hash.slice(0, 5) + '…') ],
      ]),
      note(seen
        ? 'This exact password is circulating in breach corpora — do not use it anywhere. Change it and enable 2FA on affected accounts.'
        : 'Not in the corpus, which is good, but that is no guarantee it is strong or private. Use a unique passphrase per site.'),
      note('Privacy: your password is hashed locally and only the first 5 characters of that hash are sent (k-anonymity). The service never sees the password or the full hash.'),
    ];
  });
}

function emailCard(email) {
  if (!hasKey('hibp')) {
    return card('email breaches', { wide: true },
      muted('Live email breach search needs a free Have I Been Pwned API key (the account endpoint is not open to browsers without one).'),
      h('p', {}, 'Add your key in ', pivot('settings', 'keys', 'Settings'), ', then search again. Meanwhile you can check manually:'),
      h('div', { class: 'links' }, [
        ['Have I Been Pwned', `https://haveibeenpwned.com/`],
        ['Firefox Monitor', `https://monitor.mozilla.org/`],
      ].map(([n, u]) => ext(u, n))));
  }
  return asyncCard('email breaches', async () => {
    const r = await getJSON(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      { headers: { 'hibp-api-key': getKey('hibp') } });
    if (r.status === 404) return h('div', { class: 'verdict ok' }, '✓ no breaches found for this address');
    if (r.status === 401) throw new Error('HIBP rejected the API key — check it in Settings');
    if (r.status === 429) throw new Error('rate limited by HIBP — wait a moment and retry');
    if (!r.ok || !Array.isArray(r.data)) throw new Error(`HIBP returned HTTP ${r.status}`);
    const breaches = r.data.sort((a, b) => (b.BreachDate || '').localeCompare(a.BreachDate || ''));
    const classes = [...new Set(breaches.flatMap(b => b.DataClasses || []))];
    return [
      h('div', { class: 'verdict bad' }, `⚠ found in ${breaches.length} breach${breaches.length > 1 ? 'es' : ''}`),
      h('p', { class: 'muted small' }, 'data types exposed across these breaches:'),
      h('div', { class: 'tags' }, classes.map(c => badge(c, /password|bank|credit/i.test(c) ? 'bad' : 'muted'))),
      h('div', { class: 'breach-list' }, breaches.map(b => h('div', { class: 'breach-item' },
        h('div', { class: 'bi-head' }, h('strong', {}, b.Title), h('span', { class: 'muted small' }, fmtDate(b.BreachDate))),
        h('div', { class: 'muted small' }, `${fmtNum(b.PwnCount)} accounts · `, pivotDomain(b.Domain)),
        h('div', { class: 'tags' }, (b.DataClasses || []).slice(0, 8).map(c => badge(c)))))),
    ];
  }, { wide: true });
}

const pivotDomain = d => d ? pivot('domain', d) : h('span', { class: 'muted' }, 'n/a');

export default {
  id: 'breach',
  label: 'breach',
  placeholder: 'your email, or a password to test',
  intro: 'Check whether your own email or password appears in known data breaches. Passwords are tested with k-anonymity — they never leave your browser.',
  examples: [],
  allowEmpty: true,

  run(raw) {
    const input = raw.trim();
    const isEmail = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i.test(input);

    if (!input) {
      return grid(
        card('check your exposure', { wide: true },
          muted('Enter an email address to search known breaches (needs a free HIBP key), or type a password to test it safely against the Pwned Passwords corpus.'),
          h('div', { class: 'tags' }, [badge('email → breach list'), badge('password → k-anonymity check'), badge('nothing stored')])),
        breachLibraryCard(),
      );
    }

    if (isEmail) {
      return grid(
        card('overview', {}, kv([['address', h('code', {}, input)], ['domain', pivot('domain', input.split('@')[1])],
          ['also check', pivot('email', input, 'full email intel →')]])),
        emailCard(input),
        breachLibraryCard(),
      );
    }

    // treat anything else as a password to test
    return grid(
      passwordCard(input),
      card('about this check', {}, muted('Typed a password, not an email. It is being tested with k-anonymity: hashed locally, and only the first 5 hash characters are sent. To search an email instead, type a full address.')),
    );
  },
};

// Public, non-sensitive catalogue of known breaches (names, dates, sizes, data types).
function breachLibraryCard() {
  let all = [];
  return asyncCard('breach library', async () => {
    const r = await getJSON('https://haveibeenpwned.com/api/v3/breaches', { timeout: 20000 });
    if (!r.ok || !Array.isArray(r.data)) throw new Error('could not load the breach catalogue');
    all = r.data.sort((a, b) => (b.BreachDate || '').localeCompare(a.BreachDate || ''));
    const list = h('div', { class: 'breach-list' });
    const render = term => {
      const t = term.toLowerCase();
      const rows = all.filter(b => !t || b.Name.toLowerCase().includes(t) || (b.Domain || '').includes(t)).slice(0, 120);
      list.replaceChildren(...rows.map(b => h('div', { class: 'breach-item' },
        h('div', { class: 'bi-head' }, h('strong', {}, b.Title),
          h('span', { class: 'muted small' }, fmtDate(b.BreachDate))),
        h('div', { class: 'muted small' }, `${fmtNum(b.PwnCount)} accounts · ${b.Domain ? b.Domain : 'n/a'}`),
        h('div', { class: 'tags' }, (b.DataClasses || []).slice(0, 6).map(c => badge(c, /password|bank|credit/i.test(c) ? 'bad' : 'muted'))))));
    };
    render('');
    const filter = h('input', { class: 'filter', placeholder: `search ${all.length} known breaches…`, oninput: e => render(e.target.value.trim()) });
    return [h('div', { class: 'row' }, filter, copyBtn(() => all.map(b => `${b.Title}\t${b.BreachDate}\t${b.PwnCount}`).join('\n'), 'copy')), list];
  }, { wide: true });
}

const note = t => h('p', { class: 'muted small' }, t);
