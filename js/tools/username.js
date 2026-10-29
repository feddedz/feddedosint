import { h, getJSON, card, ext, linkGroups, copyBtn, grid, fmtDate, fmtNum, muted, badge } from '../util.js';
import { SITES } from '../sites.js';
import * as be from '../backend.js';

// Live checks against public APIs that allow browser (CORS) requests.
// Each returns { state: 'found' | 'none' | 'unknown', info?: [], avatar? }.
const FOUND = (info = [], avatar) => ({ state: 'found', info: info.filter(Boolean), avatar });
const NONE = { state: 'none' };

const live = [
  {
    name: 'GitHub', url: u => `https://github.com/${u}`,
    async check(u) {
      const r = await getJSON(`https://api.github.com/users/${encodeURIComponent(u)}`);
      if (r.status === 404) return NONE;
      if (!r.ok) throw 0;
      const d = r.data;
      return FOUND([d.name, d.bio, d.location, d.company, d.blog, d.email,
        `${fmtNum(d.public_repos)} repos · ${fmtNum(d.followers)} followers`, `joined ${fmtDate(d.created_at)}`], d.avatar_url);
    },
  },
  {
    name: 'GitLab', url: u => `https://gitlab.com/${u}`,
    async check(u) {
      const r = await getJSON(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(u)}`);
      if (!r.ok) throw 0;
      const d = r.data?.[0];
      return d ? FOUND([d.name, d.state !== 'active' && d.state], d.avatar_url) : NONE;
    },
  },
  {
    name: 'Reddit', url: u => `https://www.reddit.com/user/${u}`,
    async check(u) {
      const r = await getJSON(`https://www.reddit.com/user/${encodeURIComponent(u)}/about.json`);
      if (r.status === 404) return NONE;
      if (!r.ok || !r.data?.data) throw 0;
      const d = r.data.data;
      return FOUND([`${fmtNum(d.total_karma ?? d.link_karma)} karma`, `joined ${fmtDate(d.created_utc * 1000)}`,
        d.is_suspended && 'suspended'], d.icon_img?.split('?')[0]);
    },
  },
  {
    name: 'Hacker News', url: u => `https://news.ycombinator.com/user?id=${u}`,
    async check(u) {
      const r = await getJSON(`https://hacker-news.firebaseio.com/v0/user/${encodeURIComponent(u)}.json`);
      if (!r.ok) throw 0;
      const d = r.data;
      return d ? FOUND([`${fmtNum(d.karma)} karma`, `joined ${fmtDate(d.created * 1000)}`]) : NONE;
    },
  },
  {
    name: 'Bluesky', url: u => `https://bsky.app/profile/${u.includes('.') ? u : u + '.bsky.social'}`,
    async check(u) {
      const actor = u.includes('.') ? u : `${u}.bsky.social`;
      const r = await getJSON(`https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(actor.toLowerCase())}`);
      if (r.status === 400 || r.status === 404) return NONE;
      if (!r.ok) throw 0;
      const d = r.data;
      return FOUND([d.displayName, d.description, `${fmtNum(d.followersCount)} followers · ${fmtNum(d.postsCount)} posts`,
        d.createdAt && `joined ${fmtDate(d.createdAt)}`], d.avatar);
    },
  },
  {
    name: 'Mastodon (.social)', url: u => `https://mastodon.social/@${u}`,
    async check(u) {
      const r = await getJSON(`https://mastodon.social/api/v1/accounts/lookup?acct=${encodeURIComponent(u)}`);
      if (r.status === 404) return NONE;
      if (!r.ok) throw 0;
      const d = r.data;
      return FOUND([d.display_name, `${fmtNum(d.followers_count)} followers · ${fmtNum(d.statuses_count)} posts`,
        `joined ${fmtDate(d.created_at)}`], d.avatar_static);
    },
  },
  {
    name: 'Keybase', url: u => `https://keybase.io/${u}`,
    async check(u) {
      const r = await getJSON(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(u)}&fields=basics,profile,proofs_summary,pictures`);
      if (r.data?.them?.[0] === null) return NONE;
      const d = r.data?.them?.[0];
      if (!d) throw 0;
      const proofs = (d.proofs_summary?.all || []).map(p => `${p.proof_type}: ${p.nametag}`);
      return FOUND([d.profile?.full_name, d.profile?.location, ...proofs], d.pictures?.primary?.url);
    },
  },
  {
    name: 'Chess.com', url: u => `https://www.chess.com/member/${u}`,
    async check(u) {
      const r = await getJSON(`https://api.chess.com/pub/player/${encodeURIComponent(u.toLowerCase())}`);
      if (r.status === 404 || r.status === 410) return NONE;
      if (!r.ok) throw 0;
      const d = r.data;
      return FOUND([d.name, d.location, d.country?.split('/').pop(), `joined ${fmtDate(d.joined * 1000)}`], d.avatar);
    },
  },
  {
    name: 'Lichess', url: u => `https://lichess.org/@/${u}`,
    async check(u) {
      const r = await getJSON(`https://lichess.org/api/user/${encodeURIComponent(u)}`);
      if (r.status === 404) return NONE;
      if (!r.ok) throw 0;
      const d = r.data;
      return FOUND([d.profile?.realName, d.profile?.location, d.count && `${fmtNum(d.count.all)} games`,
        `joined ${fmtDate(d.createdAt)}`, d.disabled && 'closed account']);
    },
  },
  {
    name: 'npm', url: u => `https://www.npmjs.com/~${u}`,
    async check(u) {
      const r = await getJSON(`https://registry.npmjs.org/-/v1/search?text=maintainer:${encodeURIComponent(u.toLowerCase())}&size=5`);
      if (!r.ok) throw 0;
      const objs = r.data?.objects || [];
      // the search is fuzzy, so confirm the exact maintainer name
      const exact = objs.filter(o => o.package.maintainers?.some(m => m.username === u.toLowerCase()));
      return exact.length ? FOUND([`${fmtNum(r.data.total)} packages`, exact.map(o => o.package.name).join(', ')]) : NONE;
    },
  },
  {
    name: 'Wikipedia', url: u => `https://en.wikipedia.org/wiki/User:${u}`,
    async check(u) {
      const r = await getJSON(`https://en.wikipedia.org/w/api.php?action=query&list=users&ususers=${encodeURIComponent(u)}&usprop=editcount|registration|blockinfo&format=json&origin=*`);
      const d = r.data?.query?.users?.[0];
      if (!d) throw 0;
      if ('missing' in d || 'invalid' in d) return NONE;
      return FOUND([`${fmtNum(d.editcount)} edits`, d.registration && `joined ${fmtDate(d.registration)}`, d.blockid && 'blocked']);
    },
  },
  {
    name: 'DEV', url: u => `https://dev.to/${u}`,
    async check(u) {
      const r = await getJSON(`https://dev.to/api/users/by_username?url=${encodeURIComponent(u)}`);
      if (r.status === 404) return NONE;
      if (!r.ok) throw 0;
      const d = r.data;
      return FOUND([d.name, d.summary, d.location, d.joined_at && `joined ${d.joined_at}`], d.profile_image);
    },
  },
];

function liveRow(site, u) {
  const status = h('span', { class: 'dot pending', title: 'checking' });
  const detail = h('div', { class: 'detail muted' }, 'checking…');
  const avatar = h('div', { class: 'avatar' });
  const row = h('div', { class: 'liverow pending' }, status, avatar,
    h('div', { class: 'main' }, ext(site.url(encodeURIComponent(u)), site.name), detail));

  const done = site.check(u).catch(() => ({ state: 'unknown' })).then(res => {
    row.className = `liverow ${res.state}`;
    status.className = `dot ${res.state}`;
    status.title = res.state;
    if (res.state === 'found') {
      detail.replaceChildren(res.info.length ? res.info.join(' · ') : 'account exists');
      detail.className = 'detail';
      if (res.avatar) avatar.append(h('img', { src: res.avatar, alt: '', loading: 'lazy', referrerpolicy: 'no-referrer', onerror: e => e.target.remove() }));
    } else if (res.state === 'none') {
      detail.textContent = 'not found';
    } else {
      detail.textContent = 'could not check automatically — open to verify';
    }
    return res.state;
  });
  return { row, done };
}

// ---------- deep scan across the full WhatsMyName site list ----------

function scanRow(spec, u, state, status) {
  const dot = h('span', { class: `dot ${state}`, title: state });
  const url = spec.u.replace(/\{u\}/g, encodeURIComponent(u));
  const detail = state === 'found' ? 'profile exists'
    : state === 'unknown' ? `could not verify${status ? ` (HTTP ${status})` : ''} — open to check`
    : 'not found';
  return h('div', { class: `liverow ${state}` }, dot, h('div', { class: 'avatar' }),
    h('div', { class: 'main' }, ext(url, spec.n), badge(spec.c, 'muted'), h('div', { class: 'detail muted' }, detail)));
}

function deepScanCard(u) {
  const enc = encodeURIComponent(u);
  const adult = h('input', { type: 'checkbox' });
  const filter = h('select', { class: 'mini' },
    h('option', { value: 'found' }, 'found only'),
    h('option', { value: 'open' }, 'found + unverified'),
    h('option', { value: 'all' }, 'everything'));
  const startBtn = h('button', { class: 'mini', type: 'button' }, `deep scan ${SITES.length} sites`);
  const stopBtn = h('button', { class: 'mini', type: 'button', hidden: true }, 'stop');
  const bar = h('div', { class: 'barfill' });
  const progress = h('div', { class: 'scanbar' }, bar);
  const summary = h('span', { class: 'muted small' }, `${SITES.length} sites ready`);
  const list = h('div', { class: 'livelist' });
  const found = [];               // collected hits, in order
  const copyFound = copyBtn(() => found.map(f => `${f.n}: ${f.url}`).join('\n') || 'no hits yet', 'copy found');

  const relabel = () => {
    const f = filter.value;
    list.querySelectorAll('.liverow').forEach(r => {
      const st = r.dataset.state;
      r.hidden = !(f === 'all' || (f === 'open' && st !== 'none') || (f === 'found' && st === 'found'));
    });
  };
  filter.addEventListener('change', relabel);

  let controller = null;
  const setRunning = on => {
    startBtn.hidden = on; stopBtn.hidden = !on;
    adult.disabled = on;
  };

  async function run() {
    const set = SITES.filter(s => adult.checked || s.c !== 'adult');
    list.replaceChildren(); found.length = 0;
    controller = new AbortController();
    setRunning(true);
    let checked = 0, nFound = 0;
    const tick = () => {
      bar.style.width = `${Math.round((checked / set.length) * 100)}%`;
      summary.textContent = `${checked}/${set.length} checked · ${nFound} found`;
    };
    tick();
    try {
      await be.deepScan(u, set, {
        signal: controller.signal,
        onBatch(batch, results) {
          batch.forEach((spec, i) => {
            const res = results[i] || { state: 'unknown' };
            checked++;
            if (res.state === 'found') {
              nFound++;
              found.push({ n: spec.n, url: res.url || spec.u.replace(/\{u\}/g, enc), cat: spec.c });
            }
            const row = scanRow(spec, u, res.state, res.status);
            row.dataset.state = res.state;
            // keep found rows at the top, everything else after
            if (res.state === 'found') list.prepend(row); else list.append(row);
          });
          tick(); relabel();
        },
      });
      summary.textContent = `done · ${nFound} found across ${set.length} sites`;
    } catch (e) {
      summary.textContent = 'scan error — ' + (e?.message || 'failed');
    } finally {
      bar.style.width = '100%';
      setRunning(false);
    }
  }

  startBtn.addEventListener('click', run);
  stopBtn.addEventListener('click', () => { controller?.abort(); summary.textContent += ' · stopped'; setRunning(false); });

  const opts = h('div', { class: 'scanopts' },
    h('label', { class: 'muted small' }, adult, ' include adult sites'),
    h('label', { class: 'muted small' }, 'show ', filter),
    copyFound);

  return card('deep scan — every site', { wide: true, actions: h('div', { class: 'actions' }, summary, startBtn, stopBtn) },
    muted(`Runs ${SITES.length} existence checks server-side (real status codes + page markers, no browser blocking). Results stream in as they finish; a hit means the handle is registered there, not necessarily by the same person.`),
    opts, progress, list);
}

export default {
  id: 'username',
  label: 'username',
  placeholder: 'username or handle',
  intro: 'Checks a handle live against public APIs, then deep-scans ~700 platforms server-side for every account using that name.',
  examples: ['torvalds', 'gargron'],

  run(raw) {
    const u = raw.trim().replace(/^@/, '');
    if (!u) throw new Error('enter a username');
    if (/\s/.test(u)) throw new Error('usernames cannot contain spaces — try the search tab for full names');

    const summary = h('span', { class: 'muted' }, 'checking…');
    const rows = live.map(s => liveRow(s, u));
    Promise.all(rows.map(r => r.done)).then(states => {
      const n = s => states.filter(x => x === s).length;
      summary.textContent = `${n('found')} found · ${n('none')} not found · ${n('unknown')} unverified`;
      // float hits to the top
      const list = rows[0].row.parentElement;
      for (const state of ['unknown', 'none', 'found']) {
        rows.filter((r, i) => states[i] === state).reverse().forEach(r => list.prepend(r.row));
      }
    });

    const cards = [
      card('live checks — rich profiles', { wide: true, actions: summary }, h('div', { class: 'livelist' }, rows.map(r => r.row))),
    ];

    // Deep scan needs the backend (server-side fetch) and an approved account.
    if (be.backendConfigured() && be.isApproved()) {
      cards.push(deepScanCard(u));
    } else {
      const why = !be.backendConfigured() ? 'the backend is not configured'
        : !be.isLoggedIn() ? 'sign in with GitHub to run it'
        : 'your account needs admin approval to run it';
      const enc = encodeURIComponent(u);
      const pub = SITES.filter(s => s.c !== 'adult');
      const byCat = {};
      for (const s of pub) (byCat[s.c] ||= []).push([s.n, s.u.replace(/\{u\}/g, enc)]);
      cards.push(card('manual checks', { wide: true, collapsed: true,
        actions: copyBtn(() => pub.map(s => `${s.n}: ${s.u.replace(/\{u\}/g, enc)}`).join('\n'), 'copy all') },
        muted(`Deep scan is unavailable (${why}). Meanwhile, open these ${pub.length} sites manually — a profile that loads means the handle is taken there.`),
        linkGroups(Object.entries(byCat).map(([group, items]) => ({ group, items })))));
    }

    return grid(...cards);
  },
};
