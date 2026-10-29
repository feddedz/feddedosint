import { h, getJSON, card, ext, copyBtn, grid, fmtDate, fmtNum, muted, badge } from '../util.js';
import { SITES } from '../sites.js';
import * as be from '../backend.js';

// Rich checks against public APIs that allow browser (CORS) requests — these return real
// profile detail (name, bio, followers, join date) and run client-side with no backend.
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
    name: 'Mastodon', url: u => `https://mastodon.social/@${u}`,
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

// Big platforms to surface first when results come in (and to prioritise in the capped fallback).
const POPULAR = new Set(['instagram', 'tiktok', 'x', 'twitter', 'youtube', 'facebook', 'snapchat', 'pinterest', 'twitch',
  'steam', 'spotify', 'soundcloud', 'telegram', 'tumblr', 'medium', 'patreon', 'onlyfans', 'linktree', 'cash app', 'venmo',
  'discord', 'vsco', 'flickr', 'vimeo', 'dribbble', 'behance', 'deviantart', 'replit', 'codepen', 'kaggle', 'docker hub',
  'hackerone', 'buymeacoffee', 'ko-fi', 'gumroad', 'kick', 'roblox', 'xbox gamertag', 'wattpad', 'goodreads', 'letterboxd',
  'last.fm', 'bandcamp', 'about.me', 'gravatar', 'paypal', 'fiverr', 'etsy', 'ebay', 'imgur', 'quora', 'pastebin', 'trello']);

const liveNames = new Set(live.map(s => s.name.toLowerCase()));

// A single result row. Found rows are pulled to the top; not-found rows are never created.
function makeRow(list, name, url, cat, state, applyFilter) {
  const dot = h('span', { class: `dot ${state}`, title: state });
  const av = h('div', { class: 'avatar' });
  const detail = h('div', { class: 'detail muted' }, state === 'pending' ? 'checking…' : '');
  const el = h('div', { class: `liverow ${state}`, dataset: { state } }, dot, av,
    h('div', { class: 'main' }, ext(url, name), cat ? badge(cat, 'muted') : null, detail));
  if (state === 'found') list.prepend(el); else list.append(el);
  applyFilter(el);
  return {
    el,
    update(st, info, avatar) {
      if (st === 'none') { el.remove(); return; }   // not-found is counted, never shown
      el.className = `liverow ${st}`; el.dataset.state = st;
      dot.className = `dot ${st}`; dot.title = st;
      detail.textContent = info || (st === 'found' ? 'account exists' : st === 'unknown' ? 'could not verify automatically — open to check' : 'not found');
      detail.className = 'detail' + (info ? '' : ' muted');
      if (avatar) av.append(h('img', { src: avatar, alt: '', loading: 'lazy', referrerpolicy: 'no-referrer', onerror: e => e.target.remove() }));
      if (st === 'found') list.prepend(el);
      applyFilter(el);
    },
  };
}

export default {
  id: 'username',
  label: 'username',
  placeholder: 'username or handle',
  intro: 'Type a handle and it automatically checks it against ~700 platforms, showing every account that uses the name.',
  examples: ['torvalds', 'gargron'],

  run(raw) {
    const u = raw.trim().replace(/^@/, '');
    if (!u) throw new Error('enter a username');
    if (/\s/.test(u)) throw new Error('usernames cannot contain spaces — try the search tab for full names');
    const enc = encodeURIComponent(u);

    const summary = h('span', { class: 'muted small' }, 'starting…');
    const stopBtn = h('button', { class: 'mini', type: 'button', hidden: true }, 'stop');
    const showUnverified = h('input', { type: 'checkbox' });
    const includeAdult = h('input', { type: 'checkbox' });
    const bar = h('div', { class: 'barfill' });
    const list = h('div', { class: 'livelist' });
    const note = h('p', { class: 'muted small', hidden: true });
    const found = [];
    const copyFound = copyBtn(() => found.map(f => `${f.n}: ${f.url}`).join('\n') || 'no accounts found yet', 'copy found');

    const applyFilter = el => {
      const st = el.dataset.state;
      // found + still-checking are always shown; not-found is hidden; unverified only when asked
      el.hidden = st === 'none' || (st === 'unknown' && !showUnverified.checked);
    };
    const refilter = () => list.querySelectorAll('.liverow').forEach(applyFilter);
    showUnverified.addEventListener('change', refilter);

    let liveDone = 0, scanTotal = 0, scanDone = 0;
    const tick = () => {
      const f = list.querySelectorAll('.liverow.found').length;
      const unv = list.querySelectorAll('.liverow.unknown').length;
      const total = live.length + scanTotal;
      const done = liveDone + scanDone;
      bar.style.width = `${total ? Math.round((done / total) * 100) : 5}%`;
      summary.textContent = `${f} found · ${unv} to verify · ${done}/${total} checked`;
    };

    let controller = null;
    const setRunning = on => { stopBtn.hidden = !on; includeAdult.disabled = on; bar.classList.toggle('run', on); };

    // --- client-side rich checks (always run, no backend needed) ---
    function runLive() {
      for (const site of live) {
        const row = makeRow(list, site.name, site.url(enc), 'api', 'pending', applyFilter);
        site.check(u).then(res => (res.state === 'found' ? res : res || NONE)).catch(() => ({ state: 'unknown' }))
          .then(res => {
            liveDone++;
            if (res.state === 'found') { row.update('found', res.info?.length ? res.info.join(' · ') : '', res.avatar); found.push({ n: site.name, url: site.url(enc) }); }
            else row.update(res.state === 'none' ? 'none' : 'unknown');
            tick();
          });
      }
    }

    // --- backend deep scan across the full list ---
    async function runScan() {
      const set = SITES
        .filter(s => (includeAdult.checked || s.c !== 'adult') && !liveNames.has(s.n.toLowerCase()))
        .sort((a, b) => (POPULAR.has(b.n.toLowerCase()) ? 1 : 0) - (POPULAR.has(a.n.toLowerCase()) ? 1 : 0));
      scanTotal = set.length; scanDone = 0;
      controller = new AbortController();
      setRunning(true); tick();
      try {
        const r = await be.deepScan(u, set, {
          signal: controller.signal,
          onMode(mode, error) {
            if (mode === 'blocked') { note.hidden = false; note.textContent = 'deep scan blocked — ' + (error || 'account not approved'); }
            else if (mode === 'fetch') { note.hidden = false; note.textContent = 'running a limited scan through /fetch — re-deploy the Worker (it adds /check) to scan all ~700 sites fast.'; }
            else note.hidden = true;
          },
          onBatch(batch, results) {
            batch.forEach((spec, i) => {
              const res = results[i] || { state: 'unknown' };
              scanDone++;
              const url = res.url || spec.u.replace(/\{u\}/g, enc);
              if (res.state === 'found') { makeRow(list, spec.n, url, spec.c, 'found', applyFilter); found.push({ n: spec.n, url }); }
              else if (res.state === 'unknown') makeRow(list, spec.n, url, spec.c, 'unknown', applyFilter);
              // 'none' is counted only — no row, no clutter
            });
            tick();
          },
        });
        scanDone = scanTotal;
        if (r?.partial) { note.hidden = false; note.textContent = `limited scan: checked the top ${r.scanned} sites. Re-deploy the Worker (adds /check) to scan all ~700 automatically.`; }
        tick();
      } catch (e) {
        note.hidden = false; note.textContent = 'scan error — ' + (e?.message || 'failed');
      } finally {
        setRunning(false);
        summary.textContent = summary.textContent.replace(/checked$/, 'checked · done');
      }
    }

    function start() {
      controller?.abort();
      list.replaceChildren(); found.length = 0; liveDone = 0; scanDone = 0; scanTotal = 0;
      runLive();
      if (be.backendConfigured() && be.isApproved()) runScan();
      else {
        note.hidden = false;
        note.textContent = be.backendConfigured()
          ? (be.isLoggedIn() ? 'sign-in approved only: the full 700-site auto-scan needs admin approval. The API checks above still run.' : 'sign in with GitHub to auto-scan all ~700 sites. The API checks above still run.')
          : 'connect the backend in settings to auto-scan all ~700 sites. The API checks above still run.';
        tick();
      }
    }

    includeAdult.addEventListener('change', start);
    stopBtn.addEventListener('click', () => { controller?.abort(); setRunning(false); note.hidden = false; note.textContent = 'scan stopped.'; });

    // Kick everything off once the card is in the DOM.
    requestAnimationFrame(start);

    const controls = h('div', { class: 'scanopts' },
      h('label', { class: 'muted small' }, showUnverified, ' show unverified'),
      h('label', { class: 'muted small' }, includeAdult, ' include adult sites'),
      copyFound);

    return grid(card('accounts', { wide: true, actions: h('div', { class: 'actions' }, summary, stopBtn) },
      muted('Checks run automatically — rich profile data from open APIs first, then the full platform sweep through your backend. Found accounts rise to the top; a hit means the handle is registered there, not necessarily by the same person.'),
      controls, h('div', { class: 'scanbar' }, bar), note, list));
  },
};
