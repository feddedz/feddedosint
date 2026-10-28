import { h, getJSON, card, ext, linkGroups, copyBtn, grid, fmtDate, fmtNum, muted } from '../util.js';

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

// Sites without a usable public API — opened for manual checking.
const SITES = {
  social: [
    ['X / Twitter', 'https://x.com/{u}'], ['Instagram', 'https://www.instagram.com/{u}/'], ['TikTok', 'https://www.tiktok.com/@{u}'],
    ['Facebook', 'https://www.facebook.com/{u}'], ['Threads', 'https://www.threads.net/@{u}'], ['Snapchat', 'https://www.snapchat.com/add/{u}'],
    ['YouTube', 'https://www.youtube.com/@{u}'], ['Twitch', 'https://www.twitch.tv/{u}'], ['Kick', 'https://kick.com/{u}'],
    ['Pinterest', 'https://www.pinterest.com/{u}/'], ['Tumblr', 'https://{u}.tumblr.com'], ['LinkedIn', 'https://www.linkedin.com/in/{u}'],
    ['Telegram', 'https://t.me/{u}'], ['VK', 'https://vk.com/{u}'], ['Medium', 'https://medium.com/@{u}'],
    ['Substack', 'https://{u}.substack.com'], ['Quora', 'https://www.quora.com/profile/{u}'], ['Truth Social', 'https://truthsocial.com/@{u}'],
    ['Linktree', 'https://linktr.ee/{u}'], ['About.me', 'https://about.me/{u}'], ['Gravatar', 'https://gravatar.com/{u}'],
  ],
  code: [
    ['Bitbucket', 'https://bitbucket.org/{u}/'], ['Codeberg', 'https://codeberg.org/{u}'], ['SourceForge', 'https://sourceforge.net/u/{u}/profile'],
    ['PyPI', 'https://pypi.org/user/{u}/'], ['Docker Hub', 'https://hub.docker.com/u/{u}'], ['Hugging Face', 'https://huggingface.co/{u}'],
    ['Replit', 'https://replit.com/@{u}'], ['CodePen', 'https://codepen.io/{u}'], ['Kaggle', 'https://www.kaggle.com/{u}'],
    ['LeetCode', 'https://leetcode.com/u/{u}/'], ['Codewars', 'https://www.codewars.com/users/{u}'], ['Hashnode', 'https://hashnode.com/@{u}'],
    ['HackerOne', 'https://hackerone.com/{u}'], ['Bugcrowd', 'https://bugcrowd.com/{u}'], ['TryHackMe', 'https://tryhackme.com/p/{u}'],
    ['Product Hunt', 'https://www.producthunt.com/@{u}'], ['Pastebin', 'https://pastebin.com/u/{u}'], ['Trello', 'https://trello.com/u/{u}'],
  ],
  gaming: [
    ['Steam', 'https://steamcommunity.com/id/{u}'], ['Roblox', 'https://www.roblox.com/search/users?keyword={u}'],
    ['Minecraft (NameMC)', 'https://namemc.com/profile/{u}'], ['Xbox', 'https://xboxgamertag.com/search/{u}'],
    ['PlayStation', 'https://psnprofiles.com/{u}'], ['osu!', 'https://osu.ppy.sh/users/{u}'], ['Speedrun', 'https://www.speedrun.com/users/{u}'],
    ['itch.io', 'https://{u}.itch.io'], ['Duolingo', 'https://www.duolingo.com/profile/{u}'],
  ],
  'media & creative': [
    ['SoundCloud', 'https://soundcloud.com/{u}'], ['Bandcamp', 'https://{u}.bandcamp.com'], ['Last.fm', 'https://www.last.fm/user/{u}'],
    ['Behance', 'https://www.behance.net/{u}'], ['Dribbble', 'https://dribbble.com/{u}'], ['DeviantArt', 'https://www.deviantart.com/{u}'],
    ['ArtStation', 'https://www.artstation.com/{u}'], ['Flickr', 'https://www.flickr.com/people/{u}'], ['Vimeo', 'https://vimeo.com/{u}'],
    ['500px', 'https://500px.com/p/{u}'], ['Unsplash', 'https://unsplash.com/@{u}'], ['Imgur', 'https://imgur.com/user/{u}'],
    ['Letterboxd', 'https://letterboxd.com/{u}/'], ['Wattpad', 'https://www.wattpad.com/user/{u}'], ['Disqus', 'https://disqus.com/by/{u}/'],
    ['Internet Archive', 'https://archive.org/details/@{u}'],
  ],
  'money & commerce': [
    ['Patreon', 'https://www.patreon.com/{u}'], ['Ko-fi', 'https://ko-fi.com/{u}'], ['Buy Me a Coffee', 'https://buymeacoffee.com/{u}'],
    ['Cash App', 'https://cash.app/${u}'], ['Venmo', 'https://account.venmo.com/u/{u}'], ['Etsy', 'https://www.etsy.com/people/{u}'],
    ['eBay', 'https://www.ebay.com/usr/{u}'],
  ],
  'search': [
    ['Google', 'https://www.google.com/search?q=%22{u}%22'], ['Bing', 'https://www.bing.com/search?q=%22{u}%22'],
    ['DuckDuckGo', 'https://duckduckgo.com/?q=%22{u}%22'], ['Yandex', 'https://yandex.com/search/?text=%22{u}%22'],
    ['WhatsMyName', 'https://whatsmyname.app/?q={u}'], ['GitHub code', 'https://github.com/search?q=%22{u}%22&type=code'],
  ],
};

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

export default {
  id: 'username',
  label: 'username',
  placeholder: 'username or handle',
  intro: 'Checks a handle live against public APIs, then fans out to ~80 platforms for manual verification.',
  examples: ['torvalds', 'gargron'],

  run(raw) {
    const u = raw.trim().replace(/^@/, '');
    if (!u) throw new Error('enter a username');
    if (/\s/.test(u)) throw new Error('usernames cannot contain spaces — try the search tab for full names');
    const enc = encodeURIComponent(u);

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

    const allLinks = () => Object.values(SITES).flat().map(([n, t]) => `${n}: ${t.replaceAll('{u}', enc)}`).join('\n');

    return grid(
      card('live checks', { wide: true, actions: summary }, h('div', { class: 'livelist' }, rows.map(r => r.row))),
      card('manual checks', { wide: true, actions: copyBtn(allLinks, 'copy all') },
        muted('These sites block automated lookups. A page that loads a profile means the handle is taken there — not necessarily by the same person.'),
        linkGroups(Object.entries(SITES).map(([group, items]) => ({
          group, items: items.map(([n, t]) => [n, t.replaceAll('{u}', enc)]),
        })))),
    );
  },
};
