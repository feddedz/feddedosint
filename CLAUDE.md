# feddedosint — project guide for Claude

This file auto-loads into every Claude Code session on this repo. Read it before working.
feddedosint is a **public-data OSINT toolkit** (a static site + one Cloudflare Worker). Keep
that framing: everything operates on public sources and targets the user's own assets or
subjects they're authorized to investigate. See **§9 Scope & boundary** before accepting a feature.

---

## 0. Worklog rule — DOCUMENT EVERYTHING

**Every time you change something in this repo, append an entry to [`WORKLOG.md`](WORKLOG.md)**
— code changes, new tools, Worker edits, config, deploys, fixes. Do it in the same change as
the work (so the log ships with it). Use a UTC timestamp. Format, newest first at the top of the
log's entries:

```
### 2026-10-29 09:00 UTC — <short title>
- what changed and why (1–4 bullets)
- files: path/one.js, path/two.js
- PR: #NN (merged) — or "not yet shipped"
```

Get the timestamp with `date -u '+%Y-%m-%d %H:%M UTC'`. Don't rewrite old entries; only add new
ones. If a change is trivial (typo), one line is fine. This keeps a durable history across
sessions since containers are ephemeral.

---

## 1. What it is

- Static single-page app on **GitHub Pages**: `feddedz.github.io/feddedosint`.
- Vanilla JS **ES modules, no build step**. A tiny `h()` DOM helper, hash routing (`#tool/value`).
- One **Cloudflare Worker** (`worker/worker.js`) shared by all visitors: GitHub login, an admin
  approval gate, a hidden Gemini key for the AI, and two proxies (`/fetch`, `/check`) so the
  browser can reach sites it otherwise can't (CORS / server-side existence checks).
- Dark, minimal UI; mouse-following snow background.
- **Members only:** `js/lock.js` hides the whole app until the visitor is signed in with GitHub
  *and* approved. Every visitor uses the one shared Worker,
  `https://feddedosint-api.bptiktok6.workers.dev` (hardcoded as `BACKEND` in `js/backend.js`).

## 2. Repo layout

```
index.html              entry; favicon data-URI, theme-color, loads js/app.js
css/style.css           all styling (CSS vars; dark default, light via [data-theme])
js/app.js               tool registry (GROUPS), sidebar, router, command palette
js/util.js              h(), getJSON/getText, dns() (DoH), RDAP helpers, UI blocks (card/grid/kv/
                        asyncCard/badge/pivot/copyBtn/linkGroups/mdLite), validation (isIP, normDomain…)
js/store.js             localStorage: settings, session, API keys, recent, graph, case
js/lock.js              sign-in wall (lockReason/renderLock), checked by app.js route()
js/backend.js           client for the Worker (auth, admin, aiChat, aiStream, deepScan, fetchUrl)
js/collect.js           structured collection (domain/ip/asn/url/email) used by engine + chat
js/sites.js             ~700 platform specs (WhatsMyName dataset) for the username deep scan
js/icons.js snow.js leaflet.js md5.js ai.js gate.js   support modules
js/tools/*.js           one module per tool (see §4)
worker/worker.js        the backend (see §5)
worker/worker.test.mjs  Node logic tests for the Worker
worker/wrangler.toml    Worker config (vars); worker/README.md has setup steps
```

## 3. How a tool is built (the contract)

Each `js/tools/<id>.js` default-exports:

```js
export default {
  id: 'thing', label: 'thing', placeholder: '…', intro: '…', examples: ['a','b'],
  allowEmpty: false,                       // optional
  run(rawInput) { /* return a DOM Node, an array of Nodes, or a Promise of either */ },
};
```

- Build DOM with `h(tag, attrs, ...children)` from `util.js`. Never set innerHTML on
  untrusted/model/page text — build nodes (see `mdLite`).
- Lay out with `grid(card(title, {wide, actions, collapsed}, ...body), …)`.
- `asyncCard(title, async () => body)` shows a spinner then fills or shows an error.
- Cross-tool links: `pivot(tool, value, label)` (records a graph edge); external: `ext(url, text)`.
- Register in `js/app.js`: import it, add to the right `GROUPS` entry, add `TITLES` + `BLURBS`
  lines. To surface it from universal search, add it to `js/tools/overview.js` (`TOOLS` map +
  a `classify()` rule).

## 4. Current tools

- **search** (overview) — detects input type, runs the best tool, offers related ones.
- **identity:** username (auto deep-scan ~700 sites + rich API checks), email, phone, breach.
- **network:** recon (attack-surface mapper), domain, ip, asn, url, mac, cidr.
- **geo:** geo, map (Leaflet infrastructure map).
- **assets:** crypto (btc/eth), image, file (static triage + hash).
- **threat:** cve, headers (email header analysis).
- **research:** records, dorks (search-operator builder).
- **tools:** extract (IOCs from text), utils (encode/decode/hash).
- **intelligence:** engine (autonomous, from `collect.js`), chat (streaming Gemini).
- **workspace:** graph, case, account, settings.

Sources are public APIs that allow browser requests (GitHub, GitLab, Reddit, crt.sh, rdap.org,
ipwho.is, Shodan InternetDB, Cloudflare/Google DoH, HIBP with the user's key, etc.).

## 5. The Worker (`worker/worker.js`)

Single `export default { fetch }`. KV binding **USERS** holds `user:<login>`, `session:<token>`,
`oauth:<state>`, `rl:<bucket>`.

Endpoints: `GET /health`; `GET /auth/github/start` + `/callback`; `GET /auth/me`;
`POST /auth/logout`; `GET /admin/users` + `POST /admin/user` (admin); `POST /ai/chat` and
`POST /ai/stream` (SSE, visible thinking) — **pro** gated, BESTMODEL fallback, key stays
server-side; `POST /check` — batch username existence checks (**approved** gated);
`POST /fetch` — SSRF-guarded proxy returning status, finalUrl, headers, body.

Access: users `pending`→`approved`/`denied`; `pro` gates the AI; admin = `ADMIN_USER`
(auto approved+pro). `gate(user, needPro)` enforces it; CORS from `ALLOWED_ORIGINS`;
per-user KV rate limits.

Config — **vars:** `AI_MODEL` (`BESTMODEL` or a pinned id), `ALLOWED_ORIGINS`, `SITE_URL`,
`ADMIN_USER`, `GITHUB_CLIENT_ID`; optional `AI_THINKING`, `BESTMODEL_CHAIN`.
**secrets:** `GEMINI_KEY`, `GITHUB_CLIENT_SECRET`. KV namespace bound as `USERS`.

> After any `worker.js` change the owner must re-paste it in the Cloudflare dashboard
> (Edit code → Deploy). The frontend ships automatically via GitHub Pages on merge to `main`.

## 6. Testing (before every PR)

- **Worker:** `cd worker && node worker.test.mjs` — stubs KV + global fetch, calls
  `worker.fetch(req, env)`. Add cases next to the matching feature.
- **Browser:** headless Chromium via `createRequire('/opt/node-tools/x.js')('playwright')`,
  `chromium.launch({args:['--no-sandbox']})`. Serve with `python3 -m http.server`, seed
  `localStorage` (`feddedosint.settings`, `feddedosint.session`) in `addInitScript`, mock the
  network with `page.route` (DoH takes `type=A`; backend at `BACKEND` in `js/backend.js`). The app is behind a sign-in wall, so seed an
  approved `feddedosint.session` and mock `/auth/me` or every tool test just sees the lock screen.
- A "load every tool, assert no console errors" smoke test is the fastest regression.

## 7. Release workflow

Develop on a feature branch. Commit messages are a plain `update` (intentionally nonchalant).
Open a PR to `main`, merge it, re-sync the branch to `main`. Merging deploys the site; tell the
owner when a `worker.js` re-paste is also needed. **Append a WORKLOG.md entry (§0) in the same PR.**

