# feddedosint backend (Cloudflare Worker)

One free Worker, shared by all visitors. It:

- holds the Gemini key as a server-side secret and relays AI requests — the key never reaches a browser;
- signs users in with **GitHub** (no passwords);
- keeps new users **pending** until the admin approves them, and gates the AI (chat + autonomous engine) to **pro** users;
- adds rate limits, a CORS allowlist and an SSRF-guarded fetcher.

## Setup

### 1. Create a GitHub OAuth app
GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**:
- **Homepage URL:** `https://feddedz.github.io/feddedosint/`
- **Authorization callback URL:** `https://feddedosint-api.<your-subdomain>.workers.dev/auth/github/callback`
  (your Worker URL + `/auth/github/callback`)

Copy the **Client ID**, then **Generate a client secret** and copy that too.

### 2. Create the Worker (dashboard)
Cloudflare dashboard → **Workers & Pages → Create → Worker**, name it `feddedosint-api`, Deploy, then **Edit code** and paste the contents of [`worker.js`](worker.js). Deploy.

### 3. Create the KV database and bind it
**Storage & Databases → KV → Create namespace** named `USERS`. Then on the Worker → **Settings → Bindings → Add → KV namespace**, variable name `USERS`, pick the namespace.

### 4. Variables and secrets
On the Worker → **Settings → Variables and secrets**. Add as **text**:

| name | value |
| --- | --- |
| `AI_MODEL` | `gemini-2.5-flash` |
| `ALLOWED_ORIGINS` | `https://feddedz.github.io` |
| `SITE_URL` | `https://feddedz.github.io/feddedosint/` |
| `ADMIN_USER` | your GitHub username |
| `GITHUB_CLIENT_ID` | from step 1 |

Add as **secrets** (encrypted):

| name | value |
| --- | --- |
| `GEMINI_KEY` | your Gemini key |
| `GITHUB_CLIENT_SECRET` | from step 1 |

Deploy.

### 5. Connect the site
Open `<worker-url>/health` — it should show `{"ok":true,"ai":true,"github":true,...}`. The site is pinned to this Worker in `js/backend.js` (`BACKEND`) — change that constant if the Worker URL ever changes. Then open the site and **continue with GitHub**. The first time you sign in with the `ADMIN_USER` account you become admin; everyone else is pending until you approve them (and grant pro) in the members panel.

## CLI alternative
With `wrangler` installed: fill `wrangler.toml`, then
`wrangler kv namespace create USERS`, `wrangler secret put GEMINI_KEY`, `wrangler secret put GITHUB_CLIENT_SECRET`, `wrangler deploy`.

## Endpoints
`GET /health` · `GET /auth/github/start` · `GET /auth/github/callback` · `GET /auth/me` · `POST /auth/logout` · `GET /admin/users` · `POST /admin/user` · `POST /ai/chat` · `POST /fetch`

## Notes
- No passwords are stored; GitHub handles sign-in and its own 2FA.
- AI is pro-only and rate-limited (60/min per user); keeping signups gated to approval protects your Gemini quota.
- `/fetch` blocks private/loopback/metadata hosts and caps responses at 512 KB.
- Logic tests: `node worker.test.mjs` (Node 18+).
