# feddedosint backend (Cloudflare Worker)

A single free Worker that holds your Gemini key, backs real accounts + 2FA, and
proxies OSINT fetches. The site works without it; adding it unlocks the AI, logins
and broader live data. Your Gemini key lives only here as a secret and is never
sent to any browser.

## One-time setup (~10 minutes)

1. **Create a free Cloudflare account** at <https://dash.cloudflare.com/sign-up>.

2. **Install the CLI** (needs Node 18+):
   ```bash
   npm install -g wrangler
   wrangler login
   ```

3. **From this `worker/` folder, create the KV store:**
   ```bash
   cd worker
   wrangler kv namespace create USERS
   ```
   Copy the printed `id` into `wrangler.toml` (replace `PASTE_YOUR_KV_NAMESPACE_ID_HERE`).

4. **Edit `wrangler.toml`:** set `ADMIN_USER` to the username you'll sign up with,
   and confirm `ALLOWED_ORIGINS` matches your site (e.g. `https://feddedz.github.io`).

5. **Set your secrets** (these never go in the repo):
   ```bash
   wrangler secret put GEMINI_KEY
   # paste a FRESH Gemini key — rotate the old one first
   wrangler secret put SIGNUP_CODE   # optional: an invite code to control who can register
   ```

6. **Deploy:**
   ```bash
   wrangler deploy
   ```
   It prints a URL like `https://feddedosint-api.<you>.workers.dev`.

7. **Tell the site:** open feddedosint → **settings → backend**, paste that URL, Save.
   Then **account → sign up** (use the exact `ADMIN_USER` name to get the admin view).

## Choosing the model

`AI_MODEL` must be an exact id. List what your key can use:

```bash
curl "https://generativelanguage.googleapis.com/v1beta/models?key=YOUR_KEY" | grep '"name"'
```

Pick a `*-flash` model from the list, set it in `wrangler.toml`, and `wrangler deploy` again.

## Endpoints

| method · path | purpose |
| --- | --- |
| `GET /health` | config check (no secrets) |
| `POST /auth/signup` · `POST /auth/login` · `POST /auth/logout` | accounts |
| `GET /auth/me` | current user |
| `POST /auth/2fa/setup` · `/enable` · `/disable` | TOTP 2FA |
| `GET /admin/users` | list signups (admin only; usernames + 2FA status, **never passwords**) |
| `POST /ai/chat` | Gemini proxy (your key, server-side) |
| `POST /fetch` | SSRF-guarded URL fetch for OSINT |

## Security notes

- Passwords are stored only as PBKDF2-SHA256 hashes (210k iterations, random salt).
  Nobody — including you — can read a user's password; the admin view shows who
  signed up and whether 2FA is on, nothing more.
- Rate limits: AI 60/min per user, fetch 40/min, login 10/5min, signup 5/hour per IP.
- `/fetch` blocks private/loopback/metadata addresses and caps responses at 512 KB.
- Free tier covers ~100k requests/day. Keeping `AI_REQUIRE_AUTH = "true"` means only
  people who signed up can spend your Gemini quota.

## Local test of the logic

```bash
node worker.test.mjs   # runs the auth / TOTP / AI-proxy / SSRF / CORS suite in Node 18+
```
