# Worklog

A running, timestamped record of everything done to this repo. **Newest at the top.**
Every session appends an entry for each change — see the Worklog rule in [`CLAUDE.md`](CLAUDE.md) §0.

Format:

```
### YYYY-MM-DD HH:MM UTC — short title
- what changed and why
- files: …
- PR: #NN (merged) / not yet shipped
```

---

### 2026-10-29 20:46 UTC — one shared Worker + sign-in wall
- Pinned the backend to `https://feddedosint-api.bptiktok6.workers.dev` (`BACKEND` in js/backend.js);
  removed the per-browser backend URL setting so every visitor uses the same Worker.
- New sign-in wall (`js/lock.js`): nothing renders until the visitor is signed in with GitHub and
  approved; pending/denied/expired sessions see a lock screen. The session is re-checked on each load.
- Tested headless: anon / expired / pending / denied / GitHub-error all locked; approved user loads all
  29 tools with no console errors; logging out re-locks. Worker unchanged (no re-paste needed).
- files: js/lock.js, js/app.js, js/backend.js, js/store.js, js/tools/settings.js, js/tools/account.js,
  js/tools/chat.js, index.html, css/style.css, README.md, worker/README.md, CLAUDE.md
- PR: not yet shipped

### 2026-10-29 09:00 UTC — add CLAUDE.md guide + this worklog
- Put the project handoff into `CLAUDE.md` (auto-loads for future Claude sessions) and added the
  worklog rule: every change must append a timestamped entry here.
- Seeded this log with the recent history below.
- files: CLAUDE.md, WORKLOG.md
- PR: not yet shipped

### 2026-10-29 01:42 UTC — new `recon` tool (attack-surface mapper)
- One-shot passive recon: subdomain discovery (crt.sh + passive DNS + ~160-word brute over DoH)
  → resolve → live probe via backend (status, title, tech fingerprint) → Shodan InternetDB ports
  & CVEs → findings panel flags exposed sensitive services; JSON/CSV export.
- Extended Worker `/fetch` to return response headers (for fingerprinting).
- files: js/tools/recon.js, js/app.js, js/tools/overview.js, css/style.css, worker/worker.js
- PR: #13 (merged)

### 2026-10-29 00:16 UTC — username search made fully automatic
- Auto-runs on search (no button); found accounts float to top, not-found only counted (no clutter),
  "show unverified" toggle. Falls back to the already-deployed `/fetch` when `/check` isn't present
  yet (capped top-sites scan) so it works before a Worker re-deploy. Raised `/fetch` rate limit.
- files: js/tools/username.js, js/backend.js, worker/worker.js
- PR: #12 (merged)

### 2026-10-28 22:13 UTC — streaming AI chat + deep-scan dataset
- Chat streams live (visible thinking + answer), keeps running when switching tabs, stop button.
  Added Worker `/ai/stream` (SSE) and `/check` (batch username existence checks) endpoints, plus
  the ~700-site WhatsMyName dataset (`js/sites.js`).
- files: worker/worker.js, worker/worker.test.mjs, js/backend.js, js/tools/chat.js, js/sites.js, css/style.css
- PR: #10, #11 (merged)
