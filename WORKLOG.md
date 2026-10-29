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

### 2026-10-29 23:47 UTC — ogu (OG username finder)
- New **ogu** tool (identity): finds usernames across popular sites + all 69 gaming platforms.
  Two modes: a handle -> where it's taken vs available; a wildcard pattern (? = one char, * = 1-2)
  -> generates matching candidates and ranks them by availability (handle hunting).
- Reuses the existing server-side existence checks (be.deepScan + SITES dataset); availability
  checking only, never account contents. Approved sign-in required (uses the backend proxy).
- Tested headless: single-handle shows taken/available across popular+games; pattern expands z?x
  to 24 ranked candidates with the taken one sinking to the bottom; no console errors.
- files: js/tools/ogu.js, js/app.js, js/icons.js
- PR: not yet shipped

### ### 2026-10-29 21:53 UTC — risk scoring in engine/sweep, dossier export, favicon-hash
- **Risk scoring everywhere:** collectors (js/collect.js) now emit structured findings; the
  **engine** shows a ranked risk-posture card and feeds it to the AI, and **sweep** shows a posture
  score. Same js/risk.js the playbook uses.
- New **dossier** tool (workspace): compiles the investigation graph + case notes into one
  infrastructure report (assets by type, relationships, notes) with copy-Markdown / print-PDF /
  export-JSON. No new network calls.
- New **favicon** tool (network): computes a site's Shodan mmh3 favicon hash and builds the
  http.favicon.hash: pivot (+ Shodan link). New js/mmh3.js (verified bit-exact vs python mmh3 and
  base64.encodebytes). Needs raw icon bytes, so WORKER CHANGED: /fetch now accepts bytes:true and
  returns base64 (SSRF-guarded, 256 KB cap). Worker test added.
- files: js/collect.js, js/tools/engine.js, js/tools/sweep.js, js/tools/dossier.js,
  js/tools/favicon.js, js/mmh3.js, js/backend.js, js/app.js, js/icons.js, css/style.css,
  worker/worker.js, worker/worker.test.mjs
- PR: not yet shipped  ·  **owner must re-paste worker.js** (Cloudflare -> Edit code -> Deploy)

### ### 2026-10-29 21:45 UTC — playbook + risk scoring + monitor history
- New **playbook** tool (intelligence): one target runs a full automated audit workflow — surface
  mapping, Shodan exposure, dangling-CNAME and mail-auth checks — ending in a single risk-scored,
  ranked report with copy/export, watch, and next-step pivots. Human reviews; nothing auto-acts.
- New shared **risk scoring** module (js/risk.js): findings → 0-100 score + severity band, used to
  rank the playbook report. Service-weighted (DBs/Docker/RDP/etc.), CVE clusters, takeovers, weak mail.
- **monitor**: now records a change history per watch (timeline card) and a “re-check all” button on
  the watchlist that re-snapshots every target and logs what changed.
- Wired playbook into the registry + icon; added .steplog CSS and watchHistory() to the store.
- Tested headless: playbook scores a target 98/100 (MongoDB/RDP exposed, dangling CNAME, CVE cluster,
  weak SPF); monitor re-check-all records history; no console errors.
- files: js/risk.js, js/tools/playbook.js, js/tools/monitor.js, js/store.js, js/app.js, js/icons.js, css/style.css
- PR: not yet shipped

###

### 2026-10-29 21:34 UTC — takeover + sweep tools
- New **takeover** tool: pulls a domain's subdomains from certificate transparency, follows each
  CNAME, and flags dangling / unclaimed third-party targets (GitHub Pages, S3, Heroku, Azure, +15
  more) — DNS-level signals always, live unclaimed-fingerprint confirmation via the proxy when
  approved. Ranked, with remediation note.
- New **sweep** tool: bulk exposure over an ASN (BGPView prefixes) or IPv4 CIDR — expands to hosts
  (capped 512), queries Shodan InternetDB per IP, aggregates open ports, CVEs and sensitive services,
  with a port histogram and map pivot.
- Wired both into the network group, launcher and icons.
- Tested headless: takeover flags an unclaimed GitHub Pages host; sweep (CIDR + ASN) aggregates
  ports/CVEs/sensitive services; no console errors.
- files: js/tools/takeover.js, js/tools/sweep.js, js/app.js, js/icons.js
- PR: not yet shipped

###

### 2026-10-29 21:04 UTC — monitor + wayback tools (power features)
- New **monitor** tool: snapshots a domain/IP's public footprint (CT subdomains, DNS, open ports,
  CVEs) and diffs each re-check against the last, flagging new exposure as ranked alerts. Watchlist
  persists per-browser; public-source + client-side only.
- New **wayback** tool: harvests archived URLs for a host from the Internet Archive CDX API — flags
  backups/configs/keys/admin/secret-param paths, lists hostnames and every query parameter seen.
- Wired both into the network group, universal launcher, icons; monitor shows its watchlist on idle.
- Added store watchlist helpers (watches/addWatch/removeWatch/saveSnapshot) and .chips CSS.
- Tested headless: baseline → watch → change → diff shows the new port & subdomain; wayback parses
  and flags; all tools load with no console errors.
- files: js/tools/monitor.js, js/tools/wayback.js, js/app.js, js/icons.js, js/store.js, css/style.css
- PR: not yet shipped

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
