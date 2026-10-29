# feddedosint

--
NOTE TO HIGHERUPS: This was developed with AI (artificial intelligence, Claude-Opus-5-5); nothing is associated with the creator in any way. The actions performed by users of this platform do not correlate back to him. It is an educational tool.
--


A fast, private, client-side OSINT platform that runs entirely on GitHub Pages — no backend, no tracking.
Queries go straight from your browser to public services; nothing is proxied or logged. API keys (optional) and
history are stored only in your browser.

## Tools

Tools live in a collapsible sidebar: click a group name to fold it, fold them all at once, or shrink the whole sidebar to an icon rail. On phones it becomes a drawer. Every result card folds too (click its title), and **Ctrl / ⌘ K** opens a command palette that jumps to any tool, recent search, or runs whatever you typed.

| group · tool | what it does |
| --- | --- |
| **universal search** | One box for everything — detects email, domain, URL, IP, CIDR, ASN, username, phone, wallet, MAC, coordinates, hash or CVE and runs the right tool, with one click to re-run it as another type. Its home screen lists every tool. |
| intelligence · **engine** | Autonomous investigation: point it at a domain, IP, URL, email or ASN and it expands outward across public sources (DNS, RDAP, hosting, Shodan exposure, ASN), gathering cited evidence, building the graph, and writing an evidence-backed report with an AI analysis on top. Pro feature (GitHub sign-in + approval). |
| intelligence · **chat** | An AI assistant that can see your investigation graph and notes, helps plan and interpret, and makes the entities in its replies clickable. Runs on the owner's Gemini key through the Worker, so the key never reaches the browser. Pro feature. |
| identity · **username** | Live account checks via public APIs (GitHub, GitLab, Reddit, Hacker News, Bluesky, Mastodon, Keybase, Chess.com, Lichess, npm, Wikipedia, DEV) plus ~80 one-click profile links. |
| identity · **email** | Gravatar, MX/provider detection, SPF/DMARC, free / disposable / privacy-relay detection, pivots. |
| identity · **phone** | Parsing & validation for every country (libphonenumber): line type, all formats, messenger & caller-ID links. |
| identity · **breach** | Check *your own* exposure: email breaches (via your HIBP key), a k-anonymity password check (the password never leaves the browser), and a searchable library of known breaches. |
| network · **domain** | DNS, RDAP/WHOIS, mail security (SPF/DMARC/DKIM, spoofability), service fingerprinting, hosting/ASN, certificate-transparency subdomains and Wayback history. |
| network · **ip** | Geolocation + map, ASN/ISP, reverse DNS, open ports & CVEs (Shodan InternetDB), RDAP ownership — plus Shodan and IPinfo cards when you add those keys. Empty = your own IP. |
| network · **asn** | Explore an autonomous system — operator, prefixes/address space, peers & upstreams. Accepts an ASN or an IP. |
| network · **url** | Breaks a link apart, flags phishing tricks (credentials-in-URL, punycode, raw IPs, shorteners, risky TLDs, embedded redirects), checks domain age and shows past urlscan.io scans with screenshots. |
| network · **mac** | Device maker from a MAC / BSSID, randomised-address detection, every format and the derived EUI-64 IPv6 address. |
| network · **subnet** | IPv4 & IPv6 subnet calculator — range, masks, neighbours, splits — fully offline. |
| geo · **geo** | Coordinates, DMS or maps links (or a place name) → address, nearby Wikipedia places, map, and jumps to satellite, street-level and shadow-analysis tools. |
| geo · **map** | Plots IPs, domains and coordinates on a dark world map; domains resolve to their servers and linked entities are joined by animated arcs. Empty = plot your investigation graph. |
| assets · **wallet** | Bitcoin & Ethereum address balances, activity and transactions, with links to the major chain-analysis explorers. |
| assets · **image** | Reverse image search from a URL, or drop a file to read EXIF, camera serials and GPS locally. |
| assets · **file** | Static file triage, offline: real type from magic bytes (catches disguised extensions), MD5 / SHA-1 / SHA-256, entropy, strings, PE / ELF headers, and indicators found inside. Paste a hash to look it up. |
| threat · **vuln** | CVE description, CVSS severity, EPSS exploit probability, weaknesses and references (NVD + FIRST). |
| threat · **headers** | Email header analysis for phishing triage — delivery path with per-hop delays, SPF / DKIM / DMARC, spoofing red flags, and every IP / domain inside. |
| research · **records** | Public-record & news research — company registries, courts, sanctions, academia, archives — plus live Hacker News and GitHub mentions. |
| research · **engines** | Query builder for search-engine operators (site, filetype, intitle, date ranges…) across Google, Bing, DuckDuckGo and Yandex. |
| tools · **extract** | Paste any text — report, log, email, chat — and every URL, domain, IP, hash, CVE, wallet, MAC, phone and handle is pulled out (defanged ones too) and made pivotable. |
| tools · **decoders** | Offline base64 / URL / hex / binary, SHA hashes, rot13, IOC defang/refang, timestamp and JWT decoding. |
| workspace · **graph** | A live investigation graph: every entity you open becomes a node and pivots draw the links. Drag to arrange, click to reopen, export as JSON. |
| workspace · **case** | Your investigation file: title, notes (autosaved), every entity grouped by type, a timeline, and exports to a Markdown report, JSON (re-importable) or print / PDF. |
| workspace · **account** | Sign in with GitHub. New accounts are pending until an admin approves them; the admin grants pro (which unlocks the AI). The admin sees the member list. Needs the backend. |
| workspace · **settings** | Backend URL, optional API keys (HIBP, Shodan, VirusTotal, Etherscan, IPinfo, urlscan), dark/light theme, graph recording, and clearing your data. |

## Backend — AI, accounts and access

The site is **members-only**: you sign in with GitHub and an admin approves your account before any tool is shown. Every visitor uses the one shared Worker at `https://feddedosint-api.bptiktok6.workers.dev`. Most tools then query public services straight from your browser. The **AI engine** and **chat** are powered by a small Cloudflare Worker (`worker/`), which:

- holds the Gemini key as a server-side secret, so every visitor's AI request uses it **without the key ever reaching a browser**;
- signs users in with **GitHub** (no passwords; GitHub handles 2FA);
- keeps new accounts **pending** until the admin approves, and gates the AI to **pro** users the admin grants;
- adds rate limits, a CORS allowlist and an SSRF-guarded fetcher.

It runs on Cloudflare's free tier. Setup — including the GitHub OAuth app — is in [`worker/README.md`](worker/README.md). The Gemini key is set only as a Worker secret; it is never committed.

Results cross-link: click an IP, domain, email, hash or handle in any result to pivot into that tool — and the move is recorded in the graph and case file. Every search is a shareable URL (`#domain/example.com`).

## API keys (optional)

Most tools work with no setup. Adding your own free keys under **Settings** unlocks richer live data (e.g. email breach search, Ethereum lookups). Keys are stored only in your browser's localStorage and are sent only to their own service.

## Deploy on GitHub Pages

1. Merge this branch into `main` (or pick this branch directly).
2. **Settings → Pages → Build and deployment → Deploy from a branch**, choose the branch and `/ (root)`.
3. Visit `https://<your-user>.github.io/<repo>/`.

## Run locally

ES modules don't load from `file://`, so serve the folder:

```bash
python3 -m http.server 8000
```

Then open http://localhost:8000.

## Notes

- Free public APIs can rate-limit or go down; any check that can't complete shows as *unverified* with a link to check manually.
- Third-party libraries (libphonenumber-js, exifr, Leaflet) load lazily from jsDelivr, pinned to exact versions with Subresource Integrity hashes. Map tiles © OpenStreetMap contributors © CARTO.
- For lawful, ethical research only. Respect people's privacy and each site's terms of service.
