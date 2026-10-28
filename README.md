# feddedosint

--
NOTE TO HIGHERUPS: This was developed with AI (artificial intelligence, Claude-Opus-5-5); nothing is associated with the creator in any way. The actions performed by users of this platform do not correlate back to him. It is an educational tool.
--


A fast, private, client-side OSINT platform that runs entirely on GitHub Pages — no backend, no tracking.
Queries go straight from your browser to public services; nothing is proxied or logged. API keys (optional) and
history are stored only in your browser.

## Tools

The toolbar is grouped: **universal search**, then **identity**, **network**, **assets**, **threat**, **research**, **tools**, and the **graph** + **settings**.

| group · tab | what it does |
| --- | --- |
| **search** (universal) | One box for everything — detects whether you typed an email, domain, IP, username, phone, wallet or CVE and runs the right tool, with one click to re-run it as another type. |
| identity · **username** | Live account checks via public APIs (GitHub, GitLab, Reddit, Hacker News, Bluesky, Mastodon, Keybase, Chess.com, Lichess, npm, Wikipedia, DEV) plus ~80 one-click profile links. |
| identity · **email** | Gravatar, MX/provider detection, SPF/DMARC, free / disposable / privacy-relay detection, pivots. |
| identity · **phone** | Parsing & validation for every country (libphonenumber): line type, all formats, messenger & caller-ID links. |
| identity · **breach** | Check *your own* exposure: email breaches (via your HIBP key), a k-anonymity password check (the password never leaves the browser), and a searchable library of known breaches. |
| network · **domain** | DNS, RDAP/WHOIS, mail security (SPF/DMARC/DKIM, spoofability), service fingerprinting, hosting/ASN, certificate-transparency subdomains and Wayback history. |
| network · **ip** | Geolocation + map, ASN/ISP, reverse DNS, open ports & CVEs (Shodan InternetDB), RDAP ownership. Leave empty for your own IP. |
| network · **network (ASN)** | Explore an autonomous system — operator, prefixes/address space, peers & upstreams. Accepts an ASN or an IP. |
| assets · **wallet** | Bitcoin & Ethereum address balances, activity and transactions, with links to the major chain-analysis explorers. |
| assets · **image** | Reverse image search from a URL, or drop a file to read EXIF, camera serials and GPS locally — the file never leaves the browser. |
| threat · **vuln (CVE)** | CVE description, CVSS severity, EPSS exploit probability, weaknesses and references (NVD + FIRST). |
| research · **records** | Public-record & news research — company registries, courts, sanctions, academia, archives — plus live Hacker News and GitHub mentions. |
| research · **search (dorks)** | Query builder for search-engine operators (site, filetype, intitle, date ranges…) across Google, Bing, DuckDuckGo and Yandex. |
| tools · **decoders** | Offline base64 / URL / hex / binary, SHA hashes, rot13, IOC defang/refang, timestamp and JWT decoding — all in-browser. |
| **graph** | A live investigation graph: every entity you open becomes a node and pivots draw the links. Drag to arrange, click to reopen, export as JSON. |
| **settings** | Store optional API keys (HIBP, Shodan, VirusTotal, Etherscan, IPinfo, urlscan), switch dark/light, pause the graph, and clear your data. |

Results cross-link: click an IP, domain, email or handle in any result to pivot into that tool — and the move is recorded in the graph. Every search is a shareable URL (`#domain/example.com`).

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
- Third-party libraries (libphonenumber-js, exifr) load lazily from jsDelivr, pinned to exact versions with Subresource Integrity hashes.
- For lawful, ethical research only. Respect people's privacy and each site's terms of service.
