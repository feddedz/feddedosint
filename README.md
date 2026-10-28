# feddedosint

A fast, private, client-side OSINT toolkit that runs entirely on GitHub Pages — no backend, no API keys, no tracking.
Queries go straight from your browser to public services; nothing is proxied or logged.

## Tools

| tab | what it does |
| --- | --- |
| **username** | Live account checks via public APIs (GitHub, GitLab, Reddit, Hacker News, Bluesky, Mastodon, Keybase, Chess.com, Lichess, npm, Wikipedia, DEV) plus ~80 one-click profile links grouped by category. |
| **domain** | DNS records, RDAP/WHOIS (registrar, age, expiry, nameservers), mail security (SPF / DMARC / DKIM selectors, spoofability), services fingerprinted from DNS, hosting/ASN, certificate-transparency subdomains (crt.sh) and Wayback history. |
| **ip** | Geolocation + map, ASN/ISP, reverse DNS, open ports & CVEs from Shodan InternetDB, network ownership via RDAP. Leave empty to look up your own IP. |
| **email** | Gravatar, MX/provider detection, SPF/DMARC, free / disposable / privacy-relay detection, pivots to the username and domain tools. |
| **phone** | Parsing & validation for every country (libphonenumber): line type, all formats, messenger and caller-ID links, multi-format search. |
| **image** | Reverse image search from a URL, or drop a file to read EXIF, camera serials and GPS locally — the file never leaves the browser. |
| **search** | Query builder for search-engine operators (site, filetype, intitle, inurl, date ranges…) across Google, Bing, DuckDuckGo and Yandex. |

Results cross-link: click an IP, domain, email or handle in any result to pivot into that tool. Every search is a shareable URL (`#domain/example.com`).

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
