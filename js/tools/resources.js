import { h, card, grid, muted, badge, ext, pivot } from '../util.js';

// A searchable directory of external OSINT resources, grouped by category — the breadth of an
// OSINT-framework link tree, built into the app. Public-data research tools. Where feddedosint has
// its own tool for a category, it's linked first so you can stay in-app.
//
// Scope note: this intentionally omits "find a private person" link farms (people-search engines,
// reverse-phone/voter/birth/death/family-tree lookups, dating-profile finders). Entity, asset and
// infrastructure research only — matching the project's boundary.

// { in: internal tool id, or ext links [name, url, note?] }
const CATS = [
  { c: 'Search & dorking', in: 'dorks', items: [
    ['Google Advanced', 'https://www.google.com/advanced_search'],
    ['DuckDuckGo', 'https://duckduckgo.com/'],
    ['Yandex', 'https://yandex.com/search/'],
    ['Bing', 'https://www.bing.com/'],
    ['Google Hacking DB', 'https://www.exploit-db.com/google-hacking-database', 'dork catalogue'],
    ['Intelligence X', 'https://intelx.io/', 'leaks, pastes, darkweb index'],
    ['grep.app', 'https://grep.app/', 'search code across repos'],
  ] },
  { c: 'Username', in: 'ogu', items: [
    ['WhatsMyName', 'https://whatsmyname.app/'],
    ['Sherlock', 'https://github.com/sherlock-project/sherlock', 'CLI'],
    ['Maigret', 'https://github.com/soxoj/maigret', 'CLI, profile parsing'],
    ['NameMC', 'https://namemc.com/', 'Minecraft names'],
    ['SteamID', 'https://steamid.io/'],
  ] },
  { c: 'Email', in: 'email', items: [
    ['Have I Been Pwned', 'https://haveibeenpwned.com/', 'your own breach exposure'],
    ['Hunter.io', 'https://hunter.io/', 'company email formats'],
    ['EmailRep', 'https://emailrep.io/', 'reputation'],
    ['Epieos', 'https://epieos.com/', 'email/phone footprint'],
    ['verify-email', 'https://verifyemailaddress.io/'],
  ] },
  { c: 'Domain & DNS', in: 'domain', items: [
    ['SecurityTrails', 'https://securitytrails.com/'],
    ['ViewDNS', 'https://viewdns.info/'],
    ['DNSdumpster', 'https://dnsdumpster.com/'],
    ['crt.sh', 'https://crt.sh/', 'certificate transparency'],
    ['WhoisXML / whois', 'https://who.is/'],
    ['DNSlytics', 'https://dnslytics.com/'],
  ] },
  { c: 'Subdomains & certs', in: 'recon', items: [
    ['crt.sh', 'https://crt.sh/'],
    ['Censys Search', 'https://search.censys.io/'],
    ['Subdomain Finder', 'https://subdomainfinder.c99.nl/'],
    ['CertSpotter', 'https://sslmate.com/certspotter/'],
  ] },
  { c: 'IP & network', in: 'ip', items: [
    ['Shodan', 'https://www.shodan.io/'],
    ['Censys', 'https://search.censys.io/'],
    ['ZoomEye', 'https://www.zoomeye.org/'],
    ['GreyNoise', 'https://viz.greynoise.io/', 'scanner noise'],
    ['BGP.he.net', 'https://bgp.he.net/', 'ASN/prefix'],
    ['ipinfo', 'https://ipinfo.io/'],
  ] },
  { c: 'Cloud & storage', in: 'recon', items: [
    ['GrayhatWarfare', 'https://buckets.grayhatwarfare.com/', 'open S3/blob buckets'],
    ['Cloud Enum', 'https://github.com/initstring/cloud_enum', 'AWS/Azure/GCP, CLI'],
    ['GCPBucketBrute', 'https://github.com/RhinoSecurityLabs/GCPBucketBrute', 'CLI'],
  ] },
  { c: 'Threat intel & reputation', in: 'cve', items: [
    ['VirusTotal', 'https://www.virustotal.com/'],
    ['AbuseIPDB', 'https://www.abuseipdb.com/'],
    ['URLScan', 'https://urlscan.io/'],
    ['AlienVault OTX', 'https://otx.alienvault.com/'],
    ['ThreatFox', 'https://threatfox.abuse.ch/'],
    ['MalwareBazaar', 'https://bazaar.abuse.ch/'],
  ] },
  { c: 'Vulns & exposure', in: 'assess', items: [
    ['NVD', 'https://nvd.nist.gov/'],
    ['CVE.org', 'https://www.cve.org/'],
    ['Exploit-DB', 'https://www.exploit-db.com/'],
    ['Shodan Exploits', 'https://exploits.shodan.io/'],
    ['EPSS', 'https://www.first.org/epss/'],
  ] },
  { c: 'Image, video & metadata', in: 'image', items: [
    ['Google Lens', 'https://lens.google.com/'],
    ['Yandex Images', 'https://yandex.com/images/', 'strong for faces/places'],
    ['TinEye', 'https://tineye.com/'],
    ['InVID / WeVerify', 'https://www.invid-project.eu/tools-and-services/invid-verification-plugin/', 'video verify'],
    ['Jeffrey’s EXIF', 'http://exif.regex.info/exif.cgi'],
    ['Forensically', 'https://29a.ch/photo-forensics/'],
  ] },
  { c: 'Geolocation & maps', in: 'map', items: [
    ['Google Earth', 'https://earth.google.com/'],
    ['Overpass Turbo', 'https://overpass-turbo.eu/', 'OSM queries'],
    ['SunCalc', 'https://www.suncalc.org/', 'shadow analysis'],
    ['Wikimapia', 'https://wikimapia.org/'],
    ['Sentinel Hub', 'https://apps.sentinel-hub.com/eo-browser/', 'satellite'],
    ['OpenRailwayMap', 'https://www.openrailwaymap.org/'],
  ] },
  { c: 'Transportation', items: [
    ['FlightRadar24', 'https://www.flightradar24.com/', 'aircraft'],
    ['ADS-B Exchange', 'https://globe.adsbexchange.com/', 'unfiltered aircraft'],
    ['MarineTraffic', 'https://www.marinetraffic.com/', 'vessels'],
    ['OpenSky Network', 'https://opensky-network.org/'],
    ['RailMapOnline', 'https://www.railmaponline.com/'],
  ] },
  { c: 'Business & company records', in: 'records', items: [
    ['OpenCorporates', 'https://opencorporates.com/'],
    ['SEC EDGAR', 'https://www.sec.gov/edgar/search/'],
    ['UK Companies House', 'https://find-and-update.company-information.service.gov.uk/'],
    ['Aleph (OCCRP)', 'https://aleph.occrp.org/', 'leaks + registries'],
    ['OpenSanctions', 'https://www.opensanctions.org/', 'sanctions / PEP'],
    ['GLEIF (LEI)', 'https://search.gleif.org/'],
  ] },
  { c: 'Crypto & blockchain', in: 'crypto', items: [
    ['Blockchair', 'https://blockchair.com/', 'multi-chain explorer'],
    ['Etherscan', 'https://etherscan.io/'],
    ['Arkham', 'https://platform.arkhamintelligence.com/', 'entity labels'],
    ['Breadcrumbs', 'https://www.breadcrumbs.app/', 'wallet clustering'],
    ['OXT', 'https://oxt.me/', 'Bitcoin analysis'],
  ] },
  { c: 'Archives & cache', in: 'wayback', items: [
    ['Wayback Machine', 'https://web.archive.org/'],
    ['archive.today', 'https://archive.ph/'],
    ['CachedView', 'https://cachedview.nl/'],
    ['Wayback CDX API', 'https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server'],
  ] },
  { c: 'Code & secrets', in: 'recon', items: [
    ['GitHub code search', 'https://github.com/search'],
    ['grep.app', 'https://grep.app/'],
    ['Sourcegraph', 'https://sourcegraph.com/search'],
    ['gitleaks', 'https://github.com/gitleaks/gitleaks', 'secret scanning, CLI'],
    ['TruffleHog', 'https://github.com/trufflesecurity/trufflehog', 'CLI'],
  ] },
  { c: 'File & malware analysis', in: 'file', items: [
    ['VirusTotal', 'https://www.virustotal.com/'],
    ['Hybrid Analysis', 'https://www.hybrid-analysis.com/'],
    ['ANY.RUN', 'https://any.run/', 'interactive sandbox'],
    ['CyberChef', 'https://gchq.github.io/CyberChef/', 'encode/decode'],
    ['Ghidra', 'https://ghidra-sre.org/', 'RE, local'],
  ] },
  { c: 'Dark web', items: [
    ['Ahmia', 'https://ahmia.fi/', 'Tor search (clearnet)'],
    ['Tor Project', 'https://www.torproject.org/'],
    ['Dark.fail', 'https://dark.fail/', 'verified onion directory'],
    ['Intelligence X', 'https://intelx.io/'],
  ] },
  { c: 'News & verification', items: [
    ['Google News', 'https://news.google.com/'],
    ['GDELT', 'https://www.gdeltproject.org/', 'global news graph'],
    ['Media Bias/Fact Check', 'https://mediabiasfactcheck.com/'],
    ['Hoaxy', 'https://hoaxy.osome.iu.edu/', 'claim spread'],
  ] },
];

export default {
  id: 'resources',
  label: 'resources',
  placeholder: 'filter resources… (e.g. shodan, crypto, satellite)',
  intro: 'A searchable directory of external OSINT resources by category — the breadth of a link tree, in-app. Entity, asset and infrastructure research.',
  examples: [],
  allowEmpty: true,
  noTrack: true,

  run(raw) {
    const q = (raw || '').trim().toLowerCase();
    const match = (cat) => {
      if (!q) return cat;
      if (cat.c.toLowerCase().includes(q)) return cat;
      const items = cat.items.filter(([n, , note]) => n.toLowerCase().includes(q) || (note || '').toLowerCase().includes(q));
      return items.length ? { ...cat, items } : null;
    };
    const cats = CATS.map(match).filter(Boolean);
    const total = CATS.reduce((n, c) => n + c.items.length, 0);

    if (!cats.length) return card('no matches', { wide: true }, muted(`Nothing matched “${q}”. Try a tool name, a category, or clear the filter.`));

    const cards = cats.map(cat => card(cat.c, { collapsed: !q && cat.items.length > 8 },
      cat.in ? h('p', { class: 'small', style: 'margin:0 0 8px' }, badge('in-app', 'ok'), ' ', pivot(cat.in, '', `open the ${cat.in} tool →`)) : null,
      h('div', { style: 'display:flex;flex-direction:column;gap:5px' }, cat.items.map(([name, url, note]) =>
        h('div', { class: 'small' }, ext(url, name), note ? h('span', { class: 'muted' }, ` — ${note}`) : null)))));

    const header = card('resources', { wide: true, actions: badge(`${total} links · ${CATS.length} categories`, 'muted') },
      muted('Curated external OSINT resources grouped by category. Where feddedosint has its own tool, it’s linked at the top of the group. Type in the search box above to filter.'),
      h('p', { class: 'muted small' }, 'Scope: entity, asset and infrastructure research — no private-person lookup services.'));

    return grid(header, ...cards);
  },
};
