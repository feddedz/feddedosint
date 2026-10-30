import { h, card, grid, muted, badge, ext, pivot, copyBtn, dns, getJSON, isIP, normDomain } from '../util.js';
import * as be from '../backend.js';
import { bandOf, toneOf, posture, rank } from '../risk.js';

// Web vulnerability assessment for a target you own or are authorized to test. Probes the live site
// through the backend proxy and reports findings — exposed files, missing security headers, insecure
// cookies, version disclosure, known CVEs on the host — each with its SEVERITY, IMPACT (what the
// weakness means) and REMEDIATION (how to fix it). It identifies and explains risk; it does not
// provide exploitation steps. Public-data + authorized probing only.

// Security response headers we expect, with the risk of each being absent.
const HEADERS = [
  { k: 'strict-transport-security', name: 'HSTS', score: 40, impact: 'Without HSTS a network attacker can downgrade visitors to plain HTTP and intercept traffic.', fix: 'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.' },
  { k: 'content-security-policy', name: 'Content-Security-Policy', score: 45, impact: 'No CSP means a single injected script runs unrestricted — the main backstop against XSS is missing.', fix: 'Define a Content-Security-Policy that restricts script/style/connect sources.' },
  { k: 'x-frame-options', name: 'X-Frame-Options', score: 30, impact: 'The page can be framed by other sites, enabling clickjacking of its UI.', fix: 'Send `X-Frame-Options: DENY` (or a CSP `frame-ancestors` directive).' },
  { k: 'x-content-type-options', name: 'X-Content-Type-Options', score: 20, impact: 'Browsers may MIME-sniff responses, turning an uploaded file into executable content.', fix: 'Send `X-Content-Type-Options: nosniff`.' },
  { k: 'referrer-policy', name: 'Referrer-Policy', score: 15, impact: 'Full URLs (possibly with tokens) leak to third parties via the Referer header.', fix: 'Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.' },
  { k: 'permissions-policy', name: 'Permissions-Policy', score: 15, impact: 'Camera, mic, geolocation and other features are not restricted for embedded content.', fix: 'Send a `Permissions-Policy` locking down features you don’t use.' },
];

// Sensitive paths that should never be publicly readable; `sig` confirms a real hit (not a soft 404).
const PATHS = [
  { p: '/.git/config', sig: /\[core\]|repositoryformatversion/i, score: 90, name: 'Exposed .git repository', impact: 'The source tree (and often credentials in history) can be reconstructed from an exposed .git directory.', fix: 'Block access to .git, or stop deploying the repository to the web root.' },
  { p: '/.env', sig: /[A-Z_]+=|APP_KEY|DB_PASSWORD|SECRET/i, score: 95, name: 'Exposed .env file', impact: 'Environment files typically hold database passwords, API keys and app secrets in plain text.', fix: 'Remove .env from the web root and rotate any exposed secrets immediately.' },
  { p: '/.git/HEAD', sig: /ref:\s*refs\//i, score: 85, name: 'Exposed .git/HEAD', impact: 'Confirms a browsable git directory — source and history are retrievable.', fix: 'Deny web access to the .git directory.' },
  { p: '/server-status', sig: /Apache Server Status|Server Version/i, score: 55, name: 'Apache server-status exposed', impact: 'Leaks live request data, client IPs and internal URLs.', fix: 'Restrict mod_status to localhost or disable it.' },
  { p: '/.DS_Store', sig: /Bud1|\x00\x00\x00/i, score: 35, name: 'Exposed .DS_Store', impact: 'Reveals the directory listing / file names of the deploy.', fix: 'Remove .DS_Store files and block the pattern.' },
  { p: '/phpinfo.php', sig: /phpinfo\(\)|PHP Version/i, score: 50, name: 'phpinfo() exposed', impact: 'Discloses full server configuration, paths, modules and environment.', fix: 'Delete phpinfo test files from production.' },
  { p: '/wp-config.php.bak', sig: /DB_PASSWORD|DB_NAME/i, score: 92, name: 'WordPress config backup exposed', impact: 'A readable wp-config backup leaks the database credentials.', fix: 'Remove the backup file and rotate the DB password.' },
  { p: '/.svn/entries', sig: /^\d+[\r\n]|svn:/i, score: 70, name: 'Exposed .svn metadata', impact: 'Source and structure recoverable from an exposed Subversion directory.', fix: 'Deny web access to .svn.' },
];

const TECH = [
  [/server:\s*([^\n]+)/i, 'Server'], [/x-powered-by:\s*([^\n]+)/i, 'X-Powered-By'],
  [/x-aspnet-version:\s*([^\n]+)/i, 'ASP.NET'], [/x-generator:\s*([^\n]+)/i, 'Generator'],
];
const VERSIONED = /\d+\.\d+/; // a version number present in a banner

async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  const run = async () => { while (i < items.length) { const idx = i++; const r = await fn(items[idx]).catch(() => null); onEach?.(items[idx], r); } };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, run));
}

const mkFinding = (score, title, impact, fix, extra) => ({ score, sev: bandOf(score), title, impact, fix, ...extra });

export default {
  id: 'assess',
  label: 'assess',
  placeholder: 'https://example.com  (authorized target to assess)',
  intro: 'Authorized web vulnerability assessment: exposed files, missing security headers, insecure cookies, version disclosure and known CVEs — each with its impact and how to fix it. For targets you own or are permitted to test.',
  examples: ['example.com'],

  async run(raw) {
    const input = raw.trim();
    if (!input) throw new Error('enter a target, e.g. example.com');
    const host = normDomain(input) || input.replace(/^https?:\/\//i, '').split('/')[0];
    const origin = /^https?:\/\//i.test(input) ? new URL(input).origin : `https://${host}`;

    if (!(be.backendConfigured() && be.isApproved())) {
      return card('sign-in needed', { wide: true },
        muted('The assessment probes the live site through the backend proxy, so it needs an approved sign-in.'),
        h('p', {}, pivot('account', '', 'sign in')));
    }

    const findings = [];

    // 1) Live fetch (prefer HTTPS). Collect headers + body for header/cookie/tech/listing checks.
    let r = await be.fetchUrl(origin).catch(() => null);
    if (!r?.ok || !r.data?.status) r = await be.fetchUrl(`http://${host}`).catch(() => null);
    const data = r?.data || {};
    const headers = data.headers || {};
    const hdrStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    const body = data.body || '';

    if (!data.status) {
      return card('unreachable', { wide: true }, muted(`Couldn’t reach ${origin} through the proxy. Check the host.`));
    }

    // 2) Missing security headers.
    for (const H of HEADERS) if (!(H.k in headers)) findings.push(mkFinding(H.score, `Missing ${H.name}`, H.impact, H.fix));

    // 3) HTTPS not enforced (served over http or no HSTS + http reachable).
    if (data.finalUrl && data.finalUrl.startsWith('http://')) findings.push(mkFinding(50, 'Site served over HTTP', 'Traffic, including any credentials, is sent unencrypted and can be read or modified in transit.', 'Redirect all HTTP to HTTPS and enable HSTS.'));

    // 4) Insecure cookies.
    const setCookie = headers['set-cookie'] || '';
    if (setCookie) {
      if (!/;\s*secure/i.test(setCookie)) findings.push(mkFinding(35, 'Cookie without Secure flag', 'Session cookies can be sent over plain HTTP and captured on the network.', 'Add the `Secure` attribute to cookies.'));
      if (!/;\s*httponly/i.test(setCookie)) findings.push(mkFinding(35, 'Cookie without HttpOnly flag', 'Cookies are readable from JavaScript, so an XSS flaw can steal the session.', 'Add the `HttpOnly` attribute to session cookies.'));
      if (!/;\s*samesite/i.test(setCookie)) findings.push(mkFinding(20, 'Cookie without SameSite', 'Cookies are sent on cross-site requests, enabling CSRF.', 'Set `SameSite=Lax` or `Strict`.'));
    }

    // 5) Version / tech disclosure.
    for (const [re, label] of TECH) { const m = re.exec(hdrStr); if (m && VERSIONED.test(m[1])) findings.push(mkFinding(25, `${label} version disclosed`, `The response advertises “${m[1].trim()}”, letting an attacker look up version-specific vulnerabilities.`, 'Suppress version banners (e.g. `ServerTokens Prod`, remove X-Powered-By).')); }

    // 6) Directory listing.
    if (/<title>Index of \//i.test(body) || /Directory listing for/i.test(body)) findings.push(mkFinding(40, 'Directory listing enabled', 'Visitors can browse the raw file tree and discover files not meant to be public.', 'Disable automatic directory indexing.'));

    // 7) Exposed sensitive paths (probe through the proxy).
    await pool(PATHS, 5, async P => {
      const resp = await be.fetchUrl(origin + P.p).catch(() => null);
      const d = resp?.data; if (!d) return null;
      if (d.status === 200 && P.sig.test(d.body || '')) return { P, url: d.finalUrl || origin + P.p };
      return null;
    }, (_, hit) => { if (hit) findings.push(mkFinding(hit.P.score, hit.P.name, hit.P.impact, hit.P.fix, { url: hit.url })); });

    // 8) Known CVEs on the resolved host (Shodan InternetDB).
    const a = await dns(host, 'A').catch(() => []);
    const ip = a[0]?.data;
    if (ip) {
      const idb = await getJSON(`https://internetdb.shodan.io/${ip}`).catch(() => null);
      for (const v of (idb?.data?.vulns || []).slice(0, 25)) findings.push(mkFinding(72, `Known CVE on host: ${v}`, `Shodan associates ${v} with software exposed on ${ip}. Review whether this service is patched.`, 'Patch or upgrade the affected software; restrict the service if it need not be public.', { cve: v, ip }));
    }

    // Report.
    const p = posture(findings);
    const md = [
      `# Vulnerability assessment: ${host}`, '',
      `_${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC — posture ${p.score}/100 (${p.sev}), ${findings.length} finding(s)._`, '',
      ...rank(findings).flatMap(f => [`## [${f.sev.toUpperCase()}] ${f.title}`, `**Impact:** ${f.impact}`, `**Remediation:** ${f.fix}`, f.url ? `**Location:** ${f.url}` : '', '']),
    ].join('\n');

    const sc = (n, l, tone) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' + (tone && n ? ' warn' : '') }, String(n)), h('div', { class: 'statlbl muted small' }, l));
    const bySev = s => findings.filter(f => f.sev === s).length;

    const header = card('assessment', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, badge(`${p.score}/100 · ${p.sev}`, toneOf(p.sev)), copyBtn(() => md, 'copy report')) },
      h('p', {}, h('strong', {}, host), ' · ', ext(data.finalUrl || origin, data.finalUrl || origin), ' · ', badge(`HTTP ${data.status}`, 'muted')),
      h('div', { class: 'statrow' }, sc(bySev('critical'), 'critical', 'w'), sc(bySev('high'), 'high', 'w'), sc(bySev('medium'), 'medium', 'w'), sc(bySev('low'), 'low'), sc(findings.length, 'total')));

    const findingCards = findings.length ? card('findings', { wide: true },
      muted('Ranked by severity. Each lists what the weakness means (impact) and how to close it (remediation) — no exploitation steps.'),
      rank(findings).map(f => h('div', { class: 'riskrow', style: 'flex-direction:column;align-items:stretch;gap:4px' },
        h('div', { class: 'row', style: 'gap:8px' }, badge(f.sev, toneOf(f.sev)), h('strong', {}, f.title), f.cve ? pivot('cve', f.cve, 'CVE detail') : null, f.url ? ext(f.url, 'location') : null),
        h('div', { class: 'muted small' }, h('strong', {}, 'Impact: '), f.impact),
        h('div', { class: 'muted small' }, h('strong', {}, 'Fix: '), f.fix)))) : card('clean', { wide: true }, muted('No issues surfaced by the checks run. This is not a guarantee — it covers common misconfigurations and public CVE data, not application logic.'));

    const next = card('next', {},
      h('div', { class: 'row wrap', style: 'gap:6px' },
        pivot('recon', host, 'attack surface'), pivot('headers', host, 'headers'), pivot('monitor', host, 'monitor for changes'),
        ip ? pivot('ip', ip, `host ${ip}`) : null));

    return grid(header, findingCards, next);
  },
};
