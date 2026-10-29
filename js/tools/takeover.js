import { h, card, grid, muted, badge, ext, pivot, copyBtn, dns, getJSON, normDomain } from '../util.js';
import * as be from '../backend.js';

// Subdomain-takeover / dangling-CNAME checker. For a domain you own (or are authorized to audit),
// it pulls subdomains from certificate transparency, follows each CNAME, and flags ones pointing at
// a third-party service that looks unclaimed — the classic takeover setup. Public data; live
// confirmation of the "unclaimed" fingerprint goes through the backend proxy when you're approved.

// Known takeover fingerprints (subset of the can-i-take-over-xyz dataset). cname: pattern the CNAME
// target matches; fp: strings that appear on an UNCLAIMED instance; vuln: generally takeover-able.
const SIGNATURES = [
  { service: 'GitHub Pages', cname: /\.github\.io$/i, fp: ["There isn't a GitHub Pages site here", 'For root URLs (like http://example.com/) you must provide an index.html file'], vuln: true },
  { service: 'Amazon S3', cname: /\.s3[.-].*amazonaws\.com$|\.s3\.amazonaws\.com$/i, fp: ['NoSuchBucket', 'The specified bucket does not exist'], vuln: true },
  { service: 'Heroku', cname: /\.herokudns\.com$|\.herokuapp\.com$|\.herokussl\.com$/i, fp: ['No such app', "There's nothing here, yet.", 'herokucdn.com/error-pages/no-such-app.html'], vuln: true },
  { service: 'Fastly', cname: /\.fastly\.net$/i, fp: ['Fastly error: unknown domain', 'Please check that this domain has been added to a service'], vuln: true },
  { service: 'Shopify', cname: /\.myshopify\.com$/i, fp: ['Sorry, this shop is currently unavailable', 'Only one step left!'], vuln: true },
  { service: 'Surge.sh', cname: /\.surge\.sh$/i, fp: ['project not found'], vuln: true },
  { service: 'Tumblr', cname: /\.domains\.tumblr\.com$/i, fp: ["Whatever you were looking for doesn't currently exist at this address", 'There’s nothing here.'], vuln: true },
  { service: 'Pantheon', cname: /\.pantheonsite\.io$/i, fp: ['The gods are wise', '404 error unknown site'], vuln: true },
  { service: 'Ghost', cname: /\.ghost\.io$/i, fp: ['The thing you were looking for is no longer here', 'Domain error'], vuln: true },
  { service: 'Wordpress', cname: /\.wordpress\.com$/i, fp: ['Do you want to register'], vuln: true },
  { service: 'Netlify', cname: /\.netlify\.(app|com)$/i, fp: ['Not Found - Request ID', 'Not found – Request ID'], vuln: false },
  { service: 'Azure', cname: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net|azure-api\.net|azurehdinsight\.net)$/i, fp: ['404 Web Site not found', 'The resource you are looking for has been removed'], vuln: true },
  { service: 'AWS Elastic Beanstalk', cname: /\.elasticbeanstalk\.com$/i, fp: [], vuln: true },
  { service: 'Bitbucket', cname: /\.bitbucket\.io$/i, fp: ['Repository not found'], vuln: true },
  { service: 'Zendesk', cname: /\.zendesk\.com$/i, fp: ['Help Center Closed', 'this help center no longer exists'], vuln: false },
  { service: 'Readme.io', cname: /\.readme\.io$/i, fp: ['Project doesnt exist... yet!'], vuln: true },
  { service: 'Cargo', cname: /\.cargocollective\.com$/i, fp: ['404 Not Found', "If you're moving your domain away from Cargo"], vuln: true },
  { service: 'Webflow', cname: /\.proxy\.webflow\.com$|\.website-files\.com$/i, fp: ['The page you are looking for doesn’t exist or has been moved'], vuln: false },
  { service: 'Help Scout', cname: /\.helpscoutdocs\.com$/i, fp: ['No settings were found for this company'], vuln: true },
  { service: 'Unbounce', cname: /\.unbouncepages\.com$/i, fp: ['The requested URL was not found on this server'], vuln: false },
];

const sigFor = cname => SIGNATURES.find(s => s.cname.test(cname));

async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  const run = async () => { while (i < items.length) { const idx = i++; const r = await fn(items[idx]).catch(() => null); onEach?.(items[idx], r); } };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, run));
}

// Resolve the CNAME chain for a host (DoH). Returns the final CNAME target, or '' if none.
async function cnameOf(host) {
  const r = await dns(host, 'CNAME').catch(() => []);
  return r.length ? r[0].data.replace(/\.$/, '').toLowerCase() : '';
}

// Does the apex / target host resolve at all? NXDOMAIN on the service target is the strongest signal.
async function resolves(host) {
  const [a, aaaa, cn] = await Promise.all([dns(host, 'A').catch(() => []), dns(host, 'AAAA').catch(() => []), dns(host, 'CNAME').catch(() => [])]);
  return a.length + aaaa.length + cn.length > 0;
}

async function collectSubdomains(d) {
  const set = new Set();
  const ct = await getJSON(`https://crt.sh/?q=${encodeURIComponent('%.' + d)}&output=json`, { timeout: 25000 }).catch(() => null);
  if (ct?.ok && Array.isArray(ct.data)) for (const row of ct.data) {
    String(row.name_value || '').split('\n').forEach(n => {
      n = n.trim().toLowerCase().replace(/^\*\./, '');
      if (n && n.endsWith(d) && !n.includes(' ')) set.add(n);
    });
  }
  return [...set];
}

async function assess(host) {
  const cname = await cnameOf(host);
  if (!cname) return { host, state: 'no-cname' };
  const sig = sigFor(cname);
  if (!sig) return { host, cname, state: 'third-party' }; // CNAME to something, but not a known takeover target

  // Known service. The target not resolving is a strong takeover signal on its own.
  const targetLive = await resolves(cname);
  let fpHit = false, probed = false, bodyNote = '';
  if (be.backendConfigured() && be.isApproved() && sig.fp.length) {
    probed = true;
    let r = await be.fetchUrl(`https://${host}`).catch(() => null);
    if (!r?.ok || !r.data?.status) r = await be.fetchUrl(`http://${host}`).catch(() => null);
    const body = r?.data?.body || '';
    const hit = sig.fp.find(s => body.includes(s));
    if (hit) { fpHit = true; bodyNote = hit; }
  }
  // Classify.
  let state = 'claimed';
  if (fpHit) state = 'vulnerable';
  else if (!targetLive) state = 'dangling';
  else if (probed) state = 'claimed';
  else state = 'review'; // couldn't confirm the body (not approved / no fp list)
  return { host, cname, service: sig.service, vulnService: sig.vuln, state, bodyNote, targetLive };
}

const STATE = {
  vulnerable: ['bad', 'TAKEOVER'],
  dangling: ['bad', 'dangling'],
  review: ['warn', 'review'],
  'third-party': ['muted', '3rd-party CNAME'],
  claimed: ['ok', 'claimed'],
  'no-cname': ['muted', 'no CNAME'],
};

function row(r) {
  const [tone, label] = STATE[r.state] || ['muted', r.state];
  return h('tr', {},
    h('td', {}, badge(label, tone)),
    h('td', {}, pivot('recon', r.host, r.host)),
    h('td', { class: 'muted small', style: 'word-break:break-all' }, r.cname || '—', r.service ? h('span', {}, ' ', badge(r.service, 'muted')) : null),
    h('td', { class: 'muted small' }, r.state === 'vulnerable' ? `unclaimed fingerprint matched` : r.state === 'dangling' ? 'CNAME target does not resolve' : r.bodyNote ? '' : ''));
}

export default {
  id: 'takeover',
  label: 'takeover',
  placeholder: 'example.com  (domain to audit) or sub.example.com',
  intro: 'Subdomain-takeover audit: follows each subdomain’s CNAME and flags ones pointing at an unclaimed third-party service. For domains you own or are authorized to test.',
  examples: ['example.com'],

  async run(raw) {
    const input = (normDomain(raw) || raw.trim().replace(/^https?:\/\//i, '').split('/')[0]).toLowerCase();
    if (!input) throw new Error('enter a domain, e.g. example.com');

    // A single host (has a subdomain label beyond the registrable 2) is checked directly;
    // an apex is expanded via certificate transparency.
    const labels = input.split('.');
    const single = labels.length > 2;
    let hosts;
    if (single) hosts = [input];
    else {
      hosts = await collectSubdomains(input);
      if (!hosts.length) hosts = [input, `www.${input}`];
      hosts = hosts.slice(0, 200); // keep it browser-friendly
    }

    const approved = be.backendConfigured() && be.isApproved();
    const results = [];
    await pool(hosts, 8, assess, (_, r) => r && results.push(r));

    const order = { vulnerable: 0, dangling: 1, review: 2, 'third-party': 3, claimed: 4, 'no-cname': 5 };
    results.sort((a, b) => (order[a.state] - order[b.state]) || a.host.localeCompare(b.host));

    const vuln = results.filter(r => r.state === 'vulnerable');
    const dangling = results.filter(r => r.state === 'dangling');
    const review = results.filter(r => r.state === 'review');
    const cnamed = results.filter(r => ['third-party', 'claimed', 'vulnerable', 'dangling', 'review'].includes(r.state));

    const sc = (n, l, tone) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' + (tone && n ? ' warn' : '') }, String(n)), h('div', { class: 'statlbl muted small' }, l));
    const summary = card('takeover audit', { wide: true, actions: badge(`${hosts.length} host${hosts.length === 1 ? '' : 's'}`, 'muted') },
      muted(`${single ? 'Checked' : 'Expanded from certificate transparency and checked'} ${hosts.length} host(s) for dangling CNAMEs. ${approved ? 'Live fingerprint confirmation is on (you’re approved).' : 'Sign-in/approval needed to confirm the unclaimed fingerprint live — results show DNS-level signals only.'}`),
      h('div', { class: 'statrow' },
        sc(vuln.length, 'takeover', true),
        sc(dangling.length, 'dangling', true),
        sc(review.length, 'to review', true),
        sc(cnamed.length, 'CNAMEs'),
        sc(hosts.length, 'checked')),
      (vuln.length || dangling.length) ? null : muted('No obvious takeover candidates. Re-run periodically — a service can lapse at any time.'));

    const flagged = [...vuln, ...dangling, ...review];
    const flagCard = flagged.length ? card('candidates', { wide: true },
      muted('Highest-risk first. A “takeover” row matched an unclaimed-service fingerprint; “dangling” points at a service target that no longer resolves; “review” couldn’t be confirmed live.'),
      h('table', { class: 'records' }, h('tbody', {}, flagged.map(row))),
      vuln.length ? h('p', { class: 'muted small' }, 'Remediation: remove the dangling DNS record, or (re)claim the resource on the named service before someone else does.') : null) : null;

    const rest = cnamed.filter(r => !['vulnerable', 'dangling', 'review'].includes(r.state));
    const restCard = rest.length ? card(`other CNAMEs (${rest.length})`, { wide: true, collapsed: true },
      h('table', { class: 'records' }, h('tbody', {}, rest.map(row)))) : null;

    return grid(summary, flagCard, restCard);
  },
};
