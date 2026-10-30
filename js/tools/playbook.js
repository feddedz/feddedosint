import { h, card, grid, muted, badge, ext, pivot, copyBtn, dns, getJSON, isIP, normDomain } from '../util.js';
import { trackNode, trackEdge, addWatch, saveSnapshot } from '../store.js';
import { finding, posture, rank, toneOf, bandOf } from '../risk.js';
import * as be from '../backend.js';

// Compact web-config checks (shared idea with the assess tool) folded into the workflow.
const WEB_HEADERS = [
  ['content-security-policy', 'Content-Security-Policy', 45, 'No CSP — the main backstop against XSS is missing.'],
  ['strict-transport-security', 'HSTS', 40, 'No HSTS — visitors can be downgraded to plain HTTP.'],
  ['x-frame-options', 'X-Frame-Options', 30, 'Page can be framed — clickjacking risk.'],
  ['x-content-type-options', 'X-Content-Type-Options', 20, 'MIME-sniffing not disabled.'],
];
const WEB_PATHS = [
  ['/.git/config', /\[core\]|repositoryformatversion/i, 90, 'Exposed .git repository', 'Source and credential history can be reconstructed.'],
  ['/.env', /[A-Z_]+=|DB_PASSWORD|SECRET/i, 95, 'Exposed .env file', 'Secrets/DB passwords likely exposed in plain text.'],
  ['/phpinfo.php', /phpinfo\(\)|PHP Version/i, 50, 'phpinfo() exposed', 'Discloses full server configuration.'],
];
const webFinding = (score, title, why) => ({ score, sev: bandOf(score), title, why });

async function webChecks(host, addFinding, findings, step) {
  if (!(be.backendConfigured() && be.isApproved())) return;
  const origin = `https://${host}`;
  step('web config', `checking security headers & exposed files on ${host}…`);
  let r = await be.fetchUrl(origin).catch(() => null);
  if (!r?.ok || !r.data?.status) r = await be.fetchUrl(`http://${host}`).catch(() => null);
  const headers = r?.data?.headers || {};
  if (r?.data?.status) {
    for (const [k, name, score, why] of WEB_HEADERS) if (!(k in headers)) addFinding(webFinding(score, `Missing ${name}`, why), findings);
    const sc = headers['set-cookie'] || '';
    if (sc && !/;\s*httponly/i.test(sc)) addFinding(webFinding(35, 'Cookie without HttpOnly', 'XSS could steal the session cookie.'), findings);
  }
  await pool(WEB_PATHS, 4, async ([p, sig, score, title, why]) => {
    const resp = await be.fetchUrl(origin + p).catch(() => null);
    if (resp?.data?.status === 200 && sig.test(resp.data.body || '')) return { score, title, why };
    return null;
  }, (_, hit) => { if (hit) addFinding(webFinding(hit.score, hit.title, hit.why), findings); });
}

// Automated investigation playbook: one target in, a full workflow runs itself — map the surface,
// pull exposure, check for dangling CNAMEs and weak mail auth — and out comes a single risk-scored
// report. A human reads the report and decides; nothing consequential happens on its own.
// Public data, client-side. For assets you own or are authorized to assess.

const SENSITIVE = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 135: 'MSRPC', 139: 'NetBIOS', 445: 'SMB', 1433: 'MSSQL',
  1521: 'Oracle', 2049: 'NFS', 2375: 'Docker', 2376: 'Docker', 3306: 'MySQL', 3389: 'RDP',
  5432: 'Postgres', 5601: 'Kibana', 5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis', 6443: 'Kubernetes API',
  9200: 'Elasticsearch', 9300: 'Elasticsearch', 10250: 'Kubelet', 11211: 'Memcached', 15672: 'RabbitMQ',
  27017: 'MongoDB', 27018: 'MongoDB', 2082: 'cPanel', 2083: 'cPanel', 7001: 'WebLogic',
};
const TAKEOVER_CNAME = [
  [/\.github\.io$/i, 'GitHub Pages'], [/\.s3[.-].*amazonaws\.com$|\.s3\.amazonaws\.com$/i, 'Amazon S3'],
  [/\.herokudns\.com$|\.herokuapp\.com$/i, 'Heroku'], [/\.myshopify\.com$/i, 'Shopify'],
  [/\.fastly\.net$/i, 'Fastly'], [/\.(azurewebsites\.net|cloudapp\.net|trafficmanager\.net|blob\.core\.windows\.net)$/i, 'Azure'],
  [/\.surge\.sh$/i, 'Surge'], [/\.ghost\.io$/i, 'Ghost'], [/\.bitbucket\.io$/i, 'Bitbucket'],
  [/\.pantheonsite\.io$/i, 'Pantheon'], [/\.elasticbeanstalk\.com$/i, 'Elastic Beanstalk'],
];

async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  const run = async () => { while (i < items.length) { const idx = i++; const r = await fn(items[idx]).catch(() => null); onEach?.(items[idx], r); } };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, run));
}

async function internetDB(ip) {
  const r = await getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { timeout: 9000 }).catch(() => null);
  return r?.ok ? r.data : null;
}

async function runPlaybook(target, { step, addFinding, container }) {
  const kind = isIP(target) ? 'ip' : 'domain';
  const findings = [], entities = new Set(), evidence = [];
  const addEnt = (tool, value) => entities.add(`${tool}\u0000${value}`);
  trackNode(kind, target); addEnt(kind, target);

  let ips = [];
  if (kind === 'domain') {
    step('surface', `resolving ${target} and pulling records…`);
    const [a, aaaa, mx, ns, txt] = await Promise.all([
      dns(target, 'A').catch(() => []), dns(target, 'AAAA').catch(() => []), dns(target, 'MX').catch(() => []),
      dns(target, 'NS').catch(() => []), dns(target, 'TXT').catch(() => []),
    ]);
    ips = [...a, ...aaaa].map(r => r.data);
    ips.forEach(ip => { addEnt('ip', ip); trackEdge('domain', target, 'ip', ip); });
    mx.forEach(r => addEnt('domain', r.data.replace(/^\d+\s+/, '')));
    evidence.push(`${target} resolves to ${ips.join(', ') || 'no A/AAAA'}; ${mx.length} MX, ${ns.length} NS [DNS]`);

    // Weak mail auth
    const spf = txt.find(r => /^v=spf1/i.test(r.data));
    if (!spf) addFinding(finding('weak-mail', { domain: target, why: 'No SPF record found — the domain is easier to spoof in email.' }), findings);
    else if (/[?~]all/.test(spf.data) || !/-all/.test(spf.data)) addFinding(finding('weak-mail', { domain: target, why: `SPF is permissive (${/all/.exec(spf.data) ? spf.data.match(/[-~?+]all/)?.[0] : 'no -all'}).` }), findings);

    step('subdomains', 'querying certificate transparency (crt.sh)…');
    const ct = await getJSON(`https://crt.sh/?q=${encodeURIComponent('%.' + target)}&output=json`, { timeout: 25000 }).catch(() => null);
    const subs = new Set();
    if (ct?.ok && Array.isArray(ct.data)) for (const row of ct.data) String(row.name_value || '').split('\n').forEach(n => {
      n = n.trim().toLowerCase().replace(/^\*\./, ''); if (n.endsWith(target) && !n.includes(' ')) subs.add(n);
    });
    const subList = [...subs].slice(0, 120);
    step('subdomains', `${subs.size} subdomain(s) from CT — checking for dangling CNAMEs…`);
    subList.forEach(s => addEnt('domain', s));

    // Dangling-CNAME (DNS-level) across subdomains.
    await pool(subList, 8, async host => {
      const cn = await dns(host, 'CNAME').catch(() => []);
      if (!cn.length) return null;
      const target2 = cn[0].data.replace(/\.$/, '').toLowerCase();
      const svc = TAKEOVER_CNAME.find(([re]) => re.test(target2));
      if (!svc) return null;
      const [a2, aa2, cn2] = await Promise.all([dns(target2, 'A').catch(() => []), dns(target2, 'AAAA').catch(() => []), dns(target2, 'CNAME').catch(() => [])]);
      const live = a2.length + aa2.length + cn2.length > 0;
      return { host, cname: target2, service: svc[1], live };
    }, (host, r) => { if (r && !r.live) addFinding(finding('dangling', r), findings); });
  } else {
    ips = [target]; addEnt('ip', target);
    const ptr = await dns(target.includes(':') ? target : target.split('.').reverse().join('.') + '.in-addr.arpa', 'PTR').catch(() => []);
    ptr.forEach(r => { addEnt('domain', r.data); evidence.push(`${target} reverse-resolves to ${r.data} [DNS]`); });
  }

  // Exposure per IP.
  step('exposure', `querying Shodan InternetDB for ${ips.length} IP(s)…`);
  await pool(ips, 10, internetDB, (ip, d) => {
    if (!d) return;
    const ports = (d.ports || []);
    if (ports.length) evidence.push(`${ip}: ports ${ports.join(', ')} [Shodan InternetDB]`);
    for (const p of ports) {
      if (SENSITIVE[p]) addFinding(finding('sensitive-service', { ip, port: p, service: SENSITIVE[p] }), findings);
    }
    const vulns = d.vulns || [];
    if (vulns.length >= 3) addFinding(finding('cve-cluster', { ip, count: vulns.length }), findings);
    else for (const v of vulns) addFinding(finding('cve', { ip, cve: v }), findings);
    (d.vulns || []).forEach(v => addEnt('cve', v));
    (d.hostnames || []).forEach(hn => addEnt('domain', hn));
  });

  if (kind === 'domain') await webChecks(target, addFinding, findings, step);
  step('done', `workflow complete — ${findings.length} finding(s).`);
  return { kind, findings, entities: [...entities].map(s => { const [tool, value] = s.split('\u0000'); return { tool, value }; }), evidence };
}

function reportMarkdown(target, kind, p, findings, entities, evidence) {
  const byTool = {};
  for (const e of entities) (byTool[e.tool] ||= []).push(e.value);
  return [
    `# Playbook report: ${target}`, '',
    `_${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC — risk ${p.score}/100 (${p.sev}), ${findings.length} finding(s)._`, '',
    '## Findings (ranked)', '',
    ...(findings.length ? rank(findings).map(f => `- **[${f.sev.toUpperCase()}] ${f.title}** — ${f.why}`) : ['- none']), '',
    '## Entities', '',
    ...Object.entries(byTool).map(([t, vs]) => `- **${t}** (${vs.length}): ${vs.join(', ')}`), '',
    '## Evidence', '',
    ...evidence.map(e => `- ${e}`), '',
  ].join('\n');
}

export default {
  id: 'playbook',
  label: 'playbook',
  placeholder: 'example.com or an IP  (run an automated audit workflow)',
  intro: 'One target, a full automated workflow: surface mapping, exposure, dangling-CNAME and mail-auth checks — ending in a single risk-scored report you review. For assets you own or are authorized to assess.',
  examples: ['example.com', '1.1.1.1'],

  run(raw) {
    const target = isIP(raw.trim()) ? raw.trim() : (normDomain(raw) || raw.trim());
    if (!target) throw new Error('enter a domain or IP');

    const statusEl = h('span', {}, h('span', { class: 'spin' }), h('span', { class: 'muted small' }, ' starting…'));
    const logEl = h('div', { class: 'steplog' });
    const reportEl = h('div', {});
    const container = h('div', {}, grid(
      card('automated playbook', { wide: true, actions: statusEl },
        muted(`Running the exposure-audit workflow against ${target}. Each step is logged; findings are scored and ranked below.`),
        logEl),
      reportEl));

    const findingsAll = [];
    const step = (tag, text) => { if (container.isConnected) { logEl.append(h('div', { class: 'step' }, badge(tag, 'muted'), h('span', {}, text))); logEl.scrollTop = logEl.scrollHeight; } };
    const addFinding = (f, arr) => { arr.push(f); findingsAll.push(f); };

    runPlaybook(target, { step, addFinding, container }).then(({ kind, findings, entities, evidence }) => {
      if (!container.isConnected) return;
      const p = posture(findings);
      statusEl.replaceChildren(badge(`risk ${p.score}/100 · ${p.sev}`, toneOf(p.sev)));

      const md = reportMarkdown(target, kind, p, findings, entities, evidence);
      const watchBtn = h('button', { class: 'mini', type: 'button' }, 'add to watchlist');
      watchBtn.onclick = () => { addWatch(kind, target); watchBtn.textContent = 'watching ✓'; watchBtn.disabled = true; };

      const findingCards = findings.length
        ? h('table', { class: 'records' }, h('tbody', {}, rank(findings).map(f => h('tr', {},
            h('td', {}, badge(f.sev, toneOf(f.sev))),
            h('td', {}, h('strong', {}, f.title), h('div', { class: 'muted small' }, f.why))))))
        : muted('No exposure findings surfaced. Re-run periodically — exposure changes.');

      const byTool = {};
      for (const e of entities) (byTool[e.tool] ||= []).push(e.value);

      reportEl.replaceChildren(grid(
        card('risk report', { wide: true, actions: h('div', { class: 'row', style: 'gap:6px' }, badge(`${p.score}/100`, toneOf(p.sev)), watchBtn, copyBtn(() => md, 'copy report')) },
          h('p', {}, h('strong', {}, `Overall posture: ${p.sev.toUpperCase()} (${p.score}/100)`)),
          findingCards),
        card('entities', { wide: true, collapsed: true },
          ...Object.entries(byTool).map(([t, vs]) => h('p', {}, h('strong', {}, `${t}: `),
            ...vs.slice(0, 40).flatMap((v, i) => [i ? ', ' : '', pivot(t, v, v)])))),
        card('next', {},
          h('div', { class: 'row wrap', style: 'gap:6px' },
            pivot('monitor', target, 'monitor for changes'),
            pivot('engine', target, 'autonomous engine'),
            kind === 'domain' ? pivot('takeover', target, 'full takeover audit') : pivot('sweep', target, 'sweep its network')))));
    }).catch(err => { if (container.isConnected) { statusEl.replaceChildren(badge('error', 'bad')); reportEl.replaceChildren(h('p', { class: 'error' }, err.message || String(err))); } });

    return container;
  },
};
