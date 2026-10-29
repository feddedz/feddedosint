import { h, card, grid, muted, badge, ext, pivot, copyBtn, dns, getJSON, normDomain } from '../util.js';
import * as be from '../backend.js';

// Common subdomains to brute-force via DNS (fast, client-side, no key needed). Complements the
// passive certificate-transparency pull so even domains with sparse CT logs surface something.
const WORDLIST = ('www mail smtp imap pop webmail mx mx1 mx2 ns1 ns2 remote vpn ssh sftp ftp git gitlab '
  + 'dev development staging stage test testing qa uat demo sandbox beta alpha preview '
  + 'api api1 api2 apis gateway auth login sso accounts account id oauth idp admin administrator panel '
  + 'portal dashboard console manage cpanel whm plesk internal intranet corp office vpn2 '
  + 'app apps web web1 web2 m mobile static assets cdn img images media files download downloads uploads '
  + 'store shop cart checkout pay payment payments billing invoice secure ssl '
  + 'blog news forum community help support helpdesk docs documentation wiki kb status monitor monitoring '
  + 'grafana kibana prometheus jenkins ci cd build nexus artifactory sonar registry docker k8s '
  + 'db database sql mysql postgres redis mongo elastic es cache backup backups old legacy archive '
  + 'ns ns3 dns dns1 dns2 email autodiscover autoconfig lyncdiscover sip owa exchange '
  + 'vpn1 fw firewall proxy edge lb loadbalancer router gw '
  + 'crm erp hr jira confluence slack chat video conf meet zoom teams '
  + 'analytics metrics logs log data warehouse bi report reports '
  + 'cloud aws azure gcp s3 storage bucket objects '
  + 'test1 test2 stage1 prod production live public www2 www3 origin direct').split(/\s+/).filter(Boolean);

// Port → service name + whether it's sensitive/interesting on a public host.
const PORTS = {
  21: ['FTP', 1], 22: ['SSH', 1], 23: ['Telnet', 1], 25: ['SMTP', 0], 53: ['DNS', 0], 80: ['HTTP', 0], 110: ['POP3', 0],
  111: ['RPC', 1], 135: ['MSRPC', 1], 139: ['NetBIOS', 1], 143: ['IMAP', 0], 443: ['HTTPS', 0], 445: ['SMB', 1],
  465: ['SMTPS', 0], 587: ['SMTP', 0], 993: ['IMAPS', 0], 995: ['POP3S', 0], 1433: ['MSSQL', 1], 1521: ['Oracle', 1],
  2049: ['NFS', 1], 2082: ['cPanel', 1], 2083: ['cPanel', 1], 2375: ['Docker', 1], 2376: ['Docker', 1], 3000: ['dev/app', 0],
  3306: ['MySQL', 1], 3389: ['RDP', 1], 4444: ['metasploit?', 1], 5432: ['Postgres', 1], 5601: ['Kibana', 1],
  5900: ['VNC', 1], 5984: ['CouchDB', 1], 6379: ['Redis', 1], 7001: ['WebLogic', 1], 8000: ['HTTP-alt', 0], 8008: ['HTTP-alt', 0],
  8080: ['HTTP-alt', 0], 8086: ['InfluxDB', 1], 8443: ['HTTPS-alt', 0], 8888: ['HTTP-alt', 0], 9000: ['app', 0],
  9200: ['Elasticsearch', 1], 9300: ['Elasticsearch', 1], 11211: ['Memcached', 1], 27017: ['MongoDB', 1], 27018: ['MongoDB', 1],
  5000: ['app/Docker reg', 0], 6443: ['Kubernetes API', 1], 10250: ['Kubelet', 1], 15672: ['RabbitMQ', 1],
};

// Fingerprints from response headers / body → technology.
const TECH = [
  [h => /wp-content|wp-includes/i.test(h.body), 'WordPress'],
  [h => /drupal/i.test(h.body) || /x-drupal/i.test(h.hdr), 'Drupal'],
  [h => /joomla/i.test(h.body), 'Joomla'],
  [h => /x-shopify|cdn\.shopify/i.test(h.hdr + h.body), 'Shopify'],
  [h => /wix\.com|x-wix/i.test(h.hdr + h.body), 'Wix'],
  [h => /squarespace/i.test(h.body), 'Squarespace'],
  [h => /ghost|content="Ghost/i.test(h.body), 'Ghost'],
  [h => /__NEXT_DATA__|\/_next\//.test(h.body), 'Next.js'],
  [h => /data-reactroot|react(?:-dom)?\.production/i.test(h.body), 'React'],
  [h => /ng-version=|angular/i.test(h.body), 'Angular'],
  [h => /data-v-[0-9a-f]{8}|__vue__/i.test(h.body), 'Vue'],
  [h => /x-powered-by:\s*express|x-powered-by.*express/i.test(h.hdr), 'Express'],
  [h => /x-powered-by.*php|set-cookie.*phpsessid/i.test(h.hdr), 'PHP'],
  [h => /x-aspnet-version|asp\.net|__viewstate/i.test(h.hdr + h.body), 'ASP.NET'],
  [h => /x-powered-by.*laravel|laravel_session/i.test(h.hdr), 'Laravel'],
  [h => /django|csrftoken/i.test(h.hdr + h.body), 'Django'],
  [h => /ruby|phusion|passenger/i.test(h.hdr), 'Ruby/Rails'],
  [h => /cloudflare/i.test(h.hdr), 'Cloudflare'],
  [h => /x-amz|amazonaws|x-amz-cf/i.test(h.hdr), 'AWS'],
  [h => /x-vercel|vercel/i.test(h.hdr), 'Vercel'],
  [h => /x-nf-request-id|netlify/i.test(h.hdr), 'Netlify'],
  [h => /x-github-request|github\.io/i.test(h.hdr), 'GitHub Pages'],
  [h => /server:\s*nginx/i.test(h.hdr), 'nginx'],
  [h => /server:\s*apache/i.test(h.hdr), 'Apache'],
  [h => /server:\s*(microsoft-)?iis/i.test(h.hdr), 'IIS'],
  [h => /server:\s*litespeed/i.test(h.hdr), 'LiteSpeed'],
  [h => /server:\s*caddy/i.test(h.hdr), 'Caddy'],
  [h => /jenkins|x-jenkins/i.test(h.hdr + h.body), 'Jenkins'],
  [h => /kibana|elastic/i.test(h.body), 'Kibana/Elastic'],
  [h => /grafana/i.test(h.body), 'Grafana'],
];

// Run fn across items with a fixed concurrency; calls onEach(item, result) as each finishes.
async function pool(items, concurrency, fn, onEach) {
  let i = 0;
  const run = async () => {
    while (i < items.length) {
      const idx = i++;
      const res = await fn(items[idx]).catch(() => null);
      onEach?.(items[idx], res);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) || 1 }, run));
}

const titleOf = body => {
  const m = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(body || '');
  return m ? m[1].replace(/\s+/g, ' ').trim() : '';
};
const stat = (label, el) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' }, el), h('div', { class: 'statlbl muted small' }, label));

export default {
  id: 'recon',
  label: 'recon',
  placeholder: 'domain (e.g. example.com)',
  intro: 'Full passive attack-surface map: discovers subdomains (certificate transparency + brute-force), resolves them, probes which are live, fingerprints their tech, and pulls open ports & known CVEs for every host — all from public data.',
  examples: ['github.com', 'stripe.com'],

  run(raw) {
    const d = normDomain(raw) || raw.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!d || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) throw new Error('enter a domain like example.com');

    const hasBackend = be.backendConfigured() && be.isApproved();

    // ---- live UI shell ----
    const sFound = h('span', {}, '0'), sResolved = h('span', {}, '0'), sLive = h('span', {}, '0'),
      sIPs = h('span', {}, '0'), sPorts = h('span', {}, '0'), sCVE = h('span', {}, '0');
    const phase = h('span', { class: 'muted small' }, 'starting…');
    const bar = h('div', { class: 'barfill' });
    const hostBody = h('tbody');
    const ipList = h('div', { class: 'livelist' });
    const risks = h('div', { class: 'risklist' });

    const state = { hosts: new Map(), ips: new Map(), live: 0, ports: 0, cves: 0 };
    const exportJSON = () => JSON.stringify({
      domain: d, generated: new Date().toISOString(),
      hosts: [...state.hosts.values()].map(x => ({ host: x.host, ips: x.ips, status: x.status || null, title: x.title || null, server: x.server || null, tech: x.tech || [] })),
      exposure: [...state.ips.values()].map(x => ({ ip: x.ip, ports: x.ports || [], vulns: x.vulns || [], hostnames: x.hostnames || [] })),
    }, null, 2);
    const exportCSV = () => ['host,ip,status,server,tech,title',
      ...[...state.hosts.values()].map(x => [x.host, (x.ips || []).join('|'), x.status || '', x.server || '', (x.tech || []).join('|'), (x.title || '').replace(/[",]/g, ' ')].map(c => `"${c}"`).join(','))].join('\n');

    const setStats = () => {
      sFound.textContent = state.hosts.size;
      sResolved.textContent = [...state.hosts.values()].filter(x => x.ips?.length).length;
      sLive.textContent = state.live;
      sIPs.textContent = state.ips.size;
      sPorts.textContent = state.ports;
      sCVE.textContent = state.cves;
    };

    const addRisk = (tone, text) => risks.append(h('div', { class: 'riskrow' }, badge(tone === 'bad' ? 'high' : 'note', tone), h('span', {}, text)));

    function hostRow(x) {
      const statusBadge = x.status ? badge(String(x.status), x.status < 300 ? 'ok' : x.status < 400 ? 'warn' : 'bad') : muted('—');
      return h('tr', {},
        h('td', {}, ext(`https://${x.host}`, x.host), ' ', pivot('domain', x.host, 'dns')),
        h('td', { class: 'mono small' }, (x.ips || []).map(ip => pivot('ip', ip, ip)).flatMap((n, i) => i ? [', ', n] : [n])),
        h('td', {}, statusBadge),
        h('td', { class: 'small' }, (x.tech || []).map(t => badge(t, 'muted'))),
        h('td', { class: 'small muted' }, x.title || (x.ips?.length ? (x.probed ? 'no page' : 'resolved') : 'no DNS')));
    }
    const rerenderHost = x => { if (x.rowRef) { const nr = hostRow(x); x.rowRef.replaceWith(nr); x.rowRef = nr; } };

    async function runRecon() {
      // --- phase 1: discover ---
      phase.textContent = 'discovering subdomains (certificate transparency + brute-force)…';
      bar.style.width = '8%';
      const names = new Set([d]);
      // crt.sh (passive, from CT logs)
      try {
        const r = await getJSON(`https://crt.sh/?q=%25.${encodeURIComponent(d)}&output=json`, { timeout: 45000 });
        if (r.ok && Array.isArray(r.data)) for (const row of r.data) String(row.name_value || '').split('\n').forEach(n => {
          n = n.trim().toLowerCase().replace(/^\*\./, '');
          if (n.endsWith('.' + d) || n === d) names.add(n);
        });
      } catch { /* crt.sh often overloaded; brute still covers us */ }
      // hackertarget passive DNS (via proxy, if available)
      if (hasBackend) {
        try {
          const r = await be.fetchUrl(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(d)}`);
          if (r.ok && r.data?.body && !/error|API count/i.test(r.data.body)) r.data.body.split('\n').forEach(line => {
            const host = line.split(',')[0]?.trim().toLowerCase();
            if (host && (host.endsWith('.' + d) || host === d)) names.add(host);
          });
        } catch { /* optional */ }
      }
      // brute-force wordlist
      for (const w of WORDLIST) names.add(`${w}.${d}`);

      for (const host of names) state.hosts.set(host, { host, ips: [], probed: false });
      setStats();
      phase.textContent = `resolving ${names.size} candidate hosts…`;
      bar.style.width = '25%';

      // --- phase 2: resolve via DoH ---
      let done = 0;
      await pool([...names], 24, async host => {
        const [a, aaaa] = await Promise.all([dns(host, 'A').catch(() => []), dns(host, 'AAAA').catch(() => [])]);
        return [...a.map(r => r.data), ...aaaa.map(r => r.data)];
      }, (host, ips) => {
        done++;
        const x = state.hosts.get(host);
        if (ips && ips.length) {
          x.ips = [...new Set(ips)];
          x.rowRef = hostRow(x); hostBody.append(x.rowRef);
          for (const ip of x.ips) if (!state.ips.has(ip)) state.ips.set(ip, { ip });
        }
        if (done % 10 === 0 || done === names.size) { setStats(); bar.style.width = `${25 + Math.round((done / names.size) * 25)}%`; }
      });
      // drop the hosts that never resolved from the map for cleaner exports, keep the base domain
      for (const [host, x] of state.hosts) if (!x.ips.length && host !== d) state.hosts.delete(host);
      setStats();

      const resolved = [...state.hosts.values()].filter(x => x.ips.length);
      if (!resolved.length) { phase.textContent = 'no hosts resolved — the domain may be parked or fully internal.'; bar.style.width = '100%'; return; }

      // --- phase 3: probe live hosts (needs the backend proxy) ---
      if (hasBackend) {
        phase.textContent = `probing ${Math.min(resolved.length, 80)} live hosts…`;
        const probeSet = resolved.slice(0, 80);
        let p = 0;
        await pool(probeSet, 6, async x => {
          let r = await be.fetchUrl(`https://${x.host}`);
          if (!r.ok || !r.data?.status) r = await be.fetchUrl(`http://${x.host}`);
          return r.ok ? r.data : null;
        }, (x, data) => {
          p++;
          x.probed = true;
          if (data && data.status) {
            x.status = data.status;
            x.title = titleOf(data.body);
            const hdr = Object.entries(data.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
            x.server = data.headers?.server || '';
            const fp = { hdr, body: (data.body || '').slice(0, 60000) };
            x.tech = [...new Set([...(x.server ? [] : []), ...TECH.filter(([t]) => t(fp)).map(([, n]) => n)])];
            if (x.server && !x.tech.length) x.tech = [x.server.split('/')[0]];
            if (data.status < 400) state.live++;
            if (data.finalUrl && !data.finalUrl.includes(x.host)) x.title = (x.title ? x.title + ' ' : '') + `→ ${new URL(data.finalUrl).host}`;
          }
          rerenderHost(x);
          if (p % 5 === 0 || p === probeSet.length) { setStats(); bar.style.width = `${50 + Math.round((p / probeSet.length) * 25)}%`; }
        });
      } else {
        phase.textContent = 'sign in + connect the backend to probe live hosts and fingerprint tech. Showing passive DNS only.';
      }

      // --- phase 4: exposure per IP (Shodan InternetDB, public, no key) ---
      phase.textContent = `checking exposure for ${state.ips.size} IPs…`;
      const ips = [...state.ips.keys()].slice(0, 64);
      let q = 0;
      await pool(ips, 10, async ip => getJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`).then(r => (r.ok ? r.data : null)), (ip, data) => {
        q++;
        const rec = state.ips.get(ip);
        if (data) {
          rec.ports = data.ports || [];
          rec.vulns = data.vulns || [];
          rec.hostnames = data.hostnames || [];
          state.ports += rec.ports.length;
          state.cves += rec.vulns.length;
          if (rec.ports.length || rec.vulns.length) ipList.append(ipRow(ip, rec));
          // flag sensitive services + CVEs
          const hostFor = [...state.hosts.values()].find(x => x.ips.includes(ip))?.host || ip;
          for (const port of rec.ports) { const info = PORTS[port]; if (info && info[1]) addRisk('bad', `${hostFor} (${ip}) exposes ${info[0]} on port ${port}`); }
          if (rec.vulns.length) addRisk('bad', `${hostFor} (${ip}) has ${rec.vulns.length} known CVE(s): ${rec.vulns.slice(0, 6).join(', ')}${rec.vulns.length > 6 ? '…' : ''}`);
          // reflect ports onto host rows
          for (const x of state.hosts.values()) if (x.ips.includes(ip)) rerenderHost(x);
        }
        if (q % 5 === 0 || q === ips.length) { setStats(); bar.style.width = `${75 + Math.round((q / ips.length) * 25)}%`; }
      });

      setStats();
      bar.style.width = '100%';
      if (!risks.children.length) addRisk('ok', 'no exposed sensitive services or known CVEs found on the hosts checked.');
      phase.textContent = `done — ${state.hosts.size} hosts, ${state.ips.size} IPs, ${state.ports} open ports, ${state.cves} CVEs.`;
    }

    function ipRow(ip, rec) {
      const portTags = (rec.ports || []).map(p => { const i = PORTS[p]; return badge(`${p}${i ? ' ' + i[0] : ''}`, i && i[1] ? 'bad' : 'muted'); });
      return h('div', { class: 'liverow found' }, h('span', { class: 'dot found' }), h('div', { class: 'avatar' }),
        h('div', { class: 'main' },
          h('div', {}, pivot('ip', ip, ip), ' ', pivot('map', ip, 'map'), rec.vulns?.length ? badge(`${rec.vulns.length} CVE`, 'bad') : null),
          h('div', { class: 'detail small' }, portTags.length ? portTags : muted('no ports seen'),
            rec.vulns?.length ? h('div', { class: 'small' }, 'CVEs: ', rec.vulns.slice(0, 10).map(v => [pivot('cve', v, v), ' '])) : null)));
    }

    requestAnimationFrame(runRecon);

    const statsRow = h('div', { class: 'statrow' },
      stat('subdomains', sFound), stat('resolve', sResolved), stat('live', sLive),
      stat('IPs', sIPs), stat('open ports', sPorts), stat('CVEs', sCVE));

    const hostTable = h('table', { class: 'datatable' },
      h('thead', {}, h('tr', {}, ['host', 'IP(s)', 'status', 'tech', 'title / notes'].map(c => h('th', {}, c)))),
      hostBody);

    return grid(
      card('attack surface', { wide: true, actions: h('div', { class: 'actions' }, phase, copyBtn(exportJSON, 'json'), copyBtn(exportCSV, 'csv')) },
        muted(`Passive reconnaissance of ${d}. Everything here comes from public DNS, certificate-transparency logs and Shodan's free host database — no packets are sent to the target by your browser; live-host probing goes through your own backend.`),
        statsRow, h('div', { class: 'scanbar' }, bar)),
      card('findings', { wide: true }, risks),
      card('hosts', { wide: true }, hostTable),
      card('exposed services & CVEs', { wide: true }, muted('Open ports and known vulnerabilities per IP, from Shodan InternetDB.'), ipList),
    );
  },
};
