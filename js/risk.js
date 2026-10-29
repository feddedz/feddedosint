// Shared risk scoring. Turns raw findings (exposed services, CVEs, dangling CNAMEs, weak mail
// auth, etc.) into a 0-100 score and a severity band, so the engine, playbooks and sweeps can
// rank what matters. Defensive framing: higher = more exposure a defender should fix first.

export const SEVERITY = ['info', 'low', 'medium', 'high', 'critical'];
const BAND = [[90, 'critical'], [70, 'high'], [40, 'medium'], [15, 'low'], [0, 'info']];
export const bandOf = score => BAND.find(([t]) => score >= t)[1];
export const toneOf = sev => ({ critical: 'bad', high: 'bad', medium: 'warn', low: 'muted', info: 'muted' }[sev] || 'muted');

// Management / data-store services that should rarely face the public internet.
const SERVICE_RISK = {
  Telnet: 95, 'MongoDB': 92, 'Redis': 92, 'Elasticsearch': 90, 'Memcached': 90, 'CouchDB': 88,
  'Docker': 95, 'Kubernetes API': 92, 'Kubelet': 90, 'RDP': 85, 'VNC': 88, 'SMB': 85, 'NetBIOS': 80,
  'MSRPC': 78, 'MSSQL': 82, 'MySQL': 82, 'Postgres': 82, 'Oracle': 82, 'NFS': 80, 'RabbitMQ': 78,
  'Kibana': 75, 'FTP': 65, 'SSH': 45, 'cPanel': 60, 'WebLogic': 80,
};

// Produce a finding object. kind drives the base score; detail is free context.
export function finding(kind, detail = {}) {
  let score = 10, title = kind, why = '';
  switch (kind) {
    case 'takeover':
      score = 95; title = `Subdomain takeover: ${detail.host}`;
      why = `${detail.host} points at an unclaimed ${detail.service || 'service'} — an attacker can claim it and serve content from your domain.`;
      break;
    case 'dangling':
      score = 70; title = `Dangling CNAME: ${detail.host}`;
      why = `${detail.host} → ${detail.cname} no longer resolves; potential takeover.`;
      break;
    case 'sensitive-service':
      score = SERVICE_RISK[detail.service] ?? 60; title = `${detail.service} exposed`;
      why = `${detail.service} (port ${detail.port}) is reachable on ${detail.ip} — management/data services should not face the public internet.`;
      break;
    case 'cve':
      score = 72; title = `${detail.cve}`;
      why = `${detail.ip || detail.host} is associated with ${detail.cve} by Shodan.`;
      break;
    case 'cve-cluster':
      score = Math.min(95, 60 + detail.count * 3); title = `${detail.count} known CVEs on ${detail.ip}`;
      why = `Shodan links ${detail.count} CVE(s) to software seen on ${detail.ip}.`;
      break;
    case 'weak-mail':
      score = 45; title = `Weak mail authentication on ${detail.domain}`;
      why = detail.why || 'Missing or permissive SPF/DMARC makes the domain easier to spoof.';
      break;
    case 'open-port':
      score = 18; title = `Port ${detail.port} open on ${detail.ip}`;
      why = `${detail.service || 'service'} reachable on ${detail.ip}.`;
      break;
    case 'new-subdomain':
      score = 20; title = `New subdomain: ${detail.host}`;
      why = 'New attack surface discovered via certificate transparency.';
      break;
    case 'info':
    default:
      score = detail.score ?? 10; title = detail.title || kind; why = detail.why || '';
  }
  return { kind, score, sev: bandOf(score), title, why, detail };
}

// Overall posture from a set of findings: the max severity, weighted by how many high ones.
export function posture(findings) {
  if (!findings.length) return { score: 0, sev: 'info' };
  const max = Math.max(...findings.map(f => f.score));
  const highs = findings.filter(f => f.score >= 70).length;
  const score = Math.min(100, Math.round(max + Math.min(10, highs * 2)));
  return { score, sev: bandOf(score) };
}

export const rank = findings => [...findings].sort((a, b) => b.score - a.score);
