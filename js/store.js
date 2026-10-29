// Per-browser state: API keys, settings, search history and the investigation graph.
// Everything lives in localStorage only — nothing is ever sent anywhere by this module.

const read = (key, fallback) => {
  try { const v = JSON.parse(localStorage.getItem(key)); return v == null ? fallback : v; } catch { return fallback; }
};
const write = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage blocked */ } };

// ---------- API keys ----------
// Each service that can use a key. `where` tells the user how it is used.
export const KEY_DEFS = [
  { id: 'hibp', name: 'Have I Been Pwned', hint: 'email breach search', url: 'https://haveibeenpwned.com/API/Key' },
  { id: 'shodan', name: 'Shodan', hint: 'richer host & exposure data', url: 'https://account.shodan.io/' },
  { id: 'virustotal', name: 'VirusTotal', hint: 'file / url / domain reputation', url: 'https://www.virustotal.com/gui/my-apikey' },
  { id: 'etherscan', name: 'Etherscan', hint: 'ethereum wallet lookups', url: 'https://etherscan.io/myapikey' },
  { id: 'ipinfo', name: 'IPinfo', hint: 'precise IP geolocation & ASN', url: 'https://ipinfo.io/account/token' },
  { id: 'urlscan', name: 'urlscan.io', hint: 'website scanning & screenshots', url: 'https://urlscan.io/user/profile/' },
];

const KEYS = 'feddedosint.keys';
export const getKey = id => read(KEYS, {})[id] || '';
export const setKey = (id, val) => { const k = read(KEYS, {}); if (val) k[id] = val.trim(); else delete k[id]; write(KEYS, k); };
export const hasKey = id => !!getKey(id);

// ---------- session (login) ----------
const SESSION = 'feddedosint.session';
export const getSession = () => read(SESSION, null);
export const setSession = s => (s ? write(SESSION, s) : (() => { try { localStorage.removeItem(SESSION); } catch {} })());
export const authToken = () => getSession()?.token || '';
export const currentUser = () => getSession()?.user || null;

// ---------- settings ----------
const SETTINGS = 'feddedosint.settings';
const defaults = { theme: 'dark', graph: true, rail: false, closedGroups: [] };
export const settings = () => ({ ...defaults, ...read(SETTINGS, {}) });
export const setSetting = (k, v) => { const s = settings(); s[k] = v; write(SETTINGS, s); };

export function applyTheme() {
  const t = settings().theme;
  document.documentElement.setAttribute('data-theme', t);
}

// ---------- recent searches ----------
const RECENT = 'feddedosint.recent';
export const recentFor = tool => read(RECENT, []).filter(r => r.t === tool);
export const recentAll = () => read(RECENT, []);
export function remember(t, q) {
  if (!q) return;
  write(RECENT, [{ t, q, at: Date.now() }, ...read(RECENT, []).filter(r => !(r.t === t && r.q === q))].slice(0, 60));
}
export function clearRecent(tool) {
  write(RECENT, tool ? read(RECENT, []).filter(r => r.t !== tool) : []);
}

// ---------- investigation graph ----------
// Nodes are entities visited (keyed by tool+value). Edges are pivots between them.
const GRAPH = 'feddedosint.graph';
const emptyGraph = () => ({ nodes: {}, edges: [] });
export const graph = () => read(GRAPH, emptyGraph());

export function trackNode(tool, value) {
  if (!settings().graph || !value) return;
  const g = graph();
  const id = `${tool}:${value}`;
  if (!g.nodes[id]) g.nodes[id] = { id, tool, value, at: Date.now() };
  else g.nodes[id].seen = Date.now();
  write(GRAPH, g);
}

export function trackEdge(fromTool, fromValue, toTool, toValue) {
  if (!settings().graph || !fromValue || !toValue) return;
  const from = `${fromTool}:${fromValue}`, to = `${toTool}:${toValue}`;
  if (from === to) return;
  const g = graph();
  trackNode(fromTool, fromValue);
  trackNode(toTool, toValue);
  const g2 = graph();
  if (!g2.edges.some(e => e.from === from && e.to === to)) {
    g2.edges.push({ from, to, at: Date.now() });
    write(GRAPH, g2);
  }
}

export function clearGraph() { write(GRAPH, emptyGraph()); }
export const graphSize = () => Object.keys(graph().nodes).length;

export function removeNode(id) {
  const g = graph();
  delete g.nodes[id];
  g.edges = g.edges.filter(e => e.from !== id && e.to !== id);
  write(GRAPH, g);
}

// Replace the graph with an imported one (case file restore). Only well-formed entries survive.
export function importGraph(g) {
  const nodes = {};
  for (const [id, n] of Object.entries(g?.nodes || {})) {
    if (n && typeof n.tool === 'string' && typeof n.value === 'string') nodes[id] = { id, tool: n.tool, value: n.value, at: Number(n.at) || Date.now() };
  }
  const edges = (g?.edges || []).filter(e => nodes[e?.from] && nodes[e?.to]).map(e => ({ from: e.from, to: e.to, at: Number(e.at) || Date.now() }));
  write(GRAPH, { nodes, edges });
}

// ---------- case file (title + notes) ----------
const CASE = 'feddedosint.case';
export const getCase = () => ({ title: 'untitled investigation', notes: '', ...read(CASE, {}) });
export const setCase = patch => write(CASE, { ...getCase(), ...patch, updated: Date.now() });

// ---------- geolocation cache (ip -> coordinates), so maps do not re-query ----------
const GEO = 'feddedosint.geo';
export const geoCached = ip => read(GEO, {})[ip] || null;
export function geoStore(ip, info) {
  const all = read(GEO, {});
  all[ip] = { ...info, at: Date.now() };
  const keys = Object.keys(all);
  if (keys.length > 500) keys.sort((a, b) => all[a].at - all[b].at).slice(0, keys.length - 500).forEach(k => delete all[k]);
  write(GEO, all);
}
