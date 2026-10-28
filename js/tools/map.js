import { h, getJSON, dns, card, grid, muted, badge, pivot, normDomain, isIP, flag, refang } from '../util.js';
import { graph, geoCached, geoStore } from '../store.js';
import { mapBox, arc, dot, ink } from '../leaflet.js';
import { parseCoords } from './geo.js';

async function locate(ip) {
  const hit = geoCached(ip);
  if (hit) return hit;
  const r = await getJSON(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (!r.data?.success || r.data.latitude == null) return null;
  const g = r.data, info = { lat: g.latitude, lon: g.longitude, city: g.city, country: g.country, cc: g.country_code, org: g.connection?.org || g.connection?.isp };
  geoStore(ip, info);
  return info;
}

// Run async jobs with limited concurrency so free APIs are not hammered.
async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]).catch(() => null); }
  }));
  return out;
}

// Turn free text into entities: IPs, domains/URLs and "lat,lon" pairs.
function parseList(text) {
  const out = [];
  for (let tok of refang(text).split(/[\s;|]+/).filter(Boolean)) {
    const c = /^-?\d+(\.\d+)?,-?\d+(\.\d+)?$/.test(tok) && parseCoords(tok);
    if (c) { out.push({ tool: 'geo', value: c.join(',') }); continue; }
    for (const part of tok.split(',').filter(Boolean)) {
      if (isIP(part.replace(/^\[|\]$/g, ''))) out.push({ tool: 'ip', value: part.replace(/^\[|\]$/g, '') });
      else { const d = normDomain(part); if (d) out.push({ tool: 'domain', value: d }); }
    }
  }
  return out;
}

export default {
  id: 'map',
  label: 'map',
  placeholder: 'IPs, domains or lat,lon — space separated (empty = your graph)',
  intro: 'Plot infrastructure on a world map. Domains resolve to their servers, linked entities are joined by arcs.',
  examples: ['github.com 1.1.1.1 8.8.8.8 bbc.co.uk'],
  allowEmpty: true,
  noTrack: true,

  async run(raw) {
    const fromGraph = !raw.trim();
    let ents, links = [];
    if (fromGraph) {
      const g = graph();
      ents = Object.values(g.nodes).filter(n => ['ip', 'domain', 'geo'].includes(n.tool)).map(n => ({ tool: n.tool, value: n.value }));
      links = g.edges.map(e => [e.from, e.to]);
      if (!ents.length) return card('nothing to plot yet', { wide: true },
        muted('Your investigation graph has no IPs, domains or coordinates yet. Search some, or type a list above (e.g. "github.com 1.1.1.1").'));
    } else {
      ents = parseList(raw);
      if (!ents.length) throw new Error('no IPs, domains or coordinates found in that input');
    }
    ents = [...new Map(ents.map(e => [`${e.tool}:${e.value}`, e])).values()].slice(0, 60);

    // Resolve: domain -> first A record -> location. ip -> location. geo -> as is.
    const points = new Map(), failed = [];
    await pool(ents, 4, async e => {
      const id = `${e.tool}:${e.value}`;
      if (e.tool === 'geo') {
        const [lat, lon] = e.value.split(',').map(Number);
        points.set(id, { id, ...e, lat, lon, place: 'coordinates' });
        return;
      }
      let ip = e.value;
      if (e.tool === 'domain') {
        ip = (await dns(e.value, 'A').catch(() => []))[0]?.data;
        if (!ip) { failed.push([e, 'does not resolve']); return; }
      }
      const loc = await locate(ip);
      if (!loc) { failed.push([e, 'no location']); return; }
      points.set(id, { id, ...e, ip, lat: loc.lat, lon: loc.lon, place: [loc.city, loc.country].filter(Boolean).join(', '), cc: loc.cc, org: loc.org });
      if (e.tool === 'domain') {
        const ipId = `ip:${ip}`;
        if (!points.has(ipId)) points.set(ipId, { id: ipId, tool: 'ip', value: ip, ip, lat: loc.lat, lon: loc.lon, place: [loc.city, loc.country].filter(Boolean).join(', '), cc: loc.cc, org: loc.org, derived: true });
        links.push([id, ipId, 'resolves']);
      }
    });

    const pts = [...points.values()];
    const edges = links.filter(([a, b]) => points.has(a) && points.has(b) && a !== b);
    const listEl = h('div', { class: 'maplist' });
    const markers = new Map(), lines = [];
    let lmap = null;

    const highlight = (id, on) => {
      const m = markers.get(id);
      if (m) m.setStyle({ radius: on ? 10 : 6, fillOpacity: on ? 1 : 0.85 });
      for (const l of lines) if (l.ends.includes(id)) l.line.setStyle({ opacity: on ? 1 : 0.55, weight: on ? 2.5 : 1.4 });
      listEl.querySelector(`[data-id="${CSS.escape(id)}"]`)?.classList.toggle('hot', on);
    };

    const map = mapBox((L, m) => {
      lmap = m;
      const bounds = [];
      for (const [a, b, kind] of edges) {
        const pa = points.get(a), pb = points.get(b);
        const line = L.polyline(arc([pa.lat, pa.lon], [pb.lat, pb.lon]), {
          color: ink(), weight: 1.4, opacity: 0.55, className: kind === 'resolves' ? 'arc arc-dash' : 'arc', interactive: false,
        }).addTo(m);
        lines.push({ line, ends: [a, b] });
      }
      for (const p of pts) {
        const mk = dot(L, [p.lat, p.lon], p.derived ? { radius: 5, fillOpacity: 0.5 } : {}).addTo(m);
        mk.bindPopup(h('div', { class: 'popup' },
          h('strong', {}, p.value), h('br'),
          h('span', {}, `${p.cc ? flag(p.cc) + ' ' : ''}${p.place || ''}`), p.org ? [h('br'), h('span', {}, p.org)] : null,
          p.ip && p.ip !== p.value ? [h('br'), h('span', {}, `→ ${p.ip}`)] : null, h('br'),
          pivot(p.tool, p.value, `open ${p.tool} lookup →`)));
        mk.on('mouseover', () => highlight(p.id, true));
        mk.on('mouseout', () => highlight(p.id, false));
        markers.set(p.id, mk);
        bounds.push([p.lat, p.lon]);
      }
      if (bounds.length === 1) m.setView(bounds[0], 6);
      else if (bounds.length) m.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 });
      else m.setView([20, 0], 2);
    }, { height: 460 });

    listEl.replaceChildren(...pts.map(p => {
      const row = h('div', { class: 'maprow', dataset: { id: p.id } },
        badge(p.tool), pivot(p.tool, p.value),
        h('span', { class: 'muted small' }, `${p.cc ? flag(p.cc) + ' ' : ''}${p.place || ''}${p.org ? ' · ' + p.org : ''}`));
      row.addEventListener('mouseenter', () => highlight(p.id, true));
      row.addEventListener('mouseleave', () => highlight(p.id, false));
      row.addEventListener('click', e => {
        if (e.target.closest('a')) return;
        const mk = markers.get(p.id);
        if (mk && lmap) { lmap.setView(mk.getLatLng(), Math.max(lmap.getZoom(), 6)); mk.openPopup(); }
      });
      return row;
    }));

    return grid(
      card(`infrastructure map · ${pts.length} points · ${edges.length} links`, { wide: true }, map,
        h('div', { class: 'legend muted small' }, h('span', { class: 'lg-dot' }), ' entity  ', h('span', { class: 'lg-dot dim' }), ' resolved server  ',
          h('span', { class: 'lg-line' }), ' pivot link  ', h('span', { class: 'lg-line dash' }), ' resolves to',
          fromGraph ? '  · plotted from your investigation graph' : '')),
      card('points', { wide: true }, pts.length ? listEl : muted('nothing could be located.')),
      failed.length ? card(`not plotted · ${failed.length}`, { wide: true, collapsed: true },
        h('div', { class: 'sublist' }, failed.map(([e, why]) => h('div', {}, pivot(e.tool, e.value), h('span', { class: 'muted small' }, ` ${why}`))))) : null,
    );
  },
};
