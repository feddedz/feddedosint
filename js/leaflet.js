// Shared map helper: lazy-loads Leaflet (pinned + SRI) and builds theme-matched maps.

import { h, loadScript, loadStyle } from './util.js';

const JS = 'https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js';
const JS_SRI = 'sha384-cxOPjt7s7Iz04uaHJceBmS+qpjv2JkIHNVcuOrM+YHwZOmJGBXI00mdUXEq65HTH';
const CSS = 'https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css';
const CSS_SRI = 'sha384-sHL9NAb7lN7rfvG5lfHpm643Xkcjzp4jFvuavGOndn6pjVqS6ny56CAt3nsEVT4H';

export async function leaflet() {
  await Promise.all([loadStyle(CSS, CSS_SRI), loadScript(JS, JS_SRI)]);
  return window.L;
}

const light = () => document.documentElement.getAttribute('data-theme') === 'light';
export const ink = () => (light() ? '#111114' : '#f2f2f4');

// Returns a container element; the map is created once the element is in the document
// (Leaflet needs real dimensions). `ready(L, map)` receives the live map.
export function mapBox(ready, { height = 320 } = {}) {
  const el = h('div', { class: 'leafbox', style: `height:${height}px` },
    h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'loading map…'));
  leaflet().then(L => {
    const start = () => {
      if (!el.isConnected) return requestAnimationFrame(start);
      el.replaceChildren();
      const map = L.map(el, { zoomControl: true, attributionControl: true, worldCopyJump: true, scrollWheelZoom: false });
      L.tileLayer(`https://{s}.basemaps.cartocdn.com/${light() ? 'light_all' : 'dark_all'}/{z}/{x}/{y}{r}.png`, {
        subdomains: 'abcd', maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
      }).addTo(map);
      map.on('click', () => map.scrollWheelZoom.enable());
      map.on('mouseout', () => map.scrollWheelZoom.disable());
      new ResizeObserver(() => map.invalidateSize()).observe(el);
      ready(L, map);
    };
    start();
  }).catch(() => {
    el.replaceChildren(h('p', { class: 'muted' }, 'map unavailable — the map library could not be loaded (offline or CDN blocked).'));
  });
  return el;
}

// A gently curved arc between two points (quadratic bezier sampled in lat/lon space).
export function arc(a, b, bend = 0.18, steps = 32) {
  const [lat1, lon1] = a, [lat2, lon2] = b;
  const mx = (lat1 + lat2) / 2, my = (lon1 + lon2) / 2;
  const dx = lat2 - lat1, dy = lon2 - lon1;
  const cx = mx - dy * bend, cy = my + dx * bend; // control point offset perpendicular to the chord
  const pts = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps, u = 1 - t;
    pts.push([u * u * lat1 + 2 * u * t * cx + t * t * lat2, u * u * lon1 + 2 * u * t * cy + t * t * lon2]);
  }
  return pts;
}

export const dot = (L, latlng, opts = {}) => L.circleMarker(latlng, {
  radius: 6, color: ink(), weight: 1.5, fillColor: ink(), fillOpacity: 0.85, ...opts,
});
