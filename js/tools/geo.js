import { h, getJSON, card, asyncCard, kv, ext, pivot, grid, muted, copyBtn, linkGroups, fmtNum } from '../util.js';
import { mapBox, dot } from '../leaflet.js';

const BASE32 = '0123456789bcdefghjkmnpqrstuvwxyz';
function geohash(lat, lon, precision = 9) {
  const range = { lat: [-90, 90], lon: [-180, 180] };
  let out = '', bits = 0, idx = 0, even = true;
  while (out.length < precision) {
    const axis = even ? 'lon' : 'lat', v = even ? lon : lat, r = range[axis];
    const mid = (r[0] + r[1]) / 2;
    if (v >= mid) { idx = idx * 2 + 1; r[0] = mid; } else { idx *= 2; r[1] = mid; }
    even = !even;
    if (++bits === 5) { out += BASE32[idx]; bits = 0; idx = 0; }
  }
  return out;
}

const dms = (v, pos, neg) => {
  const a = Math.abs(v), d = Math.floor(a), mf = (a - d) * 60, m = Math.floor(mf), s = (mf - m) * 60;
  return `${d}°${String(m).padStart(2, '0')}'${s.toFixed(2).padStart(5, '0')}"${v >= 0 ? pos : neg}`;
};

// Decimal pairs, DMS, or a pasted maps URL. Returns [lat, lon] or null.
export function parseCoords(s) {
  s = s.trim();
  let m = s.match(/@(-?\d+\.\d+),(-?\d+\.\d+)/) || s.match(/[?&](?:q|ll|query|center)=(-?\d+\.\d+)(?:,|%2C)\s*(-?\d+\.\d+)/i);
  if (m) return [+m[1], +m[2]];
  m = s.match(/^(-?\d+(?:\.\d+)?)\s*[,;\s]\s*(-?\d+(?:\.\d+)?)$/);
  if (m) return [+m[1], +m[2]];
  const parts = [...s.matchAll(/(\d+(?:\.\d+)?)\s*[°º]\s*(?:(\d+(?:\.\d+)?)\s*['’′]\s*)?(?:(\d+(?:\.\d+)?)\s*(?:["”″]|'')\s*)?([NSEW])/gi)];
  if (parts.length === 2) {
    const val = p => ({ v: (+p[1] + (+p[2] || 0) / 60 + (+p[3] || 0) / 3600) * (/[SW]/i.test(p[4]) ? -1 : 1), lat: /[NS]/i.test(p[4]) });
    const [a, b] = parts.map(val);
    if (a.lat !== b.lat) return a.lat ? [a.v, b.v] : [b.v, a.v];
  }
  return null;
}

const valid = ([lat, lon]) => Math.abs(lat) <= 90 && Math.abs(lon) <= 180;

export default {
  id: 'geo',
  label: 'geo',
  placeholder: 'coordinates, DMS, a maps link, or a place name',
  intro: 'Convert coordinates, see what is at a location, and jump to satellite, street-level and shadow tools.',
  examples: ['48.85837, 2.29448', `40°41'21.4"N 74°02'40.2"W`, 'Big Ben'],

  async run(raw) {
    const q = raw.trim();
    if (!q) throw new Error('enter coordinates or a place');
    let point = parseCoords(q), candidates = [];
    if (!point) {
      const r = await getJSON(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}&format=jsonv2&limit=6`);
      candidates = Array.isArray(r.data) ? r.data : [];
      if (!candidates.length) throw new Error(r.ok ? 'no place found with that name' : 'the geocoder is unavailable — enter coordinates instead');
      point = [+candidates[0].lat, +candidates[0].lon];
    }
    if (!valid(point)) throw new Error('coordinates out of range (lat ±90, lon ±180)');
    const [lat, lon] = point.map(v => +v.toFixed(6));
    const ll = `${lat},${lon}`;

    return grid(
      card('location', { actions: copyBtn(ll, 'copy') }, kv([
        ['decimal', h('code', {}, `${lat}, ${lon}`)],
        ['dms', h('code', {}, `${dms(lat, 'N', 'S')} ${dms(lon, 'E', 'W')}`)],
        ['geohash', h('code', {}, geohash(lat, lon))],
        ['hemisphere', `${lat >= 0 ? 'northern' : 'southern'} · ${lon >= 0 ? 'eastern' : 'western'}`],
        ['matched', candidates[0]?.display_name],
      ])),

      asyncCard('address (reverse geocode)', async () => {
        const r = await getJSON(`https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=jsonv2&zoom=18&addressdetails=1`);
        const a = r.data?.address;
        if (!a) throw new Error('nothing found at this point');
        return kv([
          ['place', r.data.name || null],
          ['road', [a.house_number, a.road].filter(Boolean).join(' ')],
          ['area', a.suburb || a.neighbourhood || a.quarter],
          ['city', a.city || a.town || a.village || a.municipality],
          ['region', a.state || a.county],
          ['postcode', a.postcode],
          ['country', a.country],
          ['feature', r.data.category && `${r.data.category} · ${r.data.type}`],
        ]);
      }),

      card('map', { wide: true }, mapBox((L, map) => {
        map.setView([lat, lon], candidates.length ? 15 : 16);
        dot(L, [lat, lon], { radius: 8 }).addTo(map);
        L.circle([lat, lon], { radius: 250, color: '#888', weight: 1, fillOpacity: 0.04, interactive: false }).addTo(map);
        map.on('click', e => {
          const p = `${e.latlng.lat.toFixed(6)},${e.latlng.lng.toFixed(6)}`;
          L.popup().setLatLng(e.latlng).setContent(h('div', {}, h('code', {}, p), h('br'), pivot('geo', p, 'inspect this point →'))).openOn(map);
        });
      }, { height: 360 }), h('p', { class: 'muted small' }, 'click anywhere on the map to inspect another point')),

      asyncCard('nearby (wikipedia)', async () => {
        const r = await getJSON(`https://en.wikipedia.org/w/api.php?action=query&list=geosearch&gscoord=${lat}%7C${lon}&gsradius=10000&gslimit=12&format=json&origin=*`);
        const list = r.data?.query?.geosearch || [];
        if (!list.length) return muted('no Wikipedia articles within 10 km.');
        return h('div', { class: 'breach-list' }, list.map(p => h('div', { class: 'breach-item' },
          h('div', { class: 'bi-head' }, ext(`https://en.wikipedia.org/?curid=${p.pageid}`, p.title),
            h('span', { class: 'muted small' }, p.dist < 1000 ? `${fmtNum(Math.round(p.dist))} m` : `${(p.dist / 1000).toFixed(1)} km`)),
          h('div', { class: 'small' }, pivot('geo', `${p.lat},${p.lon}`, `${p.lat.toFixed(4)}, ${p.lon.toFixed(4)}`)))));
      }),

      candidates.length > 1 ? card('other matches', {}, h('div', { class: 'breach-list' }, candidates.slice(1).map(c => h('div', { class: 'breach-item' },
        pivot('geo', `${(+c.lat).toFixed(6)},${(+c.lon).toFixed(6)}`, c.display_name))))) : null,

      card('open in', { wide: true }, linkGroups([
        { group: 'maps & street level', items: [
          ['Google Maps', `https://www.google.com/maps?q=${ll}`],
          ['Street View', `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${ll}`],
          ['Mapillary', `https://www.mapillary.com/app/?lat=${lat}&lng=${lon}&z=17`],
          ['Apple Maps', `https://maps.apple.com/?ll=${ll}&z=17`],
          ['Bing (aerial)', `https://www.bing.com/maps?cp=${lat}~${lon}&lvl=18&style=a`],
          ['Yandex', `https://yandex.com/maps/?ll=${lon},${lat}&z=17&pt=${lon},${lat}`],
          ['OpenStreetMap', `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${lat}/${lon}`],
        ] },
        { group: 'imagery & analysis', items: [
          ['Google Earth', `https://earth.google.com/web/@${lat},${lon},400a,800d,35y,0h,0t,0r`],
          ['Sentinel EO Browser', `https://apps.sentinel-hub.com/eo-browser/?zoom=15&lat=${lat}&lng=${lon}`],
          ['Zoom Earth', `https://zoom.earth/maps/satellite/#view=${lat},${lon},16z`],
          ['SunCalc (shadows)', `https://www.suncalc.org/#/${lat},${lon},17/null/null/null/null`],
          ['Overpass Turbo', `https://overpass-turbo.eu/?C=${lat};${lon};17`],
          ['Wikimapia', `https://wikimapia.org/#lat=${lat}&lon=${lon}&z=17`],
        ] },
      ])),
    );
  },
};
