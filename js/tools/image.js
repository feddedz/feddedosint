import { h, loadScript, sha256, card, kv, ext, linkGroups, grid, muted, copyBtn } from '../util.js';

const LIB = 'https://cdn.jsdelivr.net/npm/exifr@7.1.3/dist/full.umd.js';
const LIB_SRI = 'sha384-KrOocIA+lZcNUz2MDavnT/FuX+CbTREJihUi0bp8QUSwhE2AkGTNpv2b7yMbBkx5';

const HIGHLIGHTS = [
  ['Make', 'camera make'], ['Model', 'camera model'], ['LensModel', 'lens'], ['BodySerialNumber', 'body serial'],
  ['SerialNumber', 'serial'], ['InternalSerialNumber', 'internal serial'], ['DateTimeOriginal', 'taken'], ['CreateDate', 'created'],
  ['ModifyDate', 'modified'], ['OffsetTimeOriginal', 'utc offset'], ['Software', 'software'], ['CreatorTool', 'creator tool'],
  ['HostComputer', 'host computer'], ['Artist', 'artist'], ['Creator', 'creator'], ['OwnerName', 'owner'], ['CameraOwnerName', 'owner'],
  ['Copyright', 'copyright'], ['Rights', 'rights'], ['ImageDescription', 'description'], ['Headline', 'headline'],
  ['City', 'city'], ['Country', 'country'], ['GPSAltitude', 'altitude (m)'], ['GPSImgDirection', 'direction (°)'],
];

function show(v) {
  if (v instanceof Date) return isNaN(v) ? String(v) : v.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
  if (v instanceof Uint8Array || v instanceof ArrayBuffer) return `[${v.byteLength} bytes]`;
  if (Array.isArray(v)) return v.length > 12 ? `[${v.length} values]` : v.map(show).join(', ');
  if (v && typeof v === 'object') return JSON.stringify(v).slice(0, 300);
  return String(v);
}

function reverseLinks(url) {
  const enc = url && encodeURIComponent(url);
  return linkGroups([{ group: url ? 'reverse image search' : 'reverse image search (upload the file there)', items: url ? [
    ['Google Lens', `https://lens.google.com/uploadbyurl?url=${enc}`],
    ['Bing Visual', `https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:${enc}`],
    ['Yandex', `https://yandex.com/images/search?rpt=imageview&url=${enc}`],
    ['TinEye', `https://tineye.com/search?url=${enc}`],
  ] : [
    ['Google Lens', 'https://lens.google.com/'], ['Bing Visual', 'https://www.bing.com/visualsearch'],
    ['Yandex', 'https://yandex.com/images/'], ['TinEye', 'https://tineye.com/'],
  ] }]);
}

async function analyse(blob, name) {
  const buf = await blob.arrayBuffer();
  let tags = null, libError = null;
  try {
    await loadScript(LIB, LIB_SRI);
    tags = await window.exifr.parse(buf, {
      tiff: true, exif: true, gps: true, xmp: true, iptc: true, ihdr: true, icc: false,
      mergeOutput: true, translateValues: true, reviveValues: true,
    });
  } catch (e) {
    libError = /load/.test(e?.message) ? 'could not load the EXIF library' : null;
  }

  const url = URL.createObjectURL(blob);
  const img = h('img', { src: url, alt: name });
  const dims = h('span');
  img.onload = () => { dims.textContent = `${img.naturalWidth} × ${img.naturalHeight}`; };

  const lat = tags?.latitude, lon = tags?.longitude;
  const hits = HIGHLIGHTS.filter(([k]) => tags?.[k] != null && tags[k] !== '').map(([k, label]) => [label, show(tags[k])]);
  const all = tags ? Object.entries(tags).filter(([k]) => !['latitude', 'longitude'].includes(k)) : [];

  const hash = await sha256(buf);

  return grid(
    card('file', { actions: copyBtn(hash, 'copy sha-256') },
      h('div', { class: 'preview' }, img),
      kv([['name', name], ['type', blob.type || 'unknown'], ['size', `${(blob.size / 1024).toFixed(1)} KB`], ['dimensions', dims],
        ['sha-256', h('span', { class: 'mono wrap small' }, hash)]])),
    card('location', {},
      lat != null && lon != null ? [
        kv([['gps', h('span', { class: 'mono' }, `${lat.toFixed(6)}, ${lon.toFixed(6)}`)],
          ['open in', [ext(`https://www.google.com/maps?q=${lat},${lon}`, 'Google Maps'), ' · ',
            ext(`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`, 'OpenStreetMap'), ' · ',
            ext(`https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${lat},${lon}`, 'Street View')]]]),
        h('div', { class: 'map' }, h('iframe', {
          loading: 'lazy', title: 'photo location', referrerpolicy: 'no-referrer',
          src: `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 0.01},${lat - 0.005},${lon + 0.01},${lat + 0.005}&layer=mapnik&marker=${lat},${lon}`,
        })),
      ] : muted('no GPS coordinates embedded.')),
    card('metadata', { wide: true },
      libError ? muted(libError) : hits.length ? kv(hits) : muted(all.length ? 'no identifying fields.' :
        'no metadata found — most social networks and messengers strip it on upload. Try to get the original file.'),
      all.length ? h('details', {}, h('summary', {}, `all ${all.length} tags`), kv(all.map(([k, v]) => [k, show(v)]))) : null),
    card('search', { wide: true }, reverseLinks(null)),
  );
}

function dropzone(results) {
  const input = h('input', { type: 'file', accept: 'image/*', hidden: true });
  const zone = h('label', { class: 'drop' }, input,
    h('strong', {}, 'drop an image or click to choose'),
    h('span', { class: 'muted' }, 'EXIF, GPS & camera data are read locally — the file never leaves your browser.'));
  const handle = async file => {
    if (!file) return;
    results.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'reading ', file.name, '…'));
    try {
      results.replaceChildren(await analyse(file, file.name));
    } catch (e) {
      results.replaceChildren(muted(`could not read that file: ${e.message}`));
    }
  };
  input.addEventListener('change', () => handle(input.files[0]));
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('over'); handle(e.dataTransfer.files[0]); });
  return zone;
}

export default {
  id: 'image',
  label: 'image',
  placeholder: 'image URL — or drop a file below',
  intro: 'Reverse image search from a URL, or drop a photo to extract EXIF, camera serials and GPS location offline.',
  examples: [],
  allowEmpty: true,

  async run(raw) {
    const url = raw.trim();
    const results = h('div');
    const zone = dropzone(results);
    if (!url) return [zone, results];
    if (!/^https?:\/\/\S+$/i.test(url)) throw new Error('enter an http(s) image URL, or drop a file');

    // Most hosts block cross-origin reads, so metadata from a URL is best-effort.
    const meta = h('div');
    fetch(url, { referrerPolicy: 'no-referrer' })
      .then(r => (r.ok ? r.blob() : Promise.reject()))
      .then(b => analyse(b, url.split('/').pop().split('?')[0] || 'image'))
      .then(node => meta.replaceChildren(node))
      .catch(() => meta.replaceChildren(muted('this host blocks direct reads, so metadata could not be extracted — download the image and drop it above.')));

    return [
      zone,
      results,
      grid(card('reverse search', { wide: true },
        h('div', { class: 'preview' }, h('img', { src: url, alt: 'target image', referrerpolicy: 'no-referrer' })),
        reverseLinks(url))),
      meta,
    ];
  },
};
