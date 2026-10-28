// Custom minimal line icons — one thin-stroke SVG path set per id, drawn on a 24×24 grid.
// Monochrome, inherit currentColor. Keep them simple and geometric to match the UI.

const P = {
  overview: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>',          // magnifier
  username: '<circle cx="12" cy="8" r="3.4"/><path d="M5.5 19c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/>',
  email: '<rect x="3" y="5.5" width="18" height="13" rx="2"/><path d="M4 7l8 6 8-6"/>',
  phone: '<rect x="7" y="3" width="10" height="18" rx="2.2"/><path d="M11 18h2"/>',
  breach: '<path d="M12 3l7 3v5c0 4.3-2.9 7.6-7 9-4.1-1.4-7-4.7-7-9V6z"/><path d="M12 9v3.5"/><circle cx="12" cy="15.5" r="0.6" fill="currentColor"/>',
  domain: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.6 2.4 2.6 14.6 0 17M12 3.5c-2.6 2.4-2.6 14.6 0 17"/>',
  ip: '<rect x="3" y="4.5" width="18" height="6" rx="1.5"/><rect x="3" y="13.5" width="18" height="6" rx="1.5"/><circle cx="7" cy="7.5" r="0.7" fill="currentColor"/><circle cx="7" cy="16.5" r="0.7" fill="currentColor"/>',
  asn: '<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="18" r="2.2"/><circle cx="19" cy="18" r="2.2"/><path d="M12 7.2v4M12 11.2L6.5 16M12 11.2L17.5 16"/>',
  cve: '<path d="M12 2.5l9.5 16.5H2.5z"/><path d="M12 9.5v4.5"/><circle cx="12" cy="16.6" r="0.6" fill="currentColor"/>',
  crypto: '<circle cx="12" cy="12" r="8.5"/><path d="M9.5 8.5h4a2 2 0 010 4h-4zM9.5 12.5h4.3a2 2 0 010 4H9.5zM9.5 8.5v8M11 6.5v2M11 16.5v2M13 6.5v2M13 16.5v2"/>',
  image: '<rect x="3" y="4.5" width="18" height="15" rx="2"/><circle cx="8.5" cy="9.5" r="1.6"/><path d="M4 17l5-4 4 3 3-2.5 4 3.5"/>',
  records: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 15.5h6"/>',
  dorks: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5M8.5 11h5M11 8.5v5"/>',
  utils: '<path d="M14.5 6a3.5 3.5 0 00-4.9 4.3L4 15.9 6.1 18l5.6-5.6A3.5 3.5 0 0016 8.5l-2 2-1.8-1.8z"/>',
  graph: '<circle cx="6" cy="7" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="16" cy="18" r="2"/><circle cx="7" cy="17" r="2"/><path d="M8 7.5l8-1M7.2 15.2l1.4-6.4M8.9 17.3l5.2.4M17.6 8l-1.3 8"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M21.5 12h-3M5.5 12h-3M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1M18.4 18.4l-2.1-2.1M7.7 7.7L5.6 5.6"/>',
  map: '<path d="M9 4L3.5 6.5v13L9 17l6 2.5 5.5-2.5v-13L15 6.5z"/><path d="M9 4v13M15 6.5v13"/>',
  pivot: '<path d="M7 7h7a4 4 0 014 4v3"/><path d="M16 11l2 3 2-3M7 4L4 7l3 3"/>',
  export: '<path d="M12 3v11"/><path d="M8 10l4 4 4-4"/><path d="M5 18h14"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 00-2-2H5a2 2 0 00-2 2v9a2 2 0 002 2h3"/>',
  external: '<path d="M14 5h5v5"/><path d="M19 5l-8 8"/><path d="M18 13v5a1 1 0 01-1 1H6a1 1 0 01-1-1V7a1 1 0 011-1h5"/>',
};

export function icon(id, cls = '') {
  const paths = P[id] || P.overview;
  return `<svg class="icon ${cls}" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
}

// Build an <svg> element (for appending via DOM rather than innerHTML).
export function iconEl(id, cls = '') {
  const wrap = document.createElement('span');
  wrap.innerHTML = icon(id, cls);
  return wrap.firstChild;
}
