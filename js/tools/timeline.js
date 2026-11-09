import { h, card, grid, muted, badge, ext, pivot, copyBtn, getJSON, normDomain, fmtDate, fmtNum } from '../util.js';

// Reconstruct a domain's history from public records: RDAP lifecycle events, the first time each
// subdomain appeared in certificate-transparency logs, and the Internet Archive's web-presence span.
// A chronological "temporal intelligence" view — the past, where monitor watches the future.

const parseCdxTs = ts => {
  const m = String(ts).match(/^(\d{4})(\d{2})(\d{2})/);
  return m ? new Date(`${m[1]}-${m[2]}-${m[3]}T00:00:00Z`) : null;
};
const yearOf = d => new Date(d).getUTCFullYear();
const EV_TONE = { registered: 'ok', expires: 'warn', changed: 'muted', transferred: 'warn', web: 'ok', subdomain: 'muted', cert: 'muted' };

export default {
  id: 'timeline',
  label: 'timeline',
  placeholder: 'domain (e.g. example.com)',
  intro: 'Reconstructs a domain\'s history from public records — registration & expiry (RDAP), when each subdomain first appeared in certificate-transparency logs, and its Internet Archive presence — as one dated timeline. The temporal lens: monitor watches ahead, timeline looks back.',
  examples: ['github.com', 'stripe.com'],

  run(raw) {
    const d = normDomain(raw) || raw.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!d || !/\./.test(d)) throw new Error('enter a domain like example.com');

    const summary = h('span', { class: 'muted small' }, 'reconstructing history…');
    const sAge = h('span', {}, '—'), sWeb = h('span', {}, '—'), sSubs = h('span', {}, '—'), sCerts = h('span', {}, '—');
    const streamBox = h('div', {});
    const stat = (l, el) => h('div', { class: 'statcell' }, h('div', { class: 'statnum' }, el), h('div', { class: 'statlbl muted small' }, l));

    (async () => {
      const events = [];                 // {date:Date, type, text, ref?}
      const add = (date, type, text, ref) => { const t = date instanceof Date ? date : new Date(date); if (!isNaN(t)) events.push({ date: t, type, text, ref }); };

      const [rdap, certs, cdx] = await Promise.all([
        getJSON(`https://rdap.org/domain/${encodeURIComponent(d)}`, { timeout: 20000 }).catch(() => null),
        getJSON(`https://crt.sh/?q=%25.${encodeURIComponent(d)}&output=json`, { timeout: 45000 }).catch(() => null),
        getJSON(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(d)}&output=json&fl=timestamp&collapse=timestamp:6&limit=2000`, { timeout: 30000 }).catch(() => null),
      ]);

      // --- RDAP lifecycle ---
      let registered = null, expires = null;
      for (const e of (rdap?.data?.events || [])) {
        const map = { registration: 'registered', expiration: 'expires', 'last changed': 'changed', 'last update of RDAP database': null, transfer: 'transferred', reregistration: 'registered' };
        const t = map[e.eventAction];
        if (t === undefined || t === null) continue;
        add(e.eventDate, t, `Domain ${e.eventAction}`, 'RDAP');
        if (t === 'registered' && (!registered || new Date(e.eventDate) < registered)) registered = new Date(e.eventDate);
        if (t === 'expires') expires = new Date(e.eventDate);
      }

      // --- certificate transparency: first appearance of each subdomain ---
      const firstSeen = new Map();       // sub -> earliest not_before
      let certCount = 0;
      if (Array.isArray(certs?.data)) {
        certCount = certs.data.length;
        for (const c of certs.data) {
          const nb = Date.parse(c.not_before);
          if (isNaN(nb)) continue;
          for (let n of String(c.name_value || '').split('\n')) {
            n = n.trim().toLowerCase().replace(/^\*\./, '');
            if (!n.endsWith(d)) continue;
            if (!firstSeen.has(n) || nb < firstSeen.get(n)) firstSeen.set(n, nb);
          }
        }
      }
      // group subdomain emergence by year so the stream stays readable
      const subsByYear = {};
      for (const [sub, nb] of firstSeen) { if (sub === d) continue; (subsByYear[yearOf(nb)] ||= []).push({ sub, nb }); }
      for (const [yr, list] of Object.entries(subsByYear)) {
        list.sort((a, b) => a.nb - b.nb);
        const sample = list.slice(0, 6).map(x => x.sub);
        add(list[0].nb, 'subdomain', `${list.length} subdomain${list.length > 1 ? 's' : ''} first seen in CT: ${sample.join(', ')}${list.length > sample.length ? ` +${list.length - sample.length} more` : ''}`, 'crt.sh');
      }
      // apex first certificate
      const apexFirst = firstSeen.get(d) || (firstSeen.size ? Math.min(...firstSeen.values()) : null);
      if (apexFirst) add(apexFirst, 'cert', 'First certificate issued for the domain', 'crt.sh');

      // --- Internet Archive presence ---
      const caps = (Array.isArray(cdx?.data) ? cdx.data.slice(1) : []).map(r => parseCdxTs(r[0])).filter(Boolean).sort((a, b) => a - b);
      let firstCap = null, lastCap = null;
      if (caps.length) {
        firstCap = caps[0]; lastCap = caps[caps.length - 1];
        add(firstCap, 'web', 'First captured by the Internet Archive', 'Wayback');
        if (lastCap - firstCap > 86400000 * 30) add(lastCap, 'web', `Most recent Internet Archive capture (${caps.length}+ snapshots)`, 'Wayback');
      }

      if (!events.length) { summary.textContent = 'no public history found — the domain may be new, private or parked.'; return; }

      // --- stats ---
      const now = Date.now();
      const ageYears = registered ? ((now - registered) / (365.25 * 86400000)) : null;
      sAge.textContent = ageYears ? `${ageYears.toFixed(1)}y` : '—';
      sWeb.textContent = firstCap ? `${((now - firstCap) / (365.25 * 86400000)).toFixed(1)}y` : '—';
      sSubs.textContent = fmtNum([...firstSeen.keys()].filter(s => s !== d).length);
      sCerts.textContent = fmtNum(certCount);

      // --- render chronological stream, grouped by year ---
      events.sort((a, b) => a.date - b.date);
      const byYear = {};
      for (const e of events) (byYear[yearOf(e.date)] ||= []).push(e);
      const years = Object.keys(byYear).map(Number).sort((a, b) => a - b);
      streamBox.replaceChildren(...years.map(yr => h('div', { class: 'casegroup' },
        h('h4', {}, String(yr)),
        h('div', { class: 'enginelog' }, byYear[yr].map(e => h('div', { class: 'step' },
          badge(fmtDate(e.date).slice(5), EV_TONE[e.type] || 'muted'),
          h('span', {}, e.text, e.ref ? h('span', { class: 'muted small' }, ` · ${e.ref}`) : null)))))));

      const md = [`# Timeline: ${d}`, '', ...events.map(e => `- ${fmtDate(e.date)} — ${e.text} [${e.ref || ''}]`)].join('\n');
      summary.replaceChildren(h('span', { class: 'muted small' }, `${events.length} events${expires ? ` · expires ${fmtDate(expires)}` : ''}`), ' ', copyBtn(md, 'copy timeline'));
    })();

    return grid(
      card('lifecycle timeline', { wide: true, actions: summary },
        muted(`Public-record history of ${d}. Registration & expiry from RDAP, subdomain emergence from certificate-transparency logs, and web presence from the Internet Archive — merged chronologically.`),
        h('div', { class: 'statrow4' }, stat('domain age', sAge), stat('web presence', sWeb), stat('subdomains (CT)', sSubs), stat('certificates', sCerts))),
      card('history', { wide: true }, streamBox),
    );
  },
};
