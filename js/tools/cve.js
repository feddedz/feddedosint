import { h, getJSON, card, asyncCard, kv, ext, grid, muted, badge, linkGroups } from '../util.js';

const SEVERITY = { CRITICAL: 'bad', HIGH: 'bad', MEDIUM: 'warn', LOW: 'muted', NONE: 'muted' };

function metric(cve) {
  const m = cve.metrics || {};
  const v = (m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
  if (!v) return null;
  const data = v.cvssData || {};
  return { score: data.baseScore, severity: data.baseSeverity || v.baseSeverity, vector: data.vectorString, version: data.version };
}

export default {
  id: 'cve',
  label: 'vuln',
  placeholder: 'CVE id (e.g. CVE-2021-44228)',
  intro: 'Look up a vulnerability — description, CVSS severity, EPSS exploit probability, affected products and references.',
  examples: ['CVE-2021-44228', 'CVE-2014-0160'],

  async run(raw) {
    const id = raw.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new Error('enter a CVE id like CVE-2021-44228');

    return grid(
      asyncCard('vulnerability', async () => {
        const r = await getJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { timeout: 20000 });
        const cve = r.data?.vulnerabilities?.[0]?.cve;
        if (!cve) throw new Error(r.status === 403 ? 'NVD rate-limited this request — retry shortly' : 'not found in the NVD');
        const m = metric(cve);
        const desc = (cve.descriptions || []).find(d => d.lang === 'en')?.value;
        const cwe = (cve.weaknesses || []).flatMap(w => w.description || []).map(d => d.value).filter(v => /^CWE-/.test(v));
        return [
          h('div', { class: 'row-between' }, h('strong', {}, id),
            m ? badge(`${m.severity} · ${m.score}`, SEVERITY[m.severity] || 'muted') : badge('unscored', 'muted')),
          h('p', {}, desc || '—'),
          kv([
            ['published', cve.published?.slice(0, 10)],
            ['modified', cve.lastModified?.slice(0, 10)],
            ['status', cve.vulnStatus],
            ['cvss vector', m?.vector && h('code', { class: 'wrap small' }, m.vector)],
            ['weakness', cwe.length ? h('div', { class: 'tags' }, cwe.map(c =>
              ext(`https://cwe.mitre.org/data/definitions/${c.split('-')[1]}.html`, c))) : null],
          ]),
        ];
      }, { wide: true }),

      asyncCard('exploit prediction (epss)', async () => {
        const r = await getJSON(`https://api.first.org/data/v1/epss?cve=${id}`);
        const d = r.data?.data?.[0];
        if (!d) return muted('no EPSS score available.');
        const pct = (Number(d.epss) * 100).toFixed(2);
        const perc = (Number(d.percentile) * 100).toFixed(1);
        return kv([
          ['exploit probability', badge(`${pct}% in next 30 days`, Number(d.epss) > 0.1 ? 'bad' : 'muted')],
          ['percentile', `higher than ${perc}% of all CVEs`],
          ['as of', d.date],
        ]);
      }),

      card('references & tracking', {}, linkGroups([{ items: [
        ['NVD', `https://nvd.nist.gov/vuln/detail/${id}`],
        ['MITRE', `https://www.cve.org/CVERecord?id=${id}`],
        ['CISA KEV', `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`],
        ['Exploit-DB', `https://www.exploit-db.com/search?cve=${id}`],
        ['GitHub PoCs', `https://github.com/search?q=${id}&type=repositories`],
        ['VulDB', `https://vuldb.com/?search.${id}`],
      ] }])),
    );
  },
};
