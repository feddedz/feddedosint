import { h, getJSON, card, asyncCard, ext, grid, muted, linkGroups, fmtDate } from '../util.js';

export default {
  id: 'records',
  label: 'records',
  placeholder: 'person, company, or keyword',
  intro: 'Public-record and news research — company registries, courts, academia, sanctions, archives — plus live news and code mentions.',
  examples: ['OpenAI', 'Kaspersky'],

  run(raw) {
    const q = raw.trim();
    if (!q) throw new Error('enter a name, company or keyword');
    const e = encodeURIComponent(q);
    const phrase = encodeURIComponent(`"${q}"`);

    return grid(
      asyncCard('news & discussion', async () => {
        const r = await getJSON(`https://hn.algolia.com/api/v1/search?query=${e}&tags=story&hitsPerPage=12`);
        const hits = r.data?.hits || [];
        if (!hits.length) return muted('no recent Hacker News stories — try the news links below.');
        return [
          h('div', { class: 'breach-list' }, hits.map(x => h('div', { class: 'breach-item' },
            ext(x.url || `https://news.ycombinator.com/item?id=${x.objectID}`, x.title || '(untitled)'),
            h('div', { class: 'muted small' }, `${x.points || 0} pts · ${x.num_comments || 0} comments · ${fmtDate(x.created_at)} · `,
              ext(`https://news.ycombinator.com/item?id=${x.objectID}`, 'discussion'))))),
          h('div', { class: 'links' }, [
            ['Google News', `https://news.google.com/search?q=${phrase}`],
            ['GDELT', `https://www.gdeltproject.org/`],
            ['Bing News', `https://www.bing.com/news/search?q=${phrase}`],
          ].map(([n, u]) => ext(u, n))),
        ];
      }, { wide: true }),

      asyncCard('code & developer mentions', async () => {
        // GitHub public search works from the browser (unauthenticated, rate-limited).
        const r = await getJSON(`https://api.github.com/search/repositories?q=${e}&per_page=8&sort=stars`);
        if (!r.ok) throw new Error(`GitHub returned HTTP ${r.status}`);
        const items = r.data?.items || [];
        return [
          items.length ? h('div', { class: 'breach-list' }, items.map(x => h('div', { class: 'breach-item' },
            ext(x.html_url, x.full_name),
            h('div', { class: 'muted small' }, `★ ${x.stargazers_count} · ${x.language || '—'} · ${x.description || ''}`.slice(0, 120)))))
            : muted('no matching repositories.'),
          h('div', { class: 'links' }, [
            ['code', `https://github.com/search?q=${e}&type=code`],
            ['commits', `https://github.com/search?q=${e}&type=commits`],
            ['users', `https://github.com/search?q=${e}&type=users`],
          ].map(([n, u]) => ext(u, n))),
        ];
      }, { wide: true }),

      card('company & corporate', {}, linkGroups([{ items: [
        ['OpenCorporates', `https://opencorporates.com/companies?q=${e}`],
        ['SEC EDGAR', `https://www.sec.gov/cgi-bin/browse-edgar?company=${e}&action=getcompany`],
        ['UK Companies House', `https://find-and-update.company-information.service.gov.uk/search?q=${e}`],
        ['EU Business Reg.', `https://e-justice.europa.eu/content_find_a_company-489-en.do`],
        ['Crunchbase', `https://www.crunchbase.com/textsearch?q=${e}`],
        ['OpenCorporates officers', `https://opencorporates.com/officers?q=${e}`],
      ] }])),

      card('legal, sanctions & integrity', {}, linkGroups([{ items: [
        ['OpenSanctions', `https://www.opensanctions.org/search/?q=${e}`],
        ['OFAC (US sanctions)', `https://sanctionssearch.ofac.treas.gov/`],
        ['CourtListener', `https://www.courtlistener.com/?q=${e}`],
        ['OCCRP Aleph', `https://aleph.occrp.org/search?q=${e}`],
        ['ICIJ Offshore Leaks', `https://offshoreleaks.icij.org/search?q=${e}`],
        ['World Bank debarred', `https://www.worldbank.org/en/projects-operations/procurement/debarred-firms`],
      ] }])),

      card('academic & archives', {}, linkGroups([{ items: [
        ['Google Scholar', `https://scholar.google.com/scholar?q=${phrase}`],
        ['ORCID', `https://orcid.org/orcid-search/search?searchQuery=${e}`],
        ['Semantic Scholar', `https://www.semanticscholar.org/search?q=${e}`],
        ['Wikipedia', `https://en.wikipedia.org/w/index.php?search=${e}`],
        ['Wikidata', `https://www.wikidata.org/w/index.php?search=${e}`],
        ['Internet Archive', `https://archive.org/search?query=${e}`],
      ] }])),

      card('people (public profiles)', {},
        note('Public professional footprint only. This platform does not look up home addresses or other private personal data.'),
        linkGroups([{ items: [
          ['LinkedIn', `https://www.google.com/search?q=site:linkedin.com/in+${phrase}`],
          ['X / Twitter', `https://x.com/search?q=${phrase}`],
          ['Google', `https://www.google.com/search?q=${phrase}`],
          ['Bing', `https://www.bing.com/search?q=${phrase}`],
        ] }])),
    );
  },
};

const note = t => h('p', { class: 'muted small' }, t);
