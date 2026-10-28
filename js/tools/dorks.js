import { h, card, ext, copyBtn, grid, muted } from '../util.js';

const ENGINES = [
  ['Google', q => `https://www.google.com/search?q=${encodeURIComponent(q)}`],
  ['Bing', q => `https://www.bing.com/search?q=${encodeURIComponent(q)}`],
  ['DuckDuckGo', q => `https://duckduckgo.com/?q=${encodeURIComponent(q)}`],
  ['Yandex', q => `https://yandex.com/search/?text=${encodeURIComponent(q)}`],
];

// Builder fields: [key, label, placeholder, how the value becomes an operator]
const FIELDS = [
  ['phrase', 'exact phrase', 'John Smith', v => `"${v}"`],
  ['any', 'any of these words', 'cv resume portfolio', v => `(${v.split(/\s+/).join(' OR ')})`],
  ['site', 'on site', 'example.com', v => `site:${v}`],
  ['notsite', 'not on site', 'pinterest.com', v => v.split(/\s+/).map(s => `-site:${s}`).join(' ')],
  ['filetype', 'file type', 'pdf', v => `filetype:${v}`],
  ['intitle', 'in page title', 'annual report', v => `intitle:"${v}"`],
  ['inurl', 'in url', 'blog', v => `inurl:${v}`],
  ['exclude', 'exclude words', 'jobs ads', v => v.split(/\s+/).map(w => `-${w}`).join(' ')],
  ['after', 'after date (google)', '2024-01-01', v => `after:${v}`],
  ['before', 'before date (google)', '2025-01-01', v => `before:${v}`],
];

export default {
  id: 'dorks',
  label: 'engines',
  placeholder: 'keywords',
  intro: 'Build precise search-engine queries with operators (site, filetype, intitle, dates…) and run them on several engines at once.',
  examples: ['"open source intelligence"'],
  allowEmpty: true,

  run(raw) {
    const values = { keywords: raw.trim() };
    const preview = h('code', { class: 'query' });
    const engines = h('div', { class: 'links' });

    const build = () => [values.keywords, ...FIELDS.map(([k, , , fmt]) => values[k] && fmt(values[k]))]
      .filter(Boolean).join(' ');

    const update = () => {
      const q = build();
      preview.textContent = q || 'start typing…';
      engines.replaceChildren(...(q ? ENGINES.map(([name, url]) => ext(url(q), name)) : []));
    };

    const input = (key, label, placeholder) => h('label', { class: 'field' }, h('span', {}, label),
      h('input', {
        placeholder, value: values[key] || '', spellcheck: 'false',
        oninput: e => { values[key] = e.target.value.trim(); update(); },
      }));

    update();
    return grid(
      card('query builder', { wide: true },
        h('div', { class: 'fields' }, input('keywords', 'keywords', 'any words'), FIELDS.map(([k, l, p]) => input(k, l, p)))),
      card('query', { wide: true, actions: copyBtn(build, 'copy') },
        preview, engines,
        muted('Operator support differs between engines — Google supports all of them; others ignore the ones they do not know.')),
    );
  },
};
