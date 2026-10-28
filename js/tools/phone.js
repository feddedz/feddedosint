import { h, loadScript, card, kv, linkGroups, copyBtn, grid, flag, countryName, muted } from '../util.js';

const LIB = 'https://cdn.jsdelivr.net/npm/libphonenumber-js@1.13.15/bundle/libphonenumber-max.js';
const LIB_SRI = 'sha384-KFpFw4Q7EIpeK/WJ3azDRjpDeYmDLF9DdzBb3LMPtHHFi/99I94irctbZUeBVBQv';

const TYPES = {
  MOBILE: 'mobile', FIXED_LINE: 'landline', FIXED_LINE_OR_MOBILE: 'landline or mobile', TOLL_FREE: 'toll-free',
  PREMIUM_RATE: 'premium rate', SHARED_COST: 'shared cost', VOIP: 'VoIP (often virtual / burner)', PERSONAL_NUMBER: 'personal number',
  PAGER: 'pager', UAN: 'company number (UAN)', VOICEMAIL: 'voicemail',
};

function defaultCountry() {
  const region = (navigator.language || '').split('-')[1];
  return region && /^[A-Z]{2}$/.test(region) ? region : undefined;
}

export default {
  id: 'phone',
  label: 'phone',
  placeholder: '+1 415 555 2671 (include country code)',
  intro: 'Parses & validates numbers worldwide — country, line type, every format — and pivots to messengers, caller-ID and search.',
  examples: ['+14155552671', '+447911123456'],

  async run(raw) {
    const input = raw.trim();
    if (!input) throw new Error('enter a phone number');
    await loadScript(LIB, LIB_SRI).catch(() => { throw new Error('could not load the phone-number library (offline or CDN blocked)'); });
    const lp = window.libphonenumber;
    const assumed = input.startsWith('+') || input.startsWith('00') ? undefined : defaultCountry();
    const p = lp.parsePhoneNumberFromString(input.replace(/^00/, '+'), assumed);
    if (!p) throw new Error('could not parse that number — include the country code, e.g. +44…');

    const e164 = p.number;
    const digits = e164.slice(1);
    const national = p.formatNational();
    const nationalDigits = national.replace(/\D/g, '');
    const type = p.getType();
    const cc = p.country;

    // The same number written the ways people actually write it, for exact-match searching.
    const variants = [...new Set([e164, p.formatInternational(), national, nationalDigits, digits,
      p.formatInternational().replace(/\s/g, '-')])];
    const orQuery = encodeURIComponent(variants.map(v => `"${v}"`).join(' OR '));

    return grid(
      card('number', { actions: copyBtn(e164, 'copy e.164') }, kv([
        ['valid', p.isValid() ? 'yes' : p.isPossible() ? 'possible, but not a valid range' : 'no'],
        ['country', cc ? `${flag(cc)} ${countryName(cc)} (${cc})` : `+${p.countryCallingCode} (shared / non-geographic)`],
        ['line type', type ? TYPES[type] || type.toLowerCase() : 'unknown'],
        ['e.164', h('span', { class: 'mono' }, e164)],
        ['international', h('span', { class: 'mono' }, p.formatInternational())],
        ['national', h('span', { class: 'mono' }, national)],
        ['uri', h('span', { class: 'mono' }, p.getURI())],
        ['note', assumed ? `no country code given — assumed ${countryName(assumed)} from your browser language` : null],
      ])),

      card('search variants', { actions: copyBtn(variants.join('\n'), 'copy') },
        h('div', { class: 'tags' }, variants.map(v => h('span', { class: 'tag mono' }, v))),
        muted('Numbers appear online in many formats; the search links below look for all of them at once.')),

      card('pivot further', { wide: true }, linkGroups([
        { group: 'messengers', items: [
          ['WhatsApp', `https://wa.me/${digits}`], ['Telegram', `https://t.me/+${digits}`],
          ['Signal', `https://signal.me/#p/+${digits}`], ['Viber', `viber://chat?number=%2B${digits}`],
        ] },
        { group: 'caller id', items: [
          ['Truecaller', `https://www.truecaller.com/search/${(cc || 'us').toLowerCase()}/${p.nationalNumber}`],
          ['Sync.me', `https://sync.me/search/?number=${digits}`],
          ['NumLookup', `https://www.numlookup.com/`], ['CallerID Test', `https://calleridtest.com/`],
        ] },
        { group: 'search', items: [
          ['Google (all formats)', `https://www.google.com/search?q=${orQuery}`], ['Bing (all formats)', `https://www.bing.com/search?q=${orQuery}`],
          ['DuckDuckGo', `https://duckduckgo.com/?q=${encodeURIComponent(`"${national}"`)}`],
          ['Yandex', `https://yandex.com/search/?text=${orQuery}`],
        ] },
      ])),
    );
  },
};
