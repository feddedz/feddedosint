import { h, card, grid, kv, muted, badge, pivot, isIPv4, isIP, registrable } from '../util.js';
import { extractEntities, entityCards } from './extract.js';

// Unfold RFC 5322 headers (continuation lines start with whitespace) and stop at the body.
function parse(raw) {
  const text = raw.replace(/\r\n?/g, '\n').replace(/^\s+/, '');
  const head = text.split(/\n[ \t]*\n/)[0];
  const fields = [];
  for (const line of head.split('\n')) {
    if (/^[ \t]/.test(line) && fields.length) fields[fields.length - 1].value += ' ' + line.trim();
    else {
      const m = line.match(/^([!-9;-~]+):\s*(.*)$/);
      if (m) fields.push({ name: m[1], value: m[2].trim() });
    }
  }
  return fields;
}

const PRIVATE4 = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;

function received(v) {
  const semi = v.lastIndexOf(';');
  const main = semi >= 0 ? v.slice(0, semi) : v;
  const dateStr = semi >= 0 ? v.slice(semi + 1).replace(/\([^)]*\)/g, '').trim() : '';
  const time = Date.parse(dateStr);
  const ips = [...new Set([...main.matchAll(/\[(?:IPv6:)?([0-9a-f:.]+)\]|\(([0-9.]{7,15})\)/gi)]
    .map(m => m[1] || m[2]).filter(ip => ip && isIP(ip)))];
  return {
    from: main.match(/\bfrom\s+([^\s;()]+)/i)?.[1],
    by: main.match(/\bby\s+([^\s;()]+)/i)?.[1],
    with: main.match(/\bwith\s+([^\s;()]+)/i)?.[1],
    ips, time: isNaN(time) ? null : time,
  };
}

// The real address is the LAST <...>; anything before it is the display name — which may itself
// contain a fake "<someone@trusted.com>" to fool the reader.
function address(v) {
  if (!v) return {};
  const angles = [...v.matchAll(/<([^<>]+)>/g)];
  const last = angles.at(-1);
  const addr = (last ? last[1] : v.match(/[^\s<>"]+@[^\s<>"]+/)?.[0] || '').trim().toLowerCase();
  const name = last ? v.slice(0, last.index).trim().replace(/^"|"$/g, '').trim() : '';
  return { name, addr, domain: addr.split('@')[1] || '' };
}

const authResult = (text, mech) => text.match(new RegExp(`\\b${mech}=(\\w+)`, 'i'))?.[1]?.toLowerCase();
const tone = r => (r === 'pass' ? 'ok' : !r ? 'muted' : r === 'none' || r === 'neutral' || r === 'softfail' ? 'warn' : 'bad');
const dur = ms => (ms == null ? '' : ms < 1000 ? '<1s' : ms < 60000 ? `${Math.round(ms / 1000)}s` : `${Math.round(ms / 60000)}m`);

const SAMPLE = `Delivered-To: analyst@example.org
Received: by 2002:a05:6a10:1234 with SMTP id abc123; Tue, 28 Oct 2026 08:14:07 -0700 (PDT)
Received: from mail.invoice-portal.example.net (mail.invoice-portal.example.net [203.0.113.42])
        by mx.example.org with ESMTPS id x12; Tue, 28 Oct 2026 08:14:05 -0700 (PDT)
Received: from [192.168.1.20] (unknown [198.51.100.17])
        by mail.invoice-portal.example.net with ESMTPSA id q7; Tue, 28 Oct 2026 15:13:58 +0000
Authentication-Results: mx.example.org;
       spf=softfail (domain of transitioning billing@acme-bank-support.example.com does not designate 203.0.113.42) smtp.mailfrom=billing@invoice-portal.example.net;
       dkim=none;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=acme-bank-support.example.com
Return-Path: <bounce@invoice-portal.example.net>
From: "Billing Team <security@acme-bank-support.example.com>" <billing@invoice-portal.example.net>
Reply-To: helpdesk@paydesk.example.org
To: analyst@example.org
Subject: Action required: your account is on hold
Date: Tue, 28 Oct 2026 15:13:55 +0000
Message-ID: <20261028151355.1234@invoice-portal.example.net>
X-Mailer: PHPMailer 6.1
X-Originating-IP: [198.51.100.17]`;

let lastText = '';

function analyse(raw) {
  const fields = parse(raw);
  if (!fields.length) return [card('nothing to analyse', { wide: true }, muted('No header fields found — paste the full raw headers (in most mail apps: "show original" or "view source").'))];
  const get = n => fields.find(f => f.name.toLowerCase() === n)?.value;
  const all = n => fields.filter(f => f.name.toLowerCase() === n).map(f => f.value);

  const from = address(get('from')), reply = address(get('reply-to')), ret = address(get('return-path'));
  const auth = all('authentication-results').join(' ; ') + ' ' + all('arc-authentication-results').join(' ; ');
  const spf = authResult(auth, 'spf') || get('received-spf')?.split(/\s/)[0]?.toLowerCase();
  const dkim = authResult(auth, 'dkim'), dmarc = authResult(auth, 'dmarc');
  const sig = get('dkim-signature') || '';
  const dkimDomain = sig.match(/\bd=([^;\s]+)/)?.[1]?.toLowerCase(), dkimSel = sig.match(/\bs=([^;\s]+)/)?.[1];

  // Received headers are prepended by each hop, so the last one is where the message started.
  const hops = all('received').map(received).reverse();
  hops.forEach((hp, i) => { hp.delay = i && hp.time && hops[i - 1].time ? hp.time - hops[i - 1].time : null; });
  const origin = hops.flatMap(hp => hp.ips).find(ip => isIPv4(ip) ? !PRIVATE4.test(ip) : !/^(fe80|fc|fd|::1)/i.test(ip));
  const total = hops.length > 1 && hops[0].time && hops.at(-1).time ? hops.at(-1).time - hops[0].time : null;

  // Findings, worst first.
  const flags = [];
  const fromOrg = from.domain && registrable(from.domain);
  if (dmarc && dmarc !== 'pass') flags.push(['bad', `DMARC ${dmarc} — the From domain did not authenticate this message`]);
  if (spf && !['pass'].includes(spf)) flags.push([spf === 'fail' ? 'bad' : 'warn', `SPF ${spf} — the sending server is not authorised for the envelope domain`]);
  if (!dkim || dkim === 'none') flags.push(['warn', 'no DKIM signature verified']);
  else if (dkim !== 'pass') flags.push(['bad', `DKIM ${dkim}`]);
  if (from.name && /@/.test(from.name) && !from.name.toLowerCase().includes(from.addr)) {
    flags.push(['bad', `display name shows a different address ("${from.name}") than the real sender (${from.addr}) — a classic spoofing trick`]);
  }
  if (reply.domain && fromOrg && registrable(reply.domain) !== fromOrg) flags.push(['bad', `replies go to a different domain (${reply.domain}) than the sender (${from.domain})`]);
  if (ret.domain && fromOrg && registrable(ret.domain) !== fromOrg) flags.push(['warn', `bounce address domain (${ret.domain}) differs from the sender — normal for mailing services, suspicious otherwise`]);
  if (dkimDomain && fromOrg && registrable(dkimDomain) !== fromOrg) flags.push(['warn', `DKIM signed by ${dkimDomain}, not the From domain`]);
  if (get('x-originating-ip')) flags.push(['muted', `the sender's client IP is exposed in X-Originating-IP`]);
  const bad = flags.filter(f => f[0] === 'bad').length;
  const verdict = bad ? ['bad', `⚠ ${bad} serious red flag${bad > 1 ? 's' : ''} — treat as suspicious`]
    : flags.some(f => f[0] === 'warn') ? ['warn', 'some checks did not pass — verify the sender another way']
    : ['ok', '✓ authentication passed and the sender looks consistent'];

  const ents = extractEntities(fields.map(f => f.value).join('\n'));

  return [
    h('div', { class: 'verdict ' + verdict[0] }, verdict[1]),
    grid(
      card('message', {}, kv([
        ['from', from.addr ? [from.name ? `${from.name} ` : '', pivot('email', from.addr)] : get('from')],
        ['reply-to', reply.addr && pivot('email', reply.addr)],
        ['return-path', ret.addr && pivot('email', ret.addr)],
        ['to', get('to')],
        ['subject', get('subject')],
        ['date', get('date')],
        ['message-id', get('message-id') && h('code', { class: 'wrap small' }, get('message-id'))],
        ['mailer', get('x-mailer') || get('user-agent')],
        ['origin ip', origin && pivot('ip', origin)],
      ])),
      card('authentication', {}, kv([
        ['spf', badge(spf || 'not reported', tone(spf))],
        ['dkim', badge(dkim || 'not reported', tone(dkim))],
        ['dmarc', badge(dmarc || 'not reported', tone(dmarc))],
        ['dkim domain', dkimDomain && pivot('domain', dkimDomain)],
        ['dkim selector', dkimSel],
        ['sender domain', from.domain && pivot('domain', from.domain)],
      ])),
      card(`findings · ${flags.length}`, { wide: true }, flags.length
        ? h('div', { class: 'findings' }, flags.map(([t, text]) => h('div', { class: 'finding' }, badge(t === 'muted' ? 'info' : t === 'ok' ? 'ok' : t === 'warn' ? 'warning' : 'red flag', t), h('span', {}, text))))
        : muted('nothing suspicious found.')),
      card(`delivery path · ${hops.length} hops${total != null ? ` · ${dur(total)}` : ''}`, { wide: true },
        hops.length ? h('ol', { class: 'hops' }, hops.map((hp, i) => h('li', {},
          h('div', { class: 'hop-head' }, h('strong', {}, hp.from || '?'), h('span', { class: 'muted' }, ' → '), h('strong', {}, hp.by || '?'),
            hp.delay != null ? badge(`+${dur(hp.delay)}`, hp.delay > 300000 ? 'warn' : hp.delay < 0 ? 'bad' : 'muted') : null),
          h('div', { class: 'muted small' },
            [hp.with && `via ${hp.with}`, hp.time && new Date(hp.time).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'].filter(Boolean).join(' · '),
            hp.ips.length ? [' · ', ...hp.ips.flatMap((ip, j) => [j ? ', ' : '', isIPv4(ip) && PRIVATE4.test(ip) ? h('span', {}, `${ip} (private)`) : pivot('ip', ip)])] : null),
          i === 0 ? h('div', { class: 'muted small' }, 'first hop (origin)') : null)))
          : muted('no Received headers.')),
      card(`all headers · ${fields.length}`, { wide: true, collapsed: true },
        h('dl', { class: 'kv' }, fields.map(f => [h('dt', {}, f.name), h('dd', { class: 'wrap small' }, f.value)]))),
    ),
    h('div', { class: 'grid' }, entityCards(ents, { title: 'indicators' })),
  ];
}

export default {
  id: 'headers',
  label: 'headers',
  placeholder: '',
  intro: 'Paste raw email headers to trace the delivery path, check SPF / DKIM / DMARC and spot spoofing red flags.',
  examples: [],
  allowEmpty: true,
  noInput: true,

  run() {
    const ta = h('textarea', { class: 'bigtext', rows: 9, spellcheck: 'false', placeholder: 'paste raw headers ("show original" in Gmail / "view source" in Outlook)…' });
    ta.value = lastText;
    const results = h('div');
    const go = () => { lastText = ta.value; results.replaceChildren(...(ta.value.trim() ? analyse(ta.value) : [])); };
    let t;
    ta.addEventListener('input', () => { clearTimeout(t); t = setTimeout(go, 250); });
    const sample = h('button', { class: 'mini ghost', type: 'button' }, 'load sample');
    sample.onclick = () => { ta.value = SAMPLE; go(); };
    const clear = h('button', { class: 'mini ghost', type: 'button' }, 'clear');
    clear.onclick = () => { ta.value = ''; go(); };
    go();
    return [grid(card('raw headers', { wide: true, actions: [sample, clear] }, ta,
      h('p', { class: 'muted small' }, 'Parsed locally — nothing is uploaded.'))), results];
  },
};
