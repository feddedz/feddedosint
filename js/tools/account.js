import { h, card, grid, muted, badge, ext, copyBtn, fmtDate, pivot } from '../util.js';
import * as be from '../backend.js';
import { currentUser } from '../store.js';

const field = (label, attrs) => h('label', { class: 'field' }, h('span', {}, label), h('input', { autocomplete: 'off', spellcheck: 'false', ...attrs }));
const msg = (text, tone = 'bad') => h('div', { class: 'verdict ' + tone }, text);

// Re-run this tool in place after an auth state change.
const rerender = () => window.dispatchEvent(new HashChangeEvent('hashchange'));

async function loginView() {
  const info = await be.health(true);
  const wrap = h('div');
  let mode = 'login';
  const out = h('div');

  const render = () => {
    const status = h('div');
    const uname = field('username', { type: 'text', value: '' });
    const pass = field('password', { type: 'password' });
    const totp = field('2FA code', { type: 'text', inputmode: 'numeric', placeholder: '123456' });
    totp.style.display = 'none'; // revealed only if the server asks for it
    const code = field('invite code', { type: 'text' });
    const submit = h('button', { class: 'primary', type: 'submit' }, mode === 'login' ? 'log in' : 'create account');

    const form = h('form', { class: 'authform' },
      uname, pass,
      mode === 'login' ? totp : null,
      mode === 'signup' && info?.inviteRequired ? code : null,
      submit, status);

    form.addEventListener('submit', async e => {
      e.preventDefault();
      submit.disabled = true;
      const u = uname.querySelector('input').value.trim();
      const p = pass.querySelector('input').value;
      try {
        if (mode === 'signup') {
          const r = await be.signup(u, p, code.querySelector('input').value.trim());
          if (!r.ok) { status.replaceChildren(msg(r.data?.error || 'signup failed')); return; }
          rerender();
        } else {
          const t = totp.querySelector('input').value.trim();
          const r = await be.login(u, p, t || undefined);
          if (r.ok && r.data?.need_totp) {
            totp.style.display = '';
            status.replaceChildren(msg('enter your 2FA code to finish', 'warn'));
            return;
          }
          if (!r.ok) { status.replaceChildren(msg(r.data?.error || 'login failed')); return; }
          rerender();
        }
      } finally { submit.disabled = false; }
    });
    out.replaceChildren(form);
  };
  render();

  const toggle = h('div', { class: 'authtoggle' },
    h('button', { class: 'seg on', type: 'button' }, 'log in'),
    h('button', { class: 'seg', type: 'button' }, 'sign up'));
  toggle.children[0].onclick = () => { mode = 'login'; [...toggle.children].forEach((c, i) => c.classList.toggle('on', i === 0)); render(); };
  toggle.children[1].onclick = () => { mode = 'signup'; [...toggle.children].forEach((c, i) => c.classList.toggle('on', i === 1)); render(); };

  wrap.append(card('sign in', { wide: true },
    muted('Accounts are handled by your Cloudflare Worker. Passwords are hashed and can never be read back by anyone — including the admin.'),
    toggle, out,
    info?.inviteRequired && mode === 'signup' ? muted('this instance requires an invite code to register') : null));
  return wrap;
}

async function twofaPanel(user) {
  if (user.twofa) {
    const pass = field('password', { type: 'password' });
    const totp = field('current 2FA code', { type: 'text', inputmode: 'numeric', placeholder: '123456' });
    const status = h('div');
    const btn = h('button', { type: 'button' }, 'turn off 2FA');
    btn.onclick = async () => {
      const r = await be.disable2FA(pass.querySelector('input').value, totp.querySelector('input').value.trim());
      if (!r.ok) status.replaceChildren(msg(r.data?.error || 'could not disable'));
      else rerender();
    };
    return card('two-factor (on)', {}, h('div', { class: 'verdict ok' }, '✓ 2FA is protecting this account'),
      muted('To turn it off, confirm your password and a current code.'), h('div', { class: 'authform' }, pass, totp, btn, status));
  }

  const start = h('button', { class: 'primary', type: 'button' }, 'set up 2FA');
  const area = h('div');
  start.onclick = async () => {
    start.disabled = true;
    const r = await be.setup2FA();
    if (!r.ok) { area.replaceChildren(msg(r.data?.error || 'could not start setup')); start.disabled = false; return; }
    const { secret, uri } = r.data;
    const qr = h('div', { class: 'qrbox loading' }, 'rendering QR…');
    import('../../vendor/qrcode.mjs').then(m => {
      const q = m.default(0, 'M'); q.addData(uri); q.make();
      qr.classList.remove('loading');
      qr.innerHTML = q.createSvgTag({ cellSize: 5, margin: 1, scalable: true });
    }).catch(() => { qr.classList.remove('loading'); qr.replaceChildren(muted('could not render QR — use the key below')); });

    const totp = field('6-digit code from your app', { type: 'text', inputmode: 'numeric', placeholder: '123456' });
    const confirm = h('button', { class: 'primary', type: 'button' }, 'verify & enable');
    const status = h('div');
    confirm.onclick = async () => {
      const en = await be.enable2FA(totp.querySelector('input').value.trim());
      if (!en.ok) status.replaceChildren(msg(en.data?.error || 'that code did not match'));
      else rerender();
    };
    area.replaceChildren(
      h('p', { class: 'muted small' }, 'Scan this with Authy, Google Authenticator, 1Password or any TOTP app:'),
      qr,
      h('div', { class: 'row' }, h('span', { class: 'muted small' }, 'or enter this key manually:'), h('code', { class: 'wrap small' }, secret), copyBtn(secret, 'copy')),
      h('div', { class: 'authform' }, totp, confirm, status));
  };
  return card('two-factor (off)', {}, muted('Add a second step at login with a TOTP app (Authy, Google Authenticator, 1Password…).'), start, area);
}

function adminPanel() {
  const body = h('div');
  const btn = h('button', { type: 'button' }, 'load signups');
  btn.onclick = async () => {
    body.replaceChildren(h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'loading…'));
    const r = await be.adminUsers();
    if (!r.ok) { body.replaceChildren(msg(r.data?.error || 'could not load')); return; }
    body.replaceChildren(
      h('p', { class: 'muted small' }, `${r.data.count} account${r.data.count === 1 ? '' : 's'}. Passwords are never shown — they are not stored in readable form.`),
      h('table', { class: 'records' }, h('tbody', {}, r.data.users.map(u => h('tr', {},
        h('td', {}, u.username, u.admin ? badge(' admin', 'ok') : null),
        h('td', { class: 'muted small' }, 'joined ' + fmtDate(u.created)),
        h('td', {}, u.twofa ? badge('2FA', 'ok') : badge('no 2FA', 'warn')),
        h('td', { class: 'muted small' }, u.lastLogin ? 'last ' + fmtDate(u.lastLogin) : 'never'))))));
  };
  return card('signups (admin)', { wide: true }, btn, body);
}

async function accountView() {
  await be.refreshMe();
  const user = currentUser();
  const logoutBtn = h('button', { type: 'button' }, 'log out');
  logoutBtn.onclick = async () => { await be.logout(); rerender(); };
  return grid(
    card('account', { actions: logoutBtn }, kvRows([
      ['username', h('strong', {}, user.username)],
      ['role', user.admin ? badge('admin', 'ok') : 'member'],
      ['2FA', user.twofa ? badge('enabled', 'ok') : badge('off', 'warn')],
    ])),
    await twofaPanel(user),
    user.admin ? adminPanel() : null,
  );
}

function kvRows(rows) {
  return h('dl', { class: 'kv' }, rows.map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
}

export default {
  id: 'account',
  label: 'account',
  placeholder: '',
  intro: 'Sign in to unlock the AI, save your work to the backend, and manage 2FA.',
  examples: [],
  allowEmpty: true,
  noInput: true,
  noTrack: true,

  async run() {
    if (!be.backendConfigured()) {
      return card('no backend yet', { wide: true },
        muted('Accounts and the AI need the Cloudflare Worker backend.'),
        h('p', {}, 'Add your Worker URL in ', pivot('settings', 'backend', 'Settings'), ', then come back here to sign up.'),
        h('p', { class: 'muted small' }, 'Setup guide: ', ext('https://github.com/feddedz/feddedosint/blob/main/worker/README.md', 'worker/README.md')));
    }
    const h0 = await be.health(true);
    if (!h0) return card('backend unreachable', { wide: true },
      muted('The backend URL in Settings did not respond. Check that the Worker is deployed and the URL is correct.'));
    return be.isLoggedIn() ? accountView() : loginView();
  },
};
