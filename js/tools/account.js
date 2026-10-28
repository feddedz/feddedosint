import { h, card, grid, muted, badge, ext, pivot, fmtDate } from '../util.js';
import { icon } from '../icons.js';
import * as be from '../backend.js';

const rerender = () => window.dispatchEvent(new HashChangeEvent('hashchange'));

const statusBadge = u => u.admin ? badge('admin', 'ok')
  : u.status === 'approved' ? (u.pro ? badge('pro', 'ok') : badge('approved', 'ok'))
  : u.status === 'denied' ? badge('denied', 'bad') : badge('pending', 'warn');

function ghButton(label) {
  const b = h('button', { class: 'primary ghbtn', type: 'button' });
  b.innerHTML = icon('account') + `<span>${label}</span>`;
  b.onclick = () => be.loginWithGitHub();
  return b;
}

function adminPanel() {
  const body = h('div', {}, h('div', { class: 'loading' }, h('span', { class: 'spin' }), 'loading…'));
  const load = async () => {
    const r = await be.adminUsers();
    if (!r.ok) { body.replaceChildren(muted(r.data?.error || 'could not load')); return; }
    const rows = r.data.users.map(u => {
      const act = h('div', { class: 'row' });
      const btn = (label, patch, cls) => { const x = h('button', { class: cls || 'mini', type: 'button' }, label); x.onclick = async () => { x.disabled = true; const res = await be.adminSetUser(u.login, patch); if (res.ok) load(); else { x.disabled = false; } }; return x; };
      if (!u.admin) {
        if (u.status !== 'approved') act.append(btn('approve', { status: 'approved' }));
        if (u.status !== 'denied') act.append(btn('deny', { status: 'denied' }, 'mini ghost'));
        act.append(btn(u.pro ? 'revoke pro' : 'make pro', { pro: !u.pro }, u.pro ? 'mini ghost' : 'mini'));
      }
      return h('tr', {},
        h('td', {}, h('strong', {}, u.login), ' ', statusBadge(u)),
        h('td', { class: 'muted small' }, 'joined ' + fmtDate(u.created) + (u.lastLogin ? ' · last ' + fmtDate(u.lastLogin) : '')),
        h('td', {}, act));
    });
    body.replaceChildren(
      h('p', { class: 'muted small' }, `${r.data.count} account${r.data.count === 1 ? '' : 's'}. Approve people to let them in; grant pro for the AI engine & chat.`),
      h('table', { class: 'records admintable' }, h('tbody', {}, rows)));
  };
  load();
  return card('members (admin)', { wide: true }, body);
}

async function loggedInView() {
  await be.refreshMe();
  const u = be.user();
  if (!u) return loginView();
  const logoutBtn = h('button', { class: 'mini', type: 'button' }, 'log out');
  logoutBtn.onclick = async () => { await be.logout(); rerender(); };

  const note = u.admin ? 'You are the admin — approve members and grant pro below.'
    : u.status === 'pending' ? 'Your account is awaiting approval. The AI engine & chat unlock once an admin approves you and grants pro.'
    : u.status === 'denied' ? 'This account has been denied access.'
    : u.pro ? 'Pro is active — the AI engine & chat are unlocked.'
    : 'Approved. Ask the admin for pro to unlock the AI engine & chat.';

  return grid(
    card('signed in', { actions: logoutBtn },
      h('div', { class: 'profile' },
        u.avatar ? h('img', { class: 'avatar-lg', src: u.avatar, alt: '', referrerpolicy: 'no-referrer' }) : null,
        h('div', {}, h('strong', {}, u.name || u.login), h('div', { class: 'muted small' }, '@' + u.login), h('div', { style: 'margin-top:5px' }, statusBadge(u)))),
      muted(note)),
    u.admin ? adminPanel() : null,
  );
}

function loginView() {
  return card('sign in', { wide: true },
    muted('feddedosint signs in with GitHub — no passwords, and GitHub handles your 2FA. New accounts are reviewed before the AI features unlock.'),
    h('div', { style: 'margin:12px 0' }, ghButton('continue with GitHub')),
    h('p', { class: 'muted small' }, 'You are only sharing your public GitHub username and avatar.'));
}

export default {
  id: 'account',
  label: 'account',
  placeholder: '',
  intro: 'Sign in with GitHub to unlock the AI engine and chat.',
  examples: [],
  allowEmpty: true,
  noInput: true,
  noTrack: true,

  async run() {
    if (!be.backendConfigured()) {
      return card('backend not set', { wide: true },
        muted('Accounts and the AI run on the project backend.'),
        h('p', {}, 'If you host your own, add the backend URL in ', pivot('settings', 'backend', 'Settings'), '.'),
        h('p', { class: 'muted small' }, 'setup: ', ext('https://github.com/feddedz/feddedosint/blob/main/worker/README.md', 'worker/README.md')));
    }
    const info = await be.health(true);
    if (!info) return card('backend unreachable', { wide: true }, muted('The backend did not respond. Check the URL in Settings.'));
    if (!info.github) return card('github sign-in not configured', { wide: true }, muted('The backend is up but GitHub OAuth is not set (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET on the Worker).'));
    return be.isLoggedIn() ? loggedInView() : loginView();
  },
};
