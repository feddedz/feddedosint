// The sign-in wall. Nothing in the app renders until the visitor is signed in with GitHub
// and approved by the admin. The Worker enforces the same rule on every backend call.
import { h } from './util.js';
import { icon } from './icons.js';
import * as be from './backend.js';

// null when the visitor may enter, else why not: 'auth' | 'offline' | 'pending' | 'denied'.
export function lockReason() {
  if (!be.isLoggedIn()) return 'auth';
  const u = be.user();
  if (!u) return 'offline';
  if (u.admin) return null;
  if (u.status === 'denied') return 'denied';
  if (u.status !== 'approved') return 'pending';
  return null;
}

const COPY = {
  auth: ['sign in', 'feddedosint is members-only. Sign in with GitHub to continue — no password, and GitHub handles your 2FA.'],
  offline: ['can’t reach the server', 'Your session couldn’t be verified because the backend didn’t respond. Try again in a moment.'],
  pending: ['awaiting approval', 'You’re signed in. An admin has to approve your account before you can use feddedosint.'],
  denied: ['no access', 'This account has been denied access.'],
};

function btn(label, cls, onclick, ic) {
  const b = h('button', { class: cls, type: 'button' });
  b.innerHTML = (ic ? icon(ic) : '') + `<span>${label}</span>`;
  b.onclick = onclick;
  return b;
}

// Fill `el` with the wall for `reason`. `onRetry` re-checks the session.
export function renderLock(el, reason, { error, onRetry } = {}) {
  const [title, text] = COPY[reason] || COPY.auth;
  const u = be.user();
  const actions = [];
  if (reason === 'auth') actions.push(btn('continue with GitHub', 'primary ghbtn', () => be.loginWithGitHub(), 'account'));
  else {
    if (reason !== 'denied') actions.push(btn(reason === 'offline' ? 'retry' : 'check again', 'primary', onRetry));
    actions.push(btn('sign out', 'mini ghost', async () => { await be.logout(); onRetry?.(); }));
  }
  el.replaceChildren(h('div', { class: 'lockbox card' },
    h('div', { class: 'lockbrand' }, 'fedded', h('span', {}, 'osint')),
    h('h2', {}, title),
    u && reason !== 'auth' ? h('p', { class: 'muted small' }, 'signed in as @' + u.login) : null,
    h('p', { class: 'muted' }, text),
    error ? h('p', { class: 'error small' }, error) : null,
    h('div', { class: 'row wrap lockactions' }, actions),
    reason === 'auth' ? h('p', { class: 'muted small' }, 'Only your public GitHub username and avatar are shared. New accounts are reviewed by an admin.') : null));
}
