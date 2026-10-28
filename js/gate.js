// Shared access messaging for the pro-gated AI features.
import { h, pivot } from './util.js';
import * as be from './backend.js';

const accountLink = h('p', {}, 'open the ', pivot('account', '', 'account'), ' tab to continue');

// Returns null when the signed-in user may use the AI, else a {title, body, action}.
export function aiGateMessage() {
  if (!be.isLoggedIn()) return { title: 'sign in to use the AI', body: 'The AI engine and chat sign in with GitHub — no password, and GitHub handles your 2FA.', action: accountLink };
  const u = be.user();
  if (u?.status === 'denied') return { title: 'no access', body: 'This account has been denied access.', action: null };
  if (!be.isApproved()) return { title: 'awaiting approval', body: 'Your account is pending. The AI engine and chat unlock once an admin approves you and grants pro.', action: accountLink };
  if (!be.isPro()) return { title: 'pro feature', body: 'The AI engine and chat are pro features. Ask the admin to grant you pro.', action: accountLink };
  return null;
}
