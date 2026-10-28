// Thin AI layer over the Worker's Gemini proxy. The key never touches the browser.

import * as be from './backend.js';

export const available = () => be.aiAvailable();

// Ask the model. Pass either `prompt` (string) or `messages` (Gemini contents).
// `json: true` requests a JSON response and returns the parsed object.
export async function ask({ system, prompt, messages, json = false, temperature, maxOutputTokens } = {}) {
  const contents = messages || [{ role: 'user', parts: [{ text: String(prompt || '') }] }];
  const r = await be.aiChat({ contents, system, json, temperature, maxOutputTokens });
  if (!r.ok) throw new Error(r.data?.error || (r.status === 401 ? 'sign in to use the AI' : 'AI request failed'));
  if (r.data?.error) throw new Error(r.data.error);
  const text = r.data?.text || '';
  return json ? parseJSON(text) : text;
}

export const askJSON = opts => ask({ ...opts, json: true });

// Models sometimes wrap JSON in prose or code fences; recover the first object/array.
function parseJSON(text) {
  const clean = text.replace(/^```(?:json)?\s*|\s*```$/g, '').trim();
  try { return JSON.parse(clean); } catch {}
  const m = clean.match(/[[{][\s\S]*[\]}]/);
  if (m) { try { return JSON.parse(m[0]); } catch {} }
  throw new Error('the AI did not return valid JSON');
}

// Turn a flat {role,text} history into Gemini "contents" (assistant -> model).
export const toContents = history => history
  .filter(m => m.role === 'user' || m.role === 'assistant')
  .map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.text }] }));
