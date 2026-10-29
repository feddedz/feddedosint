// MurmurHash3 x86_32 over a byte array, plus the Shodan favicon-hash helper.
// Shodan keys favicons by mmh3.hash(python base64.encodebytes(bytes)) as a signed 32-bit int,
// so we re-encode the raw icon bytes exactly the way python does (base64, wrapped at 76 cols,
// trailing newline) before hashing — otherwise the number won't match Shodan's.

export function mmh3_x86_32(bytes, seed = 0) {
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  let h1 = seed >>> 0;
  const len = bytes.length;
  const nblocks = len & ~3;
  for (let i = 0; i < nblocks; i += 4) {
    let k1 = (bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24)) >>> 0;
    k1 = Math.imul(k1, c1) >>> 0;
    k1 = ((k1 << 15) | (k1 >>> 17)) >>> 0;
    k1 = Math.imul(k1, c2) >>> 0;
    h1 = (h1 ^ k1) >>> 0;
    h1 = ((h1 << 13) | (h1 >>> 19)) >>> 0;
    h1 = (Math.imul(h1, 5) + 0xe6546b64) >>> 0;
  }
  let k1 = 0;
  const tail = len & 3, t = nblocks;
  if (tail === 3) k1 ^= bytes[t + 2] << 16;
  if (tail >= 2) k1 ^= bytes[t + 1] << 8;
  if (tail >= 1) {
    k1 ^= bytes[t];
    k1 = Math.imul(k1 >>> 0, c1) >>> 0;
    k1 = ((k1 << 15) | (k1 >>> 17)) >>> 0;
    k1 = Math.imul(k1, c2) >>> 0;
    h1 = (h1 ^ k1) >>> 0;
  }
  h1 = (h1 ^ len) >>> 0;
  h1 ^= h1 >>> 16; h1 = Math.imul(h1, 0x85ebca6b) >>> 0;
  h1 ^= h1 >>> 13; h1 = Math.imul(h1, 0xc2b2ae35) >>> 0;
  h1 ^= h1 >>> 16;
  return h1 | 0; // signed, matching Shodan
}

// Replicate python base64.encodebytes: standard base64, a newline every 76 output chars, and a
// trailing newline — returned as the ASCII byte array that mmh3 then hashes.
export function pyBase64Bytes(raw) {
  let bin = '';
  for (let i = 0; i < raw.length; i++) bin += String.fromCharCode(raw[i]);
  const b64 = btoa(bin);
  let wrapped = '';
  for (let i = 0; i < b64.length; i += 76) wrapped += b64.slice(i, i + 76) + '\n';
  if (!wrapped.endsWith('\n')) wrapped += '\n';
  const out = new Uint8Array(wrapped.length);
  for (let i = 0; i < wrapped.length; i++) out[i] = wrapped.charCodeAt(i) & 0xff;
  return out;
}

// The Shodan favicon hash for raw icon bytes.
export const faviconHash = raw => mmh3_x86_32(pyBase64Bytes(raw), 0);

// Decode a base64 string (from the Worker) back into raw bytes.
export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
