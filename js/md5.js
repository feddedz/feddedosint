// MD5 (RFC 1321) over a Uint8Array. Web Crypto has no MD5, but threat-intel services still key on it.
// Processes full blocks straight from the input and only copies the padded tail.

const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;

export function md5(bytes) {
  const state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
  const M = new Uint32Array(16);

  const block = (dv, off) => {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
    let [A, B, C, D] = state;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0;
    }
    state[0] = (state[0] + A) >>> 0; state[1] = (state[1] + B) >>> 0;
    state[2] = (state[2] + C) >>> 0; state[3] = (state[3] + D) >>> 0;
  };

  const len = bytes.length;
  const full = len - (len % 64);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let off = 0; off < full; off += 64) block(dv, off);

  // tail: remaining bytes + 0x80 + zero padding + 64-bit little-endian bit length
  const rest = len - full;
  const tail = new Uint8Array(rest < 56 ? 64 : 128);
  tail.set(bytes.subarray(full));
  tail[rest] = 0x80;
  const tdv = new DataView(tail.buffer);
  const bits = len * 8;
  tdv.setUint32(tail.length - 8, bits >>> 0, true);
  tdv.setUint32(tail.length - 4, Math.floor(bits / 2 ** 32), true);
  for (let off = 0; off < tail.length; off += 64) block(tdv, off);

  return state.map(x => [x & 255, (x >>> 8) & 255, (x >>> 16) & 255, (x >>> 24) & 255]
    .map(b => b.toString(16).padStart(2, '0')).join('')).join('');
}
