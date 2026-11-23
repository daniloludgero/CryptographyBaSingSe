// SHA-256, HMAC-SHA-256 e SHAKE256 em JavaScript puro e síncrono.
// Escritos para o laboratório da RSD-S v5.2 e conferidos contra hashlib/hmac do Python
// (site/testes/paridade.test.js). NÃO são implementações para proteger dados reais:
// não têm tempo constante nem controle de memória.

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

function compress(H, block, off, W) {
  for (let i = 0; i < 16; i++) {
    const j = off + i * 4;
    W[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3];
  }
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
    const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }
  let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
  for (let i = 0; i < 64; i++) {
    const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const ch = (e & f) ^ (~e & g);
    const t1 = (h + S1 + ch + K256[i] + W[i]) | 0;
    const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
  H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
}

/** SHA-256 de um Uint8Array. Devolve Uint8Array(32). */
export function sha256(msg) {
  const H = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Int32Array(64);
  const n = msg.length;
  const total = ((n + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(total);
  buf.set(msg);
  buf[n] = 0x80;
  const bits = BigInt(n) * 8n;
  for (let i = 0; i < 8; i++) buf[total - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);
  for (let off = 0; off < total; off += 64) compress(H, buf, off, W);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = H[i] >>> 24; out[i * 4 + 1] = (H[i] >>> 16) & 255; out[i * 4 + 2] = (H[i] >>> 8) & 255; out[i * 4 + 3] = H[i] & 255;
  }
  return out;
}

/** HMAC-SHA-256 (RFC 2104). key e msg são Uint8Array. */
export function hmacSha256(key, msg) {
  let k = key;
  if (k.length > 64) k = sha256(k);
  const ipad = new Uint8Array(64 + msg.length);
  const opad = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    const kb = i < k.length ? k[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  ipad.set(msg, 64);
  opad.set(sha256(ipad), 64);
  return sha256(opad);
}

// ---- Keccak-f[1600] com lanes de 64 bits em pares (lo, hi) de Uint32 ----
const RC = [
  [0x00000001, 0x00000000], [0x00008082, 0x00000000], [0x0000808a, 0x80000000], [0x80008000, 0x80000000],
  [0x0000808b, 0x00000000], [0x80000001, 0x00000000], [0x80008081, 0x80000000], [0x00008009, 0x80000000],
  [0x0000008a, 0x00000000], [0x00000088, 0x00000000], [0x80008009, 0x00000000], [0x8000000a, 0x00000000],
  [0x8000808b, 0x00000000], [0x0000008b, 0x80000000], [0x00008089, 0x80000000], [0x00008003, 0x80000000],
  [0x00008002, 0x80000000], [0x00000080, 0x80000000], [0x0000800a, 0x00000000], [0x8000000a, 0x80000000],
  [0x80008081, 0x80000000], [0x00008080, 0x80000000], [0x80000001, 0x00000000], [0x80008008, 0x80000000],
];
const ROT = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

function keccakF(s) { // s: Uint32Array(50)
  const bc = new Uint32Array(10);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      bc[2 * x] = s[2 * x] ^ s[2 * (x + 5)] ^ s[2 * (x + 10)] ^ s[2 * (x + 15)] ^ s[2 * (x + 20)];
      bc[2 * x + 1] = s[2 * x + 1] ^ s[2 * (x + 5) + 1] ^ s[2 * (x + 10) + 1] ^ s[2 * (x + 15) + 1] ^ s[2 * (x + 20) + 1];
    }
    for (let x = 0; x < 5; x++) {
      const p = (x + 4) % 5, n = (x + 1) % 5;
      // d = bc[p] ^ rotl64(bc[n], 1)
      const lo = bc[2 * n], hi = bc[2 * n + 1];
      const rlo = (lo << 1) | (hi >>> 31), rhi = (hi << 1) | (lo >>> 31);
      const dlo = bc[2 * p] ^ rlo, dhi = bc[2 * p + 1] ^ rhi;
      for (let y = 0; y < 25; y += 5) { s[2 * (y + x)] ^= dlo; s[2 * (y + x) + 1] ^= dhi; }
    }
    // rho + pi
    let tlo = s[2], thi = s[3];
    for (let i = 0; i < 24; i++) {
      const j = PI[i], r = ROT[i];
      const blo = s[2 * j], bhi = s[2 * j + 1];
      let nlo, nhi;
      if (r === 32) { nlo = thi; nhi = tlo; }
      else if (r < 32) { nlo = (tlo << r) | (thi >>> (32 - r)); nhi = (thi << r) | (tlo >>> (32 - r)); }
      else { const q = r - 32; nlo = (thi << q) | (tlo >>> (32 - q)); nhi = (tlo << q) | (thi >>> (32 - q)); }
      s[2 * j] = nlo; s[2 * j + 1] = nhi;
      tlo = blo; thi = bhi;
    }
    // chi
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 10; x++) bc[x] = s[2 * y + x];
      for (let x = 0; x < 5; x++) {
        s[2 * (y + x)] ^= ~bc[2 * ((x + 1) % 5)] & bc[2 * ((x + 2) % 5)];
        s[2 * (y + x) + 1] ^= ~bc[2 * ((x + 1) % 5) + 1] & bc[2 * ((x + 2) % 5) + 1];
      }
    }
    s[0] ^= RC[round][0]; s[1] ^= RC[round][1];
  }
}

/** SHAKE256 (FIPS 202): absorve msg (Uint8Array) e devolve outLen bytes. */
export function shake256(msg, outLen) {
  const rate = 136;
  const s = new Uint32Array(50);
  const padded = new Uint8Array(Math.ceil((msg.length + 1) / rate) * rate);
  padded.set(msg);
  padded[msg.length] ^= 0x1f;
  padded[padded.length - 1] ^= 0x80;
  const absorb = (block) => {
    for (let i = 0; i < rate / 4; i++) {
      s[i] ^= block[4 * i] | (block[4 * i + 1] << 8) | (block[4 * i + 2] << 16) | (block[4 * i + 3] << 24);
    }
    keccakF(s);
  };
  for (let off = 0; off < padded.length; off += rate) absorb(padded.subarray(off, off + rate));
  const out = new Uint8Array(outLen);
  let pos = 0;
  while (pos < outLen) {
    for (let i = 0; i < rate && pos < outLen; i++, pos++) out[pos] = (s[i >> 2] >>> (8 * (i & 3))) & 255;
    if (pos < outLen) keccakF(s);
  }
  return out;
}

export const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
export function fromHex(h) {
  if (h.length % 2) throw new Error('hex com tamanho ímpar');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}
