import { createHash } from "crypto";

export const N = 32;
export const W = 16;
export const LEN1 = 64;
export const LEN2 = 3;
export const LEN = LEN1 + LEN2;

export function sha256(...parts: Buffer[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

export function chain(start: Buffer, steps: number): Buffer {
  let x = start;
  for (let i = 0; i < steps; i++) x = sha256(x);
  return x;
}

export function messageDigits(digest: Buffer): number[] {
  const out: number[] = new Array(LEN).fill(0);
  for (let i = 0; i < LEN1; i++) {
    const byte = digest[Math.floor(i / 2)];
    out[i] = i % 2 === 0 ? byte >> 4 : byte & 0x0f;
  }
  let checksum = 0;
  for (let j = 0; j < LEN1; j++) checksum += W - 1 - out[j];
  checksum = checksum << (8 - ((LEN2 * 4) % 8));
  for (let k = 0; k < LEN2; k++) {
    const shift = 4 * (LEN2 - 1 - k);
    out[LEN1 + k] = (checksum >> shift) & (W - 1);
  }
  return out;
}

export function secretKey(seed: number): Buffer[] {
  const sk: Buffer[] = [];
  for (let i = 0; i < LEN; i++) {
    sk.push(sha256(Buffer.from([seed]), Buffer.from([i]), Buffer.from("wots-sk-seed")));
  }
  return sk;
}

export function publicKeyCommit(sk: Buffer[]): Buffer {
  const tips: Buffer[] = sk.map((s) => chain(s, W - 1));
  return sha256(Buffer.concat(tips));
}

export function sign(sk: Buffer[], digest: Buffer): Buffer[] {
  const digits = messageDigits(digest);
  return sk.map((s, i) => chain(s, digits[i]));
}
