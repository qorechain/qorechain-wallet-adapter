// Pure, dependency-free QoreChain PQC tx-extension framing (the chain-matching bits).
export const HYBRID_SIG_TYPE_URL = '/qorechain.pqc.v1.PQCHybridSignature';
export const ALGORITHM_ML_DSA_87 = 1; // chain AlgorithmDilithium5 == FIPS-204 ML-DSA-87

export function frame(b0, auth) {
  const out = new Uint8Array(4 + b0.length + 4 + auth.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, b0.length, false);
  out.set(b0, 4);
  dv.setUint32(4 + b0.length, auth.length, false);
  out.set(auth, 8 + b0.length);
  return out;
}

export function encodePqcHybridSignature(algorithmId, sig) {
  const varint = (n) => { const b = []; while (n > 0x7f) { b.push((n & 0x7f) | 0x80); n >>>= 7; } b.push(n); return b; };
  return Uint8Array.from([0x08, ...varint(algorithmId), 0x12, ...varint(sig.length), ...sig]);
}
