// Pure, dependency-free QoreChain PQC tx-extension encoding (the chain-matching bits).
//
// The bytes the ML-DSA key signs are built in ./signbytes.js, which carries both
// forms (v1 legacy / v2) and the per-network resolver. There is deliberately no
// helper here that picks a form implicitly: every caller passes the version.
export const HYBRID_SIG_TYPE_URL = '/qorechain.pqc.v1.PQCHybridSignature';
export const ALGORITHM_ML_DSA_87 = 1; // chain AlgorithmDilithium5 == FIPS-204 ML-DSA-87

export function encodePqcHybridSignature(algorithmId, sig) {
  const varint = (n) => { const b = []; while (n > 0x7f) { b.push((n & 0x7f) | 0x80); n >>>= 7; } b.push(n); return b; };
  return Uint8Array.from([0x08, ...varint(algorithmId), 0x12, ...varint(sig.length), ...sig]);
}
