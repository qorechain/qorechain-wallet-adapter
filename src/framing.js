// Pure, dependency-free QoreChain PQC tx-extension framing (the chain-matching bits).
export const HYBRID_SIG_TYPE_URL = '/qorechain.pqc.v1.PQCHybridSignature';
export const ALGORITHM_ML_DSA_87 = 1; // chain AlgorithmDilithium5 == FIPS-204 ML-DSA-87

// HYBRID_SIGN_BYTES_DOMAIN tags the bytes the ML-DSA key signs, so a signature the
// same key produced in any other context (a login challenge, a message-signing
// request) cannot be valid transaction sign-bytes. Must match the chain's
// x/pqc/types/hybrid_signbytes.go byte for byte.
export const HYBRID_SIGN_BYTES_DOMAIN = 'qorechain-pqc-hybrid-v2';

// frame builds the v2 PQC sign-bytes:
//   domain ‖ BE64(len chainId) ‖ chainId ‖ BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
// The chain-id is bound so the post-quantum signature itself refuses to verify on
// another network. A v1 frame (no domain, no chain-id) is rejected by a v2 chain.
export function frame(chainId, b0, auth) {
  if (typeof chainId !== 'string' || chainId.length === 0) {
    throw new Error('frame: chainId is required (v2 sign-bytes bind the chain-id)');
  }
  const domain = new TextEncoder().encode(HYBRID_SIGN_BYTES_DOMAIN);
  const cid = new TextEncoder().encode(chainId);
  const out = new Uint8Array(domain.length + 8 + cid.length + 4 + b0.length + 4 + auth.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  out.set(domain, o); o += domain.length;
  dv.setBigUint64(o, BigInt(cid.length), false); o += 8;
  out.set(cid, o); o += cid.length;
  dv.setUint32(o, b0.length, false); o += 4;
  out.set(b0, o); o += b0.length;
  dv.setUint32(o, auth.length, false); o += 4;
  out.set(auth, o);
  return out;
}

export function encodePqcHybridSignature(algorithmId, sig) {
  const varint = (n) => { const b = []; while (n > 0x7f) { b.push((n & 0x7f) | 0x80); n >>>= 7; } b.push(n); return b; };
  return Uint8Array.from([0x08, ...varint(algorithmId), 0x12, ...varint(sig.length), ...sig]);
}
