import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodePqcHybridSignature, HYBRID_SIG_TYPE_URL, ALGORITHM_ML_DSA_87 } from '../src/framing.js';

test('encodePqcHybridSignature: field1 varint algId, field2 bytes sig', () => {
  const sig = Uint8Array.from([0xaa, 0xbb]);
  const out = encodePqcHybridSignature(ALGORITHM_ML_DSA_87, sig);
  // 0x08 = field1 varint; 0x01 = algId 1; 0x12 = field2 len-delim; 0x02 = len; payload
  assert.deepEqual([...out], [0x08, 0x01, 0x12, 0x02, 0xaa, 0xbb]);
});

test('constants match the chain', () => {
  assert.equal(HYBRID_SIG_TYPE_URL, '/qorechain.pqc.v1.PQCHybridSignature');
  assert.equal(ALGORITHM_ML_DSA_87, 1);
});

test('encoder handles a full 4627-byte ML-DSA-87 signature (multi-byte length varint)', () => {
  const sig = new Uint8Array(4627).fill(7);
  const out = encodePqcHybridSignature(1, sig);
  // 0x08 0x01 (algId) + 0x12 + varint(4627)= 0x93 0x24 + 4627 bytes => 2+2+1+4627
  assert.equal(out[0], 0x08);
  assert.equal(out[2], 0x12);
  assert.equal(out.length, 2 + 1 + 2 + 4627);
});
