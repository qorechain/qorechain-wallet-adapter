// @qorechain/wallet-adapter — unified wallet generation.
//
// One eth-native secp256k1 keypair → the SAME 20-byte account rendered as all
// THREE QoreChain address encodings, so a wallet never "has funds on Cosmos but
// not EVM" again. The 20 bytes are the Ethereum derivation `keccak256(pubkey)[12:]`
// so the key is natively spendable on the EVM lane; the Cosmos (`qor1…`) and SVM
// (base58) forms are just other encodings of those same 20 bytes — the chain reads
// one x/bank balance for the account, visible under all three.
//
//   {
//     mnemonic, privateKey (0x hex, 32B),
//     pubkey (33B compressed),
//     addressBytes (20B),
//     cosmos: "qor1…",              // bech32
//     evm:    "0x…" (EIP-55),       // hex
//     svm:    "<base58>",           // base58(20B ‖ 12 zero bytes) = 32-byte SVM addr
//     pqc:    { publicKey, secretKey }  // ML-DSA-87 (Dilithium-5), for the hybrid ante
//   }
//
// Eth-native accounts are fully supported by the chain (the Cosmos ante's
// SigVerification handles eth_secp256k1 and the PQC hybrid decorator keys off the
// address), so the same wallet signs EVM txs (EIP-155) AND PQC-hybrid Cosmos txs.

import { Bip39, Random, Slip10, Slip10Curve, stringToPath, Secp256k1, Keccak256, EnglishMnemonic } from '@cosmjs/crypto';
import { toBech32, toHex, fromHex, fromBech32 } from '@cosmjs/encoding';
import { mldsa, shake256 } from '@qorechain/pqc';
import { base58Encode } from './phantom.js';

// Ethereum HD path (coin-type 60) — makes the 20-byte address the keccak
// derivation, so the key is EVM-native (spendable via eth_sendRawTransaction).
const ETH_HD_PATH = "m/44'/60'/0'/0/0";
const HRP = 'qor';

// EIP-55 mixed-case checksum for a 20-byte hex address (no 0x).
function toEip55(hex20) {
  const lower = hex20.toLowerCase();
  const hash = toHex(new Keccak256(new TextEncoder().encode(lower)).digest());
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

// Derive the three encodings + the PQC key from a 20-byte account address.
// Exposed so SDKs / backends can render all three from a known account too.
export function addressesFrom20(addr20) {
  if (addr20.length !== 20) throw new Error('address must be 20 bytes');
  const hex = toHex(addr20);
  const svmBytes = new Uint8Array(32);
  svmBytes.set(addr20, 0); // right-pad with 12 zero bytes → the unified 32-byte SVM address
  return { addressBytes: addr20, cosmos: toBech32(HRP, addr20), evm: toEip55(hex), svm: base58Encode(svmBytes) };
}

function derivePqc(cosmosAddr, mnemonic) {
  const seed = shake256(new TextEncoder().encode(`qorechain:pqc:v1|${cosmosAddr}|${mnemonic}`), 32);
  return mldsa.keygen(seed); // deterministic + recoverable from {address, mnemonic}
}

async function fromMnemonicObj(mnemonic) {
  const seed = await Bip39.mnemonicToSeed(new EnglishMnemonic(mnemonic));
  const { privkey } = Slip10.derivePath(Slip10Curve.Secp256k1, seed, stringToPath(ETH_HD_PATH));
  const kp = await Secp256k1.makeKeypair(privkey);
  const uncompressed = kp.pubkey; // 65 bytes, 0x04 || X || Y
  const compressed = Secp256k1.compressPubkey(uncompressed); // 33 bytes
  // Ethereum address = last 20 bytes of keccak256 of the 64-byte pubkey (drop 0x04).
  const addr20 = new Keccak256(uncompressed.slice(1)).digest().slice(12);
  const enc = addressesFrom20(addr20);
  return {
    mnemonic,
    privateKey: '0x' + toHex(privkey),
    pubkey: '0x' + toHex(compressed),
    ...enc,
    pqc: derivePqc(enc.cosmos, mnemonic),
  };
}

/** Generate a fresh unified QoreChain wallet (random 24-word mnemonic). */
export async function generateQoreWallet(strength = 256) {
  const mnemonic = Bip39.encode(Random.getBytes(strength / 8)).toString();
  return fromMnemonicObj(mnemonic);
}

/** Recover a unified QoreChain wallet from an existing BIP39 mnemonic. */
export async function walletFromMnemonic(mnemonic) {
  return fromMnemonicObj(mnemonic);
}

/**
 * Derive a unified QoreChain wallet directly from a 32-byte seed (no mnemonic).
 *
 * The seed is used as the secp256k1 private key, so a caller can derive one
 * canonical eth-native account deterministically from any 32 bytes — e.g.
 * `shake256(phantomSignature)` for the Phantom "connect → 3 addresses" flow, or
 * an HKDF/KDF output from another wallet. Same 20-byte identity model as
 * `walletFromMnemonic`: qor1 / 0x / svm all resolve to the same account and the
 * same balance, and the key signs on every interface (incl. hybrid PQC).
 *
 * The ML-DSA-87 key is bound to `qorechain:pqc:v1|<qor1>|seed:<hex>` so it is
 * recoverable from the same seed and never collides with a mnemonic wallet.
 * `seed` accepts a 32-byte Uint8Array or a (0x-)hex string.
 */
export async function walletFromSeed(seed) {
  const privkey = typeof seed === 'string' ? fromHex(seed.replace(/^0x/, '')) : seed;
  if (!(privkey instanceof Uint8Array) || privkey.length !== 32) {
    throw new Error('seed must be 32 bytes (Uint8Array or hex)');
  }
  const kp = await Secp256k1.makeKeypair(privkey); // validates the scalar is in [1, n-1]
  const uncompressed = kp.pubkey;
  const compressed = Secp256k1.compressPubkey(uncompressed);
  const addr20 = new Keccak256(uncompressed.slice(1)).digest().slice(12);
  const enc = addressesFrom20(addr20);
  const pqcSeed = shake256(new TextEncoder().encode(`qorechain:pqc:v1|${enc.cosmos}|seed:${toHex(privkey)}`), 32);
  return {
    mnemonic: null,
    privateKey: '0x' + toHex(privkey),
    pubkey: '0x' + toHex(compressed),
    ...enc,
    pqc: mldsa.keygen(pqcSeed),
  };
}

/** Convenience: the three address encodings of an existing account. */
export function qoreAddresses({ cosmos, evm, hex }) {
  let addr20;
  if (evm) addr20 = fromHex(evm.replace(/^0x/, ''));
  else if (hex) addr20 = fromHex(hex.replace(/^0x/, ''));
  else if (cosmos) addr20 = fromBech32(cosmos).data;
  else throw new Error('provide one of {cosmos, evm, hex}');
  return addressesFrom20(addr20);
}
