// @qorechain/wallet-adapter — eth-native (eth_secp256k1) Cosmos signing.
//
// A QoreChain account created eth-native (address = keccak(pubkey)[12:]) signs
// Cosmos SDK txs with the `eth_secp256k1` scheme: the classical signature is
// secp256k1 over the KECCAK-256 of the SignDoc (not sha256), and the account's
// pubkey is `/cosmos.evm.crypto.v1.ethsecp256k1.PubKey`. This is the same account
// that spends on the EVM lane, so its qor1/0x/svm forms are one identity.
//
// Mainnet requires the ML-DSA-87 hybrid extension in the tx body; signHybridEth
// adds it. signClassicalEth omits it (used for the one-time PQC key registration,
// which is bootstrap-exempt from the hybrid requirement).

import { Secp256k1, Keccak256 } from '@cosmjs/crypto';
import { fromHex } from '@cosmjs/encoding';
import { TxBody, AuthInfo, TxRaw, SignerInfo, ModeInfo, Fee, SignDoc } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import { SignMode } from 'cosmjs-types/cosmos/tx/signing/v1beta1/signing.js';
import { PubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys.js';
import { mldsa } from '@qorechain/pqc';
import { frame, encodePqcHybridSignature, HYBRID_SIG_TYPE_URL, ALGORITHM_ML_DSA_87 } from './framing.js';

// cosmos/evm eth_secp256k1 pubkey type. Wire shape is identical to the cosmos
// secp256k1 PubKey ({1: bytes key}), only the typeUrl differs.
export const ETHSECP256K1_PUBKEY_TYPE = '/cosmos.evm.crypto.v1.ethsecp256k1.PubKey';

function toBytes(x) {
  if (x instanceof Uint8Array) return x;
  return fromHex(String(x).replace(/^0x/, ''));
}

function buildAuthInfo(compressedPubkey, sequence, fee) {
  const pubAny = {
    typeUrl: ETHSECP256K1_PUBKEY_TYPE,
    value: PubKey.encode(PubKey.fromPartial({ key: toBytes(compressedPubkey) })).finish(),
  };
  const authInfo = AuthInfo.fromPartial({
    signerInfos: [SignerInfo.fromPartial({
      publicKey: pubAny,
      modeInfo: ModeInfo.fromPartial({ single: { mode: SignMode.SIGN_MODE_DIRECT } }),
      sequence: BigInt(sequence),
    })],
    fee: Fee.fromPartial(fee),
  });
  return AuthInfo.encode(authInfo).finish();
}

// eth_secp256k1 classical signature over a SignDoc: secp256k1 sign of keccak(signBytes),
// serialized as the 64-byte r‖s (low-s normalized by @cosmjs/crypto).
async function ethSign(signBytes, privateKey) {
  const hash = new Keccak256(signBytes).digest();
  const sig = await Secp256k1.createSignature(hash, toBytes(privateKey));
  const out = new Uint8Array(64);
  out.set(sig.r(32), 0);
  out.set(sig.s(32), 32);
  return out;
}

/**
 * Classical-only eth_secp256k1 Cosmos tx (no PQC extension). Use for the one-time
 * MsgRegisterPQCKeyV2 (bootstrap-exempt). `key` = { privateKey, pubkey } from
 * generateQoreWallet/walletFromMnemonic.
 */
export async function signClassicalEth({ key, chainId, accountNumber, messages, fee, sequence, memo = '', timeoutHeight = 0n }) {
  const authInfoBytes = buildAuthInfo(key.pubkey, sequence, fee);
  const bodyBytes = TxBody.encode(TxBody.fromPartial({ messages, memo, timeoutHeight })).finish();
  const signBytes = SignDoc.encode(SignDoc.fromPartial({
    bodyBytes, authInfoBytes, chainId, accountNumber: BigInt(accountNumber),
  })).finish();
  const classical = await ethSign(signBytes, key.privateKey);
  return TxRaw.encode(TxRaw.fromPartial({ bodyBytes, authInfoBytes, signatures: [classical] })).finish();
}

/**
 * Hybrid eth_secp256k1 + ML-DSA-87 Cosmos tx. `key` must include `pqc`
 * ({publicKey, secretKey}) as produced by generateQoreWallet/walletFromMnemonic.
 */
export async function signHybridEth({ key, chainId, accountNumber, messages, fee, sequence, memo = '', timeoutHeight = 0n }) {
  const authInfoBytes = buildAuthInfo(key.pubkey, sequence, fee);
  // B0 = body without the PQC extension.
  const b0 = TxBody.encode(TxBody.fromPartial({ messages, memo, timeoutHeight })).finish();
  // ML-DSA-87 over frame(B0, authInfo).
  const pqcSig = mldsa.sign(key.pqc.secretKey, frame(b0, authInfoBytes));
  const bodyWithExt = TxBody.encode(TxBody.fromPartial({
    messages, memo, timeoutHeight,
    extensionOptions: [{ typeUrl: HYBRID_SIG_TYPE_URL, value: encodePqcHybridSignature(ALGORITHM_ML_DSA_87, pqcSig) }],
  })).finish();
  const signBytes = SignDoc.encode(SignDoc.fromPartial({
    bodyBytes: bodyWithExt, authInfoBytes, chainId, accountNumber: BigInt(accountNumber),
  })).finish();
  const classical = await ethSign(signBytes, key.privateKey);
  return TxRaw.encode(TxRaw.fromPartial({ bodyBytes: bodyWithExt, authInfoBytes, signatures: [classical] })).finish();
}
