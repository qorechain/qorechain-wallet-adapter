// @qorechain/wallet-adapter
//
// Add QoreChain to any Cosmos wallet (Keplr, Leap, Cosmostation, …) and sign its
// PQC-required transactions WITHOUT any wallet-side changes.
//
// QoreChain's ante chain requires every Cosmos tx to carry a FIPS-204 ML-DSA-87
// hybrid signature in a tx-body extension option, in addition to the account's
// classical secp256k1 signature. The trick that makes this wallet-compatible:
// the wallet only ever produces a *standard SIGN_MODE_DIRECT* signature over the
// final body — and the PQC extension is baked into that body BEFORE the wallet
// signs it. So `wallet.signDirect(...)` works unmodified; the adapter does the
// ML-DSA part with @qorechain/pqc (standard, interoperable since the chain was
// migrated to the FIPS standards).
//
// Protocol (mirrors the chain's `tx pqc cosign`):
//   B0   = TxBody{messages, memo, timeoutHeight}            (no extension)
//   v    = resolveSignBytesVersion({chainId, rest})         // 'v1' | 'v2', per network
//   sigP = ML-DSA-87.sign( hybridSignBytes(v, chainId, B0, authInfoBytes) )
//   body = TxBody{...B0, extensionOptions:[PQCHybridSignature{1, sigP}]}
//   sigC = wallet.signDirect( SignDoc{body, authInfo, chainId, accountNumber} )
//   tx   = TxRaw{ body, authInfo, [sigC] }
//
// v1 = BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth
// v2 = "qorechain-pqc-hybrid-v2" ‖ BE64(len chainId) ‖ chainId ‖ v1-layout
// A network accepts exactly one form at a time; see ./signbytes.js.

import { mldsa, shake256 } from '@qorechain/pqc';
import { encodePqcHybridSignature, HYBRID_SIG_TYPE_URL, ALGORITHM_ML_DSA_87 } from './framing.js';
import { hybridSignBytes, resolveSignBytesVersion } from './signbytes.js';
export { encodePqcHybridSignature, HYBRID_SIG_TYPE_URL, ALGORITHM_ML_DSA_87 };
// Per-network hybrid sign-bytes (v1 legacy / v2) + resolver + rejection detector.
export {
  HYBRID_SIGN_BYTES_V2_DOMAIN, SIGN_BYTES_V2_UPGRADE, LEGACY_SIGN_BYTES_CHAINS,
  hybridSignBytesV1, hybridSignBytesV2, hybridSignBytes,
  signBytesVersionFor, resolveSignBytesVersion, clearSignBytesCache,
  isHybridSignBytesRejection,
} from './signbytes.js';
// Phantom / any-ed25519-wallet support: drive the one unified account from Phantom.
export {
  base58Encode, base58Decode, SYSTEM_PROGRAM_ID, systemTransferData,
  authSignBytes, buildPhantomSvmEnvelope, buildPhantomTransfer, registerAuthenticatorMsg,
} from './phantom.js';
// Unified wallet generation: one eth-native key → cosmos/evm/svm addresses + PQC key.
export {
  generateQoreWallet, walletFromMnemonic, walletFromSeed, addressesFrom20, qoreAddresses,
} from './wallet.js';
// eth-native (eth_secp256k1) Cosmos signing — classical (register) + hybrid (PQC).
export {
  signClassicalEth, signHybridEth, ETHSECP256K1_PUBKEY_TYPE,
} from './sign-eth.js';
// v3.1.85 authenticator lanes (EVM + Native/Cosmos) + PQC key rotation.
export {
  evmAuthSignBytes, cosmosAuthSignBytes, rotationSignBytes,
  executeEvmMsg, executeCosmosMsg, revokeAuthenticatorMsg, rotatePqcKeyMsg,
  buildPhantomExecuteEvm, buildPhantomExecuteCosmos,
  registerEthAuthenticatorMsg, buildMetaMaskExecuteEvm, buildMetaMaskExecuteCosmos,
  rotatePqcKeyMsgFromMnemonic, derivePqcLegacy,
} from './authenticator.js';
import { TxBody, AuthInfo, TxRaw, SignerInfo, ModeInfo, Fee } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import { SignMode } from 'cosmjs-types/cosmos/tx/signing/v1beta1/signing.js';
import { SignDoc } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import { PubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys.js';


// Deterministically derive an ML-DSA-87 keypair bound to the wallet, without ever
// touching the mnemonic: the wallet ADR-36-signs a fixed message, and SHAKE-256 of
// that signature seeds the keygen. The same wallet always yields the same PQC key.
export async function derivePqcKeyFromWallet(wallet, chainId, address, domain = 'qorechain:pqc:v1') {
  const { signature } = await wallet.signArbitrary(chainId, address, domain);
  const sigBytes = typeof signature === 'string' ? Uint8Array.from(Buffer.from(signature, 'base64')) : signature;
  const seed = shake256(sigBytes, 32);
  return mldsa.keygen(seed); // { publicKey, secretKey } — deterministic from seed
}

export class QoreChainSigner {
  // wallet: a Keplr-like object exposing signDirect(chainId, signer, signDoc) and
  //         (optionally) signArbitrary(...). pqc: { publicKey, secretKey } ML-DSA-87.
  // rest:   the network's LCD URL; needed to auto-resolve the sign-bytes form on
  //         qorechain-vladi / qorechain-diana.
  // signBytesVersion: 'auto' (default) | 'v1' | 'v2'.
  // fetch:  optional fetch implementation for the resolver (defaults to globalThis.fetch).
  constructor({ wallet, chainId, address, pubkeySecp256k1, accountNumber, pqc, rest, signBytesVersion = 'auto', fetch }) {
    Object.assign(this, { wallet, chainId, address, pubkeySecp256k1, accountNumber, pqc, rest, signBytesVersion });
    if (fetch) this.fetch = fetch;
  }

  _resolve(signBytesVersion, forceRefresh = false) {
    return resolveSignBytesVersion({
      chainId: this.chainId, rest: this.rest,
      signBytesVersion: signBytesVersion ?? this.signBytesVersion ?? 'auto',
      forceRefresh,
      ...(this.fetch ? { fetch: this.fetch } : {}),
    });
  }

  // Re-ask the network (bypassing the cache) which form it verifies. Call this
  // after a broadcast is refused with isHybridSignBytesRejection(err), then sign
  // again and broadcast once more. With an explicit version it returns that version.
  async refreshSignBytesVersion() {
    return this._resolve(undefined, true);
  }

  // Build + hybrid-sign + return TxRaw bytes ready to broadcast. The returned
  // Uint8Array also carries `.signBytesVersion` ('v1' | 'v2'), the form used.
  // `signBytesVersion` overrides the signer's setting for this call.
  async signHybrid({ messages, fee, memo = '', sequence, timeoutHeight = 0n, signBytesVersion }) {
    const version = await this._resolve(signBytesVersion);

    // 1. AuthInfo: single DIRECT signer (secp256k1) + fee.
    const pubAny = {
      typeUrl: '/cosmos.crypto.secp256k1.PubKey',
      value: PubKey.encode(PubKey.fromPartial({ key: this.pubkeySecp256k1 })).finish(),
    };
    const authInfo = AuthInfo.fromPartial({
      signerInfos: [SignerInfo.fromPartial({
        publicKey: pubAny,
        modeInfo: ModeInfo.fromPartial({ single: { mode: SignMode.SIGN_MODE_DIRECT } }),
        sequence: BigInt(sequence),
      })],
      fee: Fee.fromPartial(fee),
    });
    const authInfoBytes = AuthInfo.encode(authInfo).finish();

    // 2. B0 = body without the PQC extension.
    const b0 = TxBody.encode(TxBody.fromPartial({ messages, memo, timeoutHeight })).finish();

    // 3. ML-DSA-87 sign the hybrid sign-bytes in the form this network verifies.
    const pqcSig = mldsa.sign(this.pqc.secretKey, hybridSignBytes(version, this.chainId, b0, authInfoBytes));

    // 4. body WITH the PQC hybrid extension.
    const bodyWithExt = TxBody.encode(TxBody.fromPartial({
      messages, memo, timeoutHeight,
      extensionOptions: [{ typeUrl: HYBRID_SIG_TYPE_URL, value: encodePqcHybridSignature(ALGORITHM_ML_DSA_87, pqcSig) }],
    })).finish();

    // 5. Classical secp256k1 signature from the wallet over the final SignDoc.
    const signDoc = SignDoc.fromPartial({
      bodyBytes: bodyWithExt, authInfoBytes, chainId: this.chainId, accountNumber: BigInt(this.accountNumber),
    });
    const { signature } = await this.wallet.signDirect(this.chainId, this.address, {
      bodyBytes: bodyWithExt, authInfoBytes, chainId: this.chainId, accountNumber: BigInt(this.accountNumber),
    });
    const classicalSig = typeof signature.signature === 'string'
      ? Uint8Array.from(Buffer.from(signature.signature, 'base64')) : signature.signature;

    // 6. Assemble TxRaw.
    const txRaw = TxRaw.encode(TxRaw.fromPartial({
      bodyBytes: bodyWithExt, authInfoBytes, signatures: [classicalSig],
    })).finish();
    txRaw.signBytesVersion = version;
    return txRaw;
  }
}

// Keplr chain-registration descriptor for QoreChain (pass to keplr.experimentalSuggestChain).
export function qoreChainInfo({ chainId = 'qorechain-diana', rpc, rest } = {}) {
  return {
    chainId, chainName: 'QoreChain', rpc, rest,
    bip44: { coinType: 118 },
    bech32Config: {
      bech32PrefixAccAddr: 'qor', bech32PrefixAccPub: 'qorpub',
      bech32PrefixValAddr: 'qorvaloper', bech32PrefixValPub: 'qorvaloperpub',
      bech32PrefixConsAddr: 'qorvalcons', bech32PrefixConsPub: 'qorvalconspub',
    },
    currencies: [{ coinDenom: 'QOR', coinMinimalDenom: 'uqor', coinDecimals: 6 }],
    feeCurrencies: [{
      coinDenom: 'QOR', coinMinimalDenom: 'uqor', coinDecimals: 6,
      // MUST be >= the chain's feemarket min_gas_price (0.1 uqor/gas). A lower
      // value (e.g. 0.001) makes wallets build txs the fee floor rejects.
      gasPriceStep: { low: 0.1, average: 0.15, high: 0.25 },
    }],
    stakeCurrency: { coinDenom: 'QOR', coinMinimalDenom: 'uqor', coinDecimals: 6 },
    features: ['cosmwasm'],
  };
}

// EIP-3085 `wallet_addEthereumChain` params for QoreChain's EVM, for MetaMask &
// any EIP-1193 wallet. IMPORTANT: the EVM native currency is the 18-decimal
// `aqor` view of QOR (1 QOR = 1e18 aqor = 1e6 uqor; the EVM lane scales the
// 6-decimal bank denom by 1e12). nativeCurrency.decimals MUST be 18 here — do
// NOT copy the 6 from the Cosmos `uqor` currency, or balances render 1e12x off.
export function qoreEvmChainParams({ evmChainId = 9800, rpcUrl, wsUrl, explorerUrl, testnet = true } = {}) {
  if (!rpcUrl) throw new Error('qoreEvmChainParams: rpcUrl is required');
  return {
    chainId: '0x' + Number(evmChainId).toString(16), // 9800 -> 0x2648, 9801 -> 0x2649
    chainName: testnet ? 'QoreChain Testnet' : 'QoreChain',
    nativeCurrency: { name: 'QORE', symbol: 'QOR', decimals: 18 },
    rpcUrls: wsUrl ? [rpcUrl, wsUrl] : [rpcUrl],
    blockExplorerUrls: explorerUrl ? [explorerUrl] : [],
  };
}

// One-call helper: prompt an EIP-1193 wallet (MetaMask) to add QoreChain's EVM.
export async function addQoreEvmToWallet(provider, opts) {
  return provider.request({ method: 'wallet_addEthereumChain', params: [qoreEvmChainParams(opts)] });
}
