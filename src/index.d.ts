export const HYBRID_SIG_TYPE_URL: string;
export const ALGORITHM_ML_DSA_87: number;

// --- Unified wallet generation (one eth-native key → qor1 / 0x / svm) ---
export interface PqcKeypair { publicKey: Uint8Array; secretKey: Uint8Array; }
export interface QoreAddresses {
  addressBytes: Uint8Array;
  cosmos: string; // qor1… (bech32)
  evm: string;    // 0x… (EIP-55)
  svm: string;    // base58
}
export interface QoreWallet extends QoreAddresses {
  mnemonic: string | null;
  privateKey: string; // 0x-hex, 32 bytes
  pubkey: string;     // 0x-hex, 33-byte compressed secp256k1
  pqc: PqcKeypair;    // ML-DSA-87 (Dilithium-5)
}
export function generateQoreWallet(strength?: number): Promise<QoreWallet>;
export function walletFromMnemonic(mnemonic: string): Promise<QoreWallet>;
export function walletFromSeed(seed: Uint8Array | string): Promise<QoreWallet>;
export function addressesFrom20(addr20: Uint8Array): QoreAddresses;
export function qoreAddresses(opts: { cosmos?: string; evm?: string; hex?: string }): QoreAddresses;

// --- eth-native (eth_secp256k1) Cosmos signing (requires chain >= v3.1.83) ---
export const ETHSECP256K1_PUBKEY_TYPE: string;
export interface EthSignKey { privateKey: Uint8Array | string; pubkey: Uint8Array | string; pqc?: PqcKeypair; }
export interface EthSignArgs {
  key: EthSignKey;
  chainId: string;
  accountNumber: number | bigint;
  messages: Array<{ typeUrl: string; value: Uint8Array }>;
  fee: any;
  sequence: number | bigint;
  memo?: string;
  timeoutHeight?: bigint;
}
/** Classical-only eth_secp256k1 Cosmos tx (e.g. the bootstrap MsgRegisterPQCKeyV2). */
export function signClassicalEth(args: EthSignArgs): Promise<Uint8Array>;
/**
 * Hybrid eth_secp256k1 + ML-DSA-87 Cosmos tx (key.pqc required). Throws on a
 * legacy network when neither an explicit signBytesVersion nor `rest` is given.
 */
export function signHybridEth(args: EthSignArgs & { signBytesVersion?: SignBytesVersionOption; rest?: string; fetch?: typeof globalThis.fetch }): Promise<SignedTxBytes>;

// --- EVM network descriptors (EIP-3085 / MetaMask) ---
export function qoreEvmChainParams(opts?: { evmChainId?: number; rpcUrl?: string; wsUrl?: string; explorerUrl?: string; testnet?: boolean }): any;
export function addQoreEvmToWallet(provider: any, opts?: any): Promise<any>;

// --- Phantom / any-ed25519-wallet support ---
export const SYSTEM_PROGRAM_ID: string;
export function base58Encode(bytes: Uint8Array): string;
export function base58Decode(str: string, size?: number): Uint8Array;
export function systemTransferData(lamports: number | bigint): Uint8Array;
export interface SvmAccountMeta { pubkey: string; isSigner: boolean; isWritable: boolean; }
export function authSignBytes(p: { programId: string; accounts: SvmAccountMeta[]; data: Uint8Array; recentBlockhashHex: string }): Promise<Uint8Array>;
export function buildPhantomSvmEnvelope(p: { wallet: any; programId?: string; accounts: SvmAccountMeta[]; data: Uint8Array; recentBlockhashHex: string }): Promise<any>;
export function buildPhantomTransfer(p: { wallet: any; fromSvmAddr: string; toSvmAddr: string; lamports: number | bigint; recentBlockhashHex: string }): Promise<any>;
export function registerAuthenticatorMsg(p: { owner: string; phantomPubkey: Uint8Array; permissions?: string[]; expiryUnix: number | bigint; label?: string }): { typeUrl: string; value: any };
// --- Per-network hybrid PQC sign-bytes (v1 legacy / v2, chain v3.2.0 / testnet v3.1.98) ---
export type SignBytesVersion = 'v1' | 'v2';
export type SignBytesVersionOption = SignBytesVersion | 'auto';
export const HYBRID_SIGN_BYTES_V2_DOMAIN: 'qorechain-pqc-hybrid-v2';
/** Every upgrade plan name that switches a network to v2, most recent first. */
export const SIGN_BYTES_V2_UPGRADES: readonly ['v3.2.0', 'v3.1.98'];
/** The primary (current release) plan name. */
export const SIGN_BYTES_V2_UPGRADE: 'v3.2.0';
export const LEGACY_SIGN_BYTES_CHAINS: readonly string[];
/** v1: BE32(len b0) ‖ b0 ‖ BE32(len authInfo) ‖ authInfo. */
export function hybridSignBytesV1(b0: Uint8Array, authInfo: Uint8Array): Uint8Array;
/** v2: domain ‖ BE64(len chainId) ‖ chainId ‖ BE32(len b0) ‖ b0 ‖ BE32(len authInfo) ‖ authInfo. */
export function hybridSignBytesV2(chainId: string, b0: Uint8Array, authInfo: Uint8Array): Uint8Array;
/** Version-dispatching builder; `version` is required. */
export function hybridSignBytes(version: SignBytesVersion, chainId: string, b0: Uint8Array, authInfo: Uint8Array): Uint8Array;
/** Mirror of the chain's SignBytesVersionFor; pass the greatest applied height over SIGN_BYTES_V2_UPGRADES. The height is compared numerically ("0" → not applied). */
export function signBytesVersionFor(chainId: string, v2AppliedHeight: string | number | bigint | null | undefined): SignBytesVersion;
export function resolveSignBytesVersion(opts: {
  chainId: string;
  rest?: string;
  signBytesVersion?: SignBytesVersionOption;
  fetch?: typeof globalThis.fetch;
  ttlMs?: number;
  forceRefresh?: boolean;
}): Promise<SignBytesVersion>;
export function clearSignBytesCache(): void;
/** True iff the error/result is the chain refusing the hybrid PQC signature (codespace "pqc", code 21). */
export function isHybridSignBytesRejection(errOrResult: unknown): boolean;
/** TxRaw bytes plus the sign-bytes form that was used. */
export type SignedTxBytes = Uint8Array & { signBytesVersion: SignBytesVersion };
export function encodePqcHybridSignature(algorithmId: number, sig: Uint8Array): Uint8Array;
export function derivePqcKeyFromWallet(wallet: any, chainId: string, address: string, domain?: string): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }>;
export function qoreChainInfo(opts?: { chainId?: string; rpc?: string; rest?: string }): any;
export class QoreChainSigner {
  constructor(opts: {
    wallet: any; chainId: string; address: string; pubkeySecp256k1: Uint8Array; accountNumber: number | bigint;
    pqc: { publicKey: Uint8Array; secretKey: Uint8Array };
    /** LCD URL; required to auto-resolve the sign-bytes form on qorechain-vladi / qorechain-diana. */
    rest?: string;
    /** Default 'auto'. */
    signBytesVersion?: SignBytesVersionOption;
    fetch?: typeof globalThis.fetch;
  });
  signHybrid(opts: { messages: any[]; fee: any; memo?: string; sequence: number | bigint; timeoutHeight?: bigint; signBytesVersion?: SignBytesVersionOption }): Promise<SignedTxBytes>;
  /** Re-resolve bypassing the cache; returns the new form. */
  refreshSignBytesVersion(): Promise<SignBytesVersion>;
}

// --- v3.1.85 authenticator lanes (EVM + Native/Cosmos) + PQC key rotation (requires chain >= v3.1.85) ---
export interface PqcKeypairFull { publicKey: Uint8Array; secretKey: Uint8Array; }
/** 32-byte digest an authenticator signs to authorize a MsgExecuteEVM. */
export function evmAuthSignBytes(p: { chainId: string; account: string; pubkey: Uint8Array; to?: string; value?: string; data?: Uint8Array; nonce: number | bigint }): Promise<Uint8Array>;
/** 32-byte digest an authenticator signs to authorize a MsgExecuteCosmos. */
export function cosmosAuthSignBytes(p: { chainId: string; account: string; pubkey: Uint8Array; to: string; amount: string; nonce: number | bigint }): Promise<Uint8Array>;
/** Domain-separated STRING both keys sign for a MsgRotatePQCKey (sign utf8 of it). */
export function rotationSignBytes(chainId: string, algorithmId: number, account: string, oldPub: Uint8Array, newPub: Uint8Array): string;
/** MsgExecuteEVM (relayer broadcasts + pays fees). */
export function executeEvmMsg(p: { relayer: string; account: string; scheme: string; pubkey: Uint8Array; signature: Uint8Array; to?: string; value?: string; data?: Uint8Array; gasLimit: number | bigint; nonce: number | bigint }): { typeUrl: string; value: any };
/** MsgExecuteCosmos (relayer broadcasts). `amount` is a single-coin string e.g. "100uqor". */
export function executeCosmosMsg(p: { relayer: string; account: string; scheme: string; pubkey: Uint8Array; signature: Uint8Array; to: string; amount: string; nonce: number | bigint }): { typeUrl: string; value: any };
/** MsgRevokeAuthenticator (owner-signed) — instantly disables a linked key. */
export function revokeAuthenticatorMsg(p: { owner: string; account?: string; scheme: string; pubkey: Uint8Array }): { typeUrl: string; value: any };
/** MsgRotatePQCKey (sender-signed hybrid with the OLD key). */
export function rotatePqcKeyMsg(p: { sender: string; oldPublicKey: Uint8Array; newPublicKey: Uint8Array; oldSignature: Uint8Array; newSignature: Uint8Array }): { typeUrl: string; value: any };
/** Phantom (ed25519) → MsgExecuteEVM ready for the relayer. */
export function buildPhantomExecuteEvm(p: { wallet: any; relayer: string; chainId: string; account: string; to?: string; value?: string; data?: Uint8Array; gasLimit?: number | bigint; nonce: number | bigint }): Promise<{ typeUrl: string; value: any }>;
/** Phantom (ed25519) → MsgExecuteCosmos ready for the relayer. */
export function buildPhantomExecuteCosmos(p: { wallet: any; relayer: string; chainId: string; account: string; to: string; amount: string; nonce: number | bigint }): Promise<{ typeUrl: string; value: any }>;
/** Build a MsgRotatePQCKey to migrate a key between derivations (default legacy→canonical). Broadcast cosigned with the OLD keypair. */
export function rotatePqcKeyMsgFromMnemonic(p: { account: string; mnemonic: string; chainId: string; algorithmId?: number; oldDerivation?: 'adapter' | 'bridge'; newDerivation?: 'adapter' | 'bridge' }): { msg: { typeUrl: string; value: any }; oldKeypair: PqcKeypairFull; newKeypair: PqcKeypairFull };
/** The LEGACY (chain-bridge) ML-DSA-87 derivation `shake256(mnemonic)`. */
export function derivePqcLegacy(mnemonic: string): PqcKeypairFull;
/** Link a MetaMask / EVM key (by 0x address) as a scoped authenticator (owner-signed). */
export function registerEthAuthenticatorMsg(p: { owner: string; account?: string; ethAddress: string; permissions?: string[]; expiryUnix: number | bigint; label?: string }): { typeUrl: string; value: any };
/** MetaMask (EIP-191 personal_sign) → MsgExecuteEVM ready for the relayer. `provider` is EIP-1193. */
export function buildMetaMaskExecuteEvm(p: { provider: any; address: string; relayer: string; chainId: string; account: string; to?: string; value?: string; data?: Uint8Array; gasLimit?: number | bigint; nonce: number | bigint }): Promise<{ typeUrl: string; value: any }>;
/** MetaMask (EIP-191 personal_sign) → MsgExecuteCosmos ready for the relayer. */
export function buildMetaMaskExecuteCosmos(p: { provider: any; address: string; relayer: string; chainId: string; account: string; to: string; amount: string; nonce: number | bigint }): Promise<{ typeUrl: string; value: any }>;

// --- v3.2.0 EVM-lane post-quantum authorisation window (requires chain >= v3.2.0) ---
//
// From v3.2.0 an EVM transaction is admitted only from an account that holds a
// registered post-quantum key AND an open, unexhausted window. Nothing in this
// package opens a window on its own: a wallet must show an explicit
// authorisation step carrying the three limits.
export const MSG_OPEN_EVM_WINDOW_TYPE_URL: '/qorechain.pqc.v1.MsgOpenEVMWindow';
export const MSG_CLOSE_EVM_WINDOW_TYPE_URL: '/qorechain.pqc.v1.MsgCloseEVMWindow';
/** 17280. NOT "about 24 hours": diana ~1.03 s/block (≈5 h), mainnet ~3.1 s (≈15 h). */
export const MAX_EVM_WINDOW_BLOCKS: bigint;
/** 1000. */
export const MAX_EVM_WINDOW_TXS: bigint;
export const EVM_WINDOW_QUERY_PATH: '/qorechain/pqc/v1/evm_window';

/** An Any-encoded message, the shape `QoreChainSigner.signHybrid` carries. */
export interface AnyMsg { typeUrl: string; value: Uint8Array }
export type WindowAmount = number | bigint | string;
export interface EvmWindowBounds {
  /** 1..17280, required. */
  blocks: WindowAmount;
  /** 1..1000, required. */
  maxTxs: WindowAmount;
  /** > 0, uqor. Bounds transferred value PLUS the maximum fee (gas limit x gas fee cap). Required. */
  maxValue: WindowAmount;
}
/** MsgOpenEVMWindow, Any-encoded. Validates the bounds client-side first. */
export function openEvmWindowMsg(p: EvmWindowBounds & { sender: string }): AnyMsg;
/** MsgCloseEVMWindow, Any-encoded. Takes effect in the same block. */
export function closeEvmWindowMsg(p: { sender: string }): AnyMsg;
/** Inverse of the composers, for confirmation screens and tests. */
export function decodeEvmWindowMsg(msg: AnyMsg): { sender: string; blocks?: bigint; maxTxs?: bigint; maxValue?: string };
/** The chain's ValidateBasic, client-side. Throws with a message naming the bound. */
export function validateEvmWindowBounds(b: EvmWindowBounds, fn?: string): { blocks: bigint; maxTxs: bigint; maxValue: string };

/** Typed window status. Every number is a BigInt — the value fields are cosmos.Int uqor and exceed 2^53. */
export interface EvmWindowStatus {
  found: boolean;
  live: boolean;
  openedHeight: bigint | null;
  expiryHeight: bigint | null;
  maxTxs: bigint | null;
  usedTxs: bigint | null;
  maxValue: bigint | null;
  usedValue: bigint | null;
  remainingBlocks: bigint | null;
  remainingTxs: bigint | null;
  remainingValue: bigint | null;
}
/** GET {rest}/qorechain/pqc/v1/evm_window/{address}. 200 + found:false when absent, so it is safe to poll. */
export function fetchEvmWindow(p: { rest: string; address: string; fetch?: typeof globalThis.fetch }): Promise<EvmWindowStatus>;
/** Parse a QueryEVMWindowResponse body with your own transport. */
export function parseEvmWindow(body: any): EvmWindowStatus;

export type EvmWindowRejectionKind = 'no-window' | 'exhausted' | 'invalid' | 'no-pqc-key';
export const EVM_WINDOW_REJECTION_KINDS: readonly EvmWindowRejectionKind[];
/** Kind → what the wallet should tell the user to do. */
export const EVM_WINDOW_REMEDIES: Readonly<Record<EvmWindowRejectionKind, string>>;
/**
 * Classify an EVM-lane refusal from codespace `pqc` codes 26/27/28 AND from the
 * chain's own text (the only thing that survives EVM JSON-RPC). Returns the kind,
 * or null when the error is something else. Text wins: code 26 covers both "no
 * window" and "no registered post-quantum key", which have different remedies.
 */
export function isEvmWindowRejection(errOrResult: unknown): EvmWindowRejectionKind | null;
