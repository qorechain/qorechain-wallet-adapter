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
/** Hybrid eth_secp256k1 + ML-DSA-87 Cosmos tx (key.pqc required). */
export function signHybridEth(args: EthSignArgs): Promise<Uint8Array>;

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
export function frame(b0: Uint8Array, auth: Uint8Array): Uint8Array;
export function encodePqcHybridSignature(algorithmId: number, sig: Uint8Array): Uint8Array;
export function derivePqcKeyFromWallet(wallet: any, chainId: string, address: string, domain?: string): Promise<{ publicKey: Uint8Array; secretKey: Uint8Array }>;
export function qoreChainInfo(opts?: { chainId?: string; rpc?: string; rest?: string }): any;
export class QoreChainSigner {
  constructor(opts: { wallet: any; chainId: string; address: string; pubkeySecp256k1: Uint8Array; accountNumber: number | bigint; pqc: { publicKey: Uint8Array; secretKey: Uint8Array } });
  signHybrid(opts: { messages: any[]; fee: any; memo?: string; sequence: number | bigint; timeoutHeight?: bigint }): Promise<Uint8Array>;
}
