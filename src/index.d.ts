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
