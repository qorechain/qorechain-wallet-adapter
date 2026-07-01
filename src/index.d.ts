export const HYBRID_SIG_TYPE_URL: string;
export const ALGORITHM_ML_DSA_87: number;

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
