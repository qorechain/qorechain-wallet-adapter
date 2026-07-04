# @qorechain/wallet-adapter

Add **QoreChain** to any Cosmos wallet — Keplr, Leap, Cosmostation — and send its
**PQC-required** transactions, with **no wallet-side changes**.

QoreChain's ante chain rejects any Cosmos tx that lacks a FIPS-204 **ML-DSA-87**
hybrid signature (in a tx-body extension option) alongside the account's classical
secp256k1 signature. Stock wallets can't produce ML-DSA signatures — so this
adapter does. The design is what makes it drop-in:

> The wallet only ever produces a **standard `SIGN_MODE_DIRECT` signature** over
> the final transaction body. The adapter bakes the ML-DSA-87 extension **into
> that body before the wallet signs it**. So `wallet.signDirect(...)` works
> exactly as it does for any Cosmos chain — it has no idea PQC is involved.

The ML-DSA part uses [`@qorechain/pqc`](https://github.com/qorechain/qorechain-pqc) — the same FIPS-204
implementation the chain itself was migrated to, so the signatures are
byte-compatible and verify in the chain's ante. (Before that migration this was
impossible: the chain ran a non-standard Dilithium variant no JS lib could match.)

## Why it works — the protocol

Mirrors the chain's own `qorechaind tx pqc cosign`:

```
B0   = TxBody{messages, memo, timeoutHeight}              // no extension
sigP = ML-DSA-87.sign( frame(B0, authInfoBytes) )         // adapter does this
body = TxBody{ ...B0, extensionOptions:[ PQCHybridSignature{1, sigP} ] }
sigC = wallet.signDirect( SignDoc{ body, authInfo, chainId, accountNumber } )
tx   = TxRaw{ body, authInfo, [sigC] }
```

where `frame(b0, auth) = BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth`, the extension
type URL is `/qorechain.pqc.v1.PQCHybridSignature`, and algorithm `1` = ML-DSA-87.

**Verified end-to-end:** an adapter-built tx (ML-DSA-87 via `@noble/post-quantum`
+ classical via a cosmjs signer standing in for Keplr) **committed with code 0**
against a live 7-validator QoreChain — the PQC ante accepted it.

## Usage (Keplr)

```js
import {
  QoreChainSigner, qoreChainInfo, derivePqcKeyFromWallet,
} from '@qorechain/wallet-adapter';

// 1. Register the chain with the wallet (one click for the user).
await window.keplr.experimentalSuggestChain(qoreChainInfo({ rpc, rest }));
await window.keplr.enable('qorechain-diana');
const signer = window.keplr.getOfflineSigner('qorechain-diana');
const [account] = await signer.getAccounts();

// 2. Derive the user's ML-DSA-87 key, bound to their wallet (no mnemonic export).
const pqc = await derivePqcKeyFromWallet(window.keplr, 'qorechain-diana', account.address);
// (first time only) register the PQC public key on-chain via MsgRegisterPQCKey —
// that message is classical-exempt, so the wallet can sign it normally.

// 3. Sign + broadcast a PQC-required tx. The wallet signs an ordinary SignDoc.
const adapter = new QoreChainSigner({
  wallet: window.keplr, chainId: 'qorechain-diana', address: account.address,
  pubkeySecp256k1: account.pubkey, accountNumber, pqc,
});
const txBytes = await adapter.signHybrid({ messages, fee, sequence });
await fetch(`${rpc}`, { method:'POST', body: JSON.stringify({
  jsonrpc:'2.0', id:1, method:'broadcast_tx_sync', params:{ tx: toBase64(txBytes) } }) });
```

## Wallet support

| Wallet | How | Status |
|---|---|---|
| **Keplr** | `experimentalSuggestChain` + `signDirect` | ✅ supported |
| **Leap / Cosmostation** | same `signDirect` interface | ✅ supported (any wallet exposing `signDirect`) |
| **MetaMask** | uses QoreChain's **EVM** path (chainId 9800) — structurally PQC-exempt | ✅ works natively, no adapter needed |
| **Phantom** | derive a unified account from a Phantom signature (`walletFromSeed`) | ✅ connect → qor1/0x/svm, receive on any, spend on any (incl. hybrid PQC) |

## API

Wallet generation & unified addresses:
- `generateQoreWallet(strength?)` / `walletFromMnemonic(mnemonic)` / `walletFromSeed(seed32)` — a unified wallet `{ mnemonic, privateKey, pubkey, cosmos, evm, svm, pqc }`.
- `addressesFrom20(bytes20)` / `qoreAddresses({cosmos|evm|hex})` — the three encodings of a known account.

eth-native Cosmos signing (chain ≥ v3.1.83):
- `signClassicalEth({ key, chainId, accountNumber, sequence, messages, fee, memo?, timeoutHeight? })` → `TxRaw` bytes (classical, e.g. PQC key registration).
- `signHybridEth({ ... })` → `TxRaw` bytes (eth_secp256k1 + ML-DSA-87 hybrid).
- `ETHSECP256K1_PUBKEY_TYPE` — the eth pubkey type URL.

Keplr / any-signDirect adapter + PQC framing:
- `QoreChainSigner#signHybrid({ messages, fee, sequence, memo?, timeoutHeight? })` → `TxRaw` bytes.
- `derivePqcKeyFromWallet(wallet, chainId, address)` — deterministic ML-DSA-87 key from a wallet signature.
- `frame(b0, auth)` — QoreChain hybrid sign-bytes framing; `encodePqcHybridSignature(algId, sig)` — proto encoder for the extension.
- `qoreChainInfo({ chainId?, rpc, rest })` — Keplr chain descriptor; `qoreEvmChainParams(...)` / `addQoreEvmToWallet(provider, opts)` — MetaMask (EIP-3085) EVM descriptor.

## License

Apache-2.0

## Unified wallet generation (all 3 addresses)

Every account is one 20-byte identity rendered as three encodings that share a
single on-chain balance. Generate an eth-native wallet and get all three at once,
plus the ML-DSA-87 (Dilithium-5) key for the PQC-hybrid Cosmos ante:

```js
import { generateQoreWallet, walletFromMnemonic } from "@qorechain/wallet-adapter";

const w = await generateQoreWallet();          // random 24-word mnemonic
// const w = await walletFromMnemonic(existing); // or recover
w.cosmos // qor1…            (bech32)
w.evm    // 0x… (EIP-55)     (hex — EVM-native, spendable via eth_sendRawTransaction)
w.svm    // <base58>         (base58 of the 20 bytes + 12 zero-byte pad)
w.privateKey // 0x… (32B)
w.pqc    // { publicKey, secretKey }  ML-DSA-87
```

The key is **eth-native** (address = `keccak256(pubkey)[12:]`), so it is spendable
on the EVM lane; `cosmos` and `svm` are just other encodings of the same 20 bytes,
under which the chain reads one `x/bank` balance. The account can sign EVM txs
(EIP-155) **and** PQC-hybrid Cosmos txs (the chain's Cosmos ante handles
`eth_secp256k1` and the hybrid decorator keys off the address).

`addressesFrom20(bytes20)` / `qoreAddresses({cosmos|evm|hex})` derive the three
encodings from a known account (for explorers / backends).

### Derive from a seed (Phantom & other non-mnemonic flows)

`walletFromSeed(seed32)` builds the same unified wallet from any 32 bytes (the
seed becomes the secp256k1 key). Because a wallet's signature over a fixed message
is deterministic, you can derive **one canonical QoreChain account from a Phantom
(ed25519) signature** — a Phantom user connects once and gets three usable
QoreChain addresses they fully control:

```js
import { walletFromSeed } from "@qorechain/wallet-adapter";
import { shake256 } from "@qorechain/pqc";

const msg = new TextEncoder().encode("QoreChain unified account derivation v1");
const { signature } = await window.solana.signMessage(msg); // Phantom, deterministic
const w = await walletFromSeed(shake256(signature, 32));     // → qor1 / 0x / svm + pqc
```

## eth-native Cosmos signing (requires chain ≥ v3.1.83)

The unified account **signs on the Cosmos lane too**, with the `eth_secp256k1`
scheme (secp256k1 over `keccak256(signBytes)`, pubkey
`/cosmos.evm.crypto.v1.ethsecp256k1.PubKey`). `signClassicalEth` builds a
classical-only tx (for the one-time, bootstrap-exempt PQC key registration);
`signHybridEth` adds the ML-DSA-87 hybrid signature the ante requires for
everything else. Both return broadcast-ready `TxRaw` bytes.

```js
import { walletFromMnemonic, signClassicalEth, signHybridEth } from "@qorechain/wallet-adapter";

const key = await walletFromMnemonic(mnemonic); // has { privateKey, pubkey, pqc }
const fee = { amount: [{ denom: "uqor", amount: "30000" }], gasLimit: 300000n };

// 1) one-time: register the account's ML-DSA-87 key (classical, PQC-exempt)
const regTx = await signClassicalEth({ key, chainId, accountNumber, sequence,
  messages: [{ typeUrl: "/qorechain.pqc.v1.MsgRegisterPQCKeyV2", value: registerMsgBytes }],
  fee: { amount: [{ denom: "uqor", amount: "600000" }], gasLimit: 6000000n } });

// 2) thereafter: hybrid eth_secp256k1 + ML-DSA-87 (e.g. a bank MsgSend)
const sendTx = await signHybridEth({ key, chainId, accountNumber, sequence,
  messages: [{ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: msgSendBytes }], fee });
```

> **Requires QoreChain ≥ v3.1.83** — that release registers the `eth_secp256k1`
> pubkey on the node's interface registry so eth-native Cosmos txs decode. Both
> `qorechain-diana` (testnet) and `qorechain-vladi` (mainnet) run it.
> `@qorechain/chain-bridge` wraps this server-side (`keyType: 'eth_secp256k1'`,
> auto-registers the PQC key on first send). **Proven live** on QoreChain: register
> (code 0) + hybrid send (code 0) + an EVM transfer from the same key, one balance.
