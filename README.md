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
v    = resolveSignBytesVersion({ chainId, rest })          // 'v1' | 'v2', per network
sigP = ML-DSA-87.sign( hybridSignBytes(v, chainId, B0, authInfoBytes) )  // adapter does this
body = TxBody{ ...B0, extensionOptions:[ PQCHybridSignature{1, sigP} ] }
sigC = wallet.signDirect( SignDoc{ body, authInfo, chainId, accountNumber } )
tx   = TxRaw{ body, authInfo, [sigC] }
```

The extension type URL is `/qorechain.pqc.v1.PQCHybridSignature` and algorithm
`1` = ML-DSA-87. The sign-bytes form `v` is chosen per network — see below.

## Hybrid sign-bytes: v1 and v2 (chain v3.2.0, testnet v3.1.98)

The ML-DSA key signs one of two byte forms (B0 = body without the PQC extension,
A = AuthInfo bytes):

```
v1 (legacy): BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
v2:          "qorechain-pqc-hybrid-v2" ‖ BE64(len chainId) ‖ chainId ‖ BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
```

v2 adds a domain tag (a signature the key made in any other context can never be
valid transaction sign-bytes) and binds the chain-id. **A network accepts exactly
one form at any height.** The networks that existed before v2
(`qorechain-vladi` mainnet, `qorechain-diana` testnet) verify v1 until the
upgrade plan that carries the switch is applied on them and v2 from then on; they
upgrade at different heights. Today the testnet verifies v2 and **mainnet stays
on v1 until its own upgrade**. Any other chain verifies v2 from its first block.

**The switch ships under two plan names.** The release is `v3.2.0`, but the
testnet already took the same handler under the earlier name `v3.1.98` and keeps
that record forever, so the chain registers both (`SIGN_BYTES_V2_UPGRADES =
['v3.2.0', 'v3.1.98']`). A client must ask for **every** name and sign v2 if the
numeric height of **any** of them is > 0. Asking for one name only resolves v1 on
a network that upgraded under the other, and every hybrid transaction is then
refused with `pqc` code 21.

`signBytesVersion` (on `QoreChainSigner`, per `signHybrid` call, and on
`signHybridEth`) takes:

- `'auto'` (default) — a non-legacy chain signs v2 with no network call. On
  `qorechain-vladi` / `qorechain-diana` the adapter asks the network
  `GET {rest}/cosmos/upgrade/v1beta1/applied_plan/{name}` for every name in
  `SIGN_BYTES_V2_UPGRADES` (`v3.2.0`, then `v3.1.98`) and signs v2 iff the
  returned height of any of them is > 0 (compared numerically: a network that has
  not taken a plan answers `{"height":"0"}` or `{}`). The names are asked in
  order and the first positive height wins, so a network on the current release
  costs one request and one that upgraded under the earlier name costs two.
  The answer is cached per (rest, chain-id) for 60 s. **Pass `rest` (the LCD URL)**;
  without it, or if a query fails, signing throws instead of guessing.
- `'v1'` / `'v2'` — used as given, no network call.

**Upgrading to 0.2.1.** 0.2.0 asked for `v3.1.98` alone, which resolves v1 on a
mainnet that upgraded as `v3.2.0` and gets every hybrid transaction refused with
`pqc` code 21. Upgrade before the mainnet upgrade height; nothing else in the
resolver changed and no call site needs touching.

**Upgrading to 0.2.0.** `rest` is optional in the TypeScript types, so a caller that forgets it compiles cleanly and only fails at runtime on `qorechain-vladi` / `qorechain-diana`. Cover your wiring with a runtime test, not just a type check. In unit tests, pass `signBytesVersion: "v1"` or `"v2"` explicitly (or inject `fetch`): `"auto"` asks the network, so a test that omits it silently depends on a live node.

Signed results are the usual `TxRaw` `Uint8Array`, with `.signBytesVersion`
(`'v1' | 'v2'`) set to the form actually used.

### Retry once on a sign-bytes refusal (caller side)

The adapter only signs; you broadcast. A network can upgrade while a wallet is
open, so when the version was `'auto'`, handle a refusal with `pqc` code 21
("hybrid PQC signature verification failed") by re-resolving once:

```js
import { QoreChainSigner, isHybridSignBytesRejection } from '@qorechain/wallet-adapter';

const signer = new QoreChainSigner({ wallet, chainId, address, pubkeySecp256k1,
  accountNumber, pqc, rest: lcdUrl /* signBytesVersion: 'auto' is the default */ });

let txBytes = await signer.signHybrid({ messages, fee, sequence });
try {
  await client.broadcastTx(txBytes);            // cosmjs throws BroadcastTxError / returns {code, rawLog}
} catch (err) {
  if (!isHybridSignBytesRejection(err)) throw err;   // only codespace "pqc" code 21
  await signer.refreshSignBytesVersion();            // bypasses the cache
  txBytes = await signer.signHybrid({ messages, fee, sequence });
  await client.broadcastTx(txBytes);            // broadcast ONCE more; surface any error
}
```

If you check a returned result instead of catching, pass it to
`isHybridSignBytesRejection(result)` the same way (`{ code, rawLog }` works).
Do not retry when you passed an explicit `'v1'`/`'v2'`, and do not treat code 21
from another codespace as this case.

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
  rest, // LCD URL: lets the adapter pick the sign-bytes form this network verifies
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
| **Phantom** | register the Phantom key as an authenticator on a QoreChain account | ✅ authorises spending under a permission set + SpendingRule, and is revocable. The old signature-derived recipe is withdrawn — see "Derive from a seed" |

## API

Wallet generation & unified addresses:
- `generateQoreWallet(strength?)` / `walletFromMnemonic(mnemonic)` / `walletFromSeed(seed32)` — a unified wallet `{ mnemonic, privateKey, pubkey, cosmos, evm, svm, pqc }`.
- `addressesFrom20(bytes20)` / `qoreAddresses({cosmos|evm|hex})` — the three encodings of a known account.

eth-native Cosmos signing (chain ≥ v3.1.83):
- `signClassicalEth({ key, chainId, accountNumber, sequence, messages, fee, memo?, timeoutHeight? })` → `TxRaw` bytes (classical, e.g. PQC key registration).
- `signHybridEth({ ..., signBytesVersion?, rest? })` → `TxRaw` bytes (eth_secp256k1 + ML-DSA-87 hybrid); throws on a legacy network with neither an explicit version nor `rest`.
- `ETHSECP256K1_PUBKEY_TYPE` — the eth pubkey type URL.

Keplr / any-signDirect adapter + PQC framing:
- `new QoreChainSigner({ wallet, chainId, address, pubkeySecp256k1, accountNumber, pqc, rest?, signBytesVersion? = 'auto', fetch? })`.
- `QoreChainSigner#signHybrid({ messages, fee, sequence, memo?, timeoutHeight?, signBytesVersion? })` → `TxRaw` bytes with `.signBytesVersion`.
- `QoreChainSigner#refreshSignBytesVersion()` → re-resolves, bypassing the cache.
- `derivePqcKeyFromWallet(wallet, chainId, address)` — deterministic ML-DSA-87 key from a wallet signature.
- `hybridSignBytesV1(b0, auth)`, `hybridSignBytesV2(chainId, b0, auth)`, `hybridSignBytes(version, chainId, b0, auth)` — the two sign-bytes forms and a dispatcher (version required; the old implicit `frame()` is removed).
- `signBytesVersionFor(chainId, v2AppliedHeight)`, `resolveSignBytesVersion({ chainId, rest?, signBytesVersion?, fetch?, ttlMs?, forceRefresh? })`, `clearSignBytesCache()`, `isHybridSignBytesRejection(errOrResult)`.
- Constants `HYBRID_SIGN_BYTES_V2_DOMAIN`, `SIGN_BYTES_V2_UPGRADES` (`["v3.2.0", "v3.1.98"]` — every plan name that switches a network to v2), `SIGN_BYTES_V2_UPGRADE` (`"v3.2.0"`, the primary name = `SIGN_BYTES_V2_UPGRADES[0]`), `LEGACY_SIGN_BYTES_CHAINS`.
- `encodePqcHybridSignature(algId, sig)` — proto encoder for the extension.
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

### Derive from a seed (non-mnemonic flows)

`walletFromSeed(seed32)` builds the same unified wallet from any 32 bytes. **The
seed becomes the secp256k1 private key**, so it must come from something secret
and stay secret: a CSPRNG, or a KDF over material only the user holds.

> **Do not derive the seed from a wallet signature.** Versions of this README up
> to 0.1.7 showed a Phantom "connect → three addresses" recipe built on
> `shake256(signature)` over a fixed message. That recipe is unsound and has
> been withdrawn. Signature schemes like ed25519 are deterministic (RFC 8032)
> and the message was public, so the signature is a *constant* that any website
> can ask the same wallet to reproduce — and whoever obtains it reconstructs the
> account's entire key material, classical and ML-DSA-87, with nothing to
> revoke. Changing the message does not fix it: any message an attacker can also
> request yields the same key.
>
> If you followed that recipe, treat every account derived from it as
> compromised and move the funds.

To let an external wallet (Phantom, MetaMask, …) authorise spending on a
QoreChain account, register its key as an **authenticator** instead:
`MsgRegisterAuthenticator`, with an explicit permission set and a `SpendingRule`.
The external key then signs authorisations for an account it never owned, and it
can be revoked. See the authenticator execution lanes (`MsgExecuteEVM` /
`MsgExecuteCosmos`, chain ≥ v3.1.85).

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
  messages: [{ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: msgSendBytes }], fee,
  rest: lcdUrl /* picks v1/v2 for this network; or signBytesVersion: 'v1' | 'v2' */ });
```

> **Requires QoreChain ≥ v3.1.83** — that release registers the `eth_secp256k1`
> pubkey on the node's interface registry so eth-native Cosmos txs decode. Both
> `qorechain-diana` (testnet) and `qorechain-vladi` (mainnet) run it.
> `@qorechain/chain-bridge` wraps this server-side (`keyType: 'eth_secp256k1'`,
> auto-registers the PQC key on first send). **Proven live** on QoreChain: register
> (code 0) + hybrid send (code 0) + an EVM transfer from the same key, one balance.

## Authenticator lanes + key rotation (v3.1.85)

Let a linked external key (Phantom ed25519 / a secp256k1 key) **spend from the
one unified PQC-required account** under least-privilege, spend-limited terms —
via a relayer, with no ML-DSA co-signature from the external key. Owner links the
key once (`registerAuthenticatorMsg`, hybrid-signed); thereafter the external key
authorizes actions on three lanes:

- **SVM** — `buildPhantomSvmEnvelope` / `buildPhantomTransfer` (post to `sendTransaction`).
- **EVM** — `buildPhantomExecuteEvm` → `MsgExecuteEVM` (relayer broadcasts).
- **Native** — `buildPhantomExecuteCosmos` → `MsgExecuteCosmos` (relayer broadcasts).

```js
import { buildPhantomExecuteEvm, buildPhantomExecuteCosmos } from "@qorechain/wallet-adapter";

// nonce = the account's CURRENT EVM nonce (eth_getTransactionCount(account0x)).
// The relayer is a DIFFERENT account than the owner, so it does NOT pre-increment it.
const evmMsg = await buildPhantomExecuteEvm({
  wallet: phantom, relayer: relayerAddr, chainId, account: qor1,
  to: "0x…", value: "100000000000000000" /* wei */, nonce });

const sendMsg = await buildPhantomExecuteCosmos({
  wallet: phantom, relayer: relayerAddr, chainId, account: qor1,
  to: "qor1…", amount: "250uqor", nonce: authSeq /* per-authenticator sequence */ });
// → hand each msg to your relayer; it broadcasts with its own hybrid-PQC signature.
```

Errors (codespace `abstractaccount`): `5` spending-limit, `6` session-key expired
(render "re-link"), `10` permission-denied, `11` replay. Fetch the live scope
taxonomy over REST: `GET /qorechain/abstractaccount/v1/permission_schema`.

**Key rotation** (`MsgRotatePQCKey`) — migrate a legacy chain-bridge key
(`shake256(mnemonic)`) to the canonical address-bound key of the SAME algorithm:

```js
import { rotatePqcKeyMsgFromMnemonic } from "@qorechain/wallet-adapter";
const { msg, oldKeypair } = rotatePqcKeyMsgFromMnemonic({ account: qor1, mnemonic, chainId });
// broadcast `msg` from the account, cosigned (hybrid) with `oldKeypair` (still the
// registered key until the rotation lands) — e.g. a QoreChainSigner whose pqc=oldKeypair.
```

For a **MetaMask / EVM** key use `registerEthAuthenticatorMsg` (link by 0x address) + `buildMetaMaskExecuteEvm` / `buildMetaMaskExecuteCosmos` — the key signs the digest with `personal_sign` (EIP-191) and the chain verifies by ecrecover, so no raw pubkey is needed. Live-proven: a MetaMask-signed EVM transfer from the unified account committed on QoreChain.

> **Requires QoreChain ≥ v3.1.85.** Auth sign-bytes (`evmAuthSignBytes`,
> `cosmosAuthSignBytes`) are rebuilt byte-for-byte from the chain and guarded by
> tests. For a **secp256k1** authenticator the chain uses cosmos `VerifySignature`
> (sha256-based), NOT MetaMask `personal_sign` — sign the digest with a
> cosmos-style secp256k1 signer, not `personal_sign`.
