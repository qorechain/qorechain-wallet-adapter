# Changelog

## [0.6.0] - 2026-11-12

Support for chain v3.2.8 (the testnet `qorechain-diana` runs it from 12 November
2026).

### Added

- `authSignBytesV3`: the chain-bound SVM authorisation digest (domain
  `qorechain-svm-auth-v3`, chain id length-framed) that a network verifies once
  it enables the protocol feature `svm-relayed-chain-bound`.
- `resolveSvmAuthVersion({ rest })` reads the network's protocol features and
  returns `'v3'` or `'v2'`; it throws when the list cannot be read.

- Chain v3.2.8 key linking: `authenticatorLinkMessage`, `phantomPossessionProof`,
  `metaMaskPossessionProof`, `spendingRuleBoundsEveryDenom`,
  `updateSpendingRulesMsg` and `linkAuthenticatorMsgs` (the spending rule and the
  link in one transaction).
- `authenticatorExecutionResults` / `assertAuthenticatorExecutionsSucceeded`: read
  `success=false` from `MsgExecuteEVM` / `MsgExecuteCosmos` inside a code 0
  transaction (chain v3.2.8).
- `openEvmWindowMsg` takes the window scope: `nativeOnly`, `allowedTargets`, and
  from chain v3.2.8 `validators`, `stakingValidators`, `ibcReceivers`;
  `decodeEvmWindowMsg` returns them; `validateEvmWindowScope` checks them.

- The QoreX request check also refuses an authz `MsgGrant` whose
  `GenericAuthorization` names a message it refuses (directly and inside
  `MsgExec`), as QoreX does, and a `MsgGrant` it cannot decode.

### Changed (breaking)

- `registerAuthenticatorMsg` / `registerEthAuthenticatorMsg` require
  `possessionProof` (chain v3.2.8 refuses a link without it).
- `decodeEvmWindowMsg` returns the scope fields (empty lists and
  `nativeOnly: false` when absent).
- `buildPhantomSvmEnvelope` / `buildPhantomTransfer` now choose the form to
  sign: pass `rest` and `chainId`, or `svmAuthVersion: 'v2' | 'v3'`. Without
  either they throw instead of signing a form the network may refuse.

## [0.5.0] - 2026-11-10

### Changed (breaking)

- `walletFromSeed(seed, opts)` now needs a second, independent secret for the
  account's PQC key: `{ recoveryCode }` (a QRC1 recovery code) or
  `{ pqcSecret }` (32 random bytes). `{ legacySeedDerivation: true }` keeps the
  previous derivation, only to recover the PQC key of an account created before
  0.5.0 so you can rotate it (`MsgRotatePQCKey`) to a key from a recovery code;
  never use it for new accounts. A PQC secret equal to the seed is refused.
  Mnemonic wallets are unchanged.
- `validateQorexRequest` / `qorexSignAndBroadcast` refuse, directly and inside
  authz `MsgExec`, the same messages QoreX keeps to its own screens:
  `MsgRegisterKEMKey`, `MsgRemoveKEMKey`, `MsgRegisterPQCMultisig`,
  `MsgRegisterAuthenticator`, `MsgRevokeAuthenticator`, `MsgUpdateSpendingRules`,
  `MsgCreateAbstractAccount`, `MsgOpenEVMWindow`, `MsgCloseEVMWindow`,
  `MsgAuthorizeEVMDelegation` and `MsgClearEVMDelegation`.

### Added

- `pqcKeyFromSecret` and `pqcRecoveryCodeFromSecret`.

Security details will be published separately.

### Migrating from 0.4

```js
// before
const w = await walletFromSeed(seed);
// after: keep a recovery code next to the seed
const recoveryCode = await generatePqcRecoveryCode();
const w = await walletFromSeed(seed, { recoveryCode });
```

## [0.4.0] — 2026-10-20

Client support for chain v3.2.3 (applied on mainnet at height 3,662,051).

### Added

- `evmAuthSignBytesV2`: the `MsgExecuteEVM` digest from chain v3.2.3, which also
  binds the call's gas limit (must be non-zero). `resolveEvmAuthDigestVersion`
  returns the form the network verifies (`v2` once it has applied v3.2.3), and
  `buildPhantomExecuteEvm` / `buildMetaMaskExecuteEvm` take
  `digestVersion: 'v1' | 'v2'` (default `'v1'`).

### Changed

- `qorexSignAndBroadcast` / `validateQorexRequest` now accept authz `MsgExec`,
  as QoreX does. The adapter decodes it and still refuses PQC key-management
  messages inside it at any depth; a `MsgExec` that cannot be decoded is
  refused.

### Changed

- Depends on `@qorechain/pqc ^0.2.1`. The `^0.1.1` range never resolved 0.2.x.

### Deprecated

- The legacy `shake256(mnemonic)` PQC derivation for new keys:
  `rotatePqcKeyMsgFromMnemonic` refuses it as the new key, as the chain CLI does.
  Rotating away from an existing legacy key still works.

### Fixed

- Documentation of the `MsgExecuteEVM` nonce, in the code and the README: it is
  the linked key's authenticator sequence, not the account's EVM nonce.

## [0.3.0]

### Removed

- **`derivePqcKeyFromWallet` is withdrawn and now throws.** A dApp should not hold
  the account's ML-DSA key: send messages through QoreX (`qorexSignAndBroadcast`).
  Accounts that registered a key with it should rotate it with
  `rotateFromLegacyWalletKey`. Security details will be published separately.

### Added

- **PQC recovery codes** — `generatePqcRecoveryCode`, `pqcKeyFromRecoveryCode`,
  `isValidRecoveryCode`, `normalizeRecoveryCode`. A random 256-bit secret held by
  the user, formatted `QRC1-` + Crockford base32 with a 24-bit checksum and bound
  to the account address.
- **`rotateFromLegacyWalletKey`** — builds a `MsgRotatePQCKey` to move an account
  off a key registered with the withdrawn function. It never returns the old key.
- **QoreX** — `qorexSignAndBroadcast` and helpers: a dApp sends QoreChain
  messages and QoreX builds, signs and broadcasts them, with bounds checked
  locally.
- **EVM authorisation window** (chain v3.2.0) — `openEvmWindowMsg`,
  `closeEvmWindowMsg`, `fetchEvmWindow`, `isEvmWindowRejection`.
- **`toExactBytes`** — decodes bytes, a byte array, hex or base64 to an exact
  length, or throws.

### Fixed

- Public keys and signatures are now normalised strictly before encoding:
  `QoreChainSigner` and `rotatePqcKeyMsg` refuse anything that is not the exact
  size instead of coercing it.
- Hybrid sign-bytes: both v2 upgrade plan names are recognised, per network.

### Upgrading

`derivePqcKeyFromWallet` throws. Move signing to QoreX, and rotate any key it
registered.
