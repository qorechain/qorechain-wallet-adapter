# Changelog

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
