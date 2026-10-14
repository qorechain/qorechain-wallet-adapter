# Changelog

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
