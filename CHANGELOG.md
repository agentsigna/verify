# Changelog

All notable changes to `@agentsigna/verify`. This project follows [Semantic Versioning](https://semver.org/).

## 1.2.0 (2026-10-15)

Implements the AgentSigna Passport Specification v1.1. The passport format (`agentsigna-passport/1.0`) is unchanged.

### Security

- **Fail-closed authorization result.** `verifyPassport` now returns `mayProceed`, and `valid` is an alias of it. Both are `false` for a correctly signed passport whose decision is `DENY`, `REQUIRE_APPROVAL` or any value other than `ALLOW` and `ALLOW_WITH_CONDITIONS`, and for a passport with an unknown `spec` identifier or an unsupported format major version (anything other than `1.x`). In 1.1.1 such passports were reported as `valid: true` when their signature verified, so a caller gating execution on `valid` could act on a passport that never authorized execution. This changes behaviour only for passports that never authorized execution: AgentSigna issues passports only for `ALLOW` and `ALLOW_WITH_CONDITIONS` decisions in format 1.0, and every such passport that 1.1.1 accepted is still accepted (see Compatibility).
- **JWKS fetch hardened against SSRF.** 1.1.x checked the hostname with one DNS lookup and then let `fetch` resolve it again, so a DNS answer that changed between the two (DNS rebinding) could reach an internal address; its IPv6 check also covered only `fe80:` and not the rest of `fe80::/10` (for example `fe90::1`). The fetcher now resolves once, requires every resolved address to be public, and pins the connection to that address. The blocked ranges cover the complete IPv4 and IPv6 special-use space, including all of `fe80::/10`, `fc00::/7`, IPv4-mapped, IPv4-compatible and IPv4-translated IPv6, NAT64, 6to4, Teredo, multicast, unspecified, documentation ranges, `169.254.0.0/16` (cloud metadata), CGNAT `100.64.0.0/10` and `0.0.0.0/8`; IPv6 is limited to global unicast. Responses are limited to 64 KB, redirects are refused, and the whole request including DNS has a 10 second deadline. No new runtime dependency; Node.js 18 or newer as before.
- **Malformed or ambiguous key sets are rejected.** Fetched key sets and key sets passed to `selectJwkForSignature` must have a unique, non-empty `kid` on every key and no private or symmetric key material. The key selected by `kid` must be an Ed25519 signing key (`kty` `OKP`, `crv` `Ed25519`, 32-byte `x`, and `use` `sig`, `alg` `EdDSA` or `Ed25519` and `key_ops` with `verify` when present). `verifyPassport` applies the same key checks to a JWK passed to it.

### Added

- Structured result fields on `verifyPassport`: `signatureValid`, `claimsValid`, `decisionAuthorizes`, `notExpired`, `actionMatches`, `audienceMatches`, `environmentMatches` and `mayProceed`. The match fields are `true` when the expectation was supplied and matched, `false` on a mismatch and `null` when not checked.
- Options `expectedActionType`, `expectedAudience` and `expectedEnvironment`. Format 1.0 has no audience or environment claim, so those two expectations cannot be confirmed with a 1.0 passport and make `mayProceed` false.
- `assertValidJwks(jwks)` and `JWKS_MAX_BYTES`.
- `fetchJwkForPassport(jwksUrl, passport)`: fetches a JWKS and returns the key whose `kid` matches the passport signature.
- `selectJwkForSignature(jwks, passportOrSignature)`: selects the matching key from a JWKS you already hold, without network access. Throws when no usable Ed25519 key with that `kid` exists; it never falls back to another key.
- `fetchJwks(jwksUrl)`: the protected JWKS fetch on its own.
- `parseSignature(signature)` and the `ParsedSignature` type.
- Tests against passports produced by the AgentSigna issuing code path with test keys, including a key rotation (old and new passports verifying against a two-key JWKS) and a regression suite that compares every result with 1.1.1; tests for every special-use range, alternative IPv4 notations, DNS rebinding, redirects, oversized responses, timeouts and duplicate kids; the test suite also runs on Node.js 18.

### Changed

- `verifyPassport` now checks the key id. When the key you pass is a JWK with a `kid`, that `kid` must equal the one in the signature (`ed25519:<kid>:<signature>`); otherwise the passport is rejected with `Key id mismatch: ...` and the key is not tried. Keys without a key id (PEM strings, `KeyObject`s, JWKs without `kid`) are verified as before.
- Unknown `spec` identifiers and unsupported format versions are errors instead of warnings. An unknown minor version of format 1 (for example `1.1`) remains a warning.
- The issuer mismatch error and the missing `expectedIssuer` warning have clearer wording.
- JWKS requests are made with Node.js `https` instead of the global `fetch`.
- README: execution must be gated on `result.mayProceed`; the result fields and the exact JWKS fetch protections are documented; the issuer in examples is `agentsigna` (the value AgentSigna passports carry); key rotation and key selection by `kid` are documented, and an error reference was added. `fetchPublicKeyFromJwks` without a `keyId` is documented as returning the first key, which is not the right key after a rotation.

### Deprecated

- **Direct keys without a `kid`.** A PEM string, a `KeyObject` or a JWK without a `kid` passed directly to `verifyPassport` remains accepted in 1.x for compatibility (no key id check is possible). Kidless direct keys are deprecated and will be rejected for passport format 2.0. Fetched JWKS entries always require a `kid` (see Security), and key selection from a JWKS with `fetchJwkForPassport` or `selectJwkForSignature` is strictly bound to the signature's `kid`. No behaviour changes in 1.2.0.

### Compatibility

Every legitimately valid `ALLOW` or `ALLOW_WITH_CONDITIONS` passport that 1.1.1 accepted is still accepted, with `valid: true` and `mayProceed: true`, and every error 1.1.1 reported for the recorded variants is unchanged. The intended differences are:

- A correctly signed passport with decision `DENY`, `REQUIRE_APPROVAL` or another non-authorizing value is now `valid: false` (1.1.1: `valid: true`).
- A passport with an unknown `spec` identifier or a format major version other than 1 is now `valid: false` (1.1.1: `valid: true` with a warning).
- A call that passes a JWK whose `kid` differs from the signature's `kid` is rejected. Such a call only succeeded in 1.1.1 when the same key material was published under a different key id.
- A JWK whose `use`, `alg` or key type does not fit EdDSA, a key set with duplicate or missing `kid`s, and JWKS responses over 64 KB are rejected.

## 1.1.1 (2026-05-11)

- Ledger chain verification rejects `eventDigest` and `previousDigest` values that are not 64-character lowercase hex.
- Wording cleanup.

## 1.1.0 (2026-05-11)

- `fetchPublicKeyFromJwks` rejects private and loopback hosts, both as literals and after DNS resolution.
- Correct ESM entry point (`dist/esm/package.json`), README and LICENSE in the package, compiled tests excluded from the package.
- Publishing from CI with npm provenance.

## 1.0.0 (2026-05-10)

- Initial release: `verifyPassport`, `verifyChain`, `fetchPublicKeyFromJwks`, `JtiCache`.
