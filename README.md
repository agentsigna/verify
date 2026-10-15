# @agentsigna/verify

Standalone offline verifier for AgentSigna Action Authorization Passports and ledger chains.

It has zero runtime dependencies and uses Node.js built-in crypto APIs only. It is designed for auditors, counterparties, and internal control systems that need to verify signed authorization evidence without calling the AgentSigna API.

It implements the [AgentSigna Passport Specification](https://github.com/agentsigna/spec) v1.1 (passport format `agentsigna-passport/1.0`).

## Install

```bash
npm install @agentsigna/verify
```

Requires Node.js 18 or newer.

## Usage

CommonJS:

```js
const { verifyPassport, verifyChain, fetchJwkForPassport, JtiCache } = require('@agentsigna/verify');
```

ES modules:

```js
import { verifyPassport, verifyChain, fetchJwkForPassport, JtiCache } from '@agentsigna/verify';
```

### Verify a passport

AgentSigna publishes its passport verification keys at:

```text
https://api.agentsigna.com/.well-known/agentsigna-jwks.json
```

A passport signature reads `ed25519:<kid>:<signature>`. Select the key whose `kid` matches the signature, then verify:

```js
const JWKS_URL = 'https://api.agentsigna.com/.well-known/agentsigna-jwks.json';

const key = await fetchJwkForPassport(JWKS_URL, passport);
const result = verifyPassport(passport, key, {
  expectedIssuer: 'agentsigna',
  actionPayload: originalActionPayload,
});

if (!result.mayProceed) {
  throw new Error(result.errors.join('; '));
}
// Only now execute the action.
```

Gate execution on `result.mayProceed` and nothing else. A valid signature on its own does not authorize anything: a correctly signed passport can still say `DENY`, be expired, name another issuer, or belong to another action. AgentSigna-issued passports always carry the issuer `agentsigna`.

### Verification result

`verifyPassport` returns these fields next to `errors`, `warnings` and a `passport` summary:

| Field | Meaning |
|---|---|
| `signatureValid` | The Ed25519 signature verifies over the canonical payload with the key whose `kid` matches. |
| `claimsValid` | The payload is a supported passport: spec identifier `agentsigna-passport`, format major version 1, issuer equal to `expectedIssuer` when given, and the copy's `status` is not `REVOKED`. |
| `decisionAuthorizes` | The signed decision is `ALLOW` or `ALLOW_WITH_CONDITIONS`. `DENY` and `REQUIRE_APPROVAL` never authorize. |
| `notExpired` | The signed `expiresAt` is a valid date that has not passed. |
| `actionMatches` | `true` when you passed `actionPayload` and/or `expectedActionType` and they matched, `false` on a mismatch, `null` when you passed neither. |
| `audienceMatches` | `true` or `false` for `expectedAudience`, `null` when not passed. Format 1.0 has no audience claim, so passing it with a 1.0 passport gives `false`. |
| `environmentMatches` | The same for `expectedEnvironment`. |
| `mayProceed` | `true` only when the signature, claims, decision and expiry checks pass and every expectation you supplied matched. |
| `valid` | The same value as `mayProceed`, kept for 1.x callers. |

Unknown spec identifiers and unsupported format major versions (anything other than `1.x`, for example `agentsigna-passport/2.0`) fail closed: they are errors and `mayProceed` is `false`.

### Key rotation

The key set can hold several keys: the current signing key and retired keys that still verify older passports. Never take the first key in the set. Select by `kid`:

- `fetchJwkForPassport(jwksUrl, passport)` fetches the set and returns the key whose `kid` matches the signature.
- `selectJwkForSignature(jwks, passport)` does the same with a key set you already hold (a cached or pinned copy).

Both throw when no Ed25519 key with that `kid` exists; neither falls back to another key. If you cache the key set and meet an unknown `kid`, fetch the set again once before rejecting the passport.

When you pass a JWK that has a `kid` to `verifyPassport`, the `kid` must equal the one in the signature, or the passport is rejected with a `Key id mismatch` error. PEM strings, KeyObjects and JWKs without a `kid` carry no key id, so with those you are responsible for choosing the right key.

#### Key ids: what is required and what is deprecated

- **Fetched key sets always require a `kid`.** Every key in a JWKS fetched by `fetchJwkForPassport` or `fetchJwks`, or passed to `selectJwkForSignature`, must have a unique, non-empty `kid`; a key set with a missing or duplicate `kid` is rejected.
- **Key selection from a key set is strictly bound to the signature's `kid`.** `fetchJwkForPassport` and `selectJwkForSignature` return only the key whose `kid` equals the `kid` in the passport signature, and never fall back to another key. (The older `fetchPublicKeyFromJwks(jwksUrl)` without a `keyId` returns the first usable key; pass the signature's `kid`, or use `fetchJwkForPassport`.)
- **Direct keys without a `kid` are still accepted, for compatibility.** A PEM string, a `KeyObject` or a JWK without a `kid` passed straight to `verifyPassport` is verified as in 1.1.x, with no key id check.
- **Kidless direct keys are deprecated.** Passport format 2.0 will reject them: a verifier for 2.0 passports will need a key that carries the signature's `kid`. Prefer `fetchJwkForPassport` or `selectJwkForSignature` now.

This release changes no behaviour here; it documents the rules that 1.2.0 already applies.

```js
// Cached or pinned key set
const jwks = JSON.parse(fs.readFileSync('agentsigna-jwks.json', 'utf8'));
const key = selectJwkForSignature(jwks, passport);
const result = verifyPassport(passport, key, { expectedIssuer: 'agentsigna' });
```

### Verify a ledger chain

```js
const result = verifyChain(ledgerEvents);

if (!result.valid) {
  throw new Error(result.errors.join('; '));
}
```

### Detect replayed passports

```js
const cache = new JtiCache();

if (result.mayProceed && cache.seen(result.passport.jti, result.passport.expiresAt)) {
  throw new Error('Replayed passport');
}
```

For distributed systems, replace `JtiCache` with a shared store such as Redis using the passport expiry as the TTL.

## API

| Function | Purpose |
|---|---|
| `verifyPassport(passport, publicKey, options)` | Verifies one passport and decides whether it authorizes the action. `publicKey` is a JWK, a PEM string or a Node.js `KeyObject`. Options: `expectedIssuer`, `actionPayload`, `expectedActionType`, `expectedAudience`, `expectedEnvironment`, `nowMs`. Returns the fields of [Verification result](#verification-result) plus `errors`, `warnings` and `passport`. |
| `verifyChain(events)` | Verifies the ledger events of one action case. Returns `{ valid, errors, checkedEvents, chainVersion, genesisDigest, tipDigest }`. |
| `fetchJwkForPassport(jwksUrl, passport)` | Fetches a key set and returns the JWK whose `kid` matches the passport signature. |
| `selectJwkForSignature(jwks, passportOrSignature)` | Selects the matching JWK from a key set you already hold. No network. |
| `fetchJwks(jwksUrl)` | Fetches a key set with the protections below. |
| `assertValidJwks(jwks)` | Throws unless a key set is well formed and unambiguous (see below). Use it on cached or pinned copies. |
| `fetchPublicKeyFromJwks(jwksUrl, keyId?)` | Fetches a key set and returns one key as a `KeyObject`. Without `keyId` it returns the first Ed25519 key, which is wrong after a rotation; prefer `fetchJwkForPassport`. |
| `parseSignature(signature)` | Splits `alg:kid:signature`, or returns `null`. |
| `JtiCache` | In-memory replay detection by `jti` with expiry-based eviction. |

## Security Model

`verifyPassport` checks:

- structural validity of the passport envelope
- the spec identifier (`agentsigna-passport`) and the format major version (1); anything else fails closed
- issuer match when `expectedIssuer` is supplied
- the decision: only `ALLOW` and `ALLOW_WITH_CONDITIONS` authorize; `DENY`, `REQUIRE_APPROVAL` and any other value make `mayProceed` false
- passport revocation status as given in the passport object
- passport expiry (the signed `expiresAt`)
- that a JWK with a `kid` matches the signature's `kid`, and that a JWK is an Ed25519 signing key (`kty` `OKP`, `crv` `Ed25519`, and `use` `sig` and `alg` `EdDSA` when present)
- Ed25519 signature validity over the canonical payload
- optional expectations: action payload hash binding, action type, audience and environment

`verifyChain` checks:

- all events belong to a single action case
- chain reconstruction from `previousDigest`
- SHA-256 digest validity for every event
- broken chains and cycles
- legacy v0 and current v1 digest formats

Always pass `expectedIssuer` in production.

The `status` field of the passport object is not covered by the signature. An offline check can only report the status in the copy you hold; it cannot learn of a revocation made after you received the passport. For high-stakes actions, read the passport's current status from the AgentSigna API before relying on it.

Only `ed25519:` signatures can be verified. Any other signature format is rejected.

## Error messages

| Error starts with | Meaning |
|---|---|
| `Key id mismatch` | The JWK given has a different `kid` from the signature. Select the key by `kid`. |
| `Signature verification failed` | The payload does not match the signature for this key: it was changed, or the key is wrong, or the signature is not an Ed25519 passport signature. |
| `Issuer mismatch` | The payload's `issuer` is not `expectedIssuer`. |
| `Passport decision "..." does not authorize the action` | The signed decision is not `ALLOW` or `ALLOW_WITH_CONDITIONS`. |
| `Unknown spec identifier` | The payload is not an `agentsigna-passport`. |
| `Unsupported passport format version`, `... is not a valid format version` | The format is not version 1.x, for example a 2.0 passport. Use a verifier that implements that format. |
| `Action type mismatch` | `expectedActionType` differs from the signed `actionType`. |
| `An expected audience was supplied`, `An expected environment was supplied` | Format 1.x has no such claim, so the expectation cannot be confirmed. |
| `Passport has been revoked` | The passport object says `REVOKED`. |
| `Passport expired at` | The signed `expiresAt` is in the past. |
| `actionHash mismatch` | The action payload you passed is not the one the passport authorized. |
| `actionPayload was provided ... but the passport has no actionHash` | The passport does not commit to an action payload, so the binding cannot be confirmed. |
| `Failed to load public key` | The key could not be parsed as an Ed25519 public key, or the JWK is not an Ed25519 signing key. |

## JWKS Fetching

`fetchJwks`, `fetchJwkForPassport` and `fetchPublicKeyFromJwks` are convenience helpers for trusted JWKS endpoints. They enforce exactly this:

- HTTPS only; URLs with a user name or password are refused.
- `localhost` and `*.localhost` are refused. IP literals are checked directly; decimal, hexadecimal, octal and shortened IPv4 forms (`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`) are normalized by the URL parser first, so they are checked as the address they denote.
- A hostname is resolved once. Every address it resolves to must be public, otherwise the request is refused. The connection is then pinned to the first of those addresses, so a different DNS answer at connection time (DNS rebinding) cannot change the target.
- Refused IPv4 ranges: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (CGNAT), `127.0.0.0/8`, `169.254.0.0/16` (link-local, including the cloud metadata address `169.254.169.254`), `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `192.175.48.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4` (multicast) and `240.0.0.0/4` (reserved and broadcast).
- IPv6: only global unicast `2000::/3` is contacted. That excludes the unspecified address `::`, loopback `::1`, IPv4-compatible `::/96`, IPv4-mapped `::ffff:0:0/96` and IPv4-translated `::ffff:0:0:0/96` addresses, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, discard-only `100::/64`, unique local `fc00::/7`, link-local `fe80::/10` (all of it, `fe80::` to `febf::`), site-local `fec0::/10` and multicast `ff00::/8`. Inside `2000::/3`, these are refused as well: `2001::/23` (including Teredo `2001::/32`), `2001:db8::/32` and `3fff::/20` (documentation), `2002::/16` (6to4) and `5f00::/16`.
- Redirects are refused, not followed. Non-2xx responses are errors.
- The response body is limited to 64 KB (`JWKS_MAX_BYTES`), and the whole request, including DNS resolution, times out after 10 seconds.
- The key set must be well formed and unambiguous (`assertValidJwks`): a non-empty `keys` array of at most 100 objects, each with a `kty` and a non-empty `kid` without `:`, no private or symmetric key material, and no two keys with the same `kid`.
- The key selected by `kid` must be an Ed25519 signing key: `kty` `OKP`, `crv` `Ed25519`, a 32-byte `x`, and, when present, `use` `sig`, `alg` `EdDSA` (or `Ed25519`) and `key_ops` including `verify`.
- Fetched content is never executed.

Do not pass user-controlled JWKS URLs, and do not fetch keys from the `publicKeyRef` field inside a passport. If users can choose trust anchors, store allowlisted issuer metadata server-side and fetch keys from those configured issuers only.

## Release Checklist

Before publishing:

```bash
npm run pack:check
npm publish --provenance --access public
```

Package maintainers should enforce npm account 2FA and publish from CI with trusted publishing or provenance enabled. The release gate should fail if the packed tarball omits `README.md` or `LICENSE`, omits the ESM package marker, or includes compiled test files.

## License

MIT
