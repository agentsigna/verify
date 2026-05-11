# @agentsigna/verify

Standalone offline verifier for AgentSigna Action Authorization Passports and ledger chains.

It has zero runtime dependencies and uses Node.js built-in crypto APIs only. It is designed for auditors, counterparties, and internal control systems that need to verify signed authorization evidence without calling the AgentSigna API.

## Install

```bash
npm install @agentsigna/verify
```

Requires Node.js 18 or newer.

## Usage

CommonJS:

```js
const { verifyPassport, verifyChain, JtiCache } = require('@agentsigna/verify');
```

ES modules:

```js
import { verifyPassport, verifyChain, JtiCache } from '@agentsigna/verify';
```

Verify a passport:

```js
const result = verifyPassport(passport, publicKey, {
  expectedIssuer: 'https://api.agentsigna.com/orgs/acme',
  actionPayload: originalActionPayload,
});

if (!result.valid) {
  throw new Error(result.errors.join('; '));
}
```

Verify a ledger chain:

```js
const result = verifyChain(ledgerEvents);

if (!result.valid) {
  throw new Error(result.errors.join('; '));
}
```

Detect replayed passports:

```js
const cache = new JtiCache();
const result = verifyPassport(passport, publicKey, {
  expectedIssuer: 'https://api.agentsigna.com/orgs/acme',
});

if (result.valid && cache.seen(result.passport.jti, result.passport.expiresAt)) {
  throw new Error('Replayed passport');
}
```

For distributed systems, replace `JtiCache` with a shared store such as Redis using the passport expiry as the TTL.

## Security Model

`verifyPassport` checks:

- Ed25519 signature validity
- issuer match when `expectedIssuer` is supplied
- passport revocation status
- passport expiry
- optional action payload hash binding
- structural validity of the passport envelope

`verifyChain` checks:

- all events belong to a single action case
- chain reconstruction from `previousDigest`
- SHA-256 digest validity for every event
- broken chains and cycles
- legacy v0 and current v1 digest formats

Always pass `expectedIssuer` in production. Without it, a passport signed by another issuer could be accepted if the caller also supplies that issuer's public key.

## JWKS Fetching

`fetchPublicKeyFromJwks(url, keyId)` is a convenience helper for trusted JWKS endpoints. It enforces HTTPS, disables redirects, rejects private and loopback literal hosts, resolves DNS before fetch, and rejects hostnames resolving to private or loopback addresses.

Do not pass user-controlled JWKS URLs. If users can choose trust anchors, store allowlisted issuer metadata server-side and fetch keys from those configured issuers only.

## Release Checklist

Before publishing:

```bash
npm run pack:check
npm publish --provenance --access public
```

Package maintainers should enforce npm account 2FA and publish from CI with trusted publishing or provenance enabled. The release gate should fail if the packed tarball omits `README.md` or `LICENSE`, omits the ESM package marker, or includes compiled test files.
