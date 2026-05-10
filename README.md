# @agentsigna/verify

Standalone offline verifier for **AgentSigna Action Authorization Passports** (ASAAP v1.0) and **AgentSigna Ledger Chains** (ASLC v1.0).

Zero runtime dependencies — uses Node.js built-in `crypto` only.

## Install

```bash
npm install @agentsigna/verify
```

Requires Node.js >= 18.0.0.

## Usage

### Verify a passport

```js
import { verifyPassport } from '@agentsigna/verify';

// Public key as PEM string, JWK object, or fetched from JWKS endpoint
const result = verifyPassport(passport, publicKey);

if (result.valid) {
  console.log('Authorized:', result.passport.decision);
  console.log('Amount:', result.passport.amount, result.passport.currency);
} else {
  console.error('Invalid passport:', result.errors);
}
```

### Fetch the public key from AgentSigna's JWKS endpoint

```js
import { fetchPublicKeyFromJwks, verifyPassport } from '@agentsigna/verify';

const publicKey = await fetchPublicKeyFromJwks(
  'https://api.agentsigna.com/.well-known/jwks.json'
);
const result = verifyPassport(passport, publicKey);
```

### Verify action payload integrity (ASAAP §4.3)

Confirms the passport was issued for the exact payload you submitted, not a different one:

```js
const result = verifyPassport(passport, publicKey, {
  actionPayload: { orderId: 'PO-9921', amount: 14500, currency: 'USD' }
});

if (!result.passport.actionHashVerified) {
  throw new Error('Payload mismatch — possible tampering');
}
```

### Verify a ledger chain

```js
import { verifyChain } from '@agentsigna/verify';

// Pass all ledger events for a single action case (any order)
const result = verifyChain(events);

console.log(result.valid);          // true/false
console.log(result.checkedEvents);  // number of events verified
console.log(result.chainVersion);   // 'v0' or 'v1'
```

## API

### `verifyPassport(passport, publicKey, options?)`

| Parameter | Type | Description |
|---|---|---|
| `passport` | `Passport` | Passport object from the AgentSigna API |
| `publicKey` | `string \| JWK \| KeyObject` | Ed25519 public key |
| `options.actionPayload` | `unknown` | Optional — re-compute actionHash to verify payload integrity |
| `options.nowMs` | `number` | Optional — override clock (for testing) |

Returns `PassportVerificationResult`:
- `valid: boolean`
- `errors: string[]`
- `warnings: string[]`
- `passport` — summary fields if valid

### `verifyChain(events)`

| Parameter | Type | Description |
|---|---|---|
| `events` | `LedgerEvent[]` | All ledger events for a single action case |

Returns `ChainVerificationResult`:
- `valid: boolean`
- `errors: string[]`
- `checkedEvents: number`
- `chainVersion: string`
- `genesisDigest: string | null`
- `tipDigest: string | null`

### `fetchPublicKeyFromJwks(jwksUrl, keyId?)`

Fetches the first Ed25519 key from a JWKS endpoint. HTTPS only (rejects HTTP to prevent MITM). Pass `keyId` to select by `kid`.

## Security properties

- **Ed25519** (RFC 8032) — constant-time verification, no timing oracle
- **Canonical JSON** (RFC 8785-style, key-sorted) — prevents key-ordering bypass
- **SHA-256 hash-chain** — tamper detection across the full event sequence
- **No network calls** in `verifyPassport` and `verifyChain` — pass the public key directly
- **HTTPS-only JWKS fetch** — SSRF/MITM protection (OWASP A10)

## Specification

The full passport format is defined in the [AgentSigna Passport Specification](https://github.com/agentsigna/spec).

## License

[MIT](./LICENSE)
