# Test fixtures

`passports.json` holds passports produced by the AgentSigna issuing code path with deterministic test keys (`fixture-2026-a`, then a rotation to `fixture-2026-b` with `fixture-2026-a` kept in the key set), the resulting two-key JWKS, and how `@agentsigna/verify` 1.1.1 judged a set of valid and invalid variants of each passport. The test suite uses them to check key selection by `kid` across a rotation and that 1.2.0 gives the same result as 1.1.1 for every variant.

The keys are test keys. Never trust them for real passports.
