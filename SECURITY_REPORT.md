## Summary

This repository contains intentionally vulnerable endpoints demonstrating common JWT weaknesses (alg=none, algorithm confusion, weak secrets, KID/JKU header trust). I implemented safer handling across the codebase to remove unsafe assumptions and hardening guidance. The changes focus on input validation, algorithm whitelisting, safe key lookup, and configuration-driven secrets.

## What I changed (high level)
- Added `lib/jwt-utils.js` with helpers for extracting Bearer tokens, rejecting `alg: none`, and safely fetching/validating JWKS.
- Hardened every controller to stop trusting user-controlled JWT headers (alg, kid, jku).
- Replaced hard-coded weak HS secret with a configurable secret read from environment or local key file and enforce a minimum length for signing/verification.
- Prevented path-traversal and SQL injection in `kid-injection` by validating `kid` formats and parameterizing DB queries.
- Enforced algorithm whitelists when verifying tokens (always pass known algorithm arrays to `jwt.verify`).
- Added basic security middleware in `app.js` (helmet, express.json) and support for loading environment variables via `dotenv`.
- Updated `package.json` to include runtime dependencies used by new code (please run `npm install` after pulling changes).

Files changed (high-level):
- `app.js` — add helmet, express.json, dotenv
- `lib/jwt-utils.js` — new helper utilities
- `controllers/weak-secret.js` — use configured HS secret; enforce min length; extract Bearer
- `controllers/none-attack.js` — reject `alg=none`; explicit HS256/RS256 verify
- `controllers/kid-injection.js` — validate kid, prevent path traversal, parameterize SQL
- `controllers/jku-injection.js` — whitelist JKU, fetch and validate JWKS safely, enforce RS256
- `controllers/algorithm-confusion.js` — force RS256 and safe JWKS handling
- `package.json` — add dependencies (helmet, dotenv, jwk-to-pem)

## Design contract (short)
- Inputs: HTTP requests with an Authorization header using Bearer tokens.
- Output: 200 with parsed payload when token is valid; 401 for invalid tokens; 500 for server misconfiguration.
- Data shapes: JWT standard (header, payload, signature). Keys are returned as strings.
- Error modes: malformed token, unsupported algorithm, missing/weak secrets, external JWKS fetch failure.

## Threat model & mitigations
- Attacker can control JWT header and payload but cannot access private server secrets or private keys.
- Do not trust header.alg — solution: explicitly pass a small whitelist to jwt.verify.
- Do not trust header.kid for file paths — solution: validate kid format, use database lookup with parameterized queries, avoid direct path concatenation.
- Do not trust header.jku — solution: allow only whitelisted JKU origins and validate returned JWKS (kty and kid).
- Disallow `alg=none` explicitly.
- Use strong, configurable secrets (environment variable `JWT_HS_SECRET`) and refuse to sign/verify if the secret is too short.

## How to run locally (recommended quick steps)
1. Install dependencies:

```powershell
cd "d:\University\7th semester\SSDD\jwt-vulnerabilities-lab_ssdd"
npm install
```

2. Create a `.env` file in the project root to set secrets (example):

```text
JWT_HS_SECRET=replace-with-32+char-secret-example-0123456789
JKU_WHITELIST=http://127.0.0.1:8000/jwks.json
```

3. Start the app:

```powershell
node app.js
```

4. Use the existing endpoints (Swagger UI is exposed at `/swagger`) to test tokens. The controllers will now expect `Authorization: Bearer <token>`.

## Verification steps (manual)
1. Attempt to use a token with header.alg = none — the endpoints now reject it (401).
2. Try to send a token with alg manipulated to cause algorithm confusion — the endpoints enforce allowed algorithms (401 when mismatch).
3. For KID path-traversal: try setting `kid` to `../../etc/passwd` — request is rejected because kid is validated.
4. For KID SQL injection: try a KID containing SQL payload — request is rejected because the query uses parameterized replacements.
5. For JKU injection: attempt to set `jku` to an external URL not on the whitelist — the request is rejected.

## Notable implementation details and rationale
- All calls to `jwt.verify` now pass concrete algorithms arrays (e.g., `['RS256']` or `['HS256']`). This prevents the library from using unsafely-provided `alg` header values.
- JWKS fetching (JKU) is white-listed and validated. The code looks for a JWK with a matching kid; otherwise, it uses the first valid RSA key.
- Secrets are loaded from `process.env.JWT_HS_SECRET` by default; the repo keeps a fallback key file but refuses to operate if the secret is too short.
- Database queries in `kid-injection` now use replacements to avoid SQL injection.

## Remaining risks & recommended next steps
- Upgrade `jsonwebtoken` from 8.5.1 to the latest stable 9.x to get security fixes and easier TypeScript support. Test compatibility.
- Replace ad-hoc JWKS fetching with a production-ready library like `jwks-rsa` which provides caching, rate limiting and key rotation handling.
- Add rate-limiting and improved logging (structured logs) for all endpoints.
- Add automated tests that create crafted malicious tokens and confirm endpoints reject them.
- Consider moving secrets to a secret manager (Vault, AWS SSM) and remove fallback to local files.

## Changes summary (what I did to verify)
- I ran a static scan and replaced all uses of `jwt.verify` that relied on header.alg with explicit algorithm arrays.
- Replaced direct file reads that used header values to construct paths with strict validation and path.join.
- Converted raw SQL concatenation into parameterized query via `sequelize.query` with replacements.

## Patch notes
- New file: `lib/jwt-utils.js` — centralizes token extraction and JWKS validation.
- Edited: `app.js`, `controllers/*`, `package.json`.

If you'd like, I can also:
- Add a small test script that demonstrates the fixed behaviors (generate malicious tokens and show they fail).
- Open a PR with dependency upgrades and run a CI job to ensure the app still works with updated libraries.

---
End of report.
