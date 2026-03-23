# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cryptdrive is an end-to-end encrypted cloud storage app. All encryption/decryption happens client-side (zero-knowledge). Built on Cloudflare Workers + D1 (SQLite) + R2 (object storage). Deployed at cryptdrive.io.

## Commands

- `npm run dev` — Start local dev server (Wrangler)
- `npm run test` — Run tests (vitest with Cloudflare Workers pool)
- `npm run test -- --run` — Run tests once (no watch)
- `npm run lint` — Lint (eslint, zero warnings allowed)
- `npm run lint:fix` — Auto-fix lint issues
- `npm run format` — Format with prettier
- `npm run format:check` — Check formatting
- `npm run check` — Lint + format check + tests (CI equivalent)
- `npm run deploy` — Deploy to Cloudflare Workers
- `npm run build` — Build frontend assets to dist/
- `npm run migrate:local` / `npm run migrate:prod` — Apply DB migrations

## Architecture

**Backend** (`src/backend/`): Cloudflare Worker exporting `fetch` and `scheduled` handlers. Manual routing in `index.js` — no framework.

- `handlers/` — Route handlers: `auth.js` (JWT challenge-response), `user.js` (registration), `files.js` (CRUD + publish), `multipart.js` (presigned R2 multipart uploads)
- `middleware/` — `auth.js` (JWT verification), `rate-limiting.js`
- `utils/` — `crypto.js` (Ed25519 signature verification), `jwt.js`, `response.js` (JSON helper), `multipart.js` (R2 presigned URL generation via aws4fetch)
- `db/migrations/` — Sequential numbered SQL files (`001_*.sql`, `002_*.sql`, ...)
- `db/migrate-cli.js` — CLI for applying migrations via Wrangler

**Frontend** (`src/frontend/`): Single-page app — vanilla JS (`client.js`), no framework. Uses argon2-browser for key derivation and Web Crypto API for E2EE. Built with esbuild, served as Cloudflare Worker static assets from `dist/`.

**Auth flow**: Client derives Ed25519 keypair from passphrase (via Argon2id + HKDF). Server issues a challenge, client signs it, server verifies and returns JWT.

**File flow**: Files are encrypted client-side (AES-256-GCM), split into blocks, uploaded via presigned R2 multipart upload URLs. Downloads use presigned R2 download URLs.

## Bindings (wrangler.jsonc)

- `DB` — D1 database
- `BUCKET` — R2 bucket (preview: `cryptdrive-test`)
- Secrets (set via `wrangler secret`): `SERVER_PEPPER`, `JWT_SECRET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`

## Testing

Tests use `@cloudflare/vitest-pool-workers` which runs tests inside the Workers runtime. Test files are in `src/backend/test/`. The test helper `src/backend/test/helpers/database.js` handles DB setup for tests.

## Key Design Docs

- `DESIGN.md` — Full cryptographic design, API spec, data formats, and security model
- `docs/MIGRATIONS.md` — Migration system documentation
