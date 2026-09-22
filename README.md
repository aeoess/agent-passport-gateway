# Agent Passport Gateway

Agent Passport Gateway is a runtime enforcement service for the Agent Passport System (APS). It evaluates requested actions against the presented delegation chain, revocation state and configured policy, then returns a permit or deny decision.

Callers can register agents, issue delegations that narrow scope, spend limit and delegation depth from parent to child, then submit actions for evaluation. The gateway returns a permit or deny decision and can issue signed APS evidence for it.

It uses the [Agent Passport System](https://github.com/aeoess/agent-passport-system) SDK for canonicalization, signature verification and delegation types.

## Requirements

- Node.js 18 or later
- npm

## Install

```sh
npm ci
```

## Configure

```sh
cp .env.example .env
```

Edit `.env` to set `DB_PATH` and any optional integrations such as Stripe or the Nano payment rail. Only `PORT` and `DB_PATH` are required to run the gateway locally with SQLite.

`GATEWAY_OPERATOR_EMAIL` identifies the tenant that should receive the `admin` role and access to `/api/v1/admin/*`. It is unset by default, so a fresh deployment elevates nobody by email until you configure it.

`GATEWAY_OPERATOR_EMAIL_ALIASES` is an optional comma-separated list of additional verified email addresses that should resolve to the same operator tenant.

These settings are used for operator reconciliation. They are not a revocation mechanism. Unsetting `GATEWAY_OPERATOR_EMAIL` later does not remove the `admin` role from a tenant that already has it.

## Build

```sh
npm run build
```

Compiles TypeScript with `tsc` and copies the regulated-action runtime assets into `dist/`.

## Run

```sh
npm run dev
```

Runs the server directly from TypeScript source with `tsx`, listening on the `PORT` from `.env` (default `3200`). `GET /healthz` returns the health check.

To run the compiled build:

```sh
npm start
```

## Type-check

```sh
npx tsc --noEmit
```

## Test

```sh
npm test
```

Runs the suite with the Node.js test runner.

`test/trust-profile-jws.test.ts` currently has a known failure because the `jose` package is not resolvable from this tree's install.

## Container build

A `Dockerfile` is included for container builds using `node:22-slim`, with `better-sqlite3` compiled at build time.

The `deploy/` directory contains Terraform, Helm, Docker and air-gapped deployment variants for running the gateway in your own infrastructure. See `deploy/README.md`.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.

Copyright 2026 Tymofii Pidlisnyi.
