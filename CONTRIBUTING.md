# Contributing

The gateway is the runtime enforcement service for the Agent Passport System. It checks delegated authority before an action executes and signs a receipt for the result. Protocol semantics live in [agent-passport-system](https://github.com/aeoess/agent-passport-system). Changes that alter what a delegation, scope or receipt means belong there first.

## Setup

```
npm ci --include=dev
npm run build
npm test
```

`npm test` and `npx tsc --noEmit` must pass before a PR. The totals are whatever the suite reports, not a number written here. `--include=dev` matters if your shell sets `NODE_ENV=production`, because npm then skips devDependencies the tests need.

## What a good PR looks like

1. A failing test that reproduces the bug, or tests that cover the new behavior.
2. The smallest change that makes it pass.
3. A PR description that says what the change enforces and what it does not.

## Good places to start

Look for issues labeled `good first issue` or `help wanted`. If you want to work on something else, open an issue first so we can agree on scope.

## Security

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is released under Apache-2.0.
