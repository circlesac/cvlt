# vlt

[![npm](https://img.shields.io/npm/v/@circlesac/vlt-cli.svg)](https://www.npmjs.com/package/@circlesac/vlt-cli)

`vlt` is the official CLI for [Circles Vault](https://github.com/circlesac/vault) — a 1Password Connect-compatible secrets manager on Cloudflare Workers. It speaks the same `op://<vault>/<item>/<field>` secret reference syntax as 1Password's `op` CLI, so most workflows that use `op read`, `op inject`, or `op run` work unchanged by setting `OP_CONNECT_HOST`.

## Install

```bash
# macOS / Linux via Homebrew
brew install circlesac/tap/vlt

# Any Node.js environment (works on GitHub Actions ubuntu-latest)
npm install -g @circlesac/vlt-cli

# Static binaries (no Node required)
# Download from https://github.com/circlesac/vlt-cli/releases/latest
```

## Authentication

`vlt` resolves credentials in this order:

1. **`OP_CONNECT_HOST` + `OP_CONNECT_TOKEN`** — drop-in for `op` CLI; useful when you already have a token.
2. **`OP_CONNECT_HOST` + GitHub Actions OIDC** — if `ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` are present (workflow has `id-token: write`), `vlt` fetches a short-lived OIDC token automatically. No stored secrets.
3. **`crcl` config** (`~/.config/crcl/config`) — interactive user. Run `crcl login`, optionally `--profile dev` to target the dev environment.

`vlt whoami` shows the resolved host + org.

## Common commands

### Read a secret

```bash
vlt read "op://my-vault/db-credentials/password"
vlt read -n "op://my-vault/db-credentials/password"   # no trailing newline
vlt read -o /tmp/password "op://..."                  # write to file
```

### Inject secrets into a template

```bash
# template.env
DB_HOST={{op://my-vault/db-credentials/host}}
DB_PASS={{op://my-vault/db-credentials/password}}

# Inject and write
vlt inject -i template.env -o .env

# Or pipe
cat template.env | vlt inject > .env
```

### Run a command with secrets injected as env vars

```bash
DB_PASS="op://my-vault/db-credentials/password" vlt run -- ./deploy.sh
```

`vlt run` scans the process env for `op://` references and replaces them with the actual secret values before exec'ing the command.

### Manage vaults

```bash
vlt vault list
vlt vault create "production"
vlt vault edit "production" --name "prod-secrets"
vlt vault delete "old-vault"
```

### Manage items

```bash
vlt item create --vault prod-secrets --category login --title "DB" username=admin password=secret
vlt item list --vault prod-secrets
vlt item get "DB" --vault prod-secrets --format json
vlt item edit "DB" --vault prod-secrets password=newpass
vlt item delete "DB" --vault prod-secrets
vlt item move "DB" --current-vault staging --destination-vault prod-secrets
```

### Documents

```bash
vlt document create ./cert.pem --vault prod-secrets --title "TLS Cert"
vlt document list --vault prod-secrets
vlt document get "TLS Cert" --vault prod-secrets -o ./cert.pem
```

### OIDC grants (operator-only)

```bash
# Allow circlesac/my-app's workflows to read any vault in the org
vlt oidc grant create circlesac/my-app

# Narrow by env, restrict to a vault, grant write access
vlt oidc grant create circlesac/my-app \
  --env production --vault prod-secrets --role write

# Org-wildcard
vlt oidc grant create "circlesac/*" --role read

# Inspect / change / revoke
vlt oidc grant list
vlt oidc grant get <id>
vlt oidc grant edit <id> --role write
vlt oidc grant edit <id> --env null              # clear an optional field
vlt oidc grant delete <id>
```

`vault create / edit / delete`, `oidc grant *`, and `whoami` require operator (user JWT) auth. OIDC tokens from GitHub Actions are scoped to data-plane operations (read items, write items if `role=write`) and cannot manage vaults or grants regardless of role.

## GitHub Actions workflow

After registering a grant once, a workflow needs zero stored secrets:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      OP_CONNECT_HOST: https://vault.circles.ac/<your-org>
    steps:
      - uses: actions/checkout@v4
      - run: npm install -g @circlesac/vlt-cli
      - run: vlt run -- ./deploy.sh
```

`vlt` detects the runner's `ACTIONS_ID_TOKEN_REQUEST_URL` / `_TOKEN` env vars, mints a GitHub OIDC token with the right audience, and sends it to Vault. The server verifies GitHub's signature, matches the claims (`repository`, `environment`, `ref`) against the grant ACL, and serves the request.

## Profile / org overrides

```bash
vlt vault list                       # default profile, default org
vlt vault list --profile dev         # crcl 'dev' profile
vlt vault list --org other-org       # different org slug
```

## Further reading

- Server-side architecture, schema, audit log, OIDC details: see the [server README](https://github.com/circlesac/vault).
- `op` CLI compatibility matrix: [`docs/api-compatibility.md`](https://github.com/circlesac/vault/blob/main/docs/api-compatibility.md) in the server repo.

## License

Internal — Circles Inc.
