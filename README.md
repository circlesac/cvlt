# vlt

[![npm](https://img.shields.io/npm/v/@circlesac/vlt-cli.svg)](https://www.npmjs.com/package/@circlesac/vlt-cli)

`vlt` is the official CLI for [Circles Vault](https://github.com/circlesac/vault) — a secrets manager on Cloudflare Workers with two parallel address surfaces:

- **`op://<vault>/<item>/<field>`** — 1Password Connect-compatible. Most workflows that use `op read`, `op inject`, or `op run` work unchanged by setting `OP_CONNECT_HOST`.
- **`vlt://<provider>/<owner>[/<repo>]#<NAME>`** — flat GitHub-Secrets-style key→value secrets, addressed by GitHub coordinates. The repo segment selects the scope: present → project secret, absent → owner-global. Designed to replace GitHub Actions secrets (the coordinate is identical to the OIDC `repository` claim).

`vlt read`, `vlt inject`, and `vlt run` accept both schemes anywhere a reference appears.

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

# op run idiom: keep references in a committed env file (references are not secrets)
vlt run --env-file=.vlt.env -- ./deploy.sh
```

```bash
# .vlt.env — safe to commit; values are fetched at runtime
DB_PASSWORD=vlt://github.com/acme/api#DB_PASSWORD
OPENAI_KEY=vlt://github.com/acme#OPENAI_KEY
LEGACY_PASS=op://my-vault/db-credentials/password
```

`vlt run` resolves `op://` / `vlt://` references found in `--env-file` entries and the process env, then exec's the command with the actual values.

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

### Flat secrets (vlt://)

Flat key→value secrets addressed by GitHub coordinates — separate from the op:// vault/item store. `vlt://github.com/<owner>#<NAME>` is owner-global, `vlt://github.com/<owner>/<repo>#<NAME>` is project-scoped; lookups resolve `project > global`. NAME charset is GitHub-isomorphic (`[A-Z0-9_]`, no digit start, no `GITHUB_` prefix); there is no escaping — anything outside the charset is rejected.

```bash
# Create / update (value from arg or stdin)
vlt secret set "vlt://github.com/acme/api#DB_PASSWORD" "s3cret"
echo -n "s3cret" | vlt secret set "vlt://github.com/acme#OPENAI_KEY"

# Read
vlt secret get "vlt://github.com/acme/api#DB_PASSWORD"

# Resolve by name with project > global precedence
vlt secret resolve DB_PASSWORD --owner acme --repo api   # humans pass the coordinate
vlt secret resolve DB_PASSWORD                            # CI: coordinate implied by OIDC identity

# List (metadata only — values are never listed) / delete
vlt secret list
vlt secret delete "vlt://github.com/acme/api#DB_PASSWORD"
```

Secrets belong to the configured org by default. `--personal` (or having no org configured) targets your personal account namespace instead — same scopes, addressed identically, isolated per user:

```bash
vlt secret set --personal "vlt://github.com/ygpark80/dotfiles#TOKEN" "..."
vlt secret list --personal
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

For vlt:// secrets the grant's `repository` doubles as the coordinate: a granted workflow can read its own project secrets plus that owner's globals — no other coordinate, regardless of what it asks for.

### Composite action

The repo ships a composite action that installs `vlt` and sets the endpoint:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: circlesac/vlt-cli/action@main
    with:
      host: https://vault.circles.ac/<your-org>
  - run: vlt run --env-file=.vlt.env -- ./deploy.sh
```

With `export-env: true` the action resolves `env-file` entries into `$GITHUB_ENV` (each value masked via `::add-mask::` first), so later steps can use `${{ env.NAME }}` — one word away from GitHub-native `${{ secrets.NAME }}`:

```yaml
  - uses: circlesac/vlt-cli/action@main
    with:
      host: https://vault.circles.ac/<your-org>
      env-file: .vlt.env
      export-env: "true"
  - run: ./deploy.sh                # $DB_PASSWORD available to the whole job
```

`vlt run` keeps secrets scoped to the child process (narrower exposure, recommended); `export-env` trades that for job-wide convenience.

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
