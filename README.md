# vlt

[![npm](https://img.shields.io/npm/v/@circlesac/vlt-cli.svg)](https://www.npmjs.com/package/@circlesac/vlt-cli)

`vlt` is the official CLI for [Circles Vault](https://github.com/circlesac/vault) — a secrets manager on Cloudflare Workers with two parallel address surfaces:

- **`op://<vault>/<item>/<field>`** — 1Password Connect-compatible. Most workflows that use `op read`, `op inject`, or `op run` work unchanged by setting `OP_CONNECT_HOST`.
- **`vlt://<provider>/<owner>[/<repo>]/<NAME>`** — flat GitHub-Secrets-style key→value secrets, addressed by GitHub coordinates. The repo segment selects the scope: present → project secret, absent → owner-global. Designed to replace GitHub Actions secrets (the coordinate is identical to the OIDC `repository` claim).

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

`vlt whoami` shows the resolved host + account (`personal` by default, or `org:<slug>` with `--org`/`CRCL_ORG`).

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
DB_PASSWORD=vlt://github.com/acme/api/DB_PASSWORD
OPENAI_KEY=vlt://github.com/acme/OPENAI_KEY
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

### GitHub-coordinate secrets (vlt://)

A secret is just an op:// **item** (there's no separate "secret" store or verb). What's special about a vault named like a GitHub coordinate — `github.com/<owner>[/<repo>]` — is that it's addressed by the **`vlt://` reference scheme**, which exists for two reasons `op://` can't cover:

1. **Coordinate names contain `/`.** An `op://<vault>/<item>/<field>` reference splits on `/`, so it can't name a vault like `github.com/acme/api` (the slashes collide). `vlt://github.com/<owner>[/<repo>]/<NAME>` knows the structure — `<NAME>` is the last segment, the leading github coordinate is the vault — so it parses unambiguously, no escaping.
2. **Inheritance.** Reads cascade `project > global` (repo→owner), like GitHub Actions repo/org secrets.

- `vlt://github.com/<owner>/<repo>/<NAME>` — project; falls back to the owner if absent
- `vlt://github.com/<owner>/<NAME>` — owner-global
- NAME charset is GitHub-isomorphic (`[A-Z0-9_]`, no digit start, no `GITHUB_` prefix)

The item itself is still managed with the op `item`/`vault` verbs — those take the coordinate as a `--vault` **name** (a flag value, not an `op://` reference, so the slashes are fine).

```bash
# Register the coordinate vault (+ CI grant for a repo coordinate; org-scoped → --org)
vlt vault create github.com/acme/api --org acme

# Write a secret = create/edit an item in that vault (--vault takes the name)
vlt item create --vault github.com/acme/api --title DB_PASSWORD 'value[password]=s3cret'
vlt item edit DB_PASSWORD --vault github.com/acme/api 'value[password]=rotated'

# Read by reference — vlt:// handles the coordinate + inherits (project→owner)
vlt read "vlt://github.com/acme/api/DB_PASSWORD"          # cascades to github.com/acme if absent

# List / delete = op item verbs (coordinate as --vault name)
vlt item list --vault github.com/acme/api
vlt item delete DB_PASSWORD --vault github.com/acme/api
```

**Scope: personal by default.** Commands target your personal account unless you escalate to an org with `--org <slug>` (or `CRCL_ORG`). Personal is always available, non-shared, isolated per user; an org is shared, so targeting it is explicit. CI via GitHub OIDC always resolves to the org.

### Registering repos for CI access (operator-only)

`vlt vault create <coordinate>` creates the op:// vault that stores the secrets; for a **repo** coordinate it also records the OIDC grant that lets that repo's CI read it (**creating it is the consent**). Grants are org-scoped, so pass `--org <owner>`. Once per repo:

```bash
vlt vault create github.com/circlesac/my-app --org circlesac
vlt vault create github.com/circlesac/my-app --org circlesac --ci-write --env production

vlt vault get github.com/circlesac/my-app --org circlesac     # registration + secret count
vlt vault delete github.com/circlesac/my-app --org circlesac  # revokes CI access; items remain
```

Owner-global (`github.com/circlesac`) needs no grant — every registered repo of that owner reads it via `project > global`, and org members write to it with `vlt item create --vault github.com/circlesac --org circlesac …`.

The legacy `vlt oidc grant create|list|get|edit|delete` commands remain for op://-vault-scoped or org-wildcard (`owner/*`) grants.

`vault create / edit / delete`, `oidc grant *`, and `whoami` require operator (user JWT) auth. OIDC tokens from GitHub Actions are scoped to data-plane operations (read secrets/items, write if allowed) and cannot manage vaults or grants regardless of role.

## GitHub Actions workflow

After registering the repo once, a workflow needs zero stored secrets:

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
