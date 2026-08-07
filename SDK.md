# Circles Vault client contract

This repository is the public reference implementation and contract for
Circles Vault clients. The hosted Vault service remains separate.

## Language implementations

| Runtime | Location or distribution | Status |
| --- | --- | --- |
| Node.js | `@circlesac/vlt-cli/client` | Reference implementation |
| Go | `sdk/go` in this repository | Reserved for a native implementation |

New language implementations belong in this repository when the ecosystem
supports a subdirectory package or module. They must not shell out to `cvlt`
and must execute the same contract cases. A separate repository is only needed
when a language registry requires the repository root to be the package root.

## Required behavior

Every implementation must:

1. Resolve `op://<vault>/<item>/<field>` references with case-insensitive vault
   names and exact field label, ID, or purpose matching.
2. Resolve `vlt://github.com/<owner>[/<repo>]/<NAME>` references using the
   canonical grammar implemented by `node/src/refs.ts`.
3. Resolve authentication in this order: explicit Connect environment,
   GitHub Actions OIDC, then the shared Circles credential provider.
4. Encrypt and decrypt item content on the client and never send plaintext
   item names, fields, or values to an E2EE Vault endpoint.
5. Store the installation private key in the operating-system credential
   store: macOS Keychain, Linux Secret Service, or Windows DPAPI.
6. Use an encrypted local key file only when the OS credential store is
   unavailable. The fallback file and its parent directory must use restrictive
   permissions where the filesystem supports them.
7. Return structured errors to SDK callers. A library must not print secrets,
   terminate the host process, or require the `cvlt` executable.

## Public API baseline

Language implementations expose equivalent operations even when naming follows
language conventions:

```text
CreateClient(options)
Client.Read(reference) -> string
Client.GetItem(vault, item) -> Item
```

The Node reference spelling is:

```js
import { createVaultClient } from "@circlesac/vlt-cli/client"

const vault = createVaultClient()
await vault.read("op://personal/Modusign/password")
await vault.getItem("personal", "Modusign")
```

## Compatibility

Contract changes must remain readable by older clients or carry an explicit
format version and migration path. Node and Go implementations must share
language-neutral fixtures before the Go package is considered supported.
