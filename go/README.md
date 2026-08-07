# Circles Vault SDK for Go

```go
import vault "github.com/circlesac/vault/go"

client, err := vault.NewClient(context.Background())
value, err := client.Read(context.Background(), "op://personal/Modusign/password")
```

The SDK resolves the shared Circles credential, reuses the Vault installation
key from macOS Keychain or Linux Secret Service, and decrypts E2EE Vault and
item content locally. Version `v0.1.x` currently supports read-only `op://`
references. Native Windows DPAPI and `vlt://` reads remain pending.
