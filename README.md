# fluxplane-secret

Shared secret reference, material, and file-store primitives for Fluxplane modules.

This module provides the portable secret contract used by Fluxplane runtimes and plugins. It owns secret references, typed material, persisted secret metadata, access grants, and a small JSON file-store implementation.

## Usage

```go
import secret "github.com/fluxplane/fluxplane-secret"

store := secret.NewFileStore("/path/to/auth")
ref := secret.Plugin("slack", "workspace-prod", "bot_token")
_ = store.SaveSecret(ctx, secret.StoredSecret{
    Ref:   ref,
    Kind:  secret.KindBearerToken,
    Value: "xoxb-...",
})
```

## Packages

- `secret.Ref` identifies environment, file, plugin, and URL secret locations.
- `secret.Material` carries resolved secret bytes plus type metadata.
- `secret.StoredSecret` is the trusted persisted secret DTO.
- `secret.FileStore` stores secrets under a local auth directory.
- `secret.AccessGrant` and `secret.CapabilityGrant` are shared grant DTOs.

This package is deliberately independent of `fluxplane-core` so other Fluxplane modules can use the same secret wire contract.
