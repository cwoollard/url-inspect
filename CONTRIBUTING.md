# Contributing

Use the Rust version pinned in `rust-toolchain.toml` and `mise.toml`.

```sh
mise trust
mise install
mise run check
mise run build
mise run run -- https://example.com --csp --headers
```

Without mise, run the corresponding Cargo commands shown in the README. Rustup reads `rust-toolchain.toml` automatically. Keep both toolchain pins in sync when upgrading Rust, and commit `Cargo.lock` because this is an application.

Keep usage examples on `example.com` or `example.local`. Network tests should use local fixtures; do not add tests that depend on access to a real company site or production credentials.

Pull requests should explain the behaviour change and the checks run. Changes to output should cover both text and JSON, including piped output without colour escapes. Authentication headers must never be forwarded after a cross-origin redirect.

The CI workflow checks Linux, macOS and Windows. GitHub runs it once this package is at the repository root; the workflow is intentionally inside this standalone project rather than the parent Terraform repository.
