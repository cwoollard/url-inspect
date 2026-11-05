# Preparing the GitHub repository

This folder is the repository root for `url-inspect`. Its `.github/workflows` are only discovered when placed at the top level of the new repository, not while nested under the Terraform repository.

Create an empty GitHub repository named `url-inspect` under your chosen account/organisation. Copy or extract this source package into a separate working directory. Include hidden files such as `.github`, `.gitignore` and `.editorconfig`; do not copy `target/`, `dist/`, or the parent Terraform repository's `.git` directory.

From that standalone directory:

```sh
git init -b main
git add .
git commit -m "Initial url-inspect utility"
git remote add origin git@github.com:OWNER/url-inspect.git
git push -u origin main
```

Replace `OWNER` with the actual GitHub owner. Set the real `repository` URL in `Cargo.toml` when known and replace `OWNER` in the README distribution commands. The Homebrew formula is a template; it also needs the repository URL and release archive checksum before use.

If your organisation restricts GitHub Actions, allow the official checkout, upload-artifact and download-artifact actions used in these workflows. The release workflow needs permission to create a draft release. These workflows target GitHub.com-hosted runners; GitHub Enterprise Server may require older compatible artifact actions.

# Creating a release

1. Run `mise run check` and review the changes. Commit `Cargo.lock`.
2. Update the version in `Cargo.toml`, regenerate the lockfile if needed, and update `CHANGELOG.md` and the Homebrew template's version test/URL. Keep `rust-toolchain.toml` and `mise.toml` aligned when changing Rust.
3. Commit and push, then push a matching version tag:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. The draft-release workflow checks the tag against the Cargo version, tests/builds macOS ARM64, macOS Intel and Linux x86_64 musl, and produces binary archives, a source-only archive and `SHA256SUMS`.
5. Review the workflow results and draft release. Publish it through GitHub when ready. It is intentionally created as a **draft**; public mise users cannot install draft assets.

The initial workflow does not produce Windows or Linux ARM64 release assets. CI still checks Windows source builds. Additional release targets can be added once their build environments are tested.

After publishing, users with a matching platform can install the binary through mise:

```sh
mise use -g github:OWNER/url-inspect@0.1.0
```

Before publishing binary releases, users with Rust and repository access can install from the Git tag:

```sh
mise use -g rust@stable
mise use -g 'cargo:https://github.com/OWNER/url-inspect@tag:v0.1.0'
```

No custom mise plugin is required. A source archive alone is not an installable binary asset for mise's GitHub backend.

# Source-only packaging

```sh
mise run source-archive
```

This creates `dist/url-inspect-v0.1.0-source.tar.gz` using Python 3. It includes project sources, tests, documentation, mise/toolchain files, packaging scripts and GitHub workflows. Build outputs, Git history, environment files and machine-specific mise settings are excluded. The archive has a single `url-inspect/` top-level directory.
