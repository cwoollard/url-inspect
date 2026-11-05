# url-inspect

A standalone Rust CLI for inspecting HTTP response headers, Content Security Policies, certificates and negotiated TLS details. Works on private/VPN sites from a machine that can reach them. No Node.js, browser driver or external scanning service is required at runtime.

## Build and install

From this directory:

```sh
mise trust
mise install
mise run check
mise run build
mise run run -- https://example.com --csp --headers --cert --tls
```

`mise.toml` selects Rust 1.99.1 and provides build, formatting, lint, test, run and source-archive tasks. Run `mise tasks` to list them. `rust-toolchain.toml` selects the same toolchain for Cargo/rustup users without mise.

Or use Cargo directly:

```sh
cargo build --release --locked
cargo install --path . --locked
```

The executable is `target/release/url-inspect`; `cargo install` places it in your Cargo bin directory. This directory is ready to use as its own repository. See [RELEASING.md](RELEASING.md) for GitHub setup, draft releases and mise distribution, and [CONTRIBUTING.md](CONTRIBUTING.md) for development.

## Usage

Running with no arguments, or a URL without an inspection switch, shows help without making a request. Use `--csp` for policies, `--headers` for all response headers, `--cert` for certificate information, and `--tls` for a direct TLS probe. These switches can be combined. `--cert-pem` implies `--cert`; `--require-csp` implies `--csp`.

Text output uses colour on terminals automatically, respecting `NO_COLOR`. Use `--color always` or `--color never` to override this. Redirected output is plain text by default, and JSON is always free of colour escapes.

```sh
# HTTPS is assumed when the scheme is omitted
url-inspect example.com --csp

# All response headers, including repeated Set-Cookie fields
url-inspect https://example.com --headers

# Negotiated TLS cipher/version, ALPN and key-exchange group
url-inspect https://example.com --tls

# Combined inspection
url-inspect https://example.com --csp --headers --cert --tls

# Certificate subject, issuer, SANs, validity dates and SHA-256 fingerprint
url-inspect https://example.com --cert

# Include the leaf certificate in PEM form
url-inspect https://example.com --cert-pem

# Machine-readable report, including raw policy strings and byte counts
url-inspect https://example.com --csp --cert --json

# Private CA bundle, added to the system trust store
url-inspect https://example.local --csp --cacert company-ca.pem

# Authenticated request; headers can be repeated
url-inspect https://example.local --csp -H 'Authorization: Bearer YOUR_TOKEN'

# Inspect the initial response only; skip HTML scanning
url-inspect http://example.local --csp --no-follow --headers-only

# Exit 2 if the final page has no enforced CSP (report-only is insufficient)
url-inspect https://example.local --require-csp

# Diagnose an invalid/untrusted certificate; output explicitly marks this
url-inspect https://example.local --cert --insecure

url-inspect --help
```

Prefer `--cacert` to `--insecure` for internal PKI. System CA roots and environment proxies (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`) are supported. `--no-proxy` bypasses proxy settings. With a TLS-inspecting corporate proxy, the displayed certificate is the certificate presented by that proxy.

Authentication headers are not logged, but command arguments may be visible in shell history and process listings. Custom headers are retained for same-origin redirects and permanently dropped after a cross-origin redirect, including if the chain later returns to the original origin. There is no browser login flow or cookie jar; inspect the status and final URL to confirm that the report describes the intended page rather than a login screen.

## What it reports

- Actual HTTP response version, remote socket address, and optional complete response headers. Repeated fields are preserved as separate JSON array entries. Header names are normalized to lowercase, and non-UTF-8 header bytes are replaced for display. Response headers can include cookies/session identifiers; handle saved reports accordingly. HTTP/2 negotiation is enabled; HTTP/3 is not tested.
- Each redirect hop, HTTP status and Location. Up to ten redirects are followed by default; use `--max-redirects N` or `--no-follow`.
- Every enforced and report-only CSP response header as a separate policy.
- CSP meta elements in the HTML head (case-insensitive `http-equiv` matching).
- Each policy's UTF-8 byte count, with a notice above the ALB header attribute's 1,024-byte limit. This limit does not apply universally to application-supplied CSPs. Meta attributes are entity-decoded before counting.
- Optional TLS **leaf** certificate information for each HTTPS response. Full certificate-chain inspection is not implemented. Expiry is displayed as a readable duration down to minutes, without a leading “in” (seconds are shown for durations below one minute), with expired certificates explicitly labelled. Months use 30 days and years use 365 days; the exact expiry date is also shown. JSON includes both `expiry` and `seconds_until_expiry`.

TLS hostname and chain validation is enabled by default. `valid_now` in certificate output refers only to the certificate's validity dates; it is not a separate chain-validation result. Request failures are errors, even when certificate display is requested. To inspect an expired/untrusted certificate, explicitly use `--insecure`.

HTML scanning reads up to 2 MiB of the decompressed body and reports truncation. HTML is interpreted as UTF-8 with replacement for invalid bytes. Redirect loops and HTTPS-to-HTTP downgrades are rejected. The timeout is per request, not for the entire chain.

This inspects policies actually returned by a server; it **does not generate a recommended CSP**, evaluate resistance to XSS, execute JavaScript, discover every application route, or prove that an SSO/chat flow works. Dynamically added meta tags are not discovered. Multiple enforced policies remain separate because browsers require every applicable policy to permit a resource. Report-only policies do not enforce restrictions. Responses such as 403/404 are still reported with a warning so their headers can be diagnosed.

Exit codes: `0` inspection completed; `1` request/parsing/output error; `2` command-line usage error or missing enforced policy with `--require-csp`.

## TLS probe and header inspection

`--tls` makes a **separate direct TLS handshake** to each HTTPS hop using its hostname/SNI and port. It reports the selected TLS version, cipher suite, ALPN, key-exchange group and leaf fingerprint. It offers TLS 1.2/1.3 and ALPN h2/http/1.1. This is the cipher selected for that probe, **not an enumeration of every cipher or protocol the server supports**. The actual HTTP version is reported independently from the HTTP response.

The direct TLS probe uses system trust roots, `--cacert` and `--insecure`, but does not use HTTP proxy settings or request authentication headers. It can fail on proxy-only networks while the HTTP inspection succeeds. A probe failure is reported as a warning. Load balancing or TLS interception can also produce a different certificate/protocol from the HTTP connection; differing leaf fingerprints are flagged. DNS resolution uses the OS resolver; the probe's connect/handshake timeout starts after DNS resolution.

`--headers` reports headers from a normal GET request, including on redirects and error pages. It requests `Accept-Encoding: identity` and disables automatic decompression so Content-Encoding/Content-Length are not silently removed. If a server still sends compressed HTML, headers remain visible but the HTML CSP meta scan is skipped with a warning. Other inspection modes retain normal decompression. HTTP trailers and headers for subresources loaded by a browser are not included.

## Homebrew and mise distribution

The utility is not published. This directory is a standalone Cargo package; place its contents at the root of a separate repository named `url-inspect` before release. Replace `OWNER` below with your GitHub account or organisation.

### Immediate local installation

From the standalone project root:

```sh
mise exec -- cargo install --path . --locked
url-inspect --version
```

This uses mise to select Rust and installs the executable through Cargo. It is not yet a mise-managed distribution of the utility itself.

### Install through mise from Git (no crates.io publishing required)

Push the standalone repository and create/push a `v0.1.1` tag. Users can then build it from Git using mise's Cargo backend:

```sh
mise use -g rust@stable
mise use -g 'cargo:https://github.com/OWNER/url-inspect@tag:v0.1.1'
url-inspect --version
```

This requires Rust and a linker on the installing machine. For private repositories, users also need Git access through their normal credentials or SSH configuration. Do not put credentials in the URL. A tag selects a version; use a commit revision for an immutable pin.

### Install through mise from prebuilt GitHub releases

For users who should not need Rust installed, publish a GitHub Release with platform-specific archives containing the executable. For example:

```text
url-inspect-v0.1.1-aarch64-apple-darwin.tar.gz
url-inspect-v0.1.1-x86_64-apple-darwin.tar.gz
url-inspect-v0.1.1-x86_64-unknown-linux-musl.tar.gz
```

Each archive should contain `url-inspect` with its executable bit set. The draft-release workflow builds/tests these three targets and attaches checksums. Only the current Mac build has been verified locally; hosted builds run after the project is pushed to GitHub. The separate CI workflow also tests Windows source builds.

Users can then run:

```sh
mise use -g github:OWNER/url-inspect@0.1.1
```

A release tag alone is insufficient for this route: mise needs compatible binary assets attached to the release. No custom mise plugin or central registry entry is required when using the explicit backend name. See the official [Cargo backend](https://mise.jdx.dev/dev-tools/backends/cargo.html) and [GitHub backend](https://mise.jdx.dev/dev-tools/backends/github.html) documentation.

### Optional crates.io and Homebrew distribution

If you later publish the crate under this exact name (check name availability first):

```sh
mise use -g cargo:url-inspect@0.1.1
```

For an initial Homebrew tap, use `packaging/url-inspect.rb.example`. Replace the repository URL and release checksum, then commit it as `Formula/url-inspect.rb` in a tap repository. It builds from source with Cargo; prebuilt binaries can be added later.

## Development

```sh
mise run check
mise run source-archive
```

The source-only archive task needs Python 3 for packaging. Direct Cargo equivalents for checks:

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
