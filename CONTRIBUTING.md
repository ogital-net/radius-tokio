# Contributing to radius-tokio

## Architecture at a glance

`radius-tokio` is a **library**, not a daemon — there is no `main`, no
config file, and no global state. Consumers construct a `Server`,
plug in two traits (`ClientStore` and `Handler`), and drive it from
their own Tokio runtime. The source tree mirrors that split:

- `src/codec/` — zero-copy wire decode, typed attribute encode, reply
  sealing. No I/O, no allocation on the hot read path.
- `src/crypto/` — safe wrappers over `aws-lc-sys` for MD5, HMAC-MD5,
  HMAC-SHA*, AES, DES, RNG, and the RadSec `SSL` layer. Every
  `unsafe` block is FFI-only and carries a `// SAFETY:` comment.
- `src/server/` — transport (UDP, RadSec/TCP+TLS), admission gating,
  dedup + retransmit cache, dispatch pipeline, CoA originator,
  Status-Server responder, graceful shutdown.
- `src/auth/` — PAP / CHAP / MS-CHAPv2 / EAP-MD5 helpers that
  handlers can call; the library never makes the auth decision
  itself.
- `crates/radius-tokio-dict/` + `crates/radius-tokio-dict-codegen/` — RFC and
  vendor dictionaries, parsed at build time into typed attribute
  handles.

The `Server` owns every wire- and protocol-level detail (decode,
dedup, authenticator verification, reply seal, mTLS). Consumer code
owns the policy (“who is this peer?”, “what should I send back?”).
Keep that boundary intact when proposing changes — anything that
leaks sockets, secrets, or authenticators into the `Handler` surface
should get scrutinised hard.

For performance budgets and the methodology used to validate them,
see [`BENCHMARKS.md`](BENCHMARKS.md).

## Development prerequisites

- Rust **1.83** or later (pinned via `rust-version` in each `Cargo.toml`).
- Native build deps for `aws-lc-sys` when the `radsec` feature is on:
  - **Linux:** `cmake`, `clang`, `libclang-dev`
  - **macOS:** `cmake` (via Homebrew)
  - **Windows:** `cmake` (preinstalled on `windows-latest`) + NASM
- Optional, for the e2e integration tests under `tests/`:
  `freeradius`, `eapoltest`, `radsecproxy` (Linux packages; the tests
  self-skip when the binaries aren't on `PATH`).
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny):
  `cargo install cargo-deny`
- [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)
  for local coverage runs: `cargo install cargo-llvm-cov`

## Building

`Cargo.lock` is committed (this is a library, but committing the
lockfile keeps CI and contributor builds reproducible — particularly
across the MSRV cell, where transitive bumps to `edition2024` would
otherwise break the build whenever crates.io ships a new minor).
Always pass `--locked` so a stray dependency change fails loudly:

```sh
cargo build --workspace --locked
cargo test --workspace --all-features --locked
```

## Lints

All lints are enforced in CI. Before pushing, run:

```sh
cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

The crate enforces:

- `unsafe_op_in_unsafe_fn = "deny"` — every `unsafe` call inside an
  `unsafe fn` must carry its own `unsafe` block with a `// SAFETY:`
  comment.
- `missing_docs = "warn"` — all public items must be documented.
- `clippy::pedantic = "warn"` — pedantic lints active; use
  `#[allow(...)]` with a comment when suppressing.

## Safety

`unsafe` is permitted when it yields a measurable performance win or
is required to call into `aws-lc-sys`. Every `unsafe` block must:

1. Have a `// SAFETY:` comment explaining the invariants that make it
   sound.
2. Be covered by unit tests.
3. Be exercised under AddressSanitizer (the `asan` CI job runs against
   `src/crypto/`, which is where every `unsafe` block in the workspace
   currently lives).
4. Be isolated behind a safe public API.

Miri is **not** run: every `unsafe` block in the workspace reaches
`aws-lc-sys` (foreign functions are unsupported by miri), and the
pure-Rust workspace members have no `unsafe`.

## Adding dependencies

Dependencies must be justified in `Cargo.toml` with a comment. Prefer
the standard library and `tokio`. Do not add crates just for
convenience — weigh the maintenance and license burden. Run
`cargo deny check` after any change to `Cargo.toml`. If a new
transitive forces a license not on the allow-list in `deny.toml`,
either add the SPDX identifier with a comment explaining the dep, or
choose a different crate.

## Adding a vendor dictionary

Vendor and RFC dictionaries are vendored under
`crates/radius-tokio-dict/dictionaries/` and compiled into typed Rust at
build time by the `radius-tokio-dict-codegen` crate. To add a new vendor:

1. **Drop the dictionary file in place.** Copy the FreeRADIUS-format
   dictionary into `crates/radius-tokio-dict/dictionaries/vendor/`,
   keeping the upstream `dictionary.<vendor>` filename. If it
   `$INCLUDE`s other files, vendor those alongside it.
2. **Verify the license.** FreeRADIUS dictionaries are typically
   BSD/ISC/permissive. If the upstream license is anything else,
   stop and discuss before merging — see `deny.toml` for the
   acceptable set.
3. **Register a feature flag and codegen entry.**
   - Add `dict-<vendor> = []` to the `[features]` table in
     `crates/radius-tokio-dict/Cargo.toml` and append the same name to the
     `dict-vendor-all` umbrella.
   - Mirror both lines in the root `Cargo.toml`, where
     `dict-<vendor>` forwards to `radius-tokio-dict/dict-<vendor>`.
   - Add a `Group { feature, module, entry }` row to `GROUPS` in
     `crates/radius-tokio-dict/build.rs`. The `module` becomes the
     submodule name under `radius_tokio_dict::*`; the `entry`
     is the path of the dictionary file relative to
     `CARGO_MANIFEST_DIR`.
4. **Build with the feature on:**
   ```sh
   cargo build -p radius-tokio-dict --features dict-<vendor>
   cargo test  -p radius-tokio-dict --features dict-<vendor>
   ```
   The build script writes the generated Rust into `OUT_DIR`; output
   is deterministic (sorted, no timestamps), so two clean builds
   produce byte-identical files.
5. **Snapshot test.** The existing snapshot test in `radius-tokio-dict`
   re-runs codegen and asserts byte-equality across runs; it will
   pick up the new dictionary automatically once the feature is on.

The library itself never special-cases a vendor — VSAs are routed
through the generated tables, so adding a new vendor is purely an
ergonomics change for consumers, not a behaviour change for the
server runtime.

## Testing

- Unit tests live next to the code they test (`#[cfg(test)]` module
  in each file).
- Integration tests live in `tests/`. The ones that drive external
  RADIUS tooling (`radclient_e2e`, `radsec_e2e*`,
  `eapol_test_mschapv2`) self-skip when the corresponding binaries
  aren't on `PATH`, so the suite stays green on developer machines
  without `freeradius` / `radsecproxy` / `eapol_test` installed.
- Property tests use `proptest`.
- Benchmarks use Criterion and live in `benches/`.

Run the full suite locally:

```sh
cargo test --workspace --all-features --locked
cargo deny check
```

To exercise the e2e tests, install the relevant tooling
(`apt install freeradius eapoltest radsecproxy` on Debian/Ubuntu)
and rerun.

### Coverage

```sh
cargo llvm-cov --workspace --all-features --summary-only
cargo llvm-cov --workspace --all-features --html  # browse target/llvm-cov/html
```

CI runs the same command via `.github/workflows/coverage.yml` and
uploads `lcov.info` as a build artifact.

## CI

GitHub Actions runs on every push and pull request
(`.github/workflows/ci.yml`):

| Job              | Toolchain          | Notes                                       |
| ---------------- | ------------------ | ------------------------------------------- |
| `fmt`            | stable             | `cargo fmt --check`                         |
| `clippy`         | stable             | `--workspace --all-features --all-targets`  |
| `docs`           | stable             | rustdoc with `-D warnings`                  |
| `test`           | stable + 1.83 MSRV | Linux x86_64, macOS aarch64, Windows MSVC   |
| `asan`           | nightly            | AddressSanitizer over `src/crypto/`         |
| `cargo-deny`     | stable             | licenses, advisories, bans, sources         |
| `publish_dryrun` | stable             | `cargo publish --dry-run` for codegen crate |

Coverage runs in a separate workflow (`.github/workflows/coverage.yml`).
All jobs must pass before merging.

## Commit style

Use short, imperative subject lines (`Add codec round-trip fuzz
target`).
