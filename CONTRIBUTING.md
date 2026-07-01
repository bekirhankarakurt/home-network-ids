# Contributing

Thanks for your interest in improving home-network-ids.

## Development setup

```bash
git clone https://github.com/bekirhankarakurt/home-network-ids
cd home-network-ids
cargo test
```

The minimum supported Rust version is **1.85**. Live capture tests need no
privileges; anything that opens a raw socket is exercised manually.

## Before opening a pull request

Run the same checks as CI:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo +1.85 test
```

- Keep commits small, with imperative subject lines ("Add X", "Fix Y").
- Add or update tests for every behaviour change. Parser changes need a
  property test in `tests/parser_props.rs`.
- New `unsafe` code is only accepted for FFI that cannot be avoided, and each
  block needs a `// SAFETY:` comment.
- Dependencies must be well known and pass `cargo deny check`.

## Fixtures

Pcap fixtures in `tests/fixtures/` are generated, never edited by hand:

```bash
cargo run --example gen_fixtures
```

To add a scenario, write a generator in `src/synth.rs`, add it to `FIXTURES`,
regenerate, and assert the expected alerts in `tests/fixtures.rs`.

## Adding a detector

1. Implement `detect::Detector` in a new module under `src/detect/`.
2. Add its configuration section to `src/config.rs` and `hnids.example.toml`.
3. Register it in `Engine::from_config`.
4. Document its alert kinds in the README rules table and in `CHANGELOG.md`.

## Reporting issues

Use the issue templates. For security problems, follow [SECURITY.md](SECURITY.md).
