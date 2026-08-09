# Contributing

Contributions that improve safe parsing, format coverage, tests, documentation, and defensive research workflows are welcome.

Before submitting a change:

1. Confirm that you are legally allowed to share every line and test fixture.
2. Do not submit proprietary or real-world protected archives. Prefer small synthetic fixtures.
3. Keep target code inert: no native loading, host import resolution, entry-point calls, or unrestricted emulation.
4. Add bounds and truncation checks to new parsers.
5. Run the complete quality suite:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo run -- self-test
```

By contributing, you confirm that you have the right to submit the contribution and accept the contribution terms in the project license.
