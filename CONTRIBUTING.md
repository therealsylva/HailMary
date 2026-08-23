# Contributing

Changes should preserve HailMary's core invariants:

- No interactive or arbitrary remote shell
- No action executes unless it is typed and locally allowlisted
- No signature or encryption bypass for convenience
- No automatic replay of an execution left in an uncertain state
- No unbounded file, frame, log or artifact processing
- No shell interpolation for command profiles

Before submitting a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --locked
cargo doc --no-deps --document-private-items
```

Security-sensitive changes should include negative tests for tampering, malformed input and authorization failure.
