## What this changes

<!-- One or two sentences. What is different after this merges. -->

## Why

<!-- The problem, not the solution. If this fixes a wrong answer, say what the
     wrong answer was. -->

## Evidence

<!-- For a control: the primary vendor source and the exact claim it supports.
     For a fix: how you know it was wrong, and how you know it is right now. -->

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo deny check`
- [ ] Tests cover the failure path, not only the success path
- [ ] No unknown, denied, or unsupported state can be reported as compliant
- [ ] No emoji, no em dashes, no attribution to any tool or assistant
