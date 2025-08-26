# Task Board

Live-tracking of tasks can move to GitHub Issues/Projects. This file provides a curated backlog to bootstrap contributions.

## Backlog

- Fix package icon path or disable packing for local builds
- Add unit tests for official test vectors (ECB/CBC, with/without padding)
- Add round-trip tests for string helpers with explicit UTF-8 encoding
- Provide a sample verifying CBC chaining vs. vectors
- Add README section: troubleshooting common build issues
- Evaluate replacing Encoding.Default with UTF-8 (non-breaking plan)
- Add a lightweight benchmark (e.g., BenchmarkDotNet) for block throughput

## In progress

- [ ] Update README with English-only guarantee and compliance note (done)
- [ ] Expand docs/seed-specs references with summaries (done)

## Up next

- [ ] Add test project for vector-based validation
- [ ] CLI tool to encrypt/decrypt using provided key/IV/plaintext (for validation)

## Done

- [x] English-only README with background/compliance
- [x] Specs/test vector documentation added
