# Project Roadmap

This roadmap outlines the planned evolution of seed.security. Timelines are indicative and may change based on community needs and maintainer capacity.

## Short term (0-1 releases)

- Packaging hygiene
  - Fix/standardize package icon path and CI packaging
  - Provide a minimal NuGet publishing workflow (manual or CI)
- Test coverage
  - Add tests using official SEED-128 test vectors (ECB and CBC)
  - Add negative tests for padding and malformed inputs
- Documentation
  - Add usage examples for ECB/CBC with/without padding
  - Clarify encoding guidance and cross-platform considerations

## Mid term (1-3 releases)

- API hardening
  - Consistent string encoding (UTF-8 default) across helpers
  - Non-breaking deprecation path for Encoding.Default usages
- Performance
  - Optimize block processing with Span<T>/Memory<T>
  - Benchmark suite and micro-optimizations
- Developer experience
  - Add simple benchmarks and a sample test harness project
  - Provide a test vector CLI utility (encrypt/decrypt against given vectors)

## Long term

- Extended algorithms/modes (if in scope)
  - Consider adding CTR mode helper (stream-like) when appropriate
  - Pluggable padding strategies
- Compliance/interop
  - Add interop tests with reference implementations
  - Optional KCMVP-related guidance (documentation only)
- Tooling
  - CI linting/build/test matrix for Windows/Linux/macOS
  - Release automation with changelog generation

## Stretch goals (nice to have)

- SourceLink and symbol packages
- Strong-naming option (if requested by consumers)
- Minimal web demo or notebook showcasing usage and test vector validation

## Out of scope (for now)

- Hardware acceleration (AES-NI-like) — unless the .NET JIT adds relevant intrinsics that benefit SEED
- Cryptographic protocol features (TLS, PKI) — this library focuses on the block cipher
