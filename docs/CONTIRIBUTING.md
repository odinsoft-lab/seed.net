# Contributing Guide

Thanks for your interest in contributing to seed.security!

This document explains how to propose changes, build and test locally, and submit pull requests in a way that keeps the project stable and easy to maintain.

## Ground rules

- Be respectful and constructive in discussions and reviews.
- Prefer small, focused PRs over large, mixed changes.
- Write clear commit messages and PR descriptions.
- Keep Markdown docs in English.
- Do not commit secrets or credentials.

## Where to start

- Good first issues: documentation improvements, unit tests for official test vectors, build/packaging fixes.
- For larger features, open an issue first to discuss scope and design.

## Branching & PRs

- Default branch: `main` (protected).
- Create feature branches from `main`: `feature/<short-description>` or `fix/<short-description>`.
- Open a PR to `main`. Include:
  - Rationale and scope
  - Summary of changes
  - Tests (when applicable)
  - Any backward-compatibility notes

## Commit messages

Use a concise, imperative style, e.g.:
- "Fix icon path for local packing"
- "Add CBC test vectors and unit tests"

If you prefer Conventional Commits, it is welcome but not required.

## Development setup

- Build the library (project-level build is recommended):
  - `src/Seed128/seed128.csproj`
- Run the console example:
  - `tests/Seed128.Test/seed128.Test.csproj`

Note on local build failures:
- `seed128.csproj` packs an icon from `..\\..\\doc\\odinsoft-symbol.png`, while the repo contains `docs/logo-files/odinsoft-logo.png`.
  - Options:
    1) Disable packing (`GeneratePackageOnBuild=False`)
    2) Update the icon path to the existing file and fix the ItemGroup
    3) Add `doc/odinsoft-symbol.png`
- The solution file may reference outdated paths; building projects individually is a reliable workaround.

## Testing

- Please add unit tests for new behavior.
- Validate the cipher with the official test vectors under `docs/seed-specs/[5]_SEED+128_Test_Vector_M.pdf`.
  - Cover ECB and CBC, with and without padding as appropriate.
  - Compare byte-for-byte results.

## Coding style

- C# code should be clean, readable, and safe by default.
- Use explicit encoding when converting strings (prefer UTF-8).
- Avoid API-breaking changes. If necessary, discuss first.
- Performance improvements are welcome (e.g., Span<T>) but must include benchmarks and tests.

## Documentation

- Keep `README.md` consistent and in English.
- Add or update docs under `docs/` where helpful (do not modify the PDF spec files).

## Security

- For potential security issues, please report privately first. Avoid disclosing details in public issues.

## License

By contributing, you agree that your contributions will be licensed under the MIT License used by this project.
