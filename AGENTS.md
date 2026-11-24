# Notes for coding agents

## Using this library in another project

Read [docs/README.md](docs/README.md) first; it maps tasks to documents. To
build a backend, follow [docs/implementing-backends.md](docs/implementing-backends.md)
and make the `privacytest` conformance suite pass against real storage.
Never use the `memory` engines outside tests.

## Working on this repository

| Command | Does |
|---|---|
| `make test` | Unit tests with `-race` |
| `make lint` | golangci-lint |
| `make security` | gosec and govulncheck |
| `make fuzz FUZZTIME=30s` | Every fuzz target |

Run with `GOWORK=off` if a parent `go.work` exists.

Rules:

- **Specs are normative.** A change to behaviour, a format or a contract
  updates the document in `docs/` in the same commit. Requirement IDs are
  never renumbered or reused.
- **Formats are permanent.** Never change the meaning of a stored identifier
  (`alg`, stream version, vault byte, HKDF label). See
  [wire-format-v2.md §9](docs/wire-format-v2.md#9-versioning-and-compatibility).
- **No secrets in output.** Keys, plaintext, token values, sealed values and
  blind indexes never go into errors, logs or test failure messages.
- **Fail closed.** On doubt (unknown version, failed authentication, failed
  audit before a reveal) return an error, never data.
- **No new dependencies** without a reason stated in the commit.
- Wrap errors with `fmt.Errorf("%w: %w", ...)`; errors name field paths,
  never values.
