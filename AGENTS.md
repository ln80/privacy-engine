# Notes for coding agents

## Using this library in another project

Start at [docs/README.md](docs/README.md). To build a backend, follow
[docs/implementing-backends.md](docs/implementing-backends.md) and pass the
`privacytest` suite against real storage. Use the `memory` engines in tests
only.

The skills in [skills/](skills/) package these workflows:
`privacy-engine-integrate` and `privacy-engine-backend`. Install them with
`npx skills add ln80/privacy-engine`.

## Working on this repository

| Command | Does |
|---|---|
| `make test` | Unit tests with `-race` |
| `make lint` | golangci-lint |
| `make security` | gosec and govulncheck |
| `make fuzz FUZZTIME=30s` | Every fuzz target |

Run with `GOWORK=off` if a parent `go.work` exists.

Rules:

- **Skills follow the docs.** A change to a requirement, an option or the
  public API updates `skills/` in the same commit. Skills point to `docs/`
  instead of repeating it.
- **Specs are normative.** A change to behaviour, a format or a contract
  updates the document in `docs/` in the same commit. Requirement IDs are
  never renumbered or reused.
- **The API is stable by rule.** Never add a method to an interface users
  implement; add an optional interface. See
  [api-stability.md](docs/api-stability.md).
- **Formats are permanent.** Never change the meaning of a stored identifier
  (`alg`, stream version, vault byte, HKDF label). See
  [wire-format.md §8](docs/wire-format.md#8-versioning-and-compatibility).
- **No secrets in output.** Keys, plaintext, token values, sealed values and
  blind indexes never go into errors, logs or test failure messages.
- **Fail closed.** On doubt (unknown version, failed authentication, failed
  audit before a reveal) return an error, never data.
- **No new dependencies** without a reason stated in the commit.
- Wrap errors with `fmt.Errorf("%w: %w", ...)`; errors name field paths,
  never values.
