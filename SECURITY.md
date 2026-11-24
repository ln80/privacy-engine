# Security policy

## Reporting a vulnerability

Report privately through GitHub:
[Report a vulnerability](https://github.com/ln80/privacy-engine/security/advisories/new).
Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Include the affected version, what an attacker gains, and a reproduction if
you have one. We aim to acknowledge a report within 7 days and to agree a
disclosure date with you once a fix is ready. Reporters are credited in the
advisory unless they ask not to be.

## Supported versions

Until v1, only the latest minor release receives security fixes. Upgrade to
it to get a fix; earlier minors are not patched.

## Scope

In scope:

- the `privacy`, `core`, `aes` and `memory` packages;
- the specifications in [`docs/`](docs/): a flaw in a format or protocol is a
  vulnerability even when the code follows the spec;
- the `privacytest` conformance suites, when they pass a backend that breaks
  a requirement they claim to check.

Out of scope:

- key and token engines you implement yourself. The library cannot protect
  data whose keys your backend stores in plaintext or exposes to the wrong
  principals;
- the `memory` engines used in production. They keep keys in process memory
  and lose them on restart; they exist for tests and examples;
- vulnerabilities in the Go toolchain or dependencies, unless this module
  uses the affected code. Report those upstream.

## Security status

The library has not had an independent security review. Its cryptography
uses Go's standard library and `golang.org/x/crypto` and does not implement
primitives of its own, but its constructions, formats and erasure guarantees
have only been reviewed by their authors. Assess it accordingly before
relying on it for regulated data.
