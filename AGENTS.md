# AGENTS.md — VC-K

VC-K is a Kotlin Multiplatform library for verifiable credentials (W3C VC, SD-JWT VC, ISO mDoc/mDL) and the OpenID
protocol family (OpenID4VCI, OpenID4VP), built for the EU Digital Identity Wallet ecosystem.

All documentation for humans and agents lives in the files below — read the relevant one before starting:

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — module boundaries, where each responsibility lives, the
  implementing-features flow, refactoring rules, and conventions (DI style, Signum/KmmResult, wire-class rules).
  Start here for any code change.
- **[DEVELOPMENT.md](DEVELOPMENT.md)** — setup prerequisites, building, testing (commands, the TestBalloon/Kotest
  stack, the optional `../signum` composite build, the root-`compileKotlin` caveat), and publishing.
- **[README.md](README.md)** — what VC-K is, features, supported standards, and which artifact to depend on.
- **[CHANGELOG.md](CHANGELOG.md)** — release-specific API changes, removals, deprecations, and migration notes. Check it
  before changing or reusing a public entry point.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — contribution process, branching, and the CLA.

Keep documentation in those files; do not duplicate it here.

Agent-only operating notes:

- Treat dirty worktree changes as user work. Do not revert, overwrite, or clean them up unless explicitly asked.
- When a VC-K build that includes the `../signum` composite build fails, verify that both projects use the same
  conventions-plugin version. Update whichever project uses the older version, then apply every upgrade or migration
  introduced by that conventions-plugin version to both VC-K and the current consuming project before diagnosing the
  build further.
- For Kotlin refactors, prefer symbol-aware navigation through IDEA MCP / Kotlin LSP when available.
- Do not infer current protocol support from deprecated compatibility types, or feature completeness from
  preparation-only abstractions such as the ISO mDoc ZKP types. Confirm the active path in `ARCHITECTURE.md`, the
  implementation, and its tests before extending it.
