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
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — contribution process, branching, and the CLA.

Keep documentation in those files; do not duplicate it here.

Agent-only operating notes:

- Treat dirty worktree changes as user work. Do not revert, overwrite, or clean them up unless explicitly asked.
- For Kotlin refactors, prefer symbol-aware navigation through IDEA MCP / Kotlin LSP when available.
