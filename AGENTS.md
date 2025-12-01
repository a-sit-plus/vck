# Repository Guidelines

VC-K is a Kotlin Multiplatform workspace that packages reusable credential agents. Follow the practices below to extend modules without breaking JVM, Android, iOS, or server consumers.

## Project Structure & Module Organization
- `vck/` hosts the core wallet, holder, verifier, and issuer agent APIs. Keep cross-platform utilities here under `src/commonMain` and add platform overrides under the respective `*Main` folders.
- Protocol extensions live in sibling modules (`vck-openid`, `vck-openid-ktor`, `vck-rqes`, `mobile-driving-licence-credential`). Data-only packages reside in `*-data-classes`. Shared Gradle conventions sit in `conventions-vclib/`.
- Tests accompany each module inside `src/commonTest`, `src/jvmTest`, etc., while performance experiments and regression datasets live in `metrics/`. Local Maven artifacts are staged in `repo/` (never commit its contents).

## Build, Test, and Development Commands
- `./gradlew clean build` – run the full multiplatform build (compilation + tests) for every module.
- `./gradlew :vck:check` – targeted verification when touching the core library; prefer per-module `:module:check` for quick feedback.
- `./gradlew publishToMavenLocal -x signKotlinMultiplatformPublication` – publish artifacts into your local repo for integration testing without requiring signing keys.
- `./gradlew :vck-openid-ktor:iosTest` (or `:jvmTest`) – execute platform-specific suites when modifying expect/actual implementations.

## Coding Style & Naming Conventions
Adhere to the official Kotlin style guide: four-space indentation, `UpperCamelCase` for types, `lowerCamelCase` for members, and descriptive package names that mirror the protocol (e.g., `openid4vp`). Keep constructor parameters explicit, favor extension functions over util classes, log through Napier, and mark public removals with `@Deprecated` so Swift bindings stay stable.

## Testing Guidelines
Tests use TestBalloon; structure specs with `context/should` blocks and prefer deterministic fixtures under `src/commonTest/resources`. Tests are all to be implemented in `commonMain`. Platform specific tests are automatically implemented via Kotlin Multiplatform. Aim to touch issuer, holder, and verifier paths for every new credential type. Run `./gradlew allTests` before opening a PR.

## Commit & Pull Request Guidelines
Recent commits follow short, imperative subjects (`Remove StatusListTokenValidator`). Keep bodies for rationale and breaking-change notes. PRs target `develop`, include a summary of affected modules, linked issues, screenshots for verifier UI outputs if applicable, and confirmation that CLA + tests passed. Rebase rather than merge from main branches, and request reviews from owners of any module you touched.

## Security & Configuration Tips
Store mutable configuration in `local.properties`; Secrets such as Sonatype or signing credentials belong in your global `~/.gradle/gradle.properties` or environment variables, never in version control.
