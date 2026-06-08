# Development

Setup, build, test, and publishing for VC-K. For what the code does see [README.md](README.md); for how it is
organized and where to make changes see [ARCHITECTURE.md](ARCHITECTURE.md).

## Prerequisites

* JDK 17.
* Clone recursively, or at least init and update the `conventions-vclib/gradle-conventions-plugin` submodule
  manually — the build won't load without it.
* Set the path to an Android SDK in `local.properties`, or the project will fail to load.

Build conventions (source sets, targets, publishing) come from the composite build under `conventions-vclib/`
(plugin id `at.asitplus.gradle.vclib-conventions`). Dependency versions are centralized in
`gradle/libs.versions.toml` — **do not** add `kotlinx-serialization` or crypto dependencies manually; they are
provided transitively via [Signum](https://github.com/a-sit-plus/signum) and the conventions plugin.

## Signum composite build

To develop against [Signum](https://github.com/a-sit-plus/signum) — e.g. to test changes there against VC-K
without publishing — clone it into a directory called `signum` beside this repository; `settings.gradle.kts`
then picks it up as a composite build automatically and it takes precedence over the published `signum` artifact
pinned in `gradle/libs.versions.toml`. Remove `../signum` to go back to the published version.

## Building & testing

Tests run on **TestBalloon** (`val Name by testSuite { "..." { ... } }`) with **Kotest** matchers and property
testing (`shouldBe`, `Arb`, `checkAll`). Put credential/serialization tests in `commonTest` so they exercise all
platforms; use `jvmTest` for fast local feedback and JVM-only dependencies.

Prefer module-scoped tasks — the root `compileKotlin` task is **ambiguous** in this multiplatform build (candidates
`compileKotlinJvm`, `compileKotlinIosArm64`, …) and fails on name resolution before showing any source error.
Start narrow, then widen to `:module:check` or `build` once the focused surface is clean.

```bash
./gradlew :vck:jvmTest                       # fastest feedback loop (also :vck-openid:jvmTest, :vck-openid-ktor:jvmTest)
./gradlew :vck:compileKotlinJvm              # quick JVM compile for one module
./gradlew :vck-openid:jvmTest --tests '*OpenId4VpSdJwtProtocolTest*'   # --tests filtering works with TestBalloon
./gradlew :csc-data-classes:check            # full checks for a single module
./gradlew build                              # build everything
```

IDE run configs live under `.run/` (Test VCK / OpenID / KTOR). Set the environment variable
`disableAppleTargets=true` to skip iOS targets for faster local builds on non-Mac machines.

## Publishing

Create a GPG key with `gpg --gen-key`, and export it with `gpg --keyring secring.gpg --export-secret-keys > ~/.gnupg/secring.gpg`. Be sure to publish it with `gpg --keyserver keyserver.ubuntu.com --send-keys <your-key-id>`. See also the information in the [Gradle docs](https://docs.gradle.org/current/userguide/signing_plugin.html).

Create a user token for your Nexus account on <https://s01.oss.sonatype.org/> (in your profile) to use as `sonatypeUsername` and `sonatypePassword`.

Configure your `~/.gradle/gradle.properties`:

```properties
signing.keyId=<last-8-chars>
signing.password=<private-key-password>
signing.secretKeyRingFile=<path-of-your-secring>
sonatypeUsername=<user-token-name>
sonatypePassword=<user-token-password>
```

To run the pipeline from GitHub, export your GPG key with `gpg --export-secret-keys --armor <keyid> | tee <keyid>.asc` and set the following environment variables:

```shell
ORG_GRADLE_PROJECT_signingKeyId=<last-8-chars>
ORG_GRADLE_PROJECT_signingKey=<ascii-armored-key>
ORG_GRADLE_PROJECT_signingPassword=<private-key-password>
ORG_GRADLE_PROJECT_sonatypeUsername=<user-token-name>
ORG_GRADLE_PROJECT_sonatypePassword=<user-token-password>
```

Actually, these environment variables are read from the repository secrets configured on Github.

Publish with:

```shell
./gradlew clean publishToSonatype
```

To also release the artifacts to Maven Central run:

```shell
./gradlew clean publishToSonatype closeAndReleaseSonatypeStagingRepository
```

To publish locally for testing, one can skip the signing tasks:

```shell
./gradlew clean publishToMavenLocal -x signJvmPublication -x signKotlinMultiplatformPublication -x signIosArm64Publication -x signIosSimulatorArm64Publication -x signIosX64Publication
```
