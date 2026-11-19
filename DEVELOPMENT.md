# Development

Setup, build, test, and publishing for VC-K. For what the code does see [README.md](README.md); for how it is
organized and where to make changes see [ARCHITECTURE.md](ARCHITECTURE.md).

## Prerequisites

* JDK 17.
* Set the path to an Android SDK in `local.properties`, or the project will fail to load.

Build conventions (source sets, targets, publishing) come from the composite build under `conventions-vclib/`
(plugin id `at.asitplus.gradle.vclib-conventions`). Dependency versions are centralized in
`gradle/libs.versions.toml` — **do not** add `kotlinx-serialization` or crypto dependencies manually; they are
provided transitively via [Signum](https://github.com/a-sit-plus/signum) and the conventions plugin.

## Dev Container

The [Dev Container configuration](.devcontainer/devcontainer.json) provides JDK 17, the Android build SDK,
Codex CLI, and Claude Code. Building the image automatically accepts the Android SDK license. You can run
JVM tests and build the Android library in the container. The image disables Apple targets and does not
include an Android emulator.

From the root of a regular Git checkout, with Docker running and Node.js and npm installed on the host, run
the following commands. The second command opens a shell in the container at `/workspaces/vck`.

```sh
npx --yes @devcontainers/cli@0.90.0 up --workspace-folder .
npx --yes @devcontainers/cli@0.90.0 exec --workspace-folder . bash
```

In that shell, run `./gradlew :vck:jvmTest` or launch either coding agent. The container is the execution
boundary: the image configures both agents to run without their own sandbox and without permission prompts.
Root owns these settings in `/etc/claude-code/managed-settings.json` and `/etc/codex/config.toml`, so the
agents cannot change them. Root also owns both agent installations, so neither agent can update itself. To
update an agent, bump `CODEX_VERSION` or `CLAUDE_CODE_VERSION` in the
[Dockerfile](.devcontainer/Dockerfile) and rebuild the container.

- **Codex**. Run `codex login --device-auth` once and follow the browser instructions. Start a session with
  `codex`.
- **Claude Code**. Run `claude` and follow the first-run sign-in prompt.

The container mounts the entire checkout with write access, including untracked and ignored files. Use a
dedicated clone for the agents and treat it as untrusted on the host: agents can change build scripts, Git
configuration, and hooks, which run with your permissions when a host tool builds or runs Git in that
directory. Run every build, Gradle sync, and Git command for that clone inside the container, and follow
the agents' work in one of these ways:

- **In the agent session**. Review each change in the Codex or Claude Code session, or ask the agent for
  `git diff`, and let the agent commit. This needs no IDE on the clone and is the simplest option.
- **IntelliJ IDEA**. Use Remote Development, not native mode, because native mode runs the IDE and its
  plugins on the host. In **Settings | Advanced Settings | Dev Containers**, clear **Open devcontainer
  projects natively**. Then open the clone with **File | Remote Development | Dev Containers**, select its
  `devcontainer.json`, and mount the local sources. IDEA downloads an IDE backend into the container, and the
  backend and the Gradle sync run there. If you open the clone as a local project by mistake, choose
  **Preview in Safe Mode** when IDEA asks whether to trust it.

  IDEA forwards your SSH agent into the container and asks on the host which key to use whenever a process
  in the container requests one. Neither the agents nor Gradle need SSH keys there, so cancel every key
  prompt that you did not trigger yourself, and never let IDEA remember a key choice. IDEA also copies your
  global Git configuration, so commits in that container carry your name and email. Start the agents in
  the container of the Dev Container CLI instead of IDEA's terminal: that container has no SSH agent
  socket, and both containers share the checkout and the agents' sign-ins.

  The IDE backend runs as the same user as the agents, so the agents can change it like any other file in
  the container. IDEA keeps its backends in the Docker volume `jb_devcontainers_shared_volume`, which every
  JetBrains Dev Container mounts. To start from a clean backend, remove the volume with
  `docker volume rm jb_devcontainers_shared_volume` while no Dev Container runs.
- **Emacs and Magit**. Open the files through TRAMP, for example `/docker:node@<container>:/workspaces/vck/`,
  so that Magit runs Git in the container.

To take agent work into your primary checkout, fetch it from there, for example
`git fetch ../vck-agent <branch>`. Fetching runs nothing from the agent clone. Review the diff in your
primary checkout before you build, especially changes to `*.gradle.kts`, `gradle/`, `gradle.properties`,
`gradlew`, and `conventions-vclib/`. Diffs shown inside the container come from the agents' environment,
so this host-side review is the one to rely on.

Docker volumes keep the Gradle cache and both agents' sign-ins across container rebuilds. The sign-in
volumes `vck-codex` and `vck-claude` have fixed names, so the containers that the Dev Container CLI and IDEA
create share them, and you sign in once per machine. Each container gets its own Gradle cache volume, so
the CLI and IDEA containers each download the Gradle distribution and dependencies once.

Root owns the Android SDK in the image, so Gradle cannot install missing SDK packages. If a build reports
that it could not install one, add the package to the `sdkmanager` command in the
[Dockerfile](.devcontainer/Dockerfile) and rebuild the container.

The supplied configuration mounts no host home directory, SSH agent socket, or Docker socket; only IDEA
adds the forwarding described above. The sibling Signum checkout is outside the mount, so the container uses
the published Signum dependency by default.

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
