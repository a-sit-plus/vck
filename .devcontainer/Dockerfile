FROM node:24-bookworm-slim

ARG ANDROID_TOOLS_REVISION=15859902
ARG ANDROID_TOOLS_SHA256=4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583
ARG ANDROID_API=34
ARG ANDROID_BUILD_TOOLS=36.0.0

ENV LANG=C.UTF-8 \
    DEVCONTAINER=true \
    EDITOR=nano \
    VISUAL=nano \
    ANDROID_HOME=/opt/android-sdk \
    GRADLE_USER_HOME=/home/node/.gradle \
    disableAppleTargets=true
ENV PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap ca-certificates curl git jq less nano openjdk-17-jdk-headless procps ripgrep tzdata \
        unzip vim \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "$ANDROID_HOME/cmdline-tools" \
    && curl --fail --silent --show-error --location \
        "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_TOOLS_REVISION}_latest.zip" \
        --output /tmp/android-tools.zip \
    && echo "$ANDROID_TOOLS_SHA256  /tmp/android-tools.zip" | sha256sum --check \
    && unzip -q /tmp/android-tools.zip -d /tmp/android-tools \
    && mv /tmp/android-tools/cmdline-tools "$ANDROID_HOME/cmdline-tools/latest" \
    && rm -rf /tmp/android-tools /tmp/android-tools.zip \
    && yes | sdkmanager --sdk_root="$ANDROID_HOME" --install \
        "platform-tools" "platforms;android-${ANDROID_API}" "build-tools;${ANDROID_BUILD_TOOLS}"

RUN install -d -o node -g node -m 0755 "$GRADLE_USER_HOME" \
    && install -d -o node -g node -m 0700 /home/node/.codex

# The agents are installed last, so that bumping a version does not rebuild the
# Android SDK layer. Root owns the global npm prefix, so neither agent can update
# itself; update them by bumping these versions and rebuilding the container.
ARG CODEX_VERSION=0.170.0
RUN npm install --global "@openai/codex@${CODEX_VERSION}" \
    && npm cache clean --force

ARG CLAUDE_CODE_VERSION=2.1.328
RUN npm install --global "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && npm cache clean --force \
    && install -d -o node -g node -m 0700 /home/node/.claude

# The container is the execution boundary, so both agents run without their
# own sandbox and without permission prompts. Root owns both files, so the
# agents cannot change these defaults.
COPY --chmod=0644 claude-managed-settings.json /etc/claude-code/managed-settings.json
COPY --chmod=0644 codex-config.toml /etc/codex/config.toml

USER node
