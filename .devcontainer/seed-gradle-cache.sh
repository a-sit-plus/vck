#!/bin/sh
# Seeds the Docker volume gradle-ro-cache, which every Dev Container mounts read-only, from the Gradle User
# Home of this host: the dependency cache modules-2 and the wrapper distributions. Run it on the host from
# the primary checkout, never from an agent clone, while no Dev Container runs.
#
# Gradle reads a read-only dependency cache without locks, so it must be a copy without lock files that
# does not change while builds read it, never a live Gradle User Home:
# https://docs.gradle.org/current/userguide/dependency_caching.html#sec:shared-readonly-cache
set -eu

volume=gradle-ro-cache
gradle_home=${GRADLE_USER_HOME:-$HOME/.gradle}

if [ ! -d "$gradle_home/caches/modules-2" ]; then
    echo "There is no dependency cache in $gradle_home/caches/modules-2. Build a project on this host first." >&2
    exit 1
fi
if [ -n "$(docker ps --quiet --filter "volume=$volume")" ]; then
    echo "Stop every Dev Container first: builds in them read $volume without locks." >&2
    exit 1
fi
if pgrep -f org.gradle.launcher.daemon.bootstrap.GradleDaemon >/dev/null 2>&1; then
    echo "Warning: Gradle daemons run on this host. If a build changes the cache during the copy, seed again." >&2
fi

# Mount only the two directories, never the whole Gradle User Home: its gradle.properties may hold secrets.
set -- --mount "type=bind,source=$gradle_home/caches/modules-2,target=/source/modules-2,readonly"
if [ -d "$gradle_home/wrapper/dists" ]; then
    set -- "$@" --mount "type=bind,source=$gradle_home/wrapper/dists,target=/source/dists,readonly"
fi

# The base image of the Dev Container is already present, and root owns the copy, so that no container can
# change it even if a container mounted the volume writable.
docker run --rm "$@" --mount "type=volume,source=$volume,target=/cache" node:24-bookworm-slim sh -euc '
    rm -rf /cache/modules-2 /cache/wrapper
    cp -R /source/modules-2 /cache/modules-2
    find /cache/modules-2 \( -name "*.lock" -o -name gc.properties \) -delete
    if [ -d /source/dists ]; then
        mkdir -p /cache/wrapper
        cp -R /source/dists /cache/wrapper/dists
    fi
    chmod -R u=rwX,go=rX /cache
    du -sh /cache/modules-2 /cache/wrapper 2>/dev/null || true
'
echo "Seeded the Docker volume $volume."
