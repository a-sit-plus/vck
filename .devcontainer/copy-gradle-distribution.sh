#!/bin/sh
# Copies the Gradle distribution that the checkout's wrapper names from the read-only cache into the Gradle
# User Home of the container, unless it is already there. The wrapper takes a lock in the directory of its
# distribution, so it cannot use the read-only copy in place. Without a cached copy, the wrapper downloads
# the distribution as usual.
set -eu

properties=${1:-gradle/wrapper/gradle-wrapper.properties}
cache=${GRADLE_RO_DEP_CACHE:-/opt/gradle-ro-cache}/wrapper/dists
target=${GRADLE_USER_HOME:-$HOME/.gradle}/wrapper/dists

[ -f "$properties" ] || exit 0
name=$(sed -n 's#^distributionUrl=.*/\(gradle-[0-9A-Za-z.-]*\)\.zip$#\1#p' "$properties")
if [ -z "$name" ] || [ ! -d "$cache/$name" ] || [ -e "$target/$name" ]; then
    exit 0
fi

mkdir -p "$target"
rm -rf "$target/$name.partial"
cp -R "$cache/$name" "$target/$name.partial"
mv "$target/$name.partial" "$target/$name"
echo "Copied the Gradle distribution $name from the read-only cache."
