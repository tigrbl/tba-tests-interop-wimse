#!/usr/bin/env bash
# Fetch immutable public runtime assets once for the hosted Ubuntu matrix.
set -euo pipefail

root=$1
mkdir -p "$root"/{release,deno}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

fetch() {
    curl --fail --silent --show-error --location --retry 3 --max-time 180 "$1" --output "$2"
    printf '%s  %s\n' "$3" "$2" | sha256sum --check
}
release=agentmaurice-one-2.2.18-linux-amd64
fetch "https://github.com/agentmaurice/maurice/releases/download/v2.2.18/$release.tar.gz" "$scratch/release.tar.gz" \
    72dd1b1a719e3a3fa63d348fe211b8bc9fff2139a52fac994789cc45e480b101
fetch 'https://registry.npmjs.org/@deno/linux-x64-glibc/-/linux-x64-glibc-2.9.6.tgz' "$scratch/deno.tgz" \
    a6596af07f3570b4f1ffa6783bfee9942aac14a719a601baa6bf5b71bf0105e2
tar -xzf "$scratch/release.tar.gz" -C "$root/release" --strip-components=1 \
    "$release/maurice" "$release/sandbox-worker"
tar -xzf "$scratch/deno.tgz" -C "$root/deno" --strip-components=1 package/deno
