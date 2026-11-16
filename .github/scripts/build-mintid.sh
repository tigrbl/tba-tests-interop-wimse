#!/usr/bin/env bash
# Build the published MintID source revision once. Runners load these same images.
set -euo pipefail
runtime=$1
vendor="$runtime/vendor"
revision=dca3d605b7a1d559ef74c444498552f64c9c8285
release=public-v2026-11-13.1
tag=tba-interop
mkdir -p "$runtime"
git init -q "$vendor"
git -C "$vendor" fetch --depth=1 https://gitlab.com/mintid/mintid.git "refs/tags/$release"
test "$(git -C "$vendor" rev-parse 'FETCH_HEAD^{commit}')" = "$revision"
git -C "$vendor" checkout --detach -q "$revision"
git -C "$vendor" archive "$revision" | gzip > "$runtime/vendor.tar.gz"

docker build --tag "mintid/idchaind:$tag" "$vendor/identity-chain"
for service in issuer-agent verifier selfrevoke-relay; do
  docker build --tag "mintid/$service:$tag" \
    --build-arg "MINTID_SOURCE_REVISION=$revision" --build-arg "MINTID_RELEASE=$release" \
    --file "$vendor/deploy/anchor/Dockerfile.$service" "$vendor"
done
docker build --tag "mintid/interop-driver:$tag" --file .github/scripts/mintid-driver.Dockerfile .github/scripts
docker image save "mintid/idchaind:$tag" "mintid/issuer-agent:$tag" "mintid/verifier:$tag" \
  "mintid/selfrevoke-relay:$tag" "mintid/interop-driver:$tag" | gzip -1 > "$runtime/images.tar.gz"
