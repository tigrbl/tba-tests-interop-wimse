#!/usr/bin/env bash
# Start a disposable synthetic MintID chain, issuer, verifier and relay.
set -euo pipefail
runtime=$1
container=${TBA_WIMSE_MINTID_CONTAINER:?}
project=tba-interop-mintid
vendor=$(realpath "$runtime/vendor")
script_dir=$(cd "$(dirname "$0")" && pwd)
bridge=$(realpath "$2")
anchor="$vendor/deploy/anchor"
driver=mintid/interop-driver:tba-interop
export ANCHOR_IMAGE_TAG=tba-interop ANCHOR_DIST=dist-tba-devmatrix ANCHOR_SECRETS=secrets-tba-devmatrix
export KYC_PROVIDER=simulated ISSUER_PUBLIC_URL=http://issuer-agent:8472
dc=(docker compose --project-name "$project" --env-file "$anchor/config.env"
    -f "$anchor/docker-compose.yml" -f "$script_dir/mintid-compose.yml")
common=(--rm --pull never --mount "type=bind,src=$vendor,dst=/src" -w /src)
docker run "${common[@]}" --network none -e WS=tba-devmatrix -e ANCHOR_PYTHON=python \
  -e PYTHONPATH=/src/deploy/anchor/foundation/src --entrypoint bash "$driver" /src/deploy/anchor/01-init-home.sh
"${dc[@]}" create --no-build --pull never idchaind
docker run "${common[@]}" --network none -v "${project}_chain-home:/chain" \
  --entrypoint bash "$driver" -c 'cp -a /src/deploy/anchor/dist-tba-devmatrix/home/. /chain/'
"${dc[@]}" up -d --no-build --pull never idchaind issuer-agent verifier
docker run "${common[@]}" --network "${project}_default" -v "${project}_chain-home:/chain" \
  -e PYTHONPATH=/src/selfrevoke-relay/src -e NODE=http://idchaind:26657 -e ANCHOR_PYTHON=python \
  -e HOME_DIR=/chain -e ANCHOR_DIST -e ANCHOR_SECRETS --entrypoint bash "$driver" -c '
    for attempt in $(seq 1 30); do
      if curl -sf http://idchaind:26657/status >/dev/null; then exec bash /src/deploy/anchor/13-fund-relay.sh; fi
      sleep 2
    done
    exit 1'
"${dc[@]}" up -d --no-build --pull never selfrevoke-relay
docker run -d --pull never --name "$container" --network "${project}_default" \
  --mount "type=bind,src=$vendor,dst=/src,readonly" --mount "type=bind,src=$bridge,dst=/tbafixture/mintid_bridge.py,readonly" \
  -w /src -e ANCHOR_DIST -e MINTID_ISSUER_URL=http://issuer-agent:8472 \
  -e MINTID_VERIFIER_URL=http://verifier:8471 -e MINTID_CHAIN_RPC=http://idchaind:26657 \
  -e MINTID_RELAY_URL=http://selfrevoke-relay:8479 \
  -e PYTHONPATH=/src/test-harness/trace:/src/test-harness/src:/src/verifier-core/src:/src/sdk/python/mintid-agent/src \
  --entrypoint sleep "$driver" infinity
