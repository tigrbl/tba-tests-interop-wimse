#!/usr/bin/env bash
# Disposable Teleport auth service and Workload API, with no published ports.
set -euo pipefail

container=${TBA_WIMSE_TELEPORT_CONTAINER:?}
lab=$(cd "$(dirname "$0")/teleport" && pwd)
image=public.ecr.aws/gravitational/teleport-distroless-debug@sha256:a09b7585c2e314a09441787d2c522aa7c901b566e15a3602efc9c979e791e029
agent=ghcr.io/spiffe/spire-agent@sha256:ab3a8ce70435374cc5d84c81eabf0278dc046ddbc0a736d59694ba9e5975b1b6
scratch=$(mktemp -d)
client=$(docker create "$agent")
trap 'docker rm "$client" >/dev/null; rm -f "$scratch/spire-agent"; rmdir "$scratch"' EXIT
docker cp "$client:/opt/spire/bin/spire-agent" "$scratch/spire-agent"
echo "b5a35df17f4491c55e5f37d2e34e35bfa81f4199311c9932cd6b174145ced9ce  $scratch/spire-agent" | sha256sum -c
docker run -d --name "$container" --network none --mount "type=bind,source=$lab,target=/fixture,readonly" \
  --entrypoint teleport "$image" start -c /fixture/teleport.yaml

ctl() { docker exec "$container" tctl -c /fixture/teleport.yaml "$@"; }
retry() {
  local attempt
  for attempt in {1..30}; do
    if "$@"; then return 0; fi
    sleep 1
  done
  return 1
}
retry ctl status >/dev/null
ctl create -f /fixture/identities.yaml
# The proxy-free Auth Service registers the bot before printing instructions.
ctl bots add --roles=tba-workload-issuer harness >/dev/null 2>&1 || ctl get bot/harness >/dev/null
docker exec "$container" /busybox/mkdir -p /opt/spire/bin
docker cp "$scratch/spire-agent" "$container:/opt/spire/bin/spire-agent"
docker exec "$container" /busybox/chmod 755 /opt/spire/bin/spire-agent
docker exec -d "$container" /busybox/sh -c 'export PATH=/busybox:$PATH; /busybox/sh /fixture/tbot.sh >/tmp/tbot.log 2>&1'
retry docker exec "$container" /busybox/test -S /tmp/tba-workload.sock
