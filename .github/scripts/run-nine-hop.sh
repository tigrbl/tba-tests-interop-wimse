#!/usr/bin/env bash
# Execute a shard of the named success inventory in an isolated loopback lab.
set -euo pipefail

upstream=$1
assets=$2
package=$3
scratch=$4
manifest=$5
shard=$6
shards=$7
name="interop-nine-hop-${GITHUB_RUN_ID:-local}"
nats="$name-nats"
capture_pid=
cleanup() {
    if [[ -n "$capture_pid" ]]; then
        sudo kill -INT "$capture_pid" 2>/dev/null || true
    fi
    docker rm -f "$nats" "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

python "$upstream/setup/gen_keys.py"
docker run -d --name "$name" --network none -e TBA_AGENTMAURICE_NINE_HOP=1 \
    --mount "type=bind,src=$assets/release,dst=/release,readonly" \
    --mount "type=bind,src=$assets/deno,dst=/deno,readonly" \
    --mount "type=bind,src=$upstream/keys/peer.jwks.json,dst=/input/issuer.jwks,readonly" \
    --mount "type=bind,src=$upstream/keys/rich.jwks.json,dst=/input/rich.jwks,readonly" \
    --mount "type=bind,src=$package/tests/support,dst=/fixture,readonly" \
    rust@sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0 \
    sh -c 'while [ ! -e /tmp/boot ]; do sleep 1; done; exec sh /fixture/nine_hop_agentmaurice_lab.sh'
docker run -d --name "$nats" --network "container:$name" \
    nats@sha256:71092f77d707a4a81b12aca5096d6b2d2e07ad16aa57c84066940a17af74f61a \
    -js -a 127.0.0.1
docker exec "$name" touch /tmp/boot
for _ in $(seq 1 125); do
    if docker exec "$name" test -f /tmp/lab-ready; then break; fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "$name")" != true ]]; then break; fi
    sleep 1
done
if ! docker exec "$name" test -f /tmp/lab-ready; then
    docker logs --tail 30 "$name"
    exit 1
fi

pid=$(docker inspect --format '{{.State.Pid}}' "$name")
agent=$(docker exec "$name" cat /tmp/test-id)
python_path=$(command -v python)
sudo nsenter -t "$pid" -n -- sh -c '
    echo "$$" > "$1/tcpdump.pid"
    exec tcpdump -Z root -i lo -U -s 0 -w "$1/chain.pcap" \
        "tcp and (port 5000 or port 5002 or port 5051 or portrange 5060-5063)"
' sh "$scratch" >"$scratch/capture.log" 2>&1 &
capture_job=$!
for _ in $(seq 1 30); do
    if grep -q 'listening on lo' "$scratch/capture.log"; then break; fi
    sleep 1
done
capture_pid=$(cat "$scratch/tcpdump.pid")
grep -q 'listening on lo' "$scratch/capture.log"

touch "$scratch/observations.jsonl"
driver_exit=0
sudo nsenter -t "$pid" -n -- env PATH="$PATH" \
    TBA_NINE_HOP_PEER_ASSETS="$(dirname "$assets")" \
    TBA_WIMSE_CRED_CHECKOUT="${TBA_WIMSE_CRED_CHECKOUT:-}" \
    TBA_WIMSE_NINE_HOP_COFIDE_BRIDGE="${TBA_WIMSE_NINE_HOP_COFIDE_BRIDGE:-}" \
    timeout 65m "$python_path" "$package/tests/ci_nine_hop_matrix.py" run \
    "$manifest" "$upstream" "$scratch/observations.jsonl" "$shard" "$shards" "$agent" \
    >"$scratch/driver.log" 2>&1 || driver_exit=$?
sudo kill -INT "$capture_pid"
wait "$capture_job"
capture_pid=
cat "$scratch/capture.log"
sudo chown "$(id -u):$(id -g)" "$scratch/chain.pcap"
chmod u+r "$scratch/chain.pcap"
test -r "$scratch/chain.pcap"
if [[ "$driver_exit" != 0 ]]; then
    printf 'Shard runner exited %s\n' "$driver_exit"
    tail -20 "$scratch/driver.log"
fi
exit "$driver_exit"
