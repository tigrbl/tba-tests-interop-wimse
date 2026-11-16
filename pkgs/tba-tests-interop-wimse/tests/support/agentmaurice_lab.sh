#!/bin/sh
# Run inside a fresh network-isolated Linux container with NATS on loopback.
set -eu

mkdir -p /tmp/bin /tmp/one/config /tmp/cli /tmp/tba-workflow
cp /release/maurice /release/sandbox-worker /tmp/
cp /deno/deno /tmp/bin/
cp /fixture/agentmaurice_request.ts /tmp/request.ts
cp /fixture/agentmaurice_receiver.ts /tmp/receiver.ts
cp /fixture/agentmaurice_outbound_replay.ts /tmp/replay.ts
cp /input/issuer.jwks /tmp/tba-issuer.jwks.json
sha256sum -c <<'SHAS'
a2b79f0565e05b8a2de1692d102e808b5b69e65954f2ea8aa7963e1bf8544bff  /tmp/maurice
b3df92e11d19c0562056d6237f13e50daed146635fd8c8afa7d39ae6f37805da  /tmp/sandbox-worker
bceb5b6a6239b0b010418406d8c77a508f67cf4337d94288f1c19fe71304aab0  /tmp/bin/deno
SHAS
chmod 700 /tmp/maurice /tmp/sandbox-worker /tmp/bin/deno
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/receiver-ca-key.pem \
  -out /tmp/receiver-ca.pem -days 2 -subj /CN=TbA-AgentMaurice-loopback \
  -addext basicConstraints=critical,CA:TRUE 2>/tmp/certificate.log
openssl req -new -newkey rsa:2048 -nodes -keyout /tmp/receiver-key.pem \
  -out /tmp/receiver.csr -subj /CN=127.0.0.1 2>>/tmp/certificate.log
cat >/tmp/receiver.ext <<'EXT'
basicConstraints=critical,CA:FALSE
subjectAltName=IP:127.0.0.1
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in /tmp/receiver.csr -CA /tmp/receiver-ca.pem -CAkey /tmp/receiver-ca-key.pem \
  -CAcreateserial -out /tmp/receiver-cert.pem -days 2 -extfile /tmp/receiver.ext 2>>/tmp/certificate.log
cp /tmp/receiver-ca.pem /usr/local/share/ca-certificates/tba-agentmaurice.crt
update-ca-certificates >/tmp/ca-setup.log 2>&1

export PATH="/tmp/bin:$PATH" APP_DATA_DIR=/tmp/one
export NATS_URL=nats://127.0.0.1:4222
# Standalone expects a control-plane JWKS at startup. The lab uses the local
# operator for setup and the separate WIMSE key store for peer authentication.
export AUTH_HANKO_JWKS_URL=http://127.0.0.1:18089
export AUTH_OIDC_JWKS_URL=http://127.0.0.1:18089
export DENO_CERT=/tmp/receiver-ca.pem DENO_TLS_CA_STORE=system
audience=https://receiver.example.org
peer_domain=example.org
peer_workload=tba-workload
if [ "${TBA_AGENTMAURICE_NINE_HOP:-}" = 1 ]; then
  audience=http://maurice.ietf127.example:5050
  peer_domain=peer.ietf127.example
  peer_workload=client
fi
deno eval 'Deno.serve({hostname:"127.0.0.1",port:18089},()=>Response.json({keys:[]}));'   >/tmp/control-plane-jwks.log 2>&1 &
jwks_pid=$!
serve_pid=
cleanup() {
  if [ -n "$serve_pid" ]; then kill "$serve_pid" 2>/dev/null || true; fi
  kill "$jwks_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

cat > /tmp/one/config/standalone.yaml <<YAML
wimse:
  enabled: true
  trust_domain: example.org
  issuer:
    iss: https://issuer.example.org
  inbound:
    audiences: [$audience]
YAML

maurice_cli() {
  /tmp/maurice --config /tmp/cli/context.yaml "$@"
}
start() {
  cd /tmp/one
  /tmp/maurice serve --data-dir /tmp/one >"$1" 2>&1 &
  serve_pid=$!
  for _ in $(seq 1 30); do
    if maurice_cli --api http://127.0.0.1:5000 ping >/tmp/ping.log 2>&1; then return; fi
    kill -0 "$serve_pid"
    sleep 1
  done
  return 1
}

start /tmp/setup-serve.log
maurice_cli --api http://127.0.0.1:5000 setup --client codex --json >/tmp/setup.json
maurice_cli test setup --fresh --save=false --deployment-name tba-agentmaurice-matrix   --json >/tmp/agent.json
deno eval 'Deno.writeTextFileSync("/tmp/test-id",JSON.parse(Deno.readTextFileSync("/tmp/agent.json")).agent_id);'
agent=$(cat /tmp/test-id)
maurice_cli spec init --env local --agent-alias test --agent-id "$agent" --dir /tmp/tba-workflow   --json >/tmp/spec.json
maurice_cli test example simple --json >/tmp/example.json
deno run --allow-read=/tmp/example.json --allow-write=/tmp/tba-workflow   /fixture/agentmaurice_workflows.ts
maurice_cli network allowlist add --deployment "$agent" --host 127.0.0.1 --port 15001   --scheme https --description "TbA WIMSE loopback" --json >/tmp/egress.json
cd /tmp/tba-workflow
git init -q
git add agentmaurice.project.json agentmaurice.lock.json agents environments
git -c user.name=TbA-Interop -c user.email=interop@example.org commit -qm fixture
maurice_cli spec deploy --env local --agent-alias test --dir /tmp/tba-workflow   --tests auto --json >/tmp/tba-deploy.json

kill "$serve_pid"
wait "$serve_pid" || true
cat >> /tmp/one/config/standalone.yaml <<YAML
    grants:
      - holder: workload:wimse://$peer_domain/$peer_workload
        agent: $agent
        workflow: text-stats
YAML
for name in workload-0 workload-1 workload-2 workload-3; do
  cat >> /tmp/one/config/standalone.yaml <<YAML
      - holder: workload:wimse://example.org/$name
        agent: $agent
        workflow: text-stats
      - holder: workload:wimse://example.org/$name
        agent: $agent
        workflow: interop-policy
YAML
done
cat >> /tmp/one/config/standalone.yaml <<YAML
  trust:
    - trust_domain: $peer_domain
      jwks_file: /tmp/tba-issuer.jwks.json
YAML
if [ "${TBA_AGENTMAURICE_NINE_HOP:-}" = 1 ]; then
  printf '      issuers: [http://peer.ietf127.example]\n' >> /tmp/one/config/standalone.yaml
fi
start /tmp/grant-serve.log
touch /tmp/lab-ready
wait "$serve_pid"
