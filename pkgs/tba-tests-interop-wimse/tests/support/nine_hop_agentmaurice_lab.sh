#!/bin/sh
# Bootstrap the pinned lab with the Research identity and File Tool audience.
set -eu

test "${TBA_AGENTMAURICE_NINE_HOP:-}" = 1
test -r /input/rich.jwks
cp /input/rich.jwks /tmp/rich-issuer.jwks.json

sed '/    audiences: \[\$audience\]/s/\]/, http:\/\/rich.ietf127.example:5063]/
/^    grants:$/a\
      - holder: workload:wimse://rich.ietf127.example/agent/research\
        agent: $agent\
        workflow: text-stats
/^start \/tmp\/grant-serve.log/i\
cat >> /tmp/one/config/standalone.yaml <<RICH_TRUST\
    - trust_domain: rich.ietf127.example\
      jwks_file: /tmp/rich-issuer.jwks.json\
      issuers: [http://rich.ietf127.example]\
RICH_TRUST
' /fixture/agentmaurice_lab.sh > /tmp/nine-hop-agentmaurice-lab.sh

exec sh /tmp/nine-hop-agentmaurice-lab.sh
