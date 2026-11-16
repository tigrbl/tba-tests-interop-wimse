#!/bin/sh
set -eu
umask 077
ctl() { tctl -c /fixture/teleport.yaml "$@"; }
token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
expires=$(date -u -d "@$(($(date +%s)+600))" '+%Y-%m-%dT%H:%M:%SZ')
cat >/tmp/bot-token.yaml <<EOF
kind: token
version: v2
metadata:
  name: $token
  expires: $expires
spec:
  roles: [Bot]
  join_method: token
  bot_name: harness
EOF
ctl create -f /tmp/bot-token.yaml >/tmp/registration.log
pin=$(ctl status | awk '/CA pins:/ {print $3}')
cat >/tmp/tbot.yaml <<EOF
version: v2
auth_server: 127.0.0.1:3025
onboarding:
  join_method: token
  token: $token
  ca_pins: [$pin]
storage:
  type: memory
services:
- type: workload-identity-api
  listen: unix:///tmp/tba-workload.sock
  selector:
    name: tba-workload
EOF
exec tbot start -c /tmp/tbot.yaml
