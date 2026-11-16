#!/bin/sh
set -eu
test "$1" = run
target=$2
shift 2
case "$target" in
  ./cmd/idchaind) exec /usr/bin/idchaind "$@" ;;
  ./tools/genesis) exec /usr/bin/idchain-genesis "$@" ;;
  *) exit 2 ;;
esac
