#!/usr/bin/env bash
# Container entry point: "e2e" (default) or "bench [SECONDS]".
set -euo pipefail
case "${1:-e2e}" in
  e2e) exec /arc/e2e.sh /arc/bin ;;
  bench) exec /arc/bench.sh /arc/bin "${@:2}" ;;
  *) echo "usage: e2e | bench [SECONDS]" >&2; exit 2 ;;
esac
