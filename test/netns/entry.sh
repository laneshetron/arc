#!/usr/bin/env bash
# Container entry point: "e2e" (default), "bench [SECONDS]", or "degraded [SECONDS]".
set -euo pipefail
case "${1:-e2e}" in
  e2e) exec /arc/e2e.sh /arc/bin ;;
  bench) exec /arc/bench.sh /arc/bin "${@:2}" ;;
  degraded) exec /arc/degraded.sh /arc/bin "${@:2}" ;;
  *) echo "usage: e2e | bench [SECONDS] | degraded [SECONDS]" >&2; exit 2 ;;
esac
