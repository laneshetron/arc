#!/usr/bin/env bash
# Container entry point: "e2e" (default), "bench [SECONDS]", "degraded [SECONDS]",
# or "fec [SECONDS] [REPS]".
set -euo pipefail
case "${1:-e2e}" in
  e2e) exec /arc/e2e.sh /arc/bin ;;
  bench) exec /arc/bench.sh /arc/bin "${@:2}" ;;
  degraded) exec /arc/degraded.sh /arc/bin "${@:2}" ;;
  fec) exec /arc/fec.sh /arc/bin "${@:2}" ;;
  *) echo "usage: e2e | bench [SECONDS] | degraded [SECONDS] | fec [SECONDS] [REPS]" >&2; exit 2 ;;
esac
