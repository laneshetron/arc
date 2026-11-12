#!/usr/bin/env bash
# Container entry point: "e2e" (default), "accounts", "bench [SECONDS]", "degraded [SECONDS]",
# "fec [SECONDS] [REPS]", or "split [SECONDS] [REPS]".
set -euo pipefail
case "${1:-e2e}" in
  e2e) exec /arc/e2e.sh /arc/bin ;;
  accounts) exec /arc/accounts.sh /arc/bin ;;
  bench) exec /arc/bench.sh /arc/bin "${@:2}" ;;
  degraded) exec /arc/degraded.sh /arc/bin "${@:2}" ;;
  fec) exec /arc/fec.sh /arc/bin "${@:2}" ;;
  split) exec /arc/split.sh /arc/bin "${@:2}" ;;
  *) echo "usage: e2e | accounts | bench [SECONDS] | degraded [SECONDS] | fec [SECONDS] [REPS] | split [SECONDS] [REPS]" >&2; exit 2 ;;
esac
