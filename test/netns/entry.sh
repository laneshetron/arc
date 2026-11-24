#!/usr/bin/env bash
# Container entry point: "e2e" (default), "accounts", "store", "enroll", "invites", "devices", "compat" (with /arc/old-bin mounted), "bench [SECONDS]", "degraded [SECONDS]",
# "fec [SECONDS] [REPS]", "split [SECONDS] [REPS]", or "stall [SECONDS] [REPS]".
set -euo pipefail
case "${1:-e2e}" in
  e2e) exec /arc/e2e.sh /arc/bin ;;
  accounts) exec /arc/accounts.sh /arc/bin ;;
  store) exec /arc/store.sh /arc/bin ;;
  enroll) exec /arc/enroll.sh /arc/bin ;;
  invites) exec /arc/invites.sh /arc/bin ;;
  devices) exec /arc/devices.sh /arc/bin ;;
  compat) exec /arc/compat.sh /arc/bin /arc/old-bin ;;
  bench) exec /arc/bench.sh /arc/bin "${@:2}" ;;
  degraded) exec /arc/degraded.sh /arc/bin "${@:2}" ;;
  fec) exec /arc/fec.sh /arc/bin "${@:2}" ;;
  split) exec /arc/split.sh /arc/bin "${@:2}" ;;
  stall) exec /arc/stall.sh /arc/bin "${@:2}" ;;
  *) echo "usage: e2e | accounts | store | enroll | invites | devices | compat | bench [SECONDS] | degraded [SECONDS] | fec [SECONDS] [REPS] | split [SECONDS] [REPS] | stall [SECONDS] [REPS]" >&2; exit 2 ;;
esac
