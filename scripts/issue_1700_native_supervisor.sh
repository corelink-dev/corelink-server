#!/bin/sh
set -eu

reject() {
    exit 64
}

# The supervisor is a private, argument-free PID 1 entrypoint.
[ "$#" -eq 0 ] || reject
[ "$$" -eq 1 ] || reject
[ "${ENVIRONMENT-}" = staging ] || reject
[ "${D1_BINDING_PROXY-}" = 1 ] || reject
[ -z "${CF_API_TOKEN-}" ] || reject
[ "${CLOUDFLARE_ACCOUNT_ID-}" = 6a1fc1c626fc2628823e60b9db01f5cd ] || reject
[ "${D1_DATABASE_ID-}" = d72a6b39-6a48-4338-bfda-1111dda98604 ] || reject

started=${CORELINK_STAGING_PROBE_STARTED_MS-}
execution_deadline=${CORELINK_STAGING_PROBE_EXECUTION_DEADLINE_MS-}
kill_at=${CORELINK_STAGING_PROBE_KILL_AT_MS-}

is_epoch_ms() {
    [ "${#1}" -eq 13 ] || return 1
    case "$1" in [1-9]*) ;; *) return 1 ;; esac
    case "$1" in *[!0-9]*) return 1 ;; esac
    return 0
}

is_epoch_ms "$started" || reject
is_epoch_ms "$execution_deadline" || reject
is_epoch_ms "$kill_at" || reject

# Compiled issue-1700 v13 source window.
window_start=1790924400000
last_entry=1790931600000
expiry=1790936100000
[ "$started" -ge "$window_start" ] && [ "$started" -le "$last_entry" ] || reject
expected_execution=$((started + 600000))
[ "$expected_execution" -le "$expiry" ] || expected_execution=$expiry
expected_kill=$((started + 1200000))
[ "$expected_kill" -le "$expiry" ] || expected_kill=$expiry
[ "$execution_deadline" -eq "$expected_execution" ] || reject
[ "$kill_at" -eq "$expected_kill" ] || reject

now=$(/usr/bin/date +%s%3N) || reject
is_epoch_ms "$now" || reject
[ "$now" -ge "$started" ] && [ "$now" -lt "$execution_deadline" ] || reject

remaining_ms=$((kill_at - now))
seconds=$((remaining_ms / 1000))
millis=$((remaining_ms % 1000))
remaining=$(printf '%d.%03d' "$seconds" "$millis")

exec /usr/bin/timeout --signal=KILL "$remaining" /usr/local/bin/corelink-server
