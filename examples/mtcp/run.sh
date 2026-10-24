#!/usr/bin/env bash
# One trial. lab.sh creates the network; records.c implements both backends.
set -Eeuo pipefail
export LC_ALL=C
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
STATE=/run/qlinq-mtcp-examples
fail() { echo "ERROR: $*" >&2; exit 1; }
[[ ${1:-} == records && $# -ge 3 && $# -le 4 ]] || {
    echo 'Usage: sudo ./run.sh records MBPS SECONDS [NEW_OUTPUT_DIRECTORY]' >&2; exit 1;
}
MBPS=${2%M}; DURATION=$3
[[ $MBPS =~ ^[0-9]+$ && $DURATION =~ ^[0-9]+$ ]] || fail 'Use integer Mbit/s and seconds'
(( MBPS > 0 && MBPS <= 1000 && DURATION >= 1 && DURATION <= 600 )) || fail 'Allowed: 1–1000 Mbit/s, 1–600 seconds'
[[ $EUID == 0 ]] || fail 'Run with sudo'
[[ -f $STATE/owner && $(cat "$STATE/owner") == qlinq-mtcp-examples-v1 ]] || fail 'Run ./lab.sh up first'
for name in qm-client qm-server qm-router; do
    expected=$(awk -v name="$name" '$1==name {print $2}' "$STATE/namespaces")
    [[ -n $expected && $(stat -Lc '%d:%i' "/run/netns/$name") == "$expected" ]] || fail "Lab namespace $name changed"
done
exec 9> "$STATE/trial.lock"
flock -n 9 || fail 'Another trial is running'
[[ -x $HERE/.build/records ]] || fail 'Run ./build.sh without sudo first'
(cd "$HERE" && sha256sum --check .build/driver.sha256 >/dev/null) || fail 'Rebuild after changing records.c or its binary'
MODE=$(cat "$STATE/mode"); PROFILE=$(cat "$STATE/profile")
BACKEND=$MODE; [[ $MODE != qlinq ]] || BACKEND=reliable
OUT=${4:-$HERE/results/$(date -u +%Y%m%dT%H%M%S)-$MODE-$PROFILE-$MBPS-$$}
[[ ! -e $OUT ]] || fail 'Output directory already exists; choose a new one'
mkdir -p -- "$OUT"; OUT=$(realpath -e "$OUT")
mkdir "$OUT/sender" "$OUT/receiver" "$OUT/inputs"
PIDS=(); SAMPLER=
cleanup() {
    rc=$?
    trap - EXIT INT TERM
    [[ -z $SAMPLER ]] || kill "$SAMPLER" 2>/dev/null || true
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    printf '%s\n' "$rc" > "$OUT/exit-code"
    if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then chown -R "$SUDO_UID:$SUDO_GID" "$OUT"; fi
    if ((rc)); then echo "Trial failed; diagnostics retained in $OUT" >&2; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
cp "$HERE/"{records.c,lab.sh,run.sh,verify.sh,build.sh} "$OUT/inputs/"
cp "$HERE/.build/"{source.txt,library.sha256,driver.sha256,build.log,records} "$OUT/inputs/"
(cd "$OUT/inputs" && sha256sum records records.c lab.sh run.sh verify.sh build.sh source.txt library.sha256 driver.sha256 build.log > SHA256SUMS)
{
    uname -a
    lscpu
    for ns in qm-client qm-server; do
        ip netns exec "$ns" sysctl net.ipv4.tcp_congestion_control net.mptcp.path_manager net.mptcp.scheduler
        ip netns exec "$ns" ip route show table all
        ip netns exec "$ns" ip rule show
        ip netns exec "$ns" ip mptcp endpoint show
    done
} > "$OUT/environment.txt"
for i in 1 2; do
    ip netns exec qm-client ping -n -c 3 -i .1 -W 2 -I "10.231.$i.1" 10.232.1.2 > "$OUT/path$i-ping.txt"
done
ip netns exec qm-client ip -j -s link show > "$OUT/links-before.json"
ip netns exec qm-router tc -j -s qdisc show > "$OUT/queues-before.json"
START=$("$HERE/.build/records" --start)
jq -n --arg mode "$BACKEND" --arg profile "$PROFILE" --argjson seconds "$DURATION" \
    --argjson mbps "$MBPS" --argjson start "$START" \
    --arg cc "${QLINQ_BENCH_CC:-default}" --arg pacing "${QLINQ_BENCH_PACING:-default}" \
    --arg crypto "${QLINQ_CRYPTO_BACKEND:-openssl}" \
    --arg cadence "${QLINQ_EXPERIMENT_RX_CADENCE_USEC:-disabled}" \
    --arg udp_payload "${QLINQ_BENCH_UDP_PAYLOAD:-1280}" \
    '{mode:$mode,profile:$profile,seconds:$seconds,offered_mbps:$mbps,start_ns:$start,record_bytes:8192,drain_seconds:10,
      qlinq_requested_policy:(if $mode=="mptcp" then null else
        {controller:$cc,pacing:$pacing,crypto:$crypto,rx_cadence_usec:$cadence,udp_payload_bytes:$udp_payload} end)}' > "$OUT/config.json"
for role in receiver sender; do
    if [[ $role == receiver ]]; then NS=qm-server; else NS=qm-client; fi
    (cd "$OUT/$role" && exec timeout --kill-after=2 "$((DURATION+20))" \
        ip netns exec "$NS" "$HERE/.build/records" "$BACKEND" "$role" \
        "$STATE/cert.pem" "$STATE/key.pem" 2 "$START" "$DURATION" "$MBPS" samples.csv \
        > result.json 2> stderr.txt) &
    PIDS+=("$!")
    [[ $role != receiver ]] || sleep .15
done
(
    TIMER=
    trap 'if [[ -n $TIMER ]]; then kill "$TIMER" 2>/dev/null || true; wait "$TIMER" 2>/dev/null || true; fi; exit 0' TERM INT
    while kill -0 "${PIDS[0]}" 2>/dev/null || kill -0 "${PIDS[1]}" 2>/dev/null; do
        date -u +%FT%TZ >> "$OUT/sockets.txt"
        ip netns exec qm-client ss -Mtin >> "$OUT/sockets.txt"
        ip netns exec qm-router tc -j -s qdisc show >> "$OUT/queues.jsonl"
        sleep 2 & TIMER=$!
        wait "$TIMER"
        TIMER=
    done
) 9>&- &
SAMPLER=$!
echo "Running $BACKEND / $PROFILE: $MBPS Mbit/s for $DURATION seconds, plus setup and 10-second drain."
for pid in "${PIDS[@]}"; do wait "$pid"; done
PIDS=()
kill "$SAMPLER" 2>/dev/null || true
wait "$SAMPLER" 2>/dev/null || true
SAMPLER=
ip netns exec qm-client ip -j -s link show > "$OUT/links-after.json"
ip netns exec qm-router tc -j -s qdisc show > "$OUT/queues-after.json"
"$HERE/verify.sh" "$OUT" > "$OUT/summary.json"
cat "$OUT/summary.json"
echo "Verified raw samples and two-path traffic. Results: $OUT"
