#!/usr/bin/env bash
# Independently recompute timing, ordering, counts and percentiles from raw CSV.
set -Eeuo pipefail
export LC_ALL=C
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUT=$(realpath -e "${1:?Usage: ./verify.sh RUN_DIRECTORY}")
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'echo "Verification failed at line $LINENO for $OUT" >&2' ERR
read -r START DURATION MBPS < <(jq -r '[.start_ns,.seconds,.offered_mbps] | @tsv' "$OUT/config.json")
jq -e -s --argjson s "$DURATION" --argjson m "$MBPS" '
    .[0] as $tx | .[1] as $rx |
    ($s*$m*1000000/65536 | floor) as $count |
    $tx.sender and ($rx.sender|not) and
    $tx.offered_records == $count and $rx.offered_records == $count and
    $tx.accepted_records + $tx.rejected_records == $count and
    $rx.received_records <= $tx.accepted_records and $rx.received_records > 0 and
    $tx.duplicates == 0 and $rx.duplicates == 0 and $tx.corrupt == 0 and $rx.corrupt == 0
' "$OUT/sender/result.json" "$OUT/receiver/result.json" >/dev/null
awk -F, -v start="$START" -v seconds="$DURATION" -v mbps="$MBPS" -v metrics="$TMP/counts.json" '
    NR==1 {if ($0!="sequence,receive_ns,latency_ms") exit 1; next}
    {
        generated=start+int($1*8192*8e9/(mbps*1e6)); delay=($2-generated)/1e6;
        difference=delay-$3; if(difference<0) difference=-difference;
        if(NF!=3 || $1!=n || $2<generated || $2<last ||
           $2>start+(seconds+10)*1e9 || difference>0.000005) {bad=1; exit 1}
        n++; window+=($2<=start+seconds*1e9); timely+=(delay<=100); last=$2;
        printf "%.9f\n",delay;
    }
    END {
        if(bad || !n) exit 1;
        printf "{\"received_records\":%d,\"in_window_records\":%d,\"within_100ms\":%d}\n",n,window,timely > metrics;
    }
' "$OUT/receiver/samples.csv" | sort -n > "$TMP/delays"
N=$(wc -l < "$TMP/delays")
awk -v n="$N" 'NR==int((n-1)*.50)+1 {p50=$1}
    NR==int((n-1)*.95)+1 {p95=$1} NR==int((n-1)*.99)+1 {p99=$1}
    END {printf "{\"p50_ms\":%.9f,\"p95_ms\":%.9f,\"p99_ms\":%.9f}\n",p50,p95,p99}' \
    "$TMP/delays" > "$TMP/percentiles.json"
jq -e -s '
    .[0] as $r | .[1] as $counts | .[2] as $p |
    all($counts|keys[]; $r[.] == $counts[.]) and
    all($p|keys[]; (($r[.] - $p[.])|fabs) < 0.000005)
' "$OUT/receiver/result.json" "$TMP/counts.json" "$TMP/percentiles.json" >/dev/null
jq -e -s '.[0] as $before | .[1] as $after |
    all(["c1","c2"][]; . as $name |
        ([$after[]|select(.ifname==$name)|.stats64.tx.bytes][0] -
         [$before[]|select(.ifname==$name)|.stats64.tx.bytes][0]) > 10000)
' "$OUT/links-before.json" "$OUT/links-after.json" >/dev/null
MODE=$(jq -r .mode "$OUT/config.json")
if [[ $MODE == mptcp ]]; then
    grep -q 'subflows_total:2' "$OUT/sockets.txt"
    for side in sender receiver; do
        grep -q 'TLS TLSv1.3 .*; peer verified' "$OUT/$side/stderr.txt"
    done
else
    jq -e '[.[]|select(.sent_bytes>10000)]|length>=2' "$OUT/sender/paths.json" >/dev/null
fi
(cd "$OUT/inputs" && sha256sum --check SHA256SUMS >/dev/null)
jq -n --slurpfile tx "$OUT/sender/result.json" --slurpfile rx "$OUT/receiver/result.json" \
    --slurpfile cfg "$OUT/config.json" '{
    mode:$cfg[0].mode, profile:$cfg[0].profile, seconds:$cfg[0].seconds,
    offered_mbps:$cfg[0].offered_mbps,
    useful_mbps:($rx[0].in_window_records*65536/$cfg[0].seconds/1000000),
    offered_records:$tx[0].offered_records, admitted_records:$tx[0].accepted_records,
    received_records:$rx[0].received_records,
    offered_received_pct:($rx[0].received_records/$tx[0].offered_records*100),
    admitted_missing:($tx[0].accepted_records-$rx[0].received_records),
    p50_ms:$rx[0].p50_ms,p95_ms:$rx[0].p95_ms,p99_ms:$rx[0].p99_ms,
    endpoint_offered_cpu_s:($tx[0].cpu_offered_seconds+$rx[0].cpu_offered_seconds)
}'
