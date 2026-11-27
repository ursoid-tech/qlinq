#!/usr/bin/env bash

set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  if ! command -v unshare >/dev/null 2>&1; then
    echo "check-emcon-netns needs root/CAP_NET_ADMIN or unshare." >&2
    exit 77
  fi
  exec unshare --user --map-root-user --net "$0" "$@"
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
test_binary="$repo_root/t/00util/test_emcon_netns"
work_dir=$(mktemp -d /tmp/qlinq-emcon-netns.XXXXXX)
holder_pids=""
test_pids=""

cleanup() {
  for pid in $test_pids $holder_pids; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

for command in awk ip nsenter sysctl tcpdump unshare timeout; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "check-emcon-netns requires $command." >&2
    exit 77
  }
done
[[ -x "$test_binary" ]] || {
  echo "build $test_binary before running this harness." >&2
  exit 1
}

unshare --net -- sleep infinity &
source_ns=$!
holder_pids="$holder_pids $source_ns"
unshare --net -- sleep infinity &
receiver1_ns=$!
holder_pids="$holder_pids $receiver1_ns"
unshare --net -- sleep infinity &
receiver2_ns=$!
holder_pids="$holder_pids $receiver2_ns"
sleep 0.1

# Bridge connects one multicast source to two silent receivers.
ip link add br0 type bridge
ip link set br0 type bridge mcast_snooping 0
ip link set br0 up

ip link add brsrc type veth peer name emsrc
ip link add brr1 type veth peer name emr1
ip link add brr2 type veth peer name emr2
ip link set brsrc master br0
ip link set brr1 master br0
ip link set brr2 master br0
ip link set brsrc up
ip link set brr1 up
ip link set brr2 up

ip link set emsrc netns "$source_ns"
ip link set emr1 netns "$receiver1_ns"
ip link set emr2 netns "$receiver2_ns"

nsenter -t "$source_ns" -n -- ip link set emsrc name eth0
nsenter -t "$receiver1_ns" -n -- ip link set emr1 name eth0
nsenter -t "$receiver2_ns" -n -- ip link set emr2 name eth0

for ns in "$source_ns" "$receiver1_ns" "$receiver2_ns"; do
  nsenter -t "$ns" -n -- sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  nsenter -t "$ns" -n -- ip link set lo up
done

nsenter -t "$source_ns" -n -- ip address add 10.242.0.1/24 dev eth0
nsenter -t "$receiver1_ns" -n -- ip address add 10.242.0.2/24 dev eth0
nsenter -t "$receiver2_ns" -n -- ip address add 10.242.0.3/24 dev eth0

for ns in "$source_ns" "$receiver1_ns" "$receiver2_ns"; do
  nsenter -t "$ns" -n -- ip link set eth0 up
done

nsenter -t "$source_ns" -n -- ip route add 224.0.0.0/4 dev eth0
nsenter -t "$receiver1_ns" -n -- ip route add 224.0.0.0/4 dev eth0
nsenter -t "$receiver2_ns" -n -- ip route add 224.0.0.0/4 dev eth0

# Pre-provision multicast membership before the silent interval starts.
nsenter -t "$receiver1_ns" -n -- "$test_binary" --hold-group 232.42.42.1 eth0 &
holder_pids="$holder_pids $!"
nsenter -t "$receiver2_ns" -n -- "$test_binary" --hold-group 232.42.42.1 eth0 &
holder_pids="$holder_pids $!"
sleep 0.3

# All addressing, link setup, and multicast provisioning finish before capture.
nsenter -t "$receiver1_ns" -n -- \
  tcpdump -Q out -U -n -i eth0 -w "$work_dir/receiver1-egress.pcap" \
  >"$work_dir/tcpdump1.log" 2>&1 &
capture1_pid=$!
test_pids="$test_pids $capture1_pid"
nsenter -t "$receiver2_ns" -n -- \
  tcpdump -Q out -U -n -i eth0 -w "$work_dir/receiver2-egress.pcap" \
  >"$work_dir/tcpdump2.log" 2>&1 &
capture2_pid=$!
test_pids="$test_pids $capture2_pid"
sleep 0.2

nsenter -t "$receiver1_ns" -n -- timeout 10 "$test_binary" \
  --receiver 232.42.42.1 10.242.0.1 >"$work_dir/receiver1.log" 2>&1 &
receiver1_pid=$!
test_pids="$test_pids $receiver1_pid"
nsenter -t "$receiver2_ns" -n -- timeout 10 "$test_binary" \
  --receiver 232.42.42.1 10.242.0.1 >"$work_dir/receiver2.log" 2>&1 &
receiver2_pid=$!
test_pids="$test_pids $receiver2_pid"
sleep 0.1

nsenter -t "$source_ns" -n -- timeout 10 "$test_binary" \
  --source 10.242.0.1 232.42.42.1 >"$work_dir/source.log" 2>&1 || {
  cat "$work_dir/source.log" >&2
  exit 1
}
if ! wait "$receiver1_pid"; then
  cat "$work_dir/receiver1.log" >&2
  exit 1
fi
test_pids=${test_pids/ $receiver1_pid/}
if ! wait "$receiver2_pid"; then
  cat "$work_dir/receiver2.log" >&2
  exit 1
fi
test_pids=${test_pids/ $receiver2_pid/}

kill -INT "$capture1_pid" "$capture2_pid" 2>/dev/null || true
wait "$capture1_pid" "$capture2_pid" 2>/dev/null || true
test_pids=${test_pids/ $capture1_pid/}
test_pids=${test_pids/ $capture2_pid/}

grep -q '===EMCON NETNS SOURCE OK===' "$work_dir/source.log"
grep -q '===EMCON NETNS RECEIVER OK===' "$work_dir/receiver1.log"
grep -q '===EMCON NETNS RECEIVER OK===' "$work_dir/receiver2.log"
for idx in 1 2; do
  if tcpdump -n -r "$work_dir/receiver${idx}-egress.pcap" 2>/dev/null | grep -q .; then
    echo "receiver ${idx} emitted Ethernet traffic during EMCON interval" >&2
    tcpdump -enn -r "$work_dir/receiver${idx}-egress.pcap" >&2 || true
    exit 1
  fi
done

echo "===EMCON NETNS ZERO EGRESS OK==="
