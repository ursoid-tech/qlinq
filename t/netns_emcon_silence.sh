#!/usr/bin/env bash

set -euo pipefail

for command in ip nsenter openssl python3 tc tcpdump timeout unshare; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "check-emcon-netns requires $command." >&2
    exit 77
  }
done

# Always put the bridge and its peers in a new network namespace, even for root.
if [[ ${1:-} != --isolated ]]; then
  unshare_args=(--net)
  if [[ $(id -u) -ne 0 ]]; then
    unshare_args+=(--user --map-root-user)
  fi
  exec unshare "${unshare_args[@]}" "$0" --isolated
fi

repo_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
emcon="$repo_root/qlinq-emcon"
multicast_helper="$repo_root/t/netns_emcon_multicast.py"
if [[ ! -x "$emcon" ]]; then
  echo "Build $emcon before running this harness." >&2
  exit 1
fi
work_dir=$(mktemp -d /tmp/qlinq-emcon-netns.XXXXXX)
declare -A active_pids=()

cleanup() {
  local status=$?
  if ((status != 0)); then
    for log in "$work_dir"/*.log "$work_dir"/*/*.log; do
      [[ -f "$log" ]] || continue
      echo "== $log ==" >&2
      cat "$log" >&2
    done
  fi
  for pid in "${!active_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait || true
  rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

wait_for() {
  local pid=$1
  shift
  for ((attempt = 0; attempt < 100; attempt++)); do
    kill -0 "$pid" 2>/dev/null || break
    if "$@"; then
      return 0
    fi
    sleep 0.05
  done
  echo "Process $pid did not become ready ($*)." >&2
  return 1
}

namespace_ready() {
  local namespace
  namespace=$(readlink "/proc/$1/ns/net") || return 1
  [[ "$namespace" != "$(readlink /proc/self/ns/net)" ]]
}

add_namespace() {
  local variable=$1 pid
  unshare --net -- sleep infinity &
  pid=$!
  active_pids[$pid]=1
  wait_for "$pid" namespace_ready "$pid"
  printf -v "$variable" '%s' "$pid"
}

wait_process() {
  local pid=$1
  wait "$pid"
  unset "active_pids[$pid]"
}

in_namespace() {
  local pid=$1
  shift
  nsenter --target "$pid" --net -- "$@"
}

add_namespace source_ns
add_namespace receiver1_ns
add_namespace receiver2_ns

ip link add br0 type bridge mcast_snooping 0
ip link set br0 up
for link in source rx1 rx2; do
  ip link add "br-$link" type veth peer name "$link"
  ip link set "br-$link" master br0
  ip link set "br-$link" up
done
ip link set source netns "$source_ns"
ip link set rx1 netns "$receiver1_ns"
ip link set rx2 netns "$receiver2_ns"

configure_link() {
  local namespace=$1 link=$2 id=$3
  in_namespace "$namespace" ip link set "$link" addrgenmode none
  if [[ "$link" != source ]]; then
    # Block all receiver Ethernet egress before addresses or groups are added.
    in_namespace "$namespace" tc qdisc add dev "$link" clsact
    in_namespace "$namespace" tc filter add dev "$link" egress matchall skip_hw action drop
  fi
  in_namespace "$namespace" ip address add "10.242.0.$id/24" dev "$link"
  in_namespace "$namespace" ip -6 address add "fd42:242::$id/64" dev "$link" nodad
  in_namespace "$namespace" ip -6 address add "fe80::$id/64" dev "$link" nodad
  in_namespace "$namespace" ip link set lo up
  in_namespace "$namespace" ip link set "$link" up
  in_namespace "$namespace" ip route add 224.0.0.0/4 dev "$link"
}

configure_link "$source_ns" source 1
configure_link "$receiver1_ns" rx1 2
configure_link "$receiver2_ns" rx2 3

source_index=$(in_namespace "$source_ns" ip -o link show source | cut -d: -f1)
receiver1_index=$(in_namespace "$receiver1_ns" ip -o link show rx1 | cut -d: -f1)
receiver2_index=$(in_namespace "$receiver2_ns" ip -o link show rx2 | cut -d: -f1)
[[ "$source_index" != "$receiver1_index" && "$source_index" != "$receiver2_index" ]]

umask 077
openssl genpkey -algorithm ED25519 -out "$work_dir/signer.key"
python3 -c 'import sys; sys.stdout.buffer.write(bytes((i * 43 + i // 256) % 256 for i in range(6145)))' >"$work_dir/input"

start_capture() {
  local variable=$1 namespace=$2 link=$3 file=$4 pid
  local command=(tcpdump -Z root --immediate-mode -Q in -U -n -i "$link" -w "$file.pcap")
  shift 4
  if [[ "$namespace" != self ]]; then
    command=(nsenter --target "$namespace" --net -- "${command[@]}")
  fi
  "${command[@]}" "$@" >"$file.log" 2>&1 &
  pid=$!
  active_pids[$pid]=1
  wait_for "$pid" grep -q "listening on" "$file.log"
  printf -v "$variable" '%s' "$pid"
}

stop_capture() {
  local pid=$1
  kill -INT "$pid"
  wait_process "$pid"
}

receiver_ready() {
  compgen -G "$1/receiver-*.claim" >/dev/null
}

check_query_control() {
  local router_source=$1 destination=$2 directory=$3 capture
  # Open one test link after the protected interval. The peer tap must see the
  # membership report when the same router query is delivered without the gate.
  start_capture capture self br-rx1 "$directory/control"
  in_namespace "$receiver1_ns" tc filter del dev rx1 egress
  in_namespace "$source_ns" python3 "$multicast_helper" query source "$router_source" "$destination"
  sleep 0.3
  in_namespace "$receiver1_ns" tc filter add dev rx1 egress matchall skip_hw action drop
  stop_capture "$capture"
  tcpdump -Z root -nn -v -r "$directory/control.pcap" >"$directory/control.txt"
  if ! grep -Ei 'igmp .*report|multicast listener report' "$directory/control.txt" |
      grep -F "$destination" >/dev/null; then
    echo "Peer capture failed to observe a membership report on the open link." >&2
    cat "$directory/control.txt" >&2
    return 1
  fi
}

check_family() {
  local family=$1 source=$2 destination=$3 router_source=$4 query_filter=$5
  local sender_endpoint="$source:12070" group_endpoint="$destination:12071"
  if [[ "$family" == 6 ]]; then
    sender_endpoint="[$source]:12070"
    group_endpoint="[$destination]:12071"
  fi
  local directory="$work_dir/ip$family"
  mkdir -p "$directory/"{sender,rx1,rx2}
  cat >"$directory/session.conf" <<CONF
session_id=random
sender_id=random
flow_id=random
key_epoch=1
initial_packet_number=100
valid_for_seconds=120
source=$sender_endpoint
destination=$group_endpoint
interface_index=$source_index
replay_window_packets=64
rate_bytes_per_second=1000000
burst_bytes=4096
metadata_repeat_interval_ms=10000
terminal_repeat_count=3
symbol_size=512
repair_symbols=4
stream=7,data,4096,netns
CONF
  "$emcon" manifest create "$directory/session.conf" --signing-key "$work_dir/signer.key" \
    --output "$directory/manifest" --signature "$directory/signature" \
    --generate-traffic-key "$directory/key" --public-key-output "$directory/signer.pub"
  local options=(--manifest "$directory/manifest" --signature "$directory/signature"
    --public-key "$directory/signer.pub" --traffic-key "$directory/key" --group 42)

  local member1 member2
  nsenter --target "$receiver1_ns" --net -- python3 "$multicast_helper" hold \
    rx1 "$destination" "$directory/member1.ready" >"$directory/member1.log" 2>&1 &
  member1=$!
  active_pids[$member1]=1
  nsenter --target "$receiver2_ns" --net -- python3 "$multicast_helper" hold \
    rx2 "$destination" "$directory/member2.ready" >"$directory/member2.log" 2>&1 &
  member2=$!
  active_pids[$member2]=1
  wait_for "$member1" test -f "$directory/member1.ready"
  wait_for "$member2" test -f "$directory/member2.ready"

  local egress1 egress2 query1 query2
  # Peer ingress is everything that made it onto the link from the receiver.
  start_capture egress1 self br-rx1 "$directory/egress1"
  start_capture egress2 self br-rx2 "$directory/egress2"
  start_capture query1 "$receiver1_ns" rx1 "$directory/query1" "$query_filter"
  start_capture query2 "$receiver2_ns" rx2 "$directory/query2" "$query_filter"

  local receiver1 receiver2
  nsenter --target "$receiver1_ns" --net -- timeout 10 "$emcon" receive "${options[@]}" \
    --preprovisioned --interface rx1 --state-dir "$directory/rx1" "$directory/output1" \
    >"$directory/receiver1.log" 2>&1 &
  receiver1=$!
  active_pids[$receiver1]=1
  nsenter --target "$receiver2_ns" --net -- timeout 10 "$emcon" receive "${options[@]}" \
    --preprovisioned --interface rx2 --state-dir "$directory/rx2" "$directory/output2" \
    >"$directory/receiver2.log" 2>&1 &
  receiver2=$!
  active_pids[$receiver2]=1
  wait_for "$receiver1" receiver_ready "$directory/rx1"
  wait_for "$receiver2" receiver_ready "$directory/rx2"
  in_namespace "$receiver1_ns" python3 "$multicast_helper" check-membership rx1 "$destination"
  in_namespace "$receiver2_ns" python3 "$multicast_helper" check-membership rx2 "$destination"

  in_namespace "$source_ns" python3 "$multicast_helper" query source "$router_source" "$destination"
  sleep 0.3
  in_namespace "$source_ns" timeout 10 "$emcon" send "${options[@]}" --block-size 2048 \
    --state-dir "$directory/sender" "$work_dir/input" >"$directory/sender.log" 2>&1
  wait_process "$receiver1"
  wait_process "$receiver2"

  for pid in "$query1" "$query2" "$egress1" "$egress2"; do
    stop_capture "$pid"
  done
  for receiver in 1 2; do
    cmp "$work_dir/input" "$directory/output$receiver"
    tcpdump -Z root -nn -v -r "$directory/query$receiver.pcap" >"$directory/query$receiver.txt"
    grep -Ei 'igmp query|multicast listener query' "$directory/query$receiver.txt"
    if ! grep -q '^0 packets dropped by kernel$' "$directory/egress$receiver.log"; then
      echo "IPv$family receiver $receiver egress capture lost packets." >&2
      return 1
    fi
    tcpdump -Z root -enn -r "$directory/egress$receiver.pcap" >"$directory/egress$receiver.txt"
    if [[ -s "$directory/egress$receiver.txt" ]]; then
      echo "IPv$family receiver $receiver emitted Ethernet traffic." >&2
      cat "$directory/egress$receiver.txt" >&2
      return 1
    fi
  done
  check_query_control "$router_source" "$destination" "$directory"
  kill "$member1" "$member2"
  wait "$member1" || [[ $? == 143 ]]
  wait "$member2" || [[ $? == 143 ]]
  unset "active_pids[$member1]" "active_pids[$member2]"
  echo "IPv$family recovered exact data on both receivers with zero Ethernet egress."
}

check_family 4 10.242.0.1 239.42.42.1 10.242.0.1 'igmp and igmp[0] = 0x11'
check_family 6 fd42:242::1 ff15::4242 fe80::1 'ip6 protochain 58'
echo "===EMCON NETNS ZERO EGRESS OK==="
