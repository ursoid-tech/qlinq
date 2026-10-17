#!/usr/bin/env bash
# Copy this directory to qlinq/examples/mtcp/. No host routes are modified.
set -Eeuo pipefail
export LC_ALL=C
STATE=/run/qlinq-mtcp-examples
CLIENT=qm-client
SERVER=qm-server
ROUTER=qm-router

usage() {
    cat <<'EOF'
Usage: sudo ./lab.sh up mptcp|qlinq equal|unequal
       sudo ./lab.sh client COMMAND [ARG ...]
       sudo ./lab.sh server COMMAND [ARG ...]
       sudo ./lab.sh status
       sudo ./lab.sh down
Only one lab at a time. qlinq uses its native reliable API; no TUN required.
EOF
}
fail() { echo "ERROR: $*" >&2; exit 1; }
ns() { local name=$1; shift; ip netns exec "$name" "$@"; }
need() { command -v "$1" >/dev/null || fail "Install $1 first"; }
owned() { [[ -f "$STATE/owner" ]] && [[ $(cat "$STATE/owner") == qlinq-mtcp-examples-v1 ]]; }

teardown() {
    [[ -e "$STATE" ]] || { echo 'No lab is running.'; return; }
    owned || fail "Unrecognized state directory: $STATE"
    local name identity pid
    while read -r name identity; do
        [[ -e /run/netns/$name ]] || continue
        [[ $(stat -Lc '%d:%i' "/run/netns/$name") == "$identity" ]] ||
            fail "Namespace $name was replaced; refusing to remove it"
        # These are the processes inside the namespaces created by this lab.
        for pid in $(ip netns pids "$name"); do kill -TERM "$pid" 2>/dev/null || true; done
    done < "$STATE/namespaces"
    sleep 0.3
    while read -r name identity; do
        [[ -e /run/netns/$name ]] || continue
        for pid in $(ip netns pids "$name"); do kill -KILL "$pid" 2>/dev/null || true; done
        ip netns del "$name"
    done < "$STATE/namespaces"
    rm -rf -- "$STATE"
    echo 'Removed the lab namespaces, processes and test credentials.'
}

network() {
    local name i endpoint router address network rate delay limit
    for name in "$CLIENT" "$SERVER" "$ROUTER"; do
        ip netns add "$name"
        printf '%s %s\n' "$name" "$(stat -Lc '%d:%i' "/run/netns/$name")" >> "$STATE/namespaces"
        ns "$name" ip link set lo up
        ns "$name" sysctl -qw net.ipv4.conf.all.rp_filter=0
    done
    ns "$ROUTER" sysctl -qw net.ipv4.ip_forward=1
    for i in 1 2; do
        rate=100; delay=10
        if [[ $PROFILE == unequal && $i == 2 ]]; then rate=40; delay=40; fi
        for name in "$CLIENT" "$SERVER"; do
            if [[ $name == "$CLIENT" ]]; then
                endpoint=c$i; router=rc$i; address=1; network=231
            else
                endpoint=s$i; router=rs$i; address=2; network=232
            fi
            ns "$ROUTER" ip link add "$router" type veth peer name "$endpoint"
            ns "$ROUTER" ip link set "$endpoint" netns "$name"
            ns "$ROUTER" ip addr add "10.$network.$i.254/24" dev "$router"
            ns "$ROUTER" ip link set "$router" up
            ns "$name" ip addr add "10.$network.$i.$address/24" dev "$endpoint"
            ns "$name" ip link set "$endpoint" up
            ns "$name" sysctl -qw "net.ipv4.conf.$endpoint.rp_filter=0"
            ns "$ROUTER" sysctl -qw "net.ipv4.conf.$router.rp_filter=0"
            ns "$ROUTER" ethtool -K "$router" tso off gso off gro off >/dev/null
            ns "$name" ethtool -K "$endpoint" tso off gso off gro off >/dev/null
            ns "$ROUTER" tc qdisc add dev "$router" root handle 1: htb default 10
            ns "$ROUTER" tc class add dev "$router" parent 1: classid 1:10 htb \
                rate "${rate}mbit" ceil "${rate}mbit" burst 16k cburst 16k
            limit=$(( (rate * 1000000 * delay + 11999999) / 12000000 + 32 ))
            ns "$ROUTER" tc qdisc add dev "$router" parent 1:10 handle 10: \
                netem limit "$limit" delay "${delay}ms"
        done
        ns "$CLIENT" ip route add "10.232.$i.0/24" via "10.231.$i.254" dev "c$i"
        ns "$SERVER" ip route add "10.231.$i.0/24" via "10.232.$i.254" dev "s$i"
    done
    # The second source address must use the second independent route, even
    # when connecting to the server's primary address.
    ns "$CLIENT" ip rule add from 10.231.2.1 table 102
    ns "$CLIENT" ip route add table 102 10.231.2.0/24 dev c2
    ns "$CLIENT" ip route add table 102 10.232.1.0/24 via 10.231.2.254 dev c2
    ns "$ROUTER" ip rule add from 10.231.2.1 to 10.232.1.2 table 102
    ns "$ROUTER" ip route add table 102 10.232.2.0/24 dev rs2
    ns "$ROUTER" ip route add table 102 10.232.1.2/32 via 10.232.2.2 dev rs2
}

[[ ${1:-} != --help && $# != 0 ]] || { usage; exit 0; }
[[ $EUID == 0 ]] || fail 'Run this command with sudo'
need ip
case $1 in
    up)
        MODE=${2:-}; PROFILE=${3:-}
        [[ $MODE == mptcp || $MODE == qlinq ]] || fail 'Choose mptcp or qlinq'
        [[ $PROFILE == equal || $PROFILE == unequal ]] || fail 'Choose equal or unequal'
        for tool in ethtool tc sysctl openssl; do need "$tool"; done
        [[ ! -e $STATE ]] || fail 'A lab already exists; run ./lab.sh down first'
        for name in "$CLIENT" "$SERVER" "$ROUTER"; do
            [[ ! -e /run/netns/$name ]] || fail "Namespace $name already exists; refusing to reuse it"
        done
        umask 077
        mkdir -m 700 "$STATE"
        printf 'qlinq-mtcp-examples-v1\n' > "$STATE/owner"
        : > "$STATE/namespaces"
        trap 'rc=$?; if ((rc)); then tail -n 12 "$STATE/"*.log 2>/dev/null || true; teardown; fi' EXIT
        trap 'exit 130' INT TERM
        printf '%s\n' "$MODE" > "$STATE/mode"
        printf '%s\n' "$PROFILE" > "$STATE/profile"
        network
        if [[ $MODE == mptcp ]]; then
            for name in "$CLIENT" "$SERVER"; do
                ns "$name" sysctl -qw net.mptcp.enabled=1
                ns "$name" ip mptcp limits set subflows 2 add_addr_accepted 2
            done
            ns "$CLIENT" ip mptcp endpoint add 10.231.2.1 dev c2 subflow
        fi
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -days 2 -subj /CN=isolated-comparison \
            -addext subjectAltName=IP:10.232.1.2 \
            -addext extendedKeyUsage=serverAuth,clientAuth \
            -keyout "$STATE/key.pem" -out "$STATE/cert.pem" 2>/dev/null
        echo "Ready: $MODE / $PROFILE. Use ./run.sh, or ./lab.sh client|server COMMAND."
        ;;
    down) teardown ;;
    client|server)
        owned || fail 'Start a lab first'
        side=$1; shift
        (($#)) || fail 'Supply a command to execute'
        if [[ $side == client ]]; then ns "$CLIENT" "$@"; else ns "$SERVER" "$@"; fi
        ;;
    status)
        owned || fail 'No lab is running'
        printf 'Mode: %s; profile: %s\n' "$(cat "$STATE/mode")" "$(cat "$STATE/profile")"
        for name in "$CLIENT" "$SERVER"; do
            echo "=== $name ==="
            ns "$name" ip -br addr
            ns "$name" ip mptcp endpoint show
        done
        ;;
    *) usage; exit 1 ;;
esac
