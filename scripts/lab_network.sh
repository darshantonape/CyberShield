#!/bin/sh
# Set up macOS reachability to the CyberShield laboratory targets.
#
# Needs NO sudo on the Mac. Colima has passwordless sudo inside the VM, and the
# Mac already routes to 192.168.64.0/24 to reach the VM itself.
#
# How this works, and why the obvious approaches do not:
#
#   * A host route to the container bridge (172.30.0.0/24) is not enough.
#     Docker installs "-A DOCKER ! -i br-<lab> -o br-<lab> -j DROP", which drops
#     traffic entering the lab bridge from anywhere else. It also needs sudo on
#     the Mac.
#   * A macvlan network does not work either: Colima's vmnet interface refuses
#     additional MAC addresses, so macvlan containers are unreachable.
#   * IP ALIASES on the VM's col0 interface DO work. They share the interface's
#     existing MAC, so ARP resolves normally, and each target gets its own
#     address — preserving four distinct hosts for host discovery.
#
# Aliases are in-memory and disappear when the VM restarts. Re-run this then.
#
# Usage:
#   sh scripts/lab_network.sh up       add aliases and start the lab
#   sh scripts/lab_network.sh down     stop the lab and remove aliases
#   sh scripts/lab_network.sh status   show current state

set -e

ALIASES="11 12 13 14"
IFACE="col0"
LAB_DIR="$(cd "$(dirname "$0")/../lab" && pwd)"

require_colima() {
    if ! colima status >/dev/null 2>&1; then
        echo "Colima is not running. Start it with:" >&2
        echo "  colima start --network-address" >&2
        exit 1
    fi
    if [ -z "$(colima list --json 2>/dev/null | /usr/bin/python3 -c \
        'import sys,json;print(json.loads(sys.stdin.readline()).get("address",""))')" ]; then
        echo "The Colima VM has no host-reachable address." >&2
        echo "Recreate it with: colima stop && colima start --network-address" >&2
        exit 1
    fi
}

case "${1:-status}" in
    up)
        require_colima
        echo "Adding IP aliases on $IFACE inside the VM..."
        for n in $ALIASES; do
            colima ssh -- sudo ip addr add "192.168.64.$n/24" dev "$IFACE" 2>/dev/null || true
        done
        echo "Starting laboratory targets..."
        # --force-recreate is not optional. The aliases this script just added
        # do not survive a VM restart, and neither does a container's binding
        # to them: `docker compose up -d` START s a pre-existing stopped
        # container with the port publishing it was CREATED with, which after a
        # VM restart is none at all. The script then printed "Started" for four
        # containers that published nothing, and every target read UNREACHABLE
        # with no indication why. Recreating is cheap — these containers hold
        # no state worth keeping.
        (cd "$LAB_DIR" && docker compose up -d --force-recreate)
        echo
        sh "$0" status
        ;;
    down)
        echo "Stopping laboratory targets..."
        (cd "$LAB_DIR" && docker compose down) || true
        echo "Removing IP aliases..."
        for n in $ALIASES; do
            colima ssh -- sudo ip addr del "192.168.64.$n/24" dev "$IFACE" 2>/dev/null || true
        done
        echo "done"
        ;;
    status)
        printf 'Target reachability from this Mac:\n'
        printf '  %-12s %-16s %-6s %s\n' NAME ADDRESS PORT STATE
        for spec in "lab-web 192.168.64.11 8080" "lab-ftp 192.168.64.12 21" \
                    "lab-cache 192.168.64.13 6379" "lab-db 192.168.64.14 3306"; do
            # POSIX sh word-splitting; note zsh would NOT split this, so always
            # run this script with sh.
            set -- $spec
            if nc -z -G 2 "$2" "$3" 2>/dev/null; then st="reachable"; else st="UNREACHABLE"; fi
            printf '  %-12s %-16s %-6s %s\n' "$1" "$2" "$3" "$st"
            if nc -z -G 2 "$2" 2222 2>/dev/null; then st="reachable"; else st="UNREACHABLE"; fi
            printf '  %-12s %-16s %-6s %s\n' "" "$2" 2222 "$st"
        done
        ;;
    *)
        echo "Usage: $0 {up|down|status}" >&2
        exit 2
        ;;
esac
