#!/bin/sh
# Add or remove the Mac route to the CyberShield laboratory network.
#
# The lab containers hold static addresses on an isolated Docker bridge
# (172.30.0.0/24) inside the Colima VM. macOS has no route to that subnet by
# default, so Nmap cannot see the targets as distinct hosts without this.
#
# Requires sudo: modifying the host routing table is a privileged operation.
# The change is in-memory only and does NOT survive a reboot, which is
# deliberate — the lab route should not persist beyond a working session.
#
# Usage:
#   sudo sh scripts/lab_route.sh add
#   sudo sh scripts/lab_route.sh del
#   sh scripts/lab_route.sh status      (no sudo needed)

set -e

LAB_SUBNET="172.30.0.0/24"
LAB_NET="172.30.0.0"
LAB_MASK="255.255.255.0"

vm_address() {
    colima list --json 2>/dev/null \
        | /usr/bin/python3 -c \
          'import sys,json;print(json.loads(sys.stdin.readline()).get("address",""))' \
          2>/dev/null
}

status() {
    printf 'Colima VM address : %s\n' "$(vm_address)"
    if netstat -rn -f inet | grep -qE '^172\.30'; then
        printf 'Route to %s : PRESENT\n' "$LAB_SUBNET"
        netstat -rn -f inet | grep -E '^172\.30' | sed 's/^/  /'
    else
        printf 'Route to %s : ABSENT\n' "$LAB_SUBNET"
    fi
    printf '\nTarget reachability from this Mac:\n'
    for hp in "172.30.0.11 8080 lab-web" "172.30.0.12 21 lab-ftp" \
              "172.30.0.13 6379 lab-cache" "172.30.0.14 3306 lab-db"; do
        set -- $hp
        if nc -z -G 2 "$1" "$2" 2>/dev/null; then
            printf '  %-10s %s:%s reachable\n' "$3" "$1" "$2"
        else
            printf '  %-10s %s:%s NOT reachable\n' "$3" "$1" "$2"
        fi
    done
}

case "${1:-status}" in
    add)
        VM="$(vm_address)"
        if [ -z "$VM" ]; then
            echo "Colima has no network address." >&2
            echo "Start it with: colima start --network-address" >&2
            exit 1
        fi

        # A Mac route alone is not enough. Docker installs
        #   -A DOCKER ! -i <lab-bridge> -o <lab-bridge> -j DROP
        # which drops traffic entering the lab bridge from anywhere else,
        # including the Colima host interface. DOCKER-USER is traversed before
        # that rule, so an ACCEPT there is what actually lets the Mac through.
        # Colima has passwordless sudo, so this half needs no Mac privileges.
        LAB_BRIDGE="$(colima ssh -- sudo ip -o -4 addr show 2>/dev/null \
            | awk '$4 ~ /^172\.30\.0\./ {print $2}' | head -1)"
        if [ -n "$LAB_BRIDGE" ]; then
            echo "Allowing col0 -> $LAB_BRIDGE forwarding inside the VM"
            colima ssh -- sudo iptables -C DOCKER-USER -i col0 -o "$LAB_BRIDGE" -j ACCEPT \
                2>/dev/null \
                || colima ssh -- sudo iptables -I DOCKER-USER 1 -i col0 -o "$LAB_BRIDGE" -j ACCEPT
        else
            echo "WARNING: lab bridge not found in the VM; is the lab running?" >&2
        fi

        echo "Adding route: $LAB_SUBNET via $VM"
        route -n add -net "$LAB_NET" -netmask "$LAB_MASK" "$VM" 2>/dev/null \
            || echo "  (route already present)"
        echo
        status
        ;;
    del)
        echo "Removing route: $LAB_SUBNET"
        route -n delete -net "$LAB_NET" -netmask "$LAB_MASK" 2>/dev/null \
            || echo "  (no route to remove)"
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {add|del|status}" >&2
        exit 2
        ;;
esac
