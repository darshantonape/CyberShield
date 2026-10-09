#!/bin/sh
# Shared laboratory-target entrypoint.
#
# Starts the SSH management channel, prepares an EMPTY nftables chain for
# CyberShield to write into, then hands off to the target service.
#
# The chain is created here, empty and with policy accept, so that:
#   * CyberShield never has to create top-level firewall structure at
#     remediation time, and
#   * rollback is a flush of one chain that CyberShield alone owns, which
#     cannot disturb any pre-existing rule on the target.
set -e

echo "[cybershield-lab] AUTHORIZED TEST TARGET — deliberately vulnerable. Do not expose."

mkdir -p /run/sshd
/usr/sbin/sshd

# `inet` covers IPv4 and IPv6. Priority 0 is the standard filter hook.
# policy accept: this chain blocks nothing until CyberShield adds a rule.
nft add table inet cybershield 2>/dev/null || true
nft add chain inet cybershield input \
    '{ type filter hook input priority 0 ; policy accept ; }' 2>/dev/null || true

echo "[cybershield-lab] sshd started; empty nftables chain 'cybershield' ready."
nft list table inet cybershield || true

exec "$@"
