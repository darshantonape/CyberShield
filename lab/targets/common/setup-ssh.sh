#!/bin/sh
# Install the SSH management channel and nftables into a laboratory target.
#
# Key-based root login only. Password authentication is disabled outright:
# CyberShield never handles passwords, and a lab target with a guessable root
# password is a liability even on an isolated network.
set -e

export DEBIAN_FRONTEND=noninteractive

# Old base images are the point of this lab, and their Debian releases are EOL:
# httpd:2.4.49 is buster-based, and deb.debian.org no longer carries a Release
# file for it. Repoint EOL releases at archive.debian.org and stop apt
# rejecting the (legitimately) expired repository metadata.
CODENAME="$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-}")"
case "$CODENAME" in
    jessie|stretch|buster)
        echo "[setup-ssh] Debian $CODENAME is EOL; switching to archive.debian.org"
        cat > /etc/apt/sources.list <<EOF
deb http://archive.debian.org/debian $CODENAME main
deb http://archive.debian.org/debian-security $CODENAME/updates main
EOF
        rm -f /etc/apt/sources.list.d/*.list 2>/dev/null || true
        echo 'Acquire::Check-Valid-Until "false";' \
            > /etc/apt/apt.conf.d/99cybershield-archive
        ;;
esac

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    openssh-server \
    nftables \
    iproute2 \
    ca-certificates \
    > /dev/null

mkdir -p /root/.ssh /run/sshd
chmod 700 /root/.ssh
cp /tmp/authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
rm -f /tmp/authorized_keys

# OpenSSH gained sshd_config.d Include support in 8.2; buster ships 7.9, where
# this directory does not exist and the drop-in is ignored. The inline sed
# below is what actually enforces the policy on those images.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/cybershield.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
UseDNS no
EOF

# Older sshd builds ignore sshd_config.d; enforce the same settings inline.
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

ssh-keygen -A

apt-get clean
rm -rf /var/lib/apt/lists/*
