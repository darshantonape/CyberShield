# CyberShield Laboratory Targets

**AUTHORIZED TEST ENVIRONMENT ONLY.** These containers run deliberately
outdated and deliberately exposed services. Never run them on a network you do
not control, and never publish their ports beyond the isolated lab network.

---

## Targets

| Container | IP | Service | Port | Policy | Management |
|---|---|---|---|---|---|
| `cybershield-lab-web` | 172.30.0.11 | Apache httpd **2.4.49** | 8080 | `eligible_for_isolation` | sshd 22 |
| `cybershield-lab-ftp` | 172.30.0.12 | vsftpd (Debian bullseye) | 21 | `eligible_for_isolation` | sshd 22 |
| `cybershield-lab-cache` | 172.30.0.13 | Redis **5.0**, no auth | 6379 | `eligible_for_isolation` | sshd 22 |
| `cybershield-lab-db` | 172.30.0.14 | MariaDB **10.5** | 3306 | `eligible_for_isolation` | sshd 22 |

Only Apache is version-pinned, chosen because 2.4.49 carries CVE-2021-41773
(CVSS 9.8) and CVE-2021-42013. vsftpd, Redis and MariaDB install whatever their
base image provides; their versions are detected and correlated like any other
rather than staged to manufacture a particular result.

### Why these ports

Apache listens on **8080, not 80**. Ports 22, 80 and 443 are on the protected
list and can never be isolated, so a service on 80 could not demonstrate
exposure reduction at all. SSH stays on 22 on every target precisely so the
anti-lockout guard is exercised: attempting to isolate it must be refused.

### Why no published ports

Nothing is published to the Docker host. A published-port side channel would
give each service a second network path, so a service could remain reachable
after its container-side rule was applied — making a failed isolation look
successful. One entry point keeps verification honest.

---

## Architecture notes

Each target carries `NET_ADMIN` (not `--privileged`) and starts with an
**empty `nftables` table and chain named `cybershield`**, policy `accept`:

```
table inet cybershield {
    chain input { type filter hook input priority 0; policy accept; }
}
```

Created at container start so that CyberShield never has to build top-level
firewall structure at remediation time, and so rollback is a flush of one chain
CyberShield alone owns — it cannot disturb any pre-existing rule.

SSH is key-only: `PermitRootLogin prohibit-password`, `PasswordAuthentication
no`. The public half of `~/.ssh/cybershield_lab_ed25519` is baked into each
image at build time.

---

## Bring-up

```bash
cd ~/Desktop/CyberShield/lab
cp ~/.ssh/cybershield_lab_ed25519.pub build/authorized_keys   # once
docker compose build
docker compose up -d
```

### Reachability from macOS

The containers sit on an isolated bridge inside the Colima VM. Two things are
required, and **neither survives a reboot**:

1. The Colima VM needs a host-reachable address:
   `colima start --network-address` (gives 192.168.64.2).
2. A route plus a VM-side forwarding rule:
   `sudo sh ../scripts/lab_route.sh add`

The second step is not just a route. Docker installs

```
-A DOCKER ! -i br-<lab> -o br-<lab> -j DROP
```

which drops traffic entering the lab bridge from anywhere else, including the
Colima host interface. `lab_route.sh` therefore also inserts an ACCEPT into
`DOCKER-USER` (traversed first) inside the VM. A macOS route on its own does
**not** work — verified.

Check state at any time with `sh ../scripts/lab_route.sh status`.

---

## Teardown

```bash
docker compose down                 # stop and remove containers
docker compose down --rmi local     # also remove the built images
sudo sh ../scripts/lab_route.sh del # remove the host route
```

The route and the VM firewall rule are in-memory only and disappear when the
Mac or the Colima VM restarts.

---

## Build notes

Two problems were hit building these images, both recorded here because they
will recur with any similarly old base:

* **`httpd:2.4.49` is Debian buster-based**, and buster has moved to
  `archive.debian.org`; `deb.debian.org` returns no Release file. The shared
  `setup-ssh.sh` detects EOL releases (jessie/stretch/buster), repoints
  `sources.list` at the archive, and sets `Acquire::Check-Valid-Until "false"`.
* **Buster ships OpenSSH 7.9**, which predates `sshd_config.d/` Include
  support, so the drop-in config is ignored there. The inline `sed` on
  `/etc/ssh/sshd_config` is what actually enforces the key-only policy on those
  images.

`mysql:5.7` publishes no arm64 image, so MariaDB 10.5 is used instead. All four
bases (`httpd:2.4.49`, `debian:bullseye`, `redis:5.0`, `mariadb:10.5`) have
native arm64 builds, so no x86_64 emulation is required on Apple Silicon.
