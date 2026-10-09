# Laboratory Setup

Target definitions and build notes live in
[`lab/README.md`](../lab/README.md). This page covers the part that took the
most work to get right: **making the targets reachable from macOS**.

## Topology

Four containers on an isolated Docker bridge (`172.30.0.0/24`) inside a local
Colima Linux VM, each published on its **own IP alias** of the VM's `col0`
interface:

| Target | Alias | Service | Port | Management |
|---|---|---|---|---|
| lab-web | 192.168.64.11 | Apache httpd 2.4.49 | 8080 | sshd 2222 |
| lab-ftp | 192.168.64.12 | vsftpd 3.0.3 | 21 | sshd 2222 |
| lab-cache | 192.168.64.13 | Redis 5.0.14 | 6379 | sshd 2222 |
| lab-db | 192.168.64.14 | MariaDB 10.5.29 | 3306 | sshd 2222 |

Authorized scope is `192.168.64.8/29`, covering .8–.15 and deliberately
excluding the Mac (.1) and the VM (.2).

## Bring-up

```bash
colima start --network-address        # VM needs a host-reachable address
sh scripts/lab_network.sh up          # adds aliases, starts the targets
sh scripts/lab_network.sh status      # confirms reachability
```

Neither the aliases nor the containers survive a VM restart. Re-run `up`.

Teardown: `sh scripts/lab_network.sh down`.

## Why IP aliases, and not the two obvious alternatives

Three approaches were tried. Only the third works.

**1. A host route to the container bridge — fails, and needs sudo.**
`sudo route -n add -net 172.30.0.0/24 <vm-ip>` is not sufficient, because Docker
installs:

```
-A DOCKER ! -i br-<lab> -o br-<lab> -j DROP
```

which drops traffic entering the lab bridge from anywhere else, including the
Colima host interface. It would also need a `DOCKER-USER` ACCEPT rule inside the
VM *and* root on the Mac.

**2. A Docker macvlan network — fails.** Colima's `vmnet` interface refuses
additional MAC addresses, so macvlan containers are unreachable from the host.
Verified: 100% packet loss to a macvlan container.

**3. IP aliases on the VM interface — works, and needs no Mac privileges.**
Aliases share the interface's existing MAC, so ARP resolves normally, and macOS
already routes to `192.168.64.0/24` in order to reach the VM. Colima has
passwordless sudo, so the aliases are added inside the VM:

```bash
colima ssh -- sudo ip addr add 192.168.64.11/24 dev col0
```

This preserves **four distinct host addresses**, so host discovery is genuinely
exercised rather than collapsed onto one IP with eight ports.

## Design decisions worth knowing

**SSH is published on 2222, not 22.** The Colima VM's own sshd binds
`0.0.0.0:22`, which occupies port 22 on every alias. Container sshd is therefore
published on 2222, and 2222 is added to the protected-port list.

This produces a **measurement artifact**: `tcp/22` appears open on all four
addresses, but it is the VM's single sshd answering four times, not a service
belonging to any target. It is excluded from per-target metrics.

**Apache listens on 8080, not 80.** Ports 22, 80 and 443 are protected and can
never be isolated, so a service on 80 could not demonstrate exposure reduction
at all.

**Only Apache is version-pinned.** 2.4.49 was chosen for CVE-2021-41773. vsftpd,
Redis and MariaDB install whatever their base image provides; their versions are
detected and correlated like any other rather than staged to manufacture a
result.

**Each container carries `NET_ADMIN`, not `--privileged`**, and starts with an
empty `nftables` table named `cybershield` (policy `accept`), so rollback is a
removal from a set the tool alone owns.

## Build notes

Two problems recur with old base images:

- **`httpd:2.4.49` is Debian buster-based**, and buster has moved to
  `archive.debian.org`; `deb.debian.org` returns no Release file. The shared
  setup script detects EOL releases and repoints `sources.list`.
- **Buster ships OpenSSH 7.9**, which predates `sshd_config.d/` Include support,
  so the drop-in is ignored there and an inline `sed` enforces the key-only
  policy.

`mysql:5.7` publishes no arm64 image, so MariaDB 10.5 is used instead. All four
bases have native arm64 builds, so no x86_64 emulation is needed on Apple
Silicon.
