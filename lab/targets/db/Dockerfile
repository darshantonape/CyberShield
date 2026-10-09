# Laboratory target: MariaDB 10.5
#
# mysql:5.7 publishes no arm64 image, so MariaDB is used instead. Its detected
# version is correlated like any other; nothing is pinned to force a result.
#
# Port 3306 is classified eligible_for_isolation: a database should not be
# reachable across the network.
FROM mariadb:10.5

COPY targets/common/setup-ssh.sh /tmp/setup-ssh.sh
COPY build/authorized_keys /tmp/authorized_keys
RUN sh /tmp/setup-ssh.sh && rm -f /tmp/setup-ssh.sh

COPY targets/common/entrypoint.sh /usr/local/bin/cybershield-entrypoint
RUN chmod +x /usr/local/bin/cybershield-entrypoint

EXPOSE 22 3306
ENTRYPOINT ["/usr/local/bin/cybershield-entrypoint"]
# Chains into the image's own docker-entrypoint.sh, which performs first-run
# database initialisation and drops privileges.
CMD ["docker-entrypoint.sh", "mysqld"]
