# Laboratory target: Redis 5.0
#
# Redis 5.0 is unauthenticated by default and, historically, bound to all
# interfaces. Port 6379 is classified eligible_for_isolation.
#
# Verified during development: cpe:2.3:a:redis:redis:5.0.14 returns 21 CVEs,
# while redislabs:redis and pivotal_software:redis return 0 despite ranking
# higher in the NVD CPE dictionary keyword search.
FROM redis:5.0

COPY targets/common/setup-ssh.sh /tmp/setup-ssh.sh
COPY build/authorized_keys /tmp/authorized_keys
RUN sh /tmp/setup-ssh.sh && rm -f /tmp/setup-ssh.sh

COPY targets/common/entrypoint.sh /usr/local/bin/cybershield-entrypoint
RUN chmod +x /usr/local/bin/cybershield-entrypoint

EXPOSE 22 6379
ENTRYPOINT ["/usr/local/bin/cybershield-entrypoint"]
# Chains into the image's own docker-entrypoint.sh, which our entrypoint would
# otherwise replace. Bound to all interfaces with no auth: exactly the exposure
# this lab exists to detect.
CMD ["docker-entrypoint.sh", "redis-server", "--bind", "0.0.0.0", "--protected-mode", "no"]
