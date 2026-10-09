# Laboratory target: vsftpd
#
# Installed from the Debian bullseye repositories, so the version is whatever
# the distribution actually ships. That version is detected and correlated like
# any other — it is NOT pinned to manufacture a specific CVE result.
#
# Port 21 is classified eligible_for_isolation in approved_services.yaml.
FROM debian:bullseye

COPY targets/common/setup-ssh.sh /tmp/setup-ssh.sh
COPY build/authorized_keys /tmp/authorized_keys
RUN sh /tmp/setup-ssh.sh && rm -f /tmp/setup-ssh.sh

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends vsftpd > /dev/null \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Anonymous read-only FTP. Deliberately permissive: this is a test target on an
# isolated network, and an exposed anonymous FTP service is the condition the
# approved-service policy is meant to flag.
RUN mkdir -p /srv/ftp /var/run/vsftpd/empty \
    && echo "CyberShield lab target - authorized test environment only" \
            > /srv/ftp/README.txt \
    && printf '%s\n' \
        'listen=YES' \
        'listen_ipv6=NO' \
        'anonymous_enable=YES' \
        'local_enable=NO' \
        'write_enable=NO' \
        'anon_root=/srv/ftp' \
        'no_anon_password=YES' \
        'secure_chroot_dir=/var/run/vsftpd/empty' \
        'pam_service_name=vsftpd' \
        'seccomp_sandbox=NO' \
        > /etc/vsftpd.conf

COPY targets/common/entrypoint.sh /usr/local/bin/cybershield-entrypoint
RUN chmod +x /usr/local/bin/cybershield-entrypoint

EXPOSE 21 22
ENTRYPOINT ["/usr/local/bin/cybershield-entrypoint"]
CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
